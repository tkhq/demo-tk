use crate::{
    auth::{KeyCurve, StoredApiKey, secure_create},
    operations::OperationOutput,
};
use anyhow::{Context, Result};
use clap::Args;
use serde_json::json;
use std::path::PathBuf;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// New credential JSON path. Existing files are never overwritten.
    #[arg(long)]
    output: PathBuf,
}

impl GenerateArgs {
    pub async fn run(self) -> Result<OperationOutput> {
        let key = TurnkeyP256ApiKey::generate();
        let mut stored = StoredApiKey {
            public_key: hex::encode(key.compressed_public_key()),
            private_key: hex::encode(key.private_key()),
            curve: KeyCurve::P256,
        };
        let encoded = serde_json::to_vec(&stored);
        stored.private_key.zeroize();
        let encoded = Zeroizing::new(encoded?);
        secure_create(&self.output, &encoded)
            .await
            .with_context(|| format!("create {}", self.output.display()))?;
        Ok(OperationOutput::result(
            "api-key.generate",
            json!({"publicKey": stored.public_key, "curve": stored.curve, "path": self.output}),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SecureCreateError;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[tokio::test]
    async fn generated_credentials_are_valid_private_and_not_in_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        let output = GenerateArgs {
            output: path.clone(),
        }
        .run()
        .await
        .unwrap();
        let stored: StoredApiKey = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        TurnkeyP256ApiKey::from_strings(&stored.private_key, Some(&stored.public_key)).unwrap();
        let result = serde_json::to_value(output).unwrap();
        assert_eq!(result["data"]["publicKey"], stored.public_key);
        assert!(!result.to_string().contains(&stored.private_key));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn existing_destination_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.json");
        fs::write(&path, b"existing").unwrap();
        let error = GenerateArgs {
            output: path.clone(),
        }
        .run()
        .await
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<SecureCreateError>(),
            Some(SecureCreateError::Exists)
        ));
        assert_eq!(fs::read(path).unwrap(), b"existing");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("link");
        symlink(&target, &path).unwrap();
        let error = GenerateArgs { output: path }.run().await.unwrap_err();
        // O_CREAT|O_EXCL fails with EEXIST on a symlink, dangling or not.
        assert!(matches!(
            error.downcast_ref::<SecureCreateError>(),
            Some(SecureCreateError::Exists)
        ));
        assert!(!target.exists());
    }
}
