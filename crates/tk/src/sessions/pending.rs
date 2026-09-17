//! A generated credential awaiting registration, remembered per profile.

use anyhow::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs;
use uuid::Uuid;

use super::CompressedPublicKey;
use crate::auth::{SecureCreateError, secure_create};
use crate::errors::{InvalidInput, Malformed};

#[derive(Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingSession {
    pub(crate) version: u32,
    pub(crate) profile: String,
    pub(crate) organization_id: Uuid,
    pub(crate) public_key: CompressedPublicKey,
    pub(crate) key_file: PathBuf,
    pub(crate) requested_at_unix_ms: u64,
}

impl PendingSession {
    pub(crate) fn path(state: &Path, profile: &str) -> PathBuf {
        state
            .join("sessions/pending")
            .join(format!("{profile}.json"))
    }

    pub(crate) async fn load(state: &Path, profile: &str) -> Result<Option<Self>> {
        let path = Self::path(state, profile);
        let bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let pending: Self = from_slice(&bytes).map_err(|error| {
            Malformed::new(
                format!(
                    "pending session state {} is malformed; delete it to start over",
                    path.display()
                ),
                error,
            )
        })?;
        if pending.version != 1 {
            return Err(InvalidInput(format!(
                "pending session state {} has unsupported version {}",
                path.display(),
                pending.version
            ))
            .into());
        }
        Ok(Some(pending))
    }

    pub(crate) async fn create(&self, state: &Path) -> Result<()> {
        let path = Self::path(state, &self.profile);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create {}", parent.display()))?;
        }
        secure_create(&path, &to_vec(self)?)
            .await
            .map_err(|error| match error {
                SecureCreateError::Exists => Error::new(error),
                SecureCreateError::Io(error) => {
                    Error::new(error).context("write pending session state")
                }
            })
    }

    pub(crate) async fn remove(state: &Path, profile: &str) -> Result<()> {
        let path = Self::path(state, profile);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::parse_public_key;
    use std::fs;

    fn sample(profile: &str) -> PendingSession {
        let key = "02abababababababababababababababababababababababababababababababab";
        PendingSession {
            version: 1,
            profile: profile.into(),
            organization_id: Uuid::nil(),
            public_key: parse_public_key(key).unwrap(),
            key_file: PathBuf::from("/keys/02ab.json"),
            requested_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn round_trips_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let pending = sample("agent");
        pending.create(dir.path()).await.unwrap();
        let loaded = PendingSession::load(dir.path(), "agent").await.unwrap();
        assert_eq!(loaded, Some(pending));
        PendingSession::remove(dir.path(), "agent").await.unwrap();
        assert_eq!(
            PendingSession::load(dir.path(), "agent").await.unwrap(),
            None
        );
        PendingSession::remove(dir.path(), "agent").await.unwrap();
    }

    #[tokio::test]
    async fn second_request_for_the_same_profile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        sample("agent").create(dir.path()).await.unwrap();
        let error = sample("agent").create(dir.path()).await.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<SecureCreateError>(),
                Some(SecureCreateError::Exists)
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn malformed_state_is_reported_as_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = PendingSession::path(dir.path(), "agent");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{").unwrap();
        let error = PendingSession::load(dir.path(), "agent").await.unwrap_err();
        assert!(error.downcast_ref::<Malformed>().is_some(), "{error}");
    }
}
