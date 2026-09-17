//! Generates a credential for a saved profile and records it as pending.

use anyhow::{Context, Result};
use serde_json::json;
use tokio::fs;
use tracing::debug;

use super::pending::PendingSession;
use super::{CompressedPublicKey, whoami};
use crate::auth::{Profile, SecureCreateError, api_keys_dir, read_key, saved_profile, state_dir};
use crate::errors::InvalidInput;
use crate::keygen::{GeneratedApiKey, generate};
use crate::operations::OperationOutput;

const COMMAND: &str = "session.request";

pub(super) async fn run(name: String, replace: bool) -> Result<OperationOutput> {
    let profile = saved_profile(&name).await?;
    let state = state_dir()?;

    if let Some(pending) = PendingSession::load(&state, &name).await? {
        if !replace {
            let key = read_key(&pending.key_file).await.with_context(|| {
                format!(
                    "a session request for profile {name} is already pending but its credential could not be read; run tk session request --profile-name {name} --replace to start over"
                )
            })?;
            return Err(InvalidInput(format!(
                "a session request for profile {name} is already pending (public key {}); run tk session activate --profile-name {name}, or pass --replace to start over",
                CompressedPublicKey::of(&key)
            ))
            .into());
        }
        let api_keys = api_keys_dir()?;
        let api_keys = fs::canonicalize(&api_keys).await.unwrap_or(api_keys);
        let disposable =
            pending.key_file.starts_with(&api_keys) && pending.key_file != profile.api_key_file;
        if disposable && let Err(error) = fs::remove_file(&pending.key_file).await {
            debug!(%error, "replaced pending key file was not removed");
        }
        PendingSession::remove(&state, &name).await?;
    }

    let GeneratedApiKey { public_key, path } = generate(None).await?;
    let pending = async {
        let key_file = fs::canonicalize(&path)
            .await
            .context("resolve credential path")?;
        let pending = PendingSession {
            version: 1,
            profile: name,
            organization_id: profile.organization_id,
            key_file,
        };
        if let Err(error) = pending.create(&state).await {
            if matches!(
                error.downcast_ref::<SecureCreateError>(),
                Some(SecureCreateError::Exists)
            ) {
                return Err(InvalidInput(format!(
                    "a session request for profile {} is already pending; run tk session activate --profile-name {0}, or tk session request --profile-name {0} --replace to start over",
                    pending.profile
                ))
                .into());
            }
            return Err(error);
        }
        anyhow::Ok(pending)
    }
    .await;
    let pending = match pending {
        Ok(pending) => pending,
        Err(error) => {
            let _ = fs::remove_file(&path).await;
            return Err(error);
        }
    };

    let user_id = current_user_id(&profile).await;
    let PendingSession {
        profile: name,
        organization_id,
        key_file,
        ..
    } = pending;
    let user_hint = user_id.as_deref().unwrap_or("<USER_ID>");
    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "profile": name,
            "organizationId": organization_id,
            "userId": user_id,
            "publicKey": public_key,
            "curve": "p256",
            "keyFile": key_file,
            "nextStep": format!(
                "give the public key and user id to the provisioner: tk session provision --user-id {user_hint} --public-key {public_key} --expires-in 7d; then run tk session activate --profile-name {name} here"
            ),
        }),
    ))
}

/// The profile's user id when its current credential still works, else `None`.
async fn current_user_id(profile: &Profile) -> Option<String> {
    let Profile {
        organization_id,
        api_base_url,
        api_key_file,
    } = profile;
    let identity = async {
        let response = whoami(
            read_key(api_key_file).await?,
            api_base_url,
            *organization_id,
        )
        .await??;
        anyhow::Ok(response.user_id)
    }
    .await;
    match identity {
        Ok(user_id) => Some(user_id),
        Err(error) => {
            debug!(%error, "current credential did not identify the user");
            None
        }
    }
}
