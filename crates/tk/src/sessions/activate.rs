//! Switches a saved profile to its pending credential once Turnkey knows it.

use anyhow::{Context, Error, Result};
use serde_json::{json, to_value};
use tokio::fs;
use tracing::debug;

use super::pending::PendingSession;
use super::{CompressedPublicKey, whoami};
use crate::auth::{Profile, api_keys_dir, read_key, saved_profile, set_profile_key, state_dir};
use crate::errors::InvalidInput;
use crate::operations::OperationOutput;

const COMMAND: &str = "session.activate";

pub(super) async fn run(name: String) -> Result<OperationOutput> {
    let Profile {
        organization_id,
        api_base_url,
        api_key_file: _,
    } = saved_profile(&name).await?;
    let state = state_dir()?;
    let Some(pending) = PendingSession::load(&state, &name).await? else {
        return Err(InvalidInput(format!(
            "no pending session request for profile {name}; run tk session request --profile-name {name} first"
        ))
        .into());
    };
    let PendingSession {
        public_key: _,
        key_file,
        ..
    } = pending;

    let key = read_key(&key_file).await?;
    let public_key = CompressedPublicKey::of(&key);
    let identity = whoami(key, &api_base_url, organization_id)
        .await?
        .map_err(Error::new)
        .with_context(|| {
            format!(
                "pending credential {public_key} is not registered yet; have the provisioner run tk session provision --public-key {public_key}, or approve its activity, then retry"
            )
        })?;

    let previous = set_profile_key(&name, &key_file).await?;
    let previous_public_key = match read_key(&previous).await {
        Ok(key) => Some(CompressedPublicKey::of(&key)),
        Err(_) => None,
    };
    let api_keys = api_keys_dir()?;
    let api_keys = fs::canonicalize(&api_keys).await.unwrap_or(api_keys);
    let disposable = previous.starts_with(&api_keys) && previous != key_file;
    let previous_removed = if disposable {
        match fs::remove_file(&previous).await {
            Ok(()) => true,
            Err(error) => {
                debug!(%error, "previous key file was not removed");
                false
            }
        }
    } else {
        false
    };
    PendingSession::remove(&state, &name).await?;

    Ok(OperationOutput::result(
        COMMAND,
        json!({
            "profile": name,
            "publicKey": public_key,
            "keyFile": key_file,
            "previousPublicKey": previous_public_key,
            "previousKeyFile": previous,
            "previousKeyFileRemoved": previous_removed,
            "identity": to_value(identity)?,
        }),
    ))
}
