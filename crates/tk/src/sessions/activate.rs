//! Switches a saved profile to its pending credential once Turnkey knows it.

use anyhow::{Context, Error, Result};
use serde_json::{json, to_value};
use tokio::fs;
use tracing::debug;
use turnkey_client::generated::GetWhoamiRequest;

use super::pending::PendingSession;
use crate::auth::{
    SavedProfile, api_keys_dir, build_turnkey_client, read_key, saved_profile, set_profile_key,
    state_dir,
};
use crate::errors::InvalidInput;
use crate::operations::OperationOutput;

const COMMAND: &str = "session.activate";

pub(super) async fn run(name: String) -> Result<OperationOutput> {
    let SavedProfile {
        organization_id,
        api_base_url,
        api_key_file: previous_key_file,
    } = saved_profile(&name).await?;
    let state = state_dir()?;
    let Some(pending) = PendingSession::load(&state, &name).await? else {
        return Err(InvalidInput(format!(
            "no pending session request for profile {name}; run tk session request --profile-name {name} first"
        ))
        .into());
    };
    let PendingSession {
        public_key,
        key_file,
        ..
    } = pending;

    let identity = build_turnkey_client(read_key(&key_file).await?, &api_base_url)?
        .get_whoami(GetWhoamiRequest {
            organization_id: organization_id.to_string(),
        })
        .await
        .map_err(Error::new)
        .with_context(|| {
            format!(
                "pending credential {public_key} is not registered yet; have the provisioner run tk session provision --public-key {public_key}, or approve its activity, then retry"
            )
        })?;

    let switched = set_profile_key(&name, &key_file).await?;
    let previous_public_key = match read_key(&previous_key_file).await {
        Ok(key) => Some(hex::encode(key.compressed_public_key())),
        Err(_) => None,
    };
    let api_keys = api_keys_dir()?;
    let api_keys = fs::canonicalize(&api_keys).await.unwrap_or(api_keys);
    let disposable = switched.previous.starts_with(&api_keys) && switched.previous != key_file;
    let previous_removed = if disposable {
        match fs::remove_file(&switched.previous).await {
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
            "publicKey": switched.public_key,
            "keyFile": key_file,
            "previousPublicKey": previous_public_key,
            "previousKeyFile": switched.previous,
            "previousKeyFileRemoved": previous_removed,
            "identity": to_value(identity)?,
        }),
    ))
}
