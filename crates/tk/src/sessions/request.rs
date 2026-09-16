//! Generates a credential for a saved profile and records it as pending.

use anyhow::{Context, Result};
use serde_json::{Value, json, to_value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tracing::debug;
use turnkey_client::generated::GetWhoamiRequest;

use super::pending::PendingSession;
use crate::auth::{
    SavedProfile, api_keys_dir, build_turnkey_client, read_key, saved_profile, state_dir,
};
use crate::keygen::{GeneratedApiKey, generate};
use crate::operations::OperationOutput;

const COMMAND: &str = "session.request";

pub(super) async fn run(name: String, replace: bool) -> Result<OperationOutput> {
    let profile = saved_profile(&name).await?;
    let state = state_dir()?;
    let api_keys = api_keys_dir()?;
    let api_keys = fs::canonicalize(&api_keys).await.unwrap_or(api_keys);

    if let Some(pending) = PendingSession::load(&state, &name).await? {
        if !replace {
            return Err(crate::errors::InvalidInput(format!(
                "a session request for profile {name} is already pending (public key {}); run tk session activate --profile-name {name}, or pass --replace to start over",
                pending.public_key
            ))
            .into());
        }
        let disposable =
            pending.key_file.starts_with(&api_keys) && pending.key_file != profile.api_key_file;
        if disposable && let Err(error) = fs::remove_file(&pending.key_file).await {
            debug!(%error, "replaced pending key file was not removed");
        }
        PendingSession::remove(&state, &name).await?;
    }

    let GeneratedApiKey { public_key, path } = generate(None).await?;
    let key_file = match fs::canonicalize(&path)
        .await
        .context("resolve credential path")
    {
        Ok(key_file) => key_file,
        Err(error) => {
            let _ = fs::remove_file(&path).await;
            return Err(error);
        }
    };
    let requested_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let pending = PendingSession {
        version: 1,
        profile: name,
        organization_id: profile.organization_id,
        public_key,
        key_file,
        requested_at_unix_ms,
    };
    if let Err(error) = pending.create(&state).await {
        let _ = fs::remove_file(&pending.key_file).await;
        return Err(error);
    }

    let user_id = current_user_id(&profile).await;
    let PendingSession {
        profile: name,
        organization_id,
        public_key,
        key_file,
        ..
    } = pending;
    let user_hint = user_id
        .as_str()
        .map_or_else(|| "<USER_ID>".to_owned(), str::to_owned);
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

/// The profile's user id when its current credential still works, else null.
async fn current_user_id(profile: &SavedProfile) -> Value {
    let SavedProfile {
        organization_id,
        api_base_url,
        api_key_file,
    } = profile;
    let identity = async {
        let client = build_turnkey_client(read_key(api_key_file).await?, api_base_url)?;
        let response = client
            .get_whoami(GetWhoamiRequest {
                organization_id: organization_id.to_string(),
            })
            .await?;
        anyhow::Ok(to_value(response)?)
    }
    .await;
    match identity {
        Ok(identity) => identity["userId"].clone(),
        Err(error) => {
            debug!(%error, "current credential did not identify the user");
            Value::Null
        }
    }
}
