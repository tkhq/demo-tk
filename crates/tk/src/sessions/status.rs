//! Reports how long a saved profile's credential remains valid.

use anyhow::Result;
use clap::Args;
use serde_json::{json, to_value};
use turnkey_client::generated::{
    GetWhoamiRequest,
    services::coordinator::public::v1::{GetApiKeysRequest, GetApiKeysResponse},
};

use super::CompressedPublicKey;
use super::duration::ExpiresIn;
use crate::auth::{SavedProfile, build_turnkey_client, read_key, saved_profile};
use crate::errors::{MissingResource, SessionExpiring};
use crate::operations::{OperationOutput, now_unix_ms, query_decoded};
use crate::resources::expires_at;

const COMMAND: &str = "session.status";

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Saved profile to inspect.
    #[arg(long = "profile-name")]
    name: String,
    /// Fail with `session_expiring` when less than this remains.
    #[arg(long, default_value = "48h")]
    warn_before: ExpiresIn,
}

pub(super) async fn run(args: StatusArgs) -> Result<OperationOutput> {
    let StatusArgs { name, warn_before } = args;
    let SavedProfile {
        organization_id,
        api_base_url,
        api_key_file,
    } = saved_profile(&name).await?;
    let stamper = read_key(&api_key_file).await?;
    let public_key = CompressedPublicKey::of(&stamper);
    let identity = build_turnkey_client(read_key(&api_key_file).await?, &api_base_url)?
        .get_whoami(GetWhoamiRequest {
            organization_id: organization_id.to_string(),
        })
        .await?;
    let listed: GetApiKeysResponse = query_decoded(
        "get_api_keys",
        &GetApiKeysRequest {
            organization_id: organization_id.to_string(),
            user_id: Some(identity.user_id.clone()),
        },
        &api_base_url,
        &stamper,
    )
    .await?;
    let key = listed
        .api_keys
        .into_iter()
        .find(|key| {
            key.credential
                .as_ref()
                .is_some_and(|credential| public_key.matches(&credential.public_key))
        })
        .ok_or_else(|| MissingResource::new("api key", public_key.to_string()))?;
    let key = to_value(key)?;
    let expires_at_ms = expires_at(&key)?;
    let now_ms = now_unix_ms()?;
    let seconds_left =
        expires_at_ms.map(|expires_at_ms| expires_at_ms.saturating_sub(now_ms) / 1000);

    let data = json!({
        "profile": name,
        "userId": identity.user_id,
        "publicKey": public_key,
        "apiKeyId": key["apiKeyId"],
        "apiKeyName": key["apiKeyName"],
        "createdAt": key["createdAt"]["seconds"],
        "expirationSeconds": key["expirationSeconds"],
        "expiresAt": expires_at_ms.map(|ms| ms.to_string()),
        "secondsLeft": seconds_left,
        "expiresIn": seconds_left.map(|left| ExpiresIn::from_seconds(left).to_string()),
        "warnBefore": warn_before.to_string(),
    });
    if let Some((expires_at_ms, seconds_left)) = expires_at_ms.zip(seconds_left)
        && seconds_left < warn_before.seconds()
    {
        return Err(SessionExpiring {
            profile: name,
            public_key: public_key.into_string(),
            expires_at_unix_ms: expires_at_ms,
            seconds_left,
            warn_before_seconds: warn_before.seconds(),
        }
        .into());
    }
    Ok(OperationOutput::result(COMMAND, data))
}
