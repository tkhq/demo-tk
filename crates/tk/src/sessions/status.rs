//! Reports how long a saved profile's credential remains valid.

use anyhow::Result;
use clap::Args;
use serde_json::{from_value, json, to_value};
use std::time::{SystemTime, UNIX_EPOCH};
use turnkey_client::generated::{
    GetWhoamiRequest,
    services::coordinator::public::v1::{GetApiKeysRequest, GetApiKeysResponse},
};

use super::duration::ExpiresIn;
use crate::auth::{SavedProfile, build_turnkey_client, read_key, saved_profile};
use crate::errors::{ActivityError, ActivityErrorKind, MissingResource, SessionExpiring};
use crate::operations::{OperationOutput, query};
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
    let public_key = hex::encode(stamper.compressed_public_key());
    let identity = build_turnkey_client(read_key(&api_key_file).await?, &api_base_url)?
        .get_whoami(GetWhoamiRequest {
            organization_id: organization_id.to_string(),
        })
        .await?;
    let listed: GetApiKeysResponse = from_value(
        query(
            "/public/v1/query/get_api_keys",
            &GetApiKeysRequest {
                organization_id: organization_id.to_string(),
                user_id: Some(identity.user_id.clone()),
            },
            &api_base_url,
            &stamper,
        )
        .await?,
    )
    .map_err(|error| {
        ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "get_api_keys response was malformed",
        )
        .with_source(error)
    })?;
    let key = listed
        .api_keys
        .into_iter()
        .find(|key| {
            key.credential
                .as_ref()
                .is_some_and(|credential| credential.public_key.eq_ignore_ascii_case(&public_key))
        })
        .ok_or_else(|| MissingResource::new("api key", public_key.clone()))?;
    let key = to_value(key)?;
    let expires_at = expires_at(&key);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let seconds_left = expires_at
        .as_str()
        .and_then(|ms| ms.parse::<u64>().ok())
        .map(|expires_at_ms| expires_at_ms.saturating_sub(now_ms) / 1000);

    let data = json!({
        "profile": name,
        "userId": identity.user_id,
        "publicKey": public_key,
        "apiKeyId": key["apiKeyId"],
        "apiKeyName": key["apiKeyName"],
        "createdAt": key["createdAt"]["seconds"],
        "expirationSeconds": key["expirationSeconds"],
        "expiresAt": expires_at,
        "secondsLeft": seconds_left,
        "expiresIn": seconds_left.map(|left| ExpiresIn::from_seconds(left).to_string()),
        "warnBefore": warn_before.to_string(),
    });
    if let Some(seconds_left) = seconds_left
        && seconds_left < warn_before.seconds()
    {
        return Err(SessionExpiring {
            profile: name,
            public_key,
            expires_at_unix_ms: now_ms.saturating_add(seconds_left.saturating_mul(1000)),
            seconds_left,
            warn_before_seconds: warn_before.seconds(),
        }
        .into());
    }
    Ok(OperationOutput::result(COMMAND, data))
}
