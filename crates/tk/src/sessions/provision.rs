//! Registers an agent's public key as an expiring API key. Runs as the
//! provisioner; re-running after approval reports the registered key instead
//! of minting another.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, from_value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use turnkey_client::generated::{
    immutable::{
        activity::v1::{ApiKeyParamsV2, CreateApiKeysIntentV2},
        common::v1::ApiKeyCurve,
    },
    services::coordinator::public::v1::{GetApiKeysRequest, GetApiKeysResponse},
};
use uuid::Uuid;

use super::duration::ExpiresIn;
use crate::auth::ResolvedAuth;
use crate::errors::{ActivityError, ActivityErrorKind};
use crate::operations::{OperationOutput, query, submit_activity};

const COMMAND: &str = "session.provision";

#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// User who will own the new expiring API key.
    #[arg(long)]
    user_id: Uuid,
    /// Compressed P256 public key (hex) printed by tk session request.
    #[arg(long, value_parser = parse_public_key)]
    public_key: String,
    /// Lifetime of the key, for example 7d, 48h, 30m.
    #[arg(long, default_value = "7d")]
    expires_in: ExpiresIn,
    /// API key label; defaults to session-<expires-in>-<unix seconds>.
    #[arg(long)]
    label: Option<String>,
}

fn parse_public_key(text: &str) -> Result<String, String> {
    let key = text.trim().to_ascii_lowercase();
    let valid = key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.chars().all(|c| c.is_ascii_hexdigit());
    if valid {
        Ok(key)
    } else {
        Err("must be a compressed P256 public key: 66 hex characters starting with 02 or 03".into())
    }
}

pub(super) async fn run(auth: ResolvedAuth, args: ProvisionArgs) -> Result<OperationOutput> {
    let ProvisionArgs {
        user_id,
        public_key,
        expires_in,
        label,
    } = args;
    let existing: GetApiKeysResponse = from_value(
        query(
            "/public/v1/query/get_api_keys",
            &GetApiKeysRequest {
                organization_id: auth.org_id.to_string(),
                user_id: Some(user_id.to_string()),
            },
            &auth.api_base_url,
            &auth.stamper,
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
    if let Some(key) = existing.api_keys.into_iter().find(|key| {
        key.credential
            .as_ref()
            .is_some_and(|credential| credential.public_key.eq_ignore_ascii_case(&public_key))
    }) {
        let lifetime = key.expiration_seconds.map(ExpiresIn::from_seconds);
        return Ok(OperationOutput::result(
            COMMAND,
            json!({
                "userId": user_id,
                "expiresIn": lifetime.map(|lifetime| lifetime.to_string()),
                "expirationSeconds": key.expiration_seconds.map(|seconds| seconds.to_string()),
                "publicKey": public_key,
                "apiKeyId": key.api_key_id,
                "apiKeyName": key.api_key_name,
                "createdAt": key.created_at.map(|at| at.seconds),
                "alreadyRegistered": true,
            }),
        ));
    }

    let api_key_name = label.unwrap_or_else(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        format!("session-{expires_in}-{now}")
    });
    let submitted = submit_activity(
        &auth,
        COMMAND,
        "create_api_keys",
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        &CreateApiKeysIntentV2 {
            api_keys: vec![ApiKeyParamsV2 {
                api_key_name: api_key_name.clone(),
                public_key: public_key.clone(),
                curve_type: ApiKeyCurve::P256,
                expiration_seconds: Some(expires_in.seconds().to_string()),
            }],
            user_id: user_id.to_string(),
        },
    )
    .await?;
    let response = submitted.into_data();
    let activity = &response["activity"];
    let api_key_id = activity["result"]["createApiKeysResult"]["apiKeyIds"][0].clone();
    let mut data = json!({
        "userId": user_id,
        "expiresIn": expires_in.to_string(),
        "expirationSeconds": expires_in.seconds().to_string(),
        "publicKey": public_key,
        "apiKeyName": api_key_name,
        "apiKeyId": api_key_id,
        "activity": {
            "id": activity["id"],
            "status": activity["status"],
            "type": activity["type"],
        },
    });
    let record = OperationOutput::result(COMMAND, data.clone());
    if record.is_pending() {
        data["nextStep"] = Value::from(format!(
            "approve activity {} (expiring key for user {user_id}, lifetime {expires_in}), then re-run this command or tk activity wait {0}",
            activity["id"].as_str().unwrap_or("<ACTIVITY_ID>")
        ));
        return Ok(OperationOutput::result(COMMAND, data));
    }
    Ok(record)
}
