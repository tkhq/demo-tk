//! Registers an agent's public key as an expiring API key. Runs as the
//! provisioner; re-running after approval reports the registered key instead
//! of minting another.

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::{self, Display, Formatter};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::{
    external::data::v1::ApiKey,
    immutable::{
        activity::v1::{ApiKeyParamsV2, CreateApiKeysIntentV2},
        common::v1::ApiKeyCurve,
    },
    services::coordinator::public::v1::{GetApiKeysRequest, GetApiKeysResponse},
};
use uuid::Uuid;

use super::duration::{ExpiresIn, format_duration};
use crate::auth::ResolvedAuth;
use crate::errors::{ActivityError, ActivityErrorKind};
use crate::operations::{OperationOutput, now_unix_ms, query_decoded, submit_activity_with_id};

const COMMAND: &str = "session.provision";

#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// User who will own the new expiring API key.
    #[arg(long)]
    user_id: Uuid,
    /// Compressed P256 public key (hex) printed by tk session request.
    #[arg(long, value_parser = parse_public_key)]
    public_key: CompressedPublicKey,
    /// Lifetime of the key, for example 7d, 48h, 30m.
    #[arg(long, default_value = "7d")]
    expires_in: ExpiresIn,
    /// API key label; defaults to session-EXPIRES_IN-UNIX_SECONDS, for example
    /// session-7d-1789000000.
    #[arg(long)]
    label: Option<String>,
}

/// A compressed P256 public key as normalized lowercase hex.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub(crate) struct CompressedPublicKey(String);

impl CompressedPublicKey {
    pub(crate) fn of(key: &TurnkeyP256ApiKey) -> Self {
        Self(hex::encode(key.compressed_public_key()))
    }

    pub(crate) fn matches(&self, hex: &str) -> bool {
        self.0.eq_ignore_ascii_case(hex)
    }
}

impl Display for CompressedPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// API key creation parameters for a P256 key, rendering the optional
/// lifetime as whole seconds.
pub(crate) fn p256_api_key(
    api_key_name: String,
    public_key: CompressedPublicKey,
    expires_in: Option<ExpiresIn>,
) -> ApiKeyParamsV2 {
    ApiKeyParamsV2 {
        api_key_name,
        public_key: public_key.0,
        curve_type: ApiKeyCurve::P256,
        expiration_seconds: expires_in.map(|expires_in| expires_in.seconds().to_string()),
    }
}

/// Normalizes a compressed P256 public key given as hex.
pub(crate) fn parse_public_key(text: &str) -> Result<CompressedPublicKey, String> {
    let key = text.trim().to_ascii_lowercase();
    let valid = key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key.chars().all(|c| c.is_ascii_hexdigit());
    if valid {
        Ok(CompressedPublicKey(key))
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
    let existing: GetApiKeysResponse = query_decoded(
        "get_api_keys",
        &GetApiKeysRequest {
            organization_id: auth.org_id.to_string(),
            user_id: Some(user_id.to_string()),
        },
        &auth.api_base_url,
        &auth.stamper,
    )
    .await?;
    if let Some(key) = existing.api_keys.into_iter().find(|key| {
        key.credential
            .as_ref()
            .is_some_and(|credential| public_key.matches(&credential.public_key))
    }) {
        let ApiKey {
            credential: _,
            api_key_id,
            api_key_name,
            created_at,
            updated_at: _,
            expiration_seconds,
        } = key;
        return Ok(OperationOutput::result(
            COMMAND,
            json!({
                "userId": user_id,
                "expiresIn": expiration_seconds.map(format_duration),
                "expirationSeconds": expiration_seconds.map(|seconds| seconds.to_string()),
                "publicKey": public_key,
                "apiKeyId": api_key_id,
                "apiKeyName": api_key_name,
                "createdAt": created_at.map(|at| at.seconds),
                "alreadyRegistered": true,
            }),
        ));
    }

    let api_key_name = match label {
        Some(label) => label,
        None => format!("session-{expires_in}-{}", now_unix_ms()? / 1000),
    };
    let (activity_id, submitted) = submit_activity_with_id(
        &auth,
        COMMAND,
        "create_api_keys",
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        &CreateApiKeysIntentV2 {
            api_keys: vec![p256_api_key(
                api_key_name.clone(),
                public_key.clone(),
                Some(expires_in),
            )],
            user_id: user_id.to_string(),
        },
    )
    .await?;
    let pending = submitted.is_pending();
    let mut response = submitted.into_data();
    let activity = &mut response["activity"];
    let api_key_id = activity
        .pointer_mut("/result/createApiKeysResult/apiKeyIds")
        .and_then(|ids| ids.get_mut(0))
        .map(Value::take)
        .unwrap_or(Value::Null);
    if !pending && api_key_id.as_str().is_none() {
        return Err(ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "create_api_keys completed without result.createApiKeysResult.apiKeyIds[0]",
        )
        .into());
    }
    let next_step = pending.then(|| {
        format!(
            "approve activity {activity_id} (expiring key for user {user_id}, lifetime {expires_in}), then re-run this command or tk activity wait {activity_id}"
        )
    });
    let mut data = json!({
        "userId": user_id,
        "expiresIn": expires_in.to_string(),
        "expirationSeconds": expires_in.seconds().to_string(),
        "publicKey": public_key,
        "apiKeyName": api_key_name,
        "apiKeyId": api_key_id,
        "activity": {
            "id": activity_id,
            "status": activity["status"].take(),
            "type": activity["type"].take(),
        },
    });
    if let Some(next_step) = next_step {
        data["nextStep"] = Value::from(next_step);
    }
    Ok(OperationOutput::result(COMMAND, data))
}
