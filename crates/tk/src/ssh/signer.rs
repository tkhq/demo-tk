//! Ed25519 signing through Turnkey's raw-payload activity.

use anyhow::{Error, Result};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::common::v1::{HashFunction, PayloadEncoding};
use turnkey_client::generated::{GetActivityRequest, SignRawPayloadIntentV2, SignRawPayloadResult};
use turnkey_client::{ActivityResult, TurnkeyClient, TurnkeyClientError};

use crate::errors::{ActivityError, ActivityErrorKind};
use crate::ssh::registry::PrivateKeyId;

pub struct TurnkeySigner<'a> {
    client: &'a TurnkeyClient<TurnkeyP256ApiKey>,
    organization_id: String,
    private_key_id: &'a PrivateKeyId,
}

impl<'a> TurnkeySigner<'a> {
    pub fn new(
        client: &'a TurnkeyClient<TurnkeyP256ApiKey>,
        organization_id: String,
        private_key_id: &'a PrivateKeyId,
    ) -> Self {
        Self {
            client,
            organization_id,
            private_key_id,
        }
    }

    pub async fn sign_raw_payload(&self, payload: &[u8]) -> Result<[u8; 64]> {
        let activity = match self
            .client
            .sign_raw_payload(
                self.organization_id.clone(),
                self.client.current_timestamp(),
                SignRawPayloadIntentV2 {
                    sign_with: self.private_key_id.to_string(),
                    payload: hex::encode(payload),
                    encoding: PayloadEncoding::Hexadecimal,
                    hash_function: HashFunction::NotApplicable,
                },
            )
            .await
        {
            Ok(activity) => activity,
            Err(TurnkeyClientError::ActivityRequiresApproval(activity_id)) => {
                return Err(self.approval_required_error(activity_id).await);
            }
            Err(error) => return Err(Error::new(error).context("sign the SSH payload")),
        };
        let ActivityResult {
            result,
            activity_id: _,
            status: _,
            app_proofs: _,
        } = activity;
        let SignRawPayloadResult { r, s, v } = result;
        let decode = |value: &str, field: &str| -> Result<[u8; 32]> {
            let malformed = |reason: &str| {
                ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    format!("{field} is {reason}"),
                )
            };
            let bytes =
                hex::decode(value).map_err(|error| malformed("not hex").with_source(error))?;
            bytes
                .try_into()
                .map_err(|_wrong_length: Vec<u8>| malformed("not 32 bytes").into())
        };
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&decode(&r, "signRawPayloadResult.r")?);
        signature[32..].copy_from_slice(&decode(&s, "signRawPayloadResult.s")?);
        let v = hex::decode(v).map_err(|error| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "signRawPayloadResult.v is not hex",
            )
            .with_source(error)
        })?;
        if v.len() != 1 {
            return Err(ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "signRawPayloadResult.v is not 1 byte",
            )
            .into());
        }
        Ok(signature)
    }

    async fn approval_required_error(&self, activity_id: String) -> Error {
        let fingerprint = self
            .client
            .get_activity(GetActivityRequest {
                organization_id: self.organization_id.clone(),
                activity_id: activity_id.clone(),
            })
            .await
            .ok()
            .and_then(|response| response.activity)
            .map(|activity| activity.fingerprint)
            .filter(|fingerprint| !fingerprint.is_empty());
        let context = match fingerprint {
            Some(fingerprint) => format!(
                "signing requires additional approval (fingerprint: {fingerprint}, activity id: {activity_id})"
            ),
            None => format!("signing requires additional approval (activity id: {activity_id})"),
        };
        Error::new(TurnkeyClientError::ActivityRequiresApproval(activity_id)).context(context)
    }
}
