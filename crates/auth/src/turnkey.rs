//! Turnkey-backed signing client helpers.

use anyhow::{Context, Error, Result, anyhow};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::generated::immutable::common::v1::{HashFunction, PayloadEncoding};
use turnkey_client::generated::{GetActivityRequest, GetPrivateKeyRequest, SignRawPayloadIntentV2};
use turnkey_client::{TurnkeyClient, TurnkeyClientError};

use crate::config::{Config, ConfigKey};
use crate::errors::MissingResource;

/// Turnkey-backed signer for fetching public keys and producing Ed25519 signatures.
pub(crate) struct TurnkeySigner {
    client: TurnkeyClient<TurnkeyP256ApiKey>,
    config: Config,
}

pub(crate) fn build_client(config: &Config) -> Result<TurnkeyClient<TurnkeyP256ApiKey>> {
    let api_key =
        TurnkeyP256ApiKey::from_strings(&config.api_private_key, Some(&config.api_public_key))
            .context("failed to load Turnkey API key")?;

    TurnkeyClient::builder()
        .api_key(api_key)
        .base_url(&config.api_base_url)
        .build()
        .context("failed to build Turnkey client")
}

impl TurnkeySigner {
    pub(crate) fn new(client: TurnkeyClient<TurnkeyP256ApiKey>, config: Config) -> Self {
        Self { client, config }
    }

    pub(crate) async fn get_public_key(&self) -> Result<[u8; 32]> {
        let private_key_id = self.required_private_key_id()?;
        let response = self
            .client
            .get_private_key(GetPrivateKeyRequest {
                organization_id: self.config.organization_id.to_string(),
                private_key_id: private_key_id.to_string(),
            })
            .await
            .map_err(map_turnkey_error)?;

        let private_key = response
            .private_key
            .ok_or_else(|| MissingResource::new("private key", private_key_id))?;

        decode_public_key(&private_key.public_key)
    }

    pub(crate) async fn sign_ed25519(&self, payload: &[u8]) -> Result<[u8; 64]> {
        let private_key_id = self.required_private_key_id()?;
        match self
            .client
            .sign_raw_payload(
                self.config.organization_id.to_string(),
                self.client.current_timestamp(),
                SignRawPayloadIntentV2 {
                    sign_with: private_key_id.to_string(),
                    payload: hex::encode(payload),
                    encoding: PayloadEncoding::Hexadecimal,
                    hash_function: HashFunction::NotApplicable,
                },
            )
            .await
        {
            Ok(response) => {
                decode_signature_parts(&response.result.r, &response.result.s, &response.result.v)
            }
            Err(TurnkeyClientError::ActivityRequiresApproval(activity_id)) => {
                Err(self.approval_required_error(activity_id).await)
            }
            Err(other) => Err(map_turnkey_error(other)),
        }
    }

    async fn approval_required_error(&self, activity_id: String) -> Error {
        let fingerprint = self
            .client
            .get_activity(GetActivityRequest {
                organization_id: self.config.organization_id.to_string(),
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

    fn required_private_key_id(&self) -> Result<&str> {
        self.config
            .private_key_id
            .as_deref()
            .ok_or_else(|| anyhow!("missing required config value: {}", ConfigKey::PrivateKeyId))
    }
}

fn map_turnkey_error(error: TurnkeyClientError) -> Error {
    Error::new(error).context("Turnkey API request failed")
}

fn decode_public_key(encoded: &str) -> Result<[u8; 32]> {
    let trimmed = encoded.trim().trim_start_matches("0x");
    let public_key = hex::decode(trimmed).context("expected hex-encoded Turnkey public key")?;
    <[u8; 32]>::try_from(public_key).map_err(|public_key| {
        anyhow!(
            "expected 32-byte Ed25519 public key from Turnkey, got {} bytes",
            public_key.len()
        )
    })
}

fn decode_signature_parts(r: &str, s: &str, v: &str) -> Result<[u8; 64]> {
    let r = decode_hex(r).context("failed to decode Turnkey signature field r")?;
    let s = decode_hex(s).context("failed to decode Turnkey signature field s")?;
    let v = decode_hex(v).context("failed to decode Turnkey signature field v")?;

    if r.len() == 32 && s.len() == 32 && v.len() == 1 {
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r);
        signature[32..].copy_from_slice(&s);
        return Ok(signature);
    }

    Err(anyhow!(
        "unsupported Ed25519 signature layout from Turnkey: r={} bytes, s={} bytes, v={} bytes",
        r.len(),
        s.len(),
        v.len()
    ))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("expected non-empty hex value"));
    }

    let trimmed = trimmed.trim_start_matches("0x");
    hex::decode(trimmed).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{TurnkeyClientError, TurnkeySigner, decode_public_key, decode_signature_parts};
    use crate::config::Config;
    use serde_json::{Value, json};
    use turnkey_api_key_stamper::TurnkeyP256ApiKey;
    use turnkey_client::TurnkeyClient;
    use uuid::{Uuid, uuid};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ORGANIZATION_ID: Uuid = uuid!("11111111-2222-4333-8444-555555555555");

    fn test_signer(server: &MockServer, private_key_id: Option<String>) -> TurnkeySigner {
        let api_key = TurnkeyP256ApiKey::generate();
        let config = Config {
            organization_id: ORGANIZATION_ID,
            api_public_key: hex::encode(api_key.compressed_public_key()),
            api_private_key: hex::encode(api_key.private_key()),
            private_key_id,
            api_base_url: server.uri(),
        };
        let client = TurnkeyClient::builder()
            .api_key(api_key)
            .base_url(&config.api_base_url)
            .build()
            .expect("client should build");
        TurnkeySigner::new(client, config)
    }

    async fn signer_with_sign_response(response: Value) -> (MockServer, TurnkeySigner) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let signer = test_signer(&server, Some("pk-id".to_string()));
        (server, signer)
    }

    fn consensus_needed_response() -> Value {
        json!({
            "activity": {
                "id": "consensus-activity-id",
                "organizationId": ORGANIZATION_ID.to_string(),
                "fingerprint": "consensus-fingerprint",
                "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"
            }
        })
    }

    #[test]
    fn decode_public_key_rejects_base64_input() {
        let error = decode_public_key("ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY=")
            .expect_err("base64 public keys should be rejected");

        assert_eq!(error.to_string(), "expected hex-encoded Turnkey public key");
    }

    #[test]
    fn decode_signature_parts_rejects_empty_v() {
        let r = "11".repeat(32);
        let s = "22".repeat(32);
        let error = decode_signature_parts(&r, &s, "").expect_err("empty v should be rejected");

        assert_eq!(
            error.to_string(),
            "failed to decode Turnkey signature field v"
        );
    }

    #[tokio::test]
    async fn sign_returns_signature_on_immediate_success() {
        let payload = b"ssh-agent-challenge";
        let signature = [0x55; 64];
        let (server, signer) = signer_with_sign_response(json!({
            "activity": {
                "id": "activity-id",
                "organizationId": ORGANIZATION_ID.to_string(),
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "result": {
                    "signRawPayloadResult": {
                        "r": hex::encode(&signature[..32]),
                        "s": hex::encode(&signature[32..]),
                        "v": "00"
                    }
                }
            }
        }))
        .await;

        let result = signer
            .sign_ed25519(payload)
            .await
            .expect("ssh auth payload should sign");

        assert_eq!(result, signature);

        let requests = server
            .received_requests()
            .await
            .expect("request recording should be enabled");
        assert_eq!(requests.len(), 1);
        let body: Value = requests[0]
            .body_json()
            .expect("request body should be valid JSON");
        assert_eq!(body["type"], "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2");
        assert_eq!(body["organizationId"], ORGANIZATION_ID.to_string());
        assert_eq!(body["parameters"]["signWith"], "pk-id");
        assert_eq!(body["parameters"]["payload"], hex::encode(payload));
        assert_eq!(
            body["parameters"]["encoding"],
            "PAYLOAD_ENCODING_HEXADECIMAL"
        );
        assert_eq!(
            body["parameters"]["hashFunction"],
            "HASH_FUNCTION_NOT_APPLICABLE"
        );
    }

    #[tokio::test]
    async fn sign_returns_error_when_consensus_needed() {
        let (server, signer) = signer_with_sign_response(consensus_needed_response()).await;

        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_activity"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "activity": {
                    "id": "consensus-activity-id",
                    "organizationId": ORGANIZATION_ID.to_string(),
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    "intent": null,
                    "result": null,
                    "votes": [],
                    "appProofs": [],
                    "fingerprint": "consensus-fingerprint",
                    "canApprove": false,
                    "canReject": true,
                    "createdAt": null,
                    "updatedAt": null,
                    "failure": null
                }
            })))
            .mount(&server)
            .await;

        let error = signer
            .sign_ed25519(b"test-payload")
            .await
            .expect_err("sign should fail when consensus needed");

        assert_eq!(
            error.to_string(),
            "signing requires additional approval (fingerprint: consensus-fingerprint, activity id: consensus-activity-id)"
        );
        assert!(matches!(
            error.downcast_ref::<TurnkeyClientError>(),
            Some(TurnkeyClientError::ActivityRequiresApproval(id)) if id == "consensus-activity-id"
        ));
    }

    #[tokio::test]
    async fn sign_falls_back_to_activity_id_when_fingerprint_lookup_fails() {
        let (server, signer) = signer_with_sign_response(consensus_needed_response()).await;

        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_activity"))
            .and(header_exists("X-Stamp"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let error = signer
            .sign_ed25519(b"test-payload")
            .await
            .expect_err("sign should fail when consensus needed");

        assert_eq!(
            error.to_string(),
            "signing requires additional approval (activity id: consensus-activity-id)"
        );
    }

    #[tokio::test]
    async fn sign_requires_private_key_id() {
        let server = MockServer::start().await;
        let signer = test_signer(&server, None);

        let error = signer
            .sign_ed25519(b"test-payload")
            .await
            .expect_err("sign should require a private key id");

        assert_eq!(
            error.to_string(),
            "missing required config value: turnkey.privateKeyId"
        );
    }
}
