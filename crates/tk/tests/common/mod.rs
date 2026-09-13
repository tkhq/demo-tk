use serde_json::json;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const ORGANIZATION_ID: &str = "11111111-2222-4333-8444-555555555555";
pub const PRIVATE_KEY_ID: &str = "pk-id";

pub fn bundle_env(api_key: &TurnkeyP256ApiKey, server: &MockServer) -> [(&'static str, String); 5] {
    [
        ("TURNKEY_ORGANIZATION_ID", ORGANIZATION_ID.to_string()),
        (
            "TURNKEY_API_PUBLIC_KEY",
            hex::encode(api_key.compressed_public_key()),
        ),
        (
            "TURNKEY_API_PRIVATE_KEY",
            hex::encode(api_key.private_key()),
        ),
        ("TURNKEY_PRIVATE_KEY_ID", PRIVATE_KEY_ID.to_string()),
        ("TURNKEY_API_BASE_URL", server.uri()),
    ]
}

pub async fn mount_get_private_key_mock(server: &MockServer, public_key: &str) {
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_private_key"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "privateKey": {
                "privateKeyId": PRIVATE_KEY_ID,
                "publicKey": public_key,
                "privateKeyName": "test signer",
                "curve": "CURVE_ED25519",
                "addresses": [],
                "privateKeyTags": [],
                "createdAt": null,
                "updatedAt": null,
                "exported": false,
                "imported": false
            }
        })))
        .mount(server)
        .await;
}
