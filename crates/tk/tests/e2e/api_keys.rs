use crate::run::{Run, result};
use serde_json::{Value, json};

#[test]
#[ignore]
fn registered_api_key_is_listed_for_its_user_and_gone_after_delete() {
    let run = Run::new();
    let (user_id, _) = run.create_user("user-keys");

    let key_path = run.home.path().join("registered.json");
    let public_key = run.generate_key(&key_path)["data"]["publicKey"]
        .as_str()
        .unwrap()
        .to_string();

    let key_name = run.name("key");
    let registered = run.submit(
        run.admin().args([
            "api-key",
            "register",
            "--input-json",
            &json!({
                "userId": user_id,
                "apiKeys": [{
                    "apiKeyName": key_name,
                    "publicKey": public_key,
                    "curveType": "API_KEY_CURVE_P256",
                }],
            })
            .to_string(),
        ]),
        "api-key.register",
    );
    let api_key_id = result(&registered, "createApiKeysResult")["apiKeyIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    let listed = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    assert_eq!(listed["command"], "api-key.list");
    let keys = listed["data"]["apiKeys"].as_array().unwrap();
    let ours = keys
        .iter()
        .find(|key| key["apiKeyId"] == api_key_id)
        .unwrap_or_else(|| panic!("registered key missing from list: {listed}"));
    assert_eq!(ours["apiKeyName"], key_name);
    assert_eq!(ours["credential"]["publicKey"], public_key);
    assert_eq!(ours["expiresAt"], Value::Null, "{ours}");

    let deleted = run.submit(
        run.admin()
            .args(["api-key", "delete", "--user-id", &user_id, &api_key_id]),
        "api-key.delete",
    );
    assert_eq!(
        result(&deleted, "deleteApiKeysResult")["apiKeyIds"],
        json!([api_key_id])
    );
    let listed = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    assert!(
        listed["data"]["apiKeys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key["apiKeyId"] != api_key_id)
    );
}
