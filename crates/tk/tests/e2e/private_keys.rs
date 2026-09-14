use crate::run::{Run, result};
use serde_json::{Value, json};

#[test]
#[ignore]
fn private_key_create_get_list_sign_and_delete() {
    let run = Run::new();
    let name = run.name("private-key");
    let created = run.submit(
        run.admin().args([
            "private-key",
            "create",
            "--input-json",
            &json!({
                "privateKeys": [{
                    "privateKeyName": name,
                    "curve": "CURVE_SECP256K1",
                    "privateKeyTags": [],
                    "addressFormats": ["ADDRESS_FORMAT_ETHEREUM"],
                }],
            })
            .to_string(),
        ]),
        "private-key.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2"
    );
    let key = &result(&created, "createPrivateKeysResultV2")["privateKeys"][0];
    let private_key_id = key["privateKeyId"].as_str().unwrap().to_string();
    assert_eq!(key["addresses"][0]["format"], "ADDRESS_FORMAT_ETHEREUM");

    let got = run.ok(run.admin().args(["private-key", "get", &private_key_id]));
    assert_eq!(got["command"], "private-key.get");
    assert_eq!(got["data"]["privateKey"]["privateKeyId"], private_key_id);
    assert_eq!(got["data"]["privateKey"]["privateKeyName"], name);
    assert_eq!(got["data"]["privateKey"]["curve"], "CURVE_SECP256K1");

    let listed = run.ok(run.admin().args(["private-key", "list"]));
    assert_eq!(listed["command"], "private-key.list");
    let ids: Vec<&str> = listed["data"]["privateKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["privateKeyId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [private_key_id.as_str()]);

    let digest = format!("0x{}", "22".repeat(32));
    let signed = run.submit(
        run.admin().args([
            "sign",
            "payload",
            "--input-json",
            &json!({
                "signWith": private_key_id,
                "payload": digest,
                "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
                "hashFunction": "HASH_FUNCTION_NO_OP",
            })
            .to_string(),
        ]),
        "sign.payload",
    );
    assert_eq!(signed["status"], "completed");
    let signature = result(&signed, "signRawPayloadResult");
    assert_eq!(signature["r"].as_str().unwrap().len(), 64);
    assert_eq!(signature["s"].as_str().unwrap().len(), 64);

    let deleted = run.submit(
        run.admin().args([
            "private-key",
            "delete",
            "--input-json",
            &json!({"privateKeyIds": [private_key_id], "deleteWithoutExport": true}).to_string(),
        ]),
        "private-key.delete",
    );
    assert_eq!(
        deleted["data"]["activity"]["type"],
        "ACTIVITY_TYPE_DELETE_PRIVATE_KEYS"
    );
    assert_eq!(
        result(&deleted, "deletePrivateKeysResult")["privateKeyIds"],
        json!([private_key_id])
    );

    let listed = run.ok(run.admin().args(["private-key", "list"]));
    assert_eq!(listed["data"]["privateKeys"], Value::Array(vec![]));
}
