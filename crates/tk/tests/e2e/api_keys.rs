use crate::run::{AGENT_TAG, Run, result};
use serde_json::{Value, json};
use std::fs;

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
    let registered = run.register_api_key(&user_id, &key_name, &public_key);
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

#[test]
#[ignore]
fn managing_identities_rotate_and_revoke() {
    let run = Run::new();
    run.create_tag(AGENT_TAG);
    let (user_id, first_key) = run.create_tagged_user("agent", AGENT_TAG);
    let first_public = hex::encode(first_key.compressed_public_key());
    let profile = run.name("agent");
    let first_file = run.login_as(&profile, &first_key);
    assert_eq!(
        run.ok(run.cli().args(["--profile", &profile, "whoami"]))["data"]["userId"],
        user_id
    );

    let next_file = run.home().join("next-key.json");
    let generated = run.generate_key(&next_file);
    assert_eq!(generated["command"], "api-key.generate");
    let next_public = generated["data"]["publicKey"].as_str().unwrap().to_string();

    let registered = run.register_api_key(&user_id, "agent-next", &next_public);
    let next_id = result(&registered, "createApiKeysResult")["apiKeyIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    let switched = run.ok(run
        .cli()
        .args(["profile", "set", &profile, "--api-key-file"])
        .arg(&next_file));
    assert_eq!(switched["command"], "profile.set");
    assert_eq!(switched["data"]["publicKey"], next_public);
    assert_eq!(
        switched["data"]["previousApiKeyFile"],
        fs::canonicalize(&first_file).unwrap().to_str().unwrap()
    );
    let whoami = run.ok(run.cli().args(["--profile", &profile, "whoami"]));
    assert_eq!(whoami["data"]["userId"], user_id);

    let listed = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    let keys = listed["data"]["apiKeys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "{listed}");
    let old = keys
        .iter()
        .find(|key| key["credential"]["publicKey"] == first_public)
        .unwrap_or_else(|| panic!("first key missing: {listed}"));
    assert_eq!(old["expiresAt"], Value::Null);
    let old_id = old["apiKeyId"].as_str().unwrap().to_string();
    assert_ne!(old_id, next_id);

    let deleted = run.submit(
        run.admin()
            .args(["api-key", "delete", "--user-id", &user_id, &old_id]),
        "api-key.delete",
    );
    assert_eq!(
        result(&deleted, "deleteApiKeysResult")["apiKeyIds"],
        json!([old_id])
    );
    let revoked = run.err(run.as_user(&first_key).arg("whoami"));
    assert_eq!(revoked["code"], "unauthorized", "{revoked}");
    assert_eq!(revoked["httpStatus"], 401, "{revoked}");
    run.ok(run.cli().args(["--profile", &profile, "whoami"]));

    let got = run.ok(run.admin().args(["user", "get", &user_id]));
    assert_eq!(got["data"]["user"]["userName"], run.name("agent"));
    let removed = run.submit(
        run.admin().args(["user", "delete", &user_id]),
        "user.delete",
    );
    assert_eq!(
        result(&removed, "deleteUsersResult")["userIds"],
        json!([user_id])
    );
    let gone = run.err(run.cli().args(["--profile", &profile, "whoami"]));
    assert_eq!(gone["code"], "unauthorized", "{gone}");
    let missing = run.err(run.admin().args(["user", "get", &user_id]));
    assert_eq!(missing["code"], "not_found", "{missing}");
}
