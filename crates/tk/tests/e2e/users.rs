use crate::run::{Run, created_user_id, one_api_key, result, user_params};
use serde_json::{Value, json};

#[test]
#[ignore]
fn user_lifecycle_from_input_json_and_stdin() {
    let run = Run::new();

    let json_name = run.name("user-json");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(&json_name, one_api_key(&run, &json_name)),
        ]),
        "user.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_USERS_V4"
    );
    let json_user = created_user_id(&created);

    let stdin_name = run.name("user-stdin");
    let created = run.submit(
        run.admin()
            .args(["user", "create", "--input-file", "-"])
            .write_stdin(user_params(&stdin_name, one_api_key(&run, &stdin_name))),
        "user.create",
    );
    let stdin_user = created_user_id(&created);

    for (id, name) in [(&json_user, &json_name), (&stdin_user, &stdin_name)] {
        let got = run.ok(run.admin().args(["user", "get", id]));
        assert_eq!(got["command"], "user.get");
        assert_eq!(got["data"]["user"]["userId"], *id);
        assert_eq!(got["data"]["user"]["userName"], *name);
    }
    let list = run.ok(run.admin().args(["user", "list"]));
    assert_eq!(list["command"], "user.list");
    let listed: Vec<&str> = list["data"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userId"].as_str().unwrap())
        .collect();
    assert!(listed.contains(&json_user.as_str()));
    assert!(listed.contains(&stdin_user.as_str()));

    let deleted = run.submit(
        run.admin().args(["user", "delete", &stdin_user]),
        "user.delete",
    );
    assert_eq!(
        result(&deleted, "deleteUsersResult")["userIds"],
        json!([stdin_user])
    );
    let missing = run.err(run.admin().args(["user", "get", &stdin_user]));
    assert_eq!(missing["code"], "not_found");
}

#[test]
#[ignore]
fn user_create_from_flags_resolves_tag_names_and_registers_anchor_and_expiring_keys() {
    let run = Run::new();
    let tag_name = run.name("agent");
    let tagged = run.submit(
        run.admin()
            .args(["user", "tag", "create", "--name", &tag_name]),
        "user.tag.create",
    );
    let tag_id = result(&tagged, "createUserTagResult")["userTagId"]
        .as_str()
        .unwrap()
        .to_string();

    let key = run.key();
    let public_key = hex::encode(key.compressed_public_key());
    let user_name = run.name("flag-user");

    // Turnkey requires one long-lived credential per user.
    let expiring_only = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &user_name,
        "--public-key",
        &public_key,
        "--expires-in",
        "2h",
    ]));
    assert_eq!(expiring_only["code"], "api_error", "{expiring_only}");
    assert_eq!(expiring_only["httpStatus"], 400, "{expiring_only}");

    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--user-name",
            &user_name,
            "--tag-name",
            &tag_name,
            "--public-key",
            &public_key,
            "--expires-in",
            "2h",
            "--anchor-key",
        ]),
        "user.create",
    );
    let user_id = created_user_id(&created);

    let got = run.ok(run.admin().args(["user", "get", &user_id]));
    assert_eq!(got["data"]["user"]["userName"], user_name);
    assert_eq!(got["data"]["user"]["userTags"], json!([tag_id]));
    let keys = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    let ours = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["credential"]["publicKey"] == public_key)
        .unwrap_or_else(|| panic!("registered key missing: {keys}"));
    assert_eq!(ours["apiKeyName"], format!("{user_name}-key"));
    assert_eq!(ours["expirationSeconds"], "7200");
    let created: u64 = ours["createdAt"]["seconds"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        ours["expiresAt"],
        ((created + 7200) * 1000).to_string(),
        "{ours}"
    );
    let anchor = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["apiKeyName"] == format!("{user_name}-anchor"))
        .unwrap_or_else(|| panic!("anchor key missing: {keys}"));
    assert_eq!(anchor["expirationSeconds"], Value::Null, "{anchor}");
    assert_eq!(keys["data"]["apiKeys"].as_array().unwrap().len(), 2);

    let whoami = run.ok(run.as_user(&key).arg("whoami"));
    assert_eq!(whoami["data"]["userId"], user_id);

    let unknown_tag = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &run.name("orphan"),
        "--tag-name",
        &run.name("no-such-tag"),
    ]));
    assert_eq!(unknown_tag["code"], "not_found", "{unknown_tag}");
}
