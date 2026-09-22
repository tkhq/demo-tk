use crate::run::{AGENT_TAG, HUMAN_TAG, Run, allow_once, result, tag_consensus};
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

fn export_policy(run: &Run, name: &str, consensus: &str, level: &str) {
    run.create_policy_from_flags(
        &run.name(name),
        "allow",
        consensus,
        &format!(
            "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == '{level}'"
        ),
    );
}

fn self_registration(user_id: &str, public_key: &str) -> String {
    json!({
        "userId": user_id,
        "apiKeys": [{
            "apiKeyName": "escape",
            "publicKey": public_key,
            "curveType": "API_KEY_CURVE_P256",
        }],
    })
    .to_string()
}

#[test]
#[ignore]
fn provisioning_agent_identity_long_lived_route() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (agent_id, agent) = run.create_tagged_user("agent", AGENT_TAG);
    let (_, human) = run.create_tagged_user("human", HUMAN_TAG);
    export_policy(
        &run,
        "agents-export-unilateral",
        &tag_consensus(&agent_tag),
        "unilateral",
    );
    export_policy(
        &run,
        "agents-export-with-approval",
        &allow_once(&agent_tag, &human_tag),
        "approval",
    );
    run.create_policy_from_flags(
        &run.name("agents-no-credentials"),
        "deny",
        &tag_consensus(&agent_tag),
        "activity.resource == 'CREDENTIAL'",
    );

    let prefix = run.name("service");
    let import = |var: &str, level: &str, value: &str| {
        let file = run.home().join(format!("{var}.txt"));
        fs::write(&file, value).unwrap();
        run.submit(
            run.admin()
                .args([
                    "secret",
                    "import",
                    &format!("{prefix}/{var}"),
                    "--property",
                    &format!("consensus={level}"),
                    "--from-file",
                ])
                .arg(&file),
            "secret.import",
        );
    };
    import("API_TOKEN", "unilateral", "tok-1");
    import("DEPLOY_KEY", "approval", "deploy-1");

    run.login_as("agent", &agent);
    let whoami = run.ok(run.cli().args(["--profile", "agent", "whoami"]));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"]["userId"], agent_id, "{whoami}");

    let token = run.ok(run.as_user(&agent).args([
        "secret",
        "export",
        "--name",
        &format!("{prefix}/API_TOKEN"),
    ]));
    assert_eq!(token["status"], "completed", "{token}");
    assert_eq!(token["data"]["value"], "tok-1");

    let deploy_args = [
        "secret",
        "export",
        "--name",
        &format!("{prefix}/DEPLOY_KEY"),
    ];
    let pending = run.ok(run.as_user(&agent).args(deploy_args));
    assert_eq!(pending["status"], "pending", "{pending}");
    assert!(pending["data"].get("value").is_none(), "{pending}");
    let activity = pending["activity"]["id"].as_str().unwrap().to_string();
    run.ok(run.as_user(&human).args(["activity", "approve", &activity]));
    run.wait(&activity);
    let deploy = run.ok(run.as_user(&agent).args(deploy_args));
    assert_eq!(deploy["status"], "completed", "{deploy}");
    assert_eq!(deploy["activity"]["id"], activity);
    assert_eq!(deploy["data"]["value"], "deploy-1");

    let escape = run.err(run.as_user(&agent).args([
        "api-key",
        "register",
        "--input-json",
        &self_registration(&agent_id, &hex::encode(run.key().compressed_public_key())),
    ]));
    assert_eq!(escape["code"], "unauthorized", "{escape}");
    assert_eq!(escape["httpStatus"], 403, "{escape}");

    let listed = run.ok(run
        .as_user(&agent)
        .args(["api-key", "list", "--user-id", &agent_id]));
    let keys = listed["data"]["apiKeys"].as_array().unwrap();
    assert_eq!(keys.len(), 1, "{listed}");
    assert_eq!(
        keys[0]["credential"]["publicKey"],
        hex::encode(agent.compressed_public_key())
    );
    assert_eq!(keys[0]["expiresAt"], Value::Null, "{listed}");
}

#[test]
#[ignore]
fn provisioning_agent_identity_isolation_denies_cross_agent_export() {
    let run = Run::new();
    let agents = [("billing", "billing-agent"), ("ops", "ops-agent")].map(|(scope, tag)| {
        let tag_id = run.create_tag(tag);
        let (_, key) = run.create_tagged_user(scope, tag);
        run.create_policy_from_flags(
            &run.name(&format!("{tag}-export")),
            "allow",
            &tag_consensus(&tag_id),
            &format!(
                "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'unilateral' && secret.static_properties['scope'] == '{scope}'"
            ),
        );
        let name = format!("{}/TOKEN", run.name(scope));
        run.submit(
            run.admin()
                .args([
                    "secret",
                    "import",
                    &name,
                    "--property",
                    "consensus=unilateral",
                    "--property",
                    &format!("scope={scope}"),
                ])
                .write_stdin(format!("{scope}-token")),
            "secret.import",
        );
        (scope, key, name)
    });
    let [(_, billing, billing_name), (_, ops, ops_name)] = &agents;

    for (scope, key, own) in &agents {
        let exported = run.ok(run.as_user(key).args(["secret", "export", "--name", own]));
        assert_eq!(exported["status"], "completed", "{exported}");
        assert_eq!(exported["data"]["value"], format!("{scope}-token"));
    }
    for (key, other) in [(billing, ops_name), (ops, billing_name)] {
        let denied = run.err(run.as_user(key).args(["secret", "export", "--name", other]));
        assert_eq!(denied["code"], "unauthorized", "{denied}");
        assert_eq!(denied["httpStatus"], 403, "{denied}");
    }

    let selected = run.err(run.as_user(billing).args([
        "secret",
        "env",
        "--name-prefix",
        &format!("{}/", run.name("ops")),
    ]));
    assert_eq!(selected["code"], "unauthorized", "{selected}");
    assert_eq!(selected["httpStatus"], 403, "{selected}");
}
