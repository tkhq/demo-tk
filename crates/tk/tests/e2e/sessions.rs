use crate::run::Run;
use serde_json::json;
use std::fs;

#[test]
#[ignore]
fn session_request_generates_a_pending_credential() {
    let run = Run::new();
    let admin = run.login_admin();

    let requested = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &admin.name]));
    assert_eq!(requested["command"], "session.request");
    assert_eq!(requested["status"], "completed");
    let public_key = requested["data"]["publicKey"].as_str().unwrap();
    assert!(public_key.starts_with("02") || public_key.starts_with("03"));
    assert_eq!(public_key.len(), 66);
    assert_eq!(requested["data"]["organizationId"], run.org());
    assert!(requested["data"]["userId"].is_string(), "{requested}");
    assert_eq!(requested["data"]["curve"], "p256");
    let key_file = requested["data"]["keyFile"].as_str().unwrap().to_string();
    assert!(
        key_file.contains("/.config/turnkey/tk/api-keys/"),
        "{key_file}"
    );
    fs::metadata(&key_file).unwrap();
    let pending = run
        .home()
        .join(".config/turnkey/tk/sessions/pending")
        .join(format!("{}.json", admin.name));
    assert!(pending.exists());

    let again = run.err(
        run.cli()
            .args(["session", "request", "--profile-name", &admin.name]),
    );
    assert_eq!(again["code"], "invalid_input", "{again}");

    let replaced = run.ok(run.cli().args([
        "session",
        "request",
        "--profile-name",
        &admin.name,
        "--replace",
    ]));
    assert_ne!(
        replaced["data"]["publicKey"],
        requested["data"]["publicKey"]
    );
    assert!(
        fs::metadata(&key_file).is_err(),
        "replaced key file was not removed"
    );
    fs::metadata(replaced["data"]["keyFile"].as_str().unwrap()).unwrap();

    let unknown =
        run.err(
            run.cli()
                .args(["session", "request", "--profile-name", "no-such-profile"]),
        );
    assert_eq!(unknown["code"], "invalid_input", "{unknown}");
}

#[test]
#[ignore]
fn session_provision_registers_an_expiring_key_once() {
    let run = Run::new();
    let (agent_id, _agent_key) = run.create_user("agent");
    let (provisioner_id, provisioner_key) = run.create_user("provisioner");
    run.create_policy(json!({
        "policyName": run.name("provisioners-mint"),
        "effect": "EFFECT_ALLOW",
        "consensus": format!("approvers.any(user, user.id == '{provisioner_id}')"),
        "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
        "notes": ""
    }));
    let public_key = hex::encode(run.key().compressed_public_key());
    let provision = |label: Option<&str>| {
        let mut cmd = run.as_user(&provisioner_key);
        cmd.args([
            "session",
            "provision",
            "--user-id",
            &agent_id,
            "--public-key",
            &public_key.to_uppercase(),
            "--expires-in",
            "2h",
        ]);
        if let Some(label) = label {
            cmd.args(["--label", label]);
        }
        cmd
    };

    let provisioned = run.submit(&mut provision(Some("first-session")), "session.provision");
    assert_eq!(provisioned["data"]["expirationSeconds"], "7200");
    assert_eq!(provisioned["data"]["expiresIn"], "2h");
    assert_eq!(provisioned["data"]["userId"], agent_id);
    assert_eq!(provisioned["data"]["publicKey"], public_key);
    assert_eq!(provisioned["data"]["apiKeyName"], "first-session");
    assert_eq!(
        provisioned["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2"
    );

    // Re-running reports the registered key instead of creating another.
    let again = run.ok(&mut provision(None));
    assert_eq!(again["command"], "session.provision");
    assert_eq!(again["status"], "completed");
    assert_eq!(again["data"]["alreadyRegistered"], true);
    assert_eq!(again["data"]["apiKeyName"], "first-session");
    assert_eq!(again["data"]["expirationSeconds"], "7200");
    assert_eq!(again["data"]["expiresIn"], "2h");
    assert!(again["data"]["apiKeyId"].is_string(), "{again}");
    assert!(again.get("activity").is_none(), "{again}");

    let listed = run.ok(run
        .admin()
        .args(["api-key", "list", "--user-id", &agent_id]));
    let matching: Vec<_> = listed["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["credential"]["publicKey"] == public_key)
        .collect();
    assert_eq!(matching.len(), 1, "{listed}");
    assert_eq!(matching[0]["expirationSeconds"], "7200");
    assert_eq!(matching[0]["apiKeyId"], again["data"]["apiKeyId"]);
}
