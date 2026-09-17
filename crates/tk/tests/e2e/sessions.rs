use crate::run::{Run, result};
use serde_json::{Value, json};
use std::fs;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

/// Creates a user allowed to mint expiring API keys for other users.
fn create_provisioner(run: &Run) -> TurnkeyP256ApiKey {
    let key = run.key();
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--user-name",
            &run.name("provisioner"),
            "--public-key",
            &hex::encode(key.compressed_public_key()),
        ]),
        "user.create",
    );
    let provisioner_id = result(&created, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string();
    run.create_policy(json!({
        "policyName": run.name("provisioners-mint"),
        "effect": "EFFECT_ALLOW",
        "consensus": format!("approvers.any(user, user.id == '{provisioner_id}')"),
        "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
        "notes": ""
    }));
    key
}

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
    assert_eq!(
        requested["data"]["userId"], admin.record["data"]["identity"]["userId"],
        "{requested}"
    );
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
    let provisioner_key = create_provisioner(&run);
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
    assert_eq!(
        again["data"]["apiKeyId"], provisioned["data"]["apiKeyId"],
        "{again}"
    );
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

#[test]
#[ignore]
fn session_loop_rotates_an_agent_profile_and_reports_status() {
    let run = Run::new();
    let provisioner_key = create_provisioner(&run);

    // The agent's first credential lives outside api-keys/ and is registered by root.
    let first_key_file = run.home().join("agent-first.json");
    let generated = run.ok(run
        .cli()
        .args(["api-key", "generate", "--output"])
        .arg(&first_key_file));
    let first_public = generated["data"]["publicKey"].as_str().unwrap().to_string();
    let stored: Value = serde_json::from_slice(&fs::read(&first_key_file).unwrap()).unwrap();
    run.secrets
        .borrow_mut()
        .push(stored["private_key"].as_str().unwrap().to_string());
    let agent_name = run.name("agent");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &json!({"users": [{
                "userName": agent_name,
                "apiKeys": [{"apiKeyName": "first", "publicKey": first_public, "curveType": "API_KEY_CURVE_P256"}],
                "authenticators": [],
                "oauthProviders": [],
                "userTags": [],
            }]})
            .to_string(),
        ]),
        "user.create",
    );
    let agent_id = result(&created, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string();
    let agent_profile = run.name("agent-profile");
    run.ok(run
        .cli()
        .args([
            "profile",
            "create",
            "--profile-name",
            &agent_profile,
            "--organization-id",
            run.org(),
            "--api-key-file",
        ])
        .arg(&first_key_file));
    run.ok(run.cli().args(["login", "--profile-name", &agent_profile]));

    let no_expiry = run.ok(run
        .cli()
        .args(["session", "status", "--profile-name", &agent_profile]));
    assert_eq!(no_expiry["command"], "session.status");
    assert_eq!(no_expiry["data"]["userId"], agent_id);
    assert_eq!(no_expiry["data"]["publicKey"], first_public);
    assert!(no_expiry["data"]["secondsLeft"].is_null(), "{no_expiry}");
    assert!(no_expiry["data"]["expiresAt"].is_null(), "{no_expiry}");

    let nothing_pending =
        run.err(
            run.cli()
                .args(["session", "activate", "--profile-name", &agent_profile]),
        );
    assert_eq!(
        nothing_pending["code"], "invalid_input",
        "{nothing_pending}"
    );

    let requested =
        run.ok(run
            .cli()
            .args(["session", "request", "--profile-name", &agent_profile]));
    assert_eq!(requested["data"]["userId"], agent_id);
    let public_key = requested["data"]["publicKey"].as_str().unwrap().to_string();
    let new_key_file = requested["data"]["keyFile"].as_str().unwrap().to_string();

    let not_yet =
        run.err(
            run.cli()
                .args(["session", "activate", "--profile-name", &agent_profile]),
        );
    assert_eq!(not_yet["code"], "unauthorized", "{not_yet}");
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &agent_profile]))["data"]["profile"]["api_key_file"],
        fs::canonicalize(&first_key_file).unwrap().to_str().unwrap()
    );

    run.submit(
        run.as_user(&provisioner_key).args([
            "session",
            "provision",
            "--user-id",
            &agent_id,
            "--public-key",
            &public_key,
            "--expires-in",
            "2h",
        ]),
        "session.provision",
    );

    let activated =
        run.ok(run
            .cli()
            .args(["session", "activate", "--profile-name", &agent_profile]));
    assert_eq!(activated["command"], "session.activate");
    assert_eq!(activated["data"]["publicKey"], public_key);
    assert_eq!(activated["data"]["previousPublicKey"], first_public);
    assert_eq!(activated["data"]["previousKeyFileRemoved"], false);
    assert_eq!(activated["data"]["identity"]["userId"], agent_id);
    assert!(first_key_file.exists());
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &agent_profile]))["data"]["profile"]["api_key_file"],
        new_key_file
    );
    assert!(
        !run.home()
            .join(".config/turnkey/tk/sessions/pending")
            .join(format!("{agent_profile}.json"))
            .exists()
    );
    let identity = run.ok(run.cli().args(["--profile", &agent_profile, "whoami"]));
    assert_eq!(identity["data"]["userId"], agent_id);

    let status = run.ok(run.cli().args([
        "session",
        "status",
        "--profile-name",
        &agent_profile,
        "--warn-before",
        "1h",
    ]));
    assert_eq!(status["data"]["publicKey"], public_key);
    assert_eq!(status["data"]["expirationSeconds"], "7200");
    let seconds_left = status["data"]["secondsLeft"].as_u64().unwrap();
    assert!((7000..=7200).contains(&seconds_left), "{status}");
    assert!(status["data"]["expiresAt"].is_string(), "{status}");
    assert_eq!(status["data"]["warnBefore"], "1h");

    // The default window is 48h, so a 2h key is already expiring.
    let expiring = run.err(
        run.cli()
            .args(["session", "status", "--profile-name", &agent_profile]),
    );
    assert_eq!(expiring["code"], "session_expiring", "{expiring}");
    assert_eq!(expiring["details"]["profile"], agent_profile);
    assert_eq!(expiring["details"]["warnBeforeSeconds"], 172_800);
    assert_eq!(expiring["details"]["publicKey"], public_key);

    // A second rotation removes the previous generated key file.
    let second = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &agent_profile]));
    run.submit(
        run.as_user(&provisioner_key).args([
            "session",
            "provision",
            "--user-id",
            &agent_id,
            "--public-key",
            second["data"]["publicKey"].as_str().unwrap(),
            "--expires-in",
            "2h",
        ]),
        "session.provision",
    );
    let rotated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &agent_profile]));
    assert_eq!(rotated["data"]["previousKeyFileRemoved"], true);
    assert!(
        fs::metadata(&new_key_file).is_err(),
        "old generated key file kept"
    );
}
