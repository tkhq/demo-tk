use crate::run::{Run, created_user_id, user_params};
use serde_json::{Value, json};
use std::fs;
use std::io::ErrorKind;

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
    assert_eq!(
        key_file,
        fs::canonicalize(
            run.home()
                .join(".config/turnkey/tk/api-keys")
                .join(format!("{public_key}.json"))
        )
        .unwrap()
        .to_str()
        .unwrap()
    );
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
    assert_eq!(
        fs::metadata(&key_file).unwrap_err().kind(),
        ErrorKind::NotFound,
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
    let provisioner_key = run.create_provisioner();
    let public_key = hex::encode(run.key().compressed_public_key());
    let provision = |label: Option<&str>| {
        let mut cmd = run.provision(&provisioner_key, &agent_id, &public_key.to_uppercase());
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
    assert_eq!(again["data"].get("activity"), None, "{again}");

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
    let provisioner_key = run.create_provisioner();

    let first_key_file = run.home().join("agent-first.json");
    let first_public = run.generate_key(&first_key_file)["data"]["publicKey"]
        .as_str()
        .unwrap()
        .to_string();
    let agent_name = run.name("agent");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(
                &agent_name,
                json!([{"apiKeyName": "first", "publicKey": first_public, "curveType": "API_KEY_CURVE_P256"}]),
            ),
        ]),
        "user.create",
    );
    let agent_id = created_user_id(&created);
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
    assert_eq!(no_expiry["data"]["secondsLeft"], Value::Null, "{no_expiry}");
    assert_eq!(no_expiry["data"]["expiresAt"], Value::Null, "{no_expiry}");

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
        &mut run.provision(&provisioner_key, &agent_id, &public_key),
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
    let created: u64 = status["data"]["createdAt"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        status["data"]["expiresAt"],
        ((created + 7200) * 1000).to_string(),
        "{status}"
    );
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

    let second = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &agent_profile]));
    run.submit(
        &mut run.provision(
            &provisioner_key,
            &agent_id,
            second["data"]["publicKey"].as_str().unwrap(),
        ),
        "session.provision",
    );
    let rotated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &agent_profile]));
    assert_eq!(rotated["data"]["previousKeyFileRemoved"], true);
    assert_eq!(
        fs::metadata(&new_key_file).unwrap_err().kind(),
        ErrorKind::NotFound,
        "old generated key file kept"
    );
}
