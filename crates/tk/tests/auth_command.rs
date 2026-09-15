//! Tests for `tk auth`.
// Test helpers may panic.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use std::{fs, path::Path};
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

const ORG: &str = "00000000-0000-4000-8000-000000000001";
fn command(temp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in [
        "TK_PROFILE",
        "TURNKEY_ORGANIZATION_ID",
        "TURNKEY_API_PUBLIC_KEY",
        "TURNKEY_API_PRIVATE_KEY",
        "TURNKEY_API_BASE_URL",
    ] {
        command.env_remove(name);
    }
    command
        .env("HOME", temp.path())
        .arg("--message-format=json");
    command
}

fn key(path: &Path) {
    let key = TurnkeyP256ApiKey::generate();
    let stored = json!({
        "public_key": hex::encode(key.compressed_public_key()),
        "private_key": hex::encode(key.private_key()),
        "curve": "p256",
    });
    fs::write(path, serde_json::to_vec(&stored).unwrap()).unwrap();
}

fn registry(temp: &TempDir) {
    let directory = temp.path().join(".config/turnkey");
    fs::create_dir_all(&directory).unwrap();
    key(&directory.join("admin.json"));
    key(&directory.join("agent.json"));
    fs::write(
        directory.join("tk.config.toml"),
        format!(
            r#"version = 1
active_profile = "admin"
[profiles.admin]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "{}/admin.json"
[profiles.agent]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "{}/agent.json"
"#,
            directory.display(),
            directory.display()
        ),
    )
    .unwrap();
}

fn output(command: &mut Command) -> Value {
    let result = command.assert().success();
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}

fn failure(command: &mut Command, code: i32) -> Value {
    let result = command
        .assert()
        .code(code)
        .stderr(predicate::str::is_empty());
    serde_json::from_slice(&result.get_output().stdout).unwrap()
}
#[test]
fn malformed_selected_registry_reports_invalid_input_without_source_text() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    fs::write(
        temp.path().join(".config/turnkey/tk.config.toml"),
        "secret-pasted-on-invalid-line",
    )
    .unwrap();
    let result = command(&temp)
        .args(["--profile", "agent", "auth", "status"])
        .assert()
        .failure();
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    assert!(
        !parsed["message"]
            .as_str()
            .unwrap()
            .contains("secret-pasted")
    );
}
#[test]
fn relative_credential_path_in_registry_is_invalid_input() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    fs::write(
        temp.path().join(".config/turnkey/tk.config.toml"),
        format!(
            r#"version = 1
active_profile = "admin"
[profiles.admin]
organization_id = "{ORG}"
api_base_url = "https://api.turnkey.com"
api_key_file = "admin.json"
"#
        ),
    )
    .unwrap();
    let result = command(&temp)
        .current_dir(temp.path().join(".config/turnkey"))
        .args(["auth", "status"])
        .assert()
        .failure();
    let parsed: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(parsed["code"], "invalid_input");
    assert!(
        parsed["message"]
            .as_str()
            .unwrap()
            .contains("relative api_key_file admin.json")
    );
}
#[tokio::test]
async fn login_verifies_a_created_profile_and_selects_it() {
    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("key.json");
    key(&key_path);
    let server = MockServer::start().await;
    let identity = json!({"organizationId": ORG, "organizationName": "test", "userId": "user-1", "username": "alice"});
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .and(body_json(json!({"organizationId": ORG})))
        .respond_with(ResponseTemplate::new(200).set_body_json(&identity))
        .expect(2)
        .mount(&server)
        .await;
    output(
        command(&temp)
            .args([
                "--organization-id",
                ORG,
                "--api-base-url",
                &server.uri(),
                "profile",
                "create",
                "admin",
                "--api-key-file",
            ])
            .arg(&key_path),
    );
    let unselected = failure(command(&temp).args(["auth", "status"]), 1);
    assert_eq!(unselected["code"], "invalid_input");

    let login = output(command(&temp).args(["login", "admin"]));
    assert_eq!(
        login["data"],
        json!({"profile": "admin", "identity": identity})
    );
    let whoami = output(command(&temp).arg("whoami"));
    assert_eq!(whoami["data"], identity);

    let parsed = failure(
        command(&temp)
            .env("TK_PROFILE", "ambient")
            .args(["login", "admin"]),
        1,
    );
    assert_eq!(parsed["code"], "invalid_input");
    server.verify().await;
}

#[tokio::test]
async fn typed_client_does_not_follow_redirects() {
    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("key.json");
    key(&key_path);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/whoami"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", "/leak"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/leak"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(0)
        .mount(&server)
        .await;
    output(
        command(&temp)
            .args([
                "--organization-id",
                ORG,
                "--api-base-url",
                &server.uri(),
                "profile",
                "create",
                "admin",
                "--api-key-file",
            ])
            .arg(&key_path),
    );
    let parsed = failure(command(&temp).args(["login", "admin"]), 1);
    assert_eq!(parsed["code"], "api_error");
    server.verify().await;
}

#[tokio::test]
async fn typed_client_http_status_is_classified_end_to_end() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/public/v1/query/get_user"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message":"no such user"})))
        .expect(1)
        .mount(&server)
        .await;
    let parsed = failure(
        command(&temp).args([
            "--api-base-url",
            &server.uri(),
            "user",
            "get",
            "00000000-0000-4000-8000-000000000002",
        ]),
        1,
    );
    assert_eq!(parsed["reason"], "command_error");
    assert_eq!(parsed["code"], "not_found");
    assert_eq!(parsed["httpStatus"], 404);
    assert!(parsed["message"].as_str().unwrap().contains("no such user"));
}

#[test]
fn invalid_key_length_is_an_error_without_panic() {
    let temp = TempDir::new().unwrap();
    let parsed = failure(
        command(&temp)
            .env("TURNKEY_ORGANIZATION_ID", ORG)
            .env("TURNKEY_API_PUBLIC_KEY", "00")
            .env("TURNKEY_API_PRIVATE_KEY", "01")
            .args(["auth", "status"]),
        1,
    );
    assert_eq!(parsed["reason"], "command_error");
    assert_eq!(parsed["code"], "invalid_input");
    assert!(!parsed["message"].as_str().unwrap().contains("'0'"));
}

#[test]
fn stale_lock_file_from_a_dead_process_does_not_block() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let lock = temp.path().join(".config/turnkey/tk.config.lock");
    fs::write(&lock, "99999").unwrap();
    output(command(&temp).args(["profile", "use", "agent"]));
}

#[test]
fn empty_environment_bundle_does_not_fall_back_to_saved_admin() {
    let temp = TempDir::new().unwrap();
    registry(&temp);
    let parsed = failure(
        command(&temp)
            .env("TURNKEY_API_PRIVATE_KEY", "")
            .args(["auth", "status"]),
        1,
    );
    assert_eq!(parsed["code"], "invalid_input");
    output(command(&temp).env("TURNKEY_API_PRIVATE_KEY", "").args([
        "--profile",
        "agent",
        "auth",
        "status",
    ]));
}

#[test]
fn api_key_generate_defaults_to_the_state_directory() {
    let temp = TempDir::new().unwrap();
    let generated = output(command(&temp).args(["api-key", "generate"]));
    let public_key = generated["data"]["publicKey"].as_str().unwrap();
    let expected = temp
        .path()
        .join(".config/turnkey/tk/api-keys")
        .join(format!("{public_key}.json"));
    assert_eq!(generated["data"]["path"], json!(expected));
    let stored: Value = serde_json::from_slice(&fs::read(&expected).unwrap()).unwrap();
    assert_eq!(stored["public_key"], public_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&expected).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn profile_create_generates_a_credential_and_login_rejects_local_mismatches() {
    let temp = TempDir::new().unwrap();
    let missing_org = failure(command(&temp).args(["profile", "create"]), 2);
    assert_eq!(missing_org["code"], "usage_error");

    let missing_profile = failure(command(&temp).arg("login"), 1);
    assert_eq!(missing_profile["code"], "invalid_input");
    assert_eq!(
        missing_profile["message"],
        "profile default does not exist; run tk profile create default --organization-id <org>"
    );

    let created = output(command(&temp).args(["--organization-id", ORG, "profile", "create"]));
    let public_key = created["data"]["publicKey"].as_str().unwrap().to_string();
    let key_file = temp
        .path()
        .join(".config/turnkey/tk/api-keys")
        .join(format!("{public_key}.json"));
    assert_eq!(created["command"], "profile.create");
    assert_eq!(
        created["data"],
        json!({
            "name": "default",
            "profile": {
                "organization_id": ORG,
                "api_base_url": "https://api.turnkey.com",
                "api_key_file": key_file,
            },
            "publicKey": public_key,
            "nextStep": format!("register public key {public_key} (API_KEY_CURVE_P256) on a user in organization {ORG}, then run tk login default"),
        })
    );
    let stored: Value = serde_json::from_slice(&fs::read(&key_file).unwrap()).unwrap();
    assert_eq!(stored["public_key"], public_key);
    assert!(
        !created
            .to_string()
            .contains(stored["private_key"].as_str().unwrap())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        output(command(&temp).args(["profile", "list"]))["data"]["activeProfile"],
        Value::Null
    );

    let duplicate = failure(
        command(&temp).args(["--organization-id", ORG, "profile", "create"]),
        1,
    );
    assert_eq!(duplicate["code"], "invalid_input");
    assert_eq!(
        duplicate["message"],
        "profile default already exists; run tk login default to select it"
    );

    let other_org = "00000000-0000-4000-8000-000000000002";
    let org_mismatch = failure(
        command(&temp).args(["--organization-id", other_org, "login"]),
        1,
    );
    assert_eq!(org_mismatch["code"], "invalid_input");
    assert_eq!(
        org_mismatch["message"],
        format!(
            "profile default is saved with organization {ORG}; run tk profile set default --organization-id {other_org} to change it"
        )
    );
    let url_mismatch = failure(
        command(&temp).args(["--api-base-url", "https://example.com", "login"]),
        1,
    );
    assert_eq!(url_mismatch["code"], "invalid_input");
    assert_eq!(
        url_mismatch["message"],
        "profile default is saved with API base URL https://api.turnkey.com; run tk profile set default --api-base-url https://example.com to change it"
    );
}

#[cfg(unix)]
#[test]
fn nonunicode_credential_environment_does_not_fall_back() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let temp = TempDir::new().unwrap();
    registry(&temp);
    command(&temp)
        .env("TURNKEY_API_PRIVATE_KEY", OsString::from_vec(vec![255]))
        .args(["auth", "status"])
        .assert()
        .code(1);
}
