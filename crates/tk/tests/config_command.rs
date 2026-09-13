//! Tests for `tk config`.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

fn config_path() -> (TempDir, PathBuf) {
    let temp = tempdir().expect("temp dir should exist");
    let config_path = temp.path().join("tk.toml");
    (temp, config_path)
}

fn tk(config_path: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.env("TURNKEY_TK_CONFIG_PATH", config_path)
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .env_remove("TURNKEY_PRIVATE_KEY_ID")
        .env_remove("TURNKEY_API_BASE_URL");
    cmd
}

#[test]
fn config_command_help_lists_subcommands() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.args(["config", "--help"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("list"));
}

#[test]
fn config_round_trip() {
    let (_temp, config_path) = config_path();

    tk(&config_path)
        .args(["config", "set", "turnkey.organizationId", "persisted-org"])
        .assert()
        .success();

    let stored = fs::read_to_string(&config_path).expect("config file should exist");
    let stored: toml::Value = toml::from_str(&stored).expect("config file should be TOML");
    let expected: toml::Value = toml::from_str(
        r#"
[turnkey]
organizationId = "persisted-org"
"#,
    )
    .expect("expected config should be TOML");
    assert_eq!(stored, expected);

    tk(&config_path)
        .args(["config", "get", "turnkey.organizationId"])
        .assert()
        .success()
        .stdout(predicate::str::contains("persisted-org"));

    let output = tk(&config_path)
        .args(["config", "list"])
        .env("TURNKEY_ORGANIZATION_ID", "env-org")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).expect("config list should output json");
    assert_eq!(value["turnkey"]["organizationId"], "env-org");
}

#[test]
fn config_list_and_get_redact_private_key() {
    let (_temp, config_path) = config_path();

    tk(&config_path)
        .args([
            "config",
            "set",
            "turnkey.apiPrivateKey",
            "persisted-private-key",
        ])
        .assert()
        .success();

    let output = tk(&config_path)
        .args(["config", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).expect("config list should output json");
    assert_eq!(value["turnkey"]["apiPrivateKey"], "<redacted>");
    assert!(!String::from_utf8_lossy(&output).contains("persisted-private-key"));

    tk(&config_path)
        .args(["config", "get", "turnkey.apiPrivateKey"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<redacted>"))
        .stdout(predicate::str::contains("persisted-private-key").not());
}

#[test]
fn config_set_writes_owner_only_file() {
    use std::os::unix::fs::PermissionsExt;

    let (_temp, config_path) = config_path();

    let mode = |path: &Path| {
        fs::metadata(path)
            .expect("config file should exist")
            .permissions()
            .mode()
            & 0o777
    };

    tk(&config_path)
        .args(["config", "set", "turnkey.apiPrivateKey", "persisted-key"])
        .assert()
        .success();
    assert_eq!(mode(&config_path), 0o600);

    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o644))
        .expect("permissions should update");

    tk(&config_path)
        .args(["config", "set", "turnkey.organizationId", "persisted-org"])
        .assert()
        .success();
    assert_eq!(mode(&config_path), 0o600);
}

// Exact Clap golden shared by the get/set usage-error tests.
const UNSUPPORTED_KEY_MESSAGE: &str = r#"error: invalid value 'not.a.key' for '<KEY>': unsupported config key: not.a.key; supported keys: turnkey.organizationId, turnkey.apiPublicKey, turnkey.apiPrivateKey, turnkey.privateKeyId, turnkey.apiBaseUrl

For more information, try '--help'."#;

#[test]
fn config_get_rejects_unsupported_key_in_human_mode() {
    let (_temp, config_path) = config_path();

    let assert = tk(&config_path)
        .args(["config", "get", "not.a.key"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let stderr = String::from_utf8(assert.get_output().stderr.clone())
        .expect("stderr should be valid utf-8");
    assert_eq!(stderr.trim_end(), UNSUPPORTED_KEY_MESSAGE);
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_set_rejects_unsupported_key_in_human_mode() {
    let (_temp, config_path) = config_path();

    let assert = tk(&config_path)
        .args(["config", "set", "not.a.key", "some-value"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());

    let stderr = String::from_utf8(assert.get_output().stderr.clone())
        .expect("stderr should be valid utf-8");
    assert_eq!(stderr.trim_end(), UNSUPPORTED_KEY_MESSAGE);
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_get_unsupported_key_json_emits_usage_error_envelope() {
    let (_temp, config_path) = config_path();

    let output = tk(&config_path)
        .args(["config", "get", "not.a.key", "--message-format=json"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).expect("stdout should be one JSON object");
    assert_eq!(
        record,
        json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": UNSUPPORTED_KEY_MESSAGE,
        })
    );
    assert!(!config_path.exists(), "a usage error must not touch config");
}

#[test]
fn config_set_unsupported_key_json_emits_usage_error_envelope() {
    let (_temp, config_path) = config_path();

    let output = tk(&config_path)
        .args([
            "config",
            "set",
            "not.a.key",
            "some-value",
            "--message-format=json",
        ])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();

    let record: Value = serde_json::from_slice(&output).expect("stdout should be one JSON object");
    assert_eq!(
        record,
        json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": UNSUPPORTED_KEY_MESSAGE,
        })
    );
    assert!(!config_path.exists(), "a usage error must not touch config");
}
