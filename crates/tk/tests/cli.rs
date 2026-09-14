//! Tests for top-level CLI parsing.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn cli_help_lists_registry_ssh_commands() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    command.arg("--help");
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh"))
        .stdout(predicate::str::contains("gpg"))
        .stdout(predicate::str::contains("TK_CONFIG"))
        .stdout(predicate::str::contains("TURNKEY_ORGANIZATION_ID"))
        .stdout(predicate::str::contains("TURNKEY_PRIVATE_KEY_ID").not())
        .stdout(predicate::str::contains("TURNKEY_TK_CONFIG_PATH").not())
        .stdout(predicate::str::contains(
            "export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock",
        ));

    let mut ssh = Command::new(env!("CARGO_BIN_EXE_tk"));
    ssh.args(["ssh", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys"))
        .stdout(predicate::str::contains("public-key"))
        .stdout(predicate::str::contains("git-sign"))
        .stdout(predicate::str::contains("agent"));

    let mut start = Command::new(env!("CARGO_BIN_EXE_tk"));
    start
        .args(["ssh", "agent", "start", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--key"))
        .stdout(predicate::str::contains("--socket"))
        .stdout(predicate::str::contains("--pid-file"));
}

#[test]
fn config_is_an_unknown_command() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = command
        .args(["--message-format=json", "config", "list"])
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let record: Value = serde_json::from_slice(&output).expect("usage error is JSON");
    assert_eq!(record["code"], "usage_error");
}

#[test]
fn empty_ssh_registry_is_an_invalid_input() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let registry = directory.path().join("registry.toml");
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let output = command
        .arg("--config")
        .arg(registry)
        .args(["--message-format=json", "ssh", "public-key"])
        .env_remove("TK_CONFIG")
        .env_remove("TK_PROFILE")
        .env_remove("TURNKEY_ORGANIZATION_ID")
        .env_remove("TURNKEY_API_PUBLIC_KEY")
        .env_remove("TURNKEY_API_PRIVATE_KEY")
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let record: Value = serde_json::from_slice(&output).expect("runtime error is JSON");
    assert_eq!(record["code"], "invalid_input");
    assert!(record["message"].as_str().is_some_and(|message| {
        message.contains("registry holds no SSH keys")
            && message.contains("tk ssh keys add --private-key-id ID")
    }));
}

#[test]
fn usage_errors_follow_the_json_protocol() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
    let result = command
        .args(["--message-format=json", "unknown-command"])
        .assert()
        .code(2);
    let record: Value =
        serde_json::from_slice(&result.get_output().stdout).expect("usage error is JSON");
    assert_eq!(record["reason"], "command_error");
    assert_eq!(record["code"], "usage_error");
    assert!(result.get_output().stderr.is_empty());
}

#[test]
fn profile_set_requires_a_change_and_agent_keys_repeat() {
    let mut profile = Command::new(env!("CARGO_BIN_EXE_tk"));
    profile
        .args(["profile", "set", "work"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "profile set requires --organization-id or --api-base-url",
        ));

    let mut remove = Command::new(env!("CARGO_BIN_EXE_tk"));
    remove
        .args(["ssh", "keys", "remove"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("<KEY>"));

    let directory = tempfile::tempdir().expect("temporary directory");
    let mut agent = Command::new(env!("CARGO_BIN_EXE_tk"));
    agent
        .arg("--config")
        .arg(directory.path().join("registry.toml"))
        .args(["ssh", "agent", "start", "--key", "first", "--key", "second"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("registry holds no SSH keys"));
}
