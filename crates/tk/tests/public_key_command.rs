//! Tests for `tk public-key`.

mod common;

use assert_cmd::Command;
use common::{bundle_env, mount_get_private_key_mock};
use predicates::prelude::*;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::MockServer;

#[tokio::test]
async fn public_key_prints_openssh_line_from_turnkey_key() {
    let server = MockServer::start().await;
    mount_get_private_key_mock(
        &server,
        "6666666666666666666666666666666666666666666666666666666666666666",
    )
    .await;

    Command::new(env!("CARGO_BIN_EXE_tk"))
        .arg("ssh")
        .arg("public-key")
        .envs(bundle_env(&TurnkeyP256ApiKey::generate(), &server))
        .assert()
        .success()
        .stdout(predicate::eq(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm\n",
        ));
}
