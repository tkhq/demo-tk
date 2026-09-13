//! Tests for Git SSH signing.

mod common;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::{ORGANIZATION_ID, bundle_env, mount_get_private_key_mock};
use predicates::prelude::*;
use serde_json::json;
use tempfile::{TempDir, tempdir};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::ssh;
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TURNKEY_TEST_V: &str = "00";

#[tokio::test]
async fn git_sign_writes_verifiable_sshsig_file() {
    let signer = signer_fixture().await;
    let raw_signature = extract_raw_signature(&signer.key_path, &signer.payload_path).await;
    let public_key_line = signer.public_key_line().await;
    let parsed_public_key =
        ssh::parse_public_key_line(&public_key_line).expect("public key should parse");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(parsed_public_key.public_key)).await;
    mount_sign_raw_payload_mock(&server, &raw_signature).await;

    tk_command(&server)
        .arg("ssh")
        .arg("git-sign")
        .args(signer.sign_args())
        .assert()
        .success();

    signer.assert_signature_verifies(&public_key_line).await;
}

#[tokio::test]
async fn direct_ssh_signer_invocation_writes_verifiable_sshsig_file() {
    let signer = signer_fixture().await;
    let raw_signature = extract_raw_signature(&signer.key_path, &signer.payload_path).await;
    let public_key_line = signer.public_key_line().await;
    let parsed_public_key =
        ssh::parse_public_key_line(&public_key_line).expect("public key should parse");

    let server = MockServer::start().await;
    mount_get_private_key_mock(&server, &hex::encode(parsed_public_key.public_key)).await;
    mount_sign_raw_payload_mock(&server, &raw_signature).await;

    tk_command(&server)
        .args(signer.sign_args())
        .assert()
        .success();

    signer.assert_signature_verifies(&public_key_line).await;
}

#[tokio::test]
async fn git_sign_rejects_public_key_that_does_not_match_configured_turnkey_key() {
    let signer = signer_fixture().await;

    let server = MockServer::start().await;
    mount_get_private_key_mock(
        &server,
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .await;

    tk_command(&server)
        .arg("ssh")
        .arg("git-sign")
        .args(signer.sign_args())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "does not match the configured Turnkey key",
        ));

    assert!(
        !fs::try_exists(signer.signature_path())
            .await
            .expect("signature path should be readable"),
        "signature file should not be created"
    );
}

struct SignerFixture {
    temp: TempDir,
    key_path: PathBuf,
    public_key_path: PathBuf,
    payload_path: PathBuf,
}

async fn signer_fixture() -> SignerFixture {
    let temp = tempdir().expect("temp dir should exist");
    let key_path = temp.path().join("id_ed25519");
    let public_key_path = temp.path().join("id_ed25519.pub");
    let payload_path = temp.path().join("payload.txt");

    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key_path)
        .status()
        .await
        .expect("ssh-keygen should run");
    assert!(status.success());

    fs::write(&payload_path, b"hello world")
        .await
        .expect("payload should be written");

    SignerFixture {
        temp,
        key_path,
        public_key_path,
        payload_path,
    }
}

impl SignerFixture {
    async fn public_key_line(&self) -> String {
        fs::read_to_string(&self.public_key_path)
            .await
            .expect("public key should exist")
    }

    fn signature_path(&self) -> PathBuf {
        self.payload_path.with_extension("txt.sig")
    }

    fn sign_args(&self) -> Vec<&OsStr> {
        let mut args = ["-Y", "sign", "-n", "git", "-f"].map(OsStr::new).to_vec();
        args.push(self.public_key_path.as_os_str());
        args.push(self.payload_path.as_os_str());
        args
    }

    async fn assert_signature_verifies(&self, public_key_line: &str) {
        let signature_path = self.signature_path();
        assert!(
            fs::try_exists(&signature_path)
                .await
                .expect("signature path should be readable"),
            "signature file should be created"
        );

        let allowed_signers_path = self.temp.path().join("allowed_signers");
        fs::write(
            &allowed_signers_path,
            format!("git {}", public_key_line.trim()),
        )
        .await
        .expect("allowed signers should be written");

        let payload = fs::read(&self.payload_path)
            .await
            .expect("payload should be readable");
        let mut verify = Command::new("ssh-keygen");
        verify
            .args(["-Y", "verify", "-n", "git", "-I", "git", "-f"])
            .arg(&allowed_signers_path)
            .arg("-s")
            .arg(&signature_path)
            .stdin(Stdio::piped());
        let mut child = verify.spawn().expect("ssh-keygen verify should spawn");
        child
            .stdin
            .take()
            .expect("stdin should be piped")
            .write_all(&payload)
            .await
            .expect("payload should write to stdin");
        let status = child.wait().await.expect("ssh-keygen verify should run");

        assert!(status.success(), "ssh-keygen should verify auth output");
    }
}

fn tk_command(server: &MockServer) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_tk"));
    cmd.envs(bundle_env(&TurnkeyP256ApiKey::generate(), server));
    cmd
}

async fn mount_sign_raw_payload_mock(server: &MockServer, raw_signature: &[u8]) {
    Mock::given(method("POST"))
        .and(path("/public/v1/submit/sign_raw_payload"))
        .and(header_exists("X-Stamp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "activity": {
                "id": "activity-id",
                "organizationId": ORGANIZATION_ID,
                "fingerprint": "fingerprint",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                "result": {
                    "signRawPayloadResult": {
                        "r": hex::encode(&raw_signature[..32]),
                        "s": hex::encode(&raw_signature[32..]),
                        "v": TURNKEY_TEST_V
                    }
                }
            }
        })))
        .mount(server)
        .await;
}

async fn extract_raw_signature(key_path: &Path, payload_path: &Path) -> Vec<u8> {
    let status = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(key_path)
        .arg(payload_path)
        .status()
        .await
        .expect("ssh-keygen sign should run");
    assert!(status.success());

    let signature_path = payload_path.with_extension("txt.sig");
    let armored = fs::read_to_string(signature_path)
        .await
        .expect("signature should exist");
    parse_raw_signature_from_armored(&armored)
}

fn parse_raw_signature_from_armored(armored: &str) -> Vec<u8> {
    let base64 = armored
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let blob = STANDARD
        .decode(base64)
        .expect("signature body should decode");

    let mut cursor = blob.as_slice();
    assert_eq!(&cursor[..6], b"SSHSIG");
    cursor = &cursor[6 + 4..];

    let _public_key = read_ssh_bytes(&mut cursor);
    let _namespace = read_ssh_bytes(&mut cursor);
    let _reserved = read_ssh_bytes(&mut cursor);
    let _hash_algorithm = read_ssh_bytes(&mut cursor);
    let signature_blob = read_ssh_bytes(&mut cursor);

    let mut signature_cursor = signature_blob.as_slice();
    let algorithm = read_ssh_bytes(&mut signature_cursor);
    assert_eq!(str::from_utf8(&algorithm).unwrap(), "ssh-ed25519");
    read_ssh_bytes(&mut signature_cursor)
}

fn read_ssh_bytes(cursor: &mut &[u8]) -> Vec<u8> {
    let length = u32::from_be_bytes(cursor[..4].try_into().expect("ssh length should exist"));
    *cursor = &cursor[4..];
    let length = length as usize;
    let value = cursor[..length].to_vec();
    *cursor = &cursor[length..];
    value
}
