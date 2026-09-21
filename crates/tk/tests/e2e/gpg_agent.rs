//! Live foreground `OpenPGP` agent coverage.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use serde_json::json;
use tempfile::TempDir;

use crate::run::{Run, result};
use crate::ssh::{inherit_admin_environment, locate};

const USER_ID: &str = "tk gpg agent e2e <tk-gpg-agent-e2e@example.com>";

struct Agent<'r> {
    child: Option<Child>,
    run: &'r Run,
    socket: PathBuf,
}

impl<'r> Agent<'r> {
    fn start(run: &'r Run, fingerprint: &str, socket: PathBuf) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
        inherit_admin_environment(run, &mut command);
        let child = command
            .args(["gpg", "agent", "serve", "--key", fingerprint, "--socket"])
            .arg(&socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the OpenPGP agent should start");
        let mut agent = Self {
            child: Some(child),
            run,
            socket,
        };
        run.wait_for_child_socket(
            &mut agent.child,
            &agent.socket,
            "OpenPGP agent",
            "accepting connections",
        );
        agent
    }

    fn terminate(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().unwrap().is_none() {
            // SAFETY: the PID comes from the live child owned by this guard.
            let signaled = unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
            assert_eq!(signaled, 0, "failed to terminate the OpenPGP agent");
        }
        let output = child
            .wait_with_output()
            .expect("the OpenPGP agent should exit after SIGTERM");
        assert_redacted(self.run, "OpenPGP agent shutdown", &output);
        assert!(
            output.status.success(),
            "OpenPGP agent failed: {}",
            self.run.redact(&output.stderr)
        );
        assert!(!self.socket.exists(), "the agent socket was not removed");
    }
}

impl Drop for Agent<'_> {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn create_wallet(run: &Run) -> String {
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({
                "walletName": run.name("gpg-agent-wallet"),
                "accounts": [{
                    "curve": "CURVE_SECP256K1",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/5261136'/0'/0'/0'",
                    "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
                }],
            })
            .to_string(),
        ]),
        "wallet.create",
    );
    result(&created, "createWalletResult")["walletId"]
        .as_str()
        .unwrap()
        .to_string()
}

fn import_public_key(run: &Run, gpg: &Path, home: &Path, armored: &str) -> PathBuf {
    let gnupghome = home.join("gnupg");
    fs::create_dir(&gnupghome).unwrap();
    fs::set_permissions(&gnupghome, fs::Permissions::from_mode(0o700)).unwrap();
    let public_key = home.join("public-key.asc");
    fs::write(&public_key, armored).unwrap();
    let imported = Command::new(gpg)
        .env_clear()
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--import"])
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "GnuPG import failed: {}",
        run.redact(&imported.stderr)
    );
    gnupghome
}

fn assert_redacted(run: &Run, operation: &str, output: &Output) {
    let stdout = run.redact(&output.stdout);
    let stderr = run.redact(&output.stderr);
    for (stream, raw) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert_eq!(
            run.redact(raw),
            String::from_utf8_lossy(raw),
            r#"private key leaked during {operation} on {stream}
stdout: {stdout}
stderr: {stderr}"#
        );
    }
}

struct GitClient<'a> {
    executable: &'a Path,
    repository: &'a Path,
    home: &'a Path,
    gnupghome: &'a Path,
    gpg: &'a Path,
}

impl GitClient<'_> {
    fn run(&self, socket: Option<&Path>, config: &[String], args: &[&str]) -> Output {
        let mut command = Command::new(self.executable);
        command
            .env_clear()
            .env("HOME", self.home)
            .env("GNUPGHOME", self.gnupghome)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("TK_GPG_PROGRAM", self.gpg)
            .current_dir(self.repository)
            .args([
                "-c",
                "user.name=tk gpg agent e2e",
                "-c",
                "user.email=tk-gpg-agent-e2e@example.com",
                "-c",
                "gpg.format=openpgp",
            ])
            .arg("-c")
            .arg(format!("gpg.program={}", env!("CARGO_BIN_EXE_tk")));
        if let Some(socket) = socket {
            command.env("TK_GPG_AGENT_SOCK", socket);
        }
        for setting in config {
            command.arg("-c").arg(setting);
        }
        command.args(args).output().expect("git should run")
    }
}

#[test]
#[ignore]
fn foreground_agent_signs_for_a_credential_free_git_client() {
    let (Some(gpg), Some(git_executable)) = (locate("gpg"), locate("git")) else {
        eprintln!("skipping the GPG agent test: gpg or git is not on PATH");
        return;
    };
    let run = Run::new();
    let wallet = create_wallet(&run);
    let created = run.ok(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--user-id",
        USER_ID,
    ]));
    assert_eq!(created["reason"], "gpg_key_created");
    let fingerprint = created["fingerprint"].as_str().unwrap();
    let exported = run.ok(run
        .admin()
        .args(["gpg", "keys", "export", "--key", fingerprint]));

    let client_home = TempDir::new().unwrap();
    let repository = client_home.path().join("repository");
    fs::create_dir(&repository).unwrap();
    let gnupghome = import_public_key(
        &run,
        &gpg,
        client_home.path(),
        exported["armored"].as_str().unwrap(),
    );
    let socket = run.home().join("gpg-agent-e2e.sock");
    let _agent = Agent::start(&run, fingerprint, socket.clone());
    let git = GitClient {
        executable: &git_executable,
        repository: &repository,
        home: client_home.path(),
        gnupghome: &gnupghome,
        gpg: &gpg,
    };

    let signing_key = format!("user.signingkey={fingerprint}");
    let initialized = git.run(None, &[], &["init", "--quiet"]);
    assert_redacted(&run, "Git initialization", &initialized);
    assert!(
        initialized.status.success(),
        "{}",
        run.redact(&initialized.stderr)
    );
    let committed = git.run(
        Some(&socket),
        &[signing_key],
        &[
            "commit",
            "-S",
            "--quiet",
            "--allow-empty",
            "-m",
            "signed through the foreground agent",
        ],
    );
    assert_redacted(&run, "Git commit signing", &committed);
    assert!(committed.stdout.is_empty());
    assert!(
        committed.status.success(),
        "Git signing failed: {}",
        run.redact(&committed.stderr)
    );
    let verified = git.run(None, &[], &["verify-commit", "HEAD"]);
    assert_redacted(&run, "Git commit verification", &verified);
    assert!(
        verified.status.success(),
        "local Git verification failed: {}",
        run.redact(&verified.stderr)
    );

    let other = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    let refused = git.run(
        Some(&socket),
        &[format!("user.signingkey={other}")],
        &[
            "commit",
            "-S",
            "--quiet",
            "--allow-empty",
            "-m",
            "unserved key must fail",
        ],
    );
    assert_redacted(&run, "unserved Git key refusal", &refused);
    assert!(!refused.status.success(), "Git signed with an unserved key");
    assert!(refused.stdout.is_empty());
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused_stderr.contains("OpenPGP agent does not serve the requested key"),
        "unexpected refusal: {refused_stderr}"
    );
    assert!(!refused_stderr.contains("SIG_CREATED"));
}
