//! Live SSH registry command coverage.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::run::{Run, bare_cli, result};

pub(crate) fn locate(binary: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the Unix epoch")
        .as_millis()
        .to_string()
}

pub(crate) fn create_private_key(run: &Run, curve: &str) -> String {
    let body = json!({
        "type": "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2",
        "timestampMs": now_ms(),
        "organizationId": run.org(),
        "parameters": {
            "privateKeys": [{
                "privateKeyName": run.name(&format!("ssh-signing-key-{}", uuid::Uuid::new_v4())),
                "curve": curve,
                "privateKeyTags": [],
                "addressFormats": [],
            }],
        },
    })
    .to_string();
    let created = run.submit(
        run.admin().args([
            "request",
            "--path",
            "/public/v1/submit/create_private_keys",
            "--body",
            &body,
        ]),
        "request",
    );
    result(&created, "createPrivateKeysResultV2")["privateKeys"][0]["privateKeyId"]
        .as_str()
        .expect("create private keys should return one private key ID")
        .to_string()
}

pub(crate) fn create_ed25519_key(run: &Run) -> String {
    create_private_key(run, "CURVE_ED25519")
}

pub(crate) fn register_key(run: &Run, private_key_id: &str) -> Value {
    run.ok(run
        .admin()
        .args(["ssh", "keys", "add", "--private-key-id", private_key_id]))
}

pub(crate) fn text(value: &Value) -> &str {
    value.as_str().expect("the record field should be a string")
}

/// The binary with the admin bundle in the environment and no tk flags, as
/// git and ssh-keygen invoke it.
pub(crate) fn inherit_admin_environment(run: &Run, command: &mut Command) {
    for (name, value) in run.admin().get_envs() {
        match value {
            Some(value) => command.env(name, value),
            None => command.env_remove(name),
        };
    }
    command
        .env("HOME", run.home())
        .env("TURNKEY_API_BASE_URL", &run.config.api_base_url);
}

/// Writes a fresh OpenSSH key pair and returns its public key path.
pub(crate) fn generate_local_key(ssh_keygen: &Path, path: &Path, key_type: &str) -> PathBuf {
    let generated = Command::new(ssh_keygen)
        .args(["-q", "-t", key_type, "-N", "", "-C", "local", "-f"])
        .arg(path)
        .output()
        .expect("ssh-keygen should run");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    path.with_extension("pub")
}

pub(crate) fn local_fingerprint(ssh_keygen: &Path, public_key_path: &Path) -> String {
    let listed = Command::new(ssh_keygen)
        .arg("-lf")
        .arg(public_key_path)
        .output()
        .expect("ssh-keygen should run");
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .nth(1)
        .expect("ssh-keygen -l prints the fingerprint second")
        .to_string()
}

/// Verifies an SSHSIG against one public key without an allowed signers file.
pub(crate) fn check_signature(
    ssh_keygen: &Path,
    public_key_path: &Path,
    payload: &Path,
    signature: &Path,
) -> std::process::Output {
    Command::new(ssh_keygen)
        .args(["-Y", "check-novalidate", "-n", "git", "-f"])
        .arg(public_key_path)
        .arg("-s")
        .arg(signature)
        .stdin(fs::File::open(payload).expect("the payload should open"))
        .output()
        .expect("ssh-keygen should run")
}

fn registered(key: &Value) -> Value {
    json!({
        "fingerprint": key["fingerprint"],
        "publicKey": key["publicKey"],
        "organizationId": key["organizationId"],
        "privateKeyId": key["privateKeyId"],
    })
}

fn registration_record(reason: &str, key: &Value) -> Value {
    let mut record = registered(key);
    record["reason"] = json!(reason);
    record
}

#[test]
#[ignore]
fn ssh_key_register_list_print_and_remove_by_every_name() {
    let run = Run::new();
    let private_key_id = create_ed25519_key(&run);

    let added = register_key(&run, &private_key_id);
    assert_eq!(added["reason"], "ssh_key_registered");
    assert_eq!(added["organizationId"], run.org());
    assert_eq!(added["privateKeyId"], private_key_id);
    let fingerprint = added["fingerprint"]
        .as_str()
        .expect("registration should return a fingerprint")
        .to_string();
    let public_key = added["publicKey"]
        .as_str()
        .expect("registration should return a public key")
        .to_string();
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(public_key.starts_with("ssh-ed25519 "));

    let listed = json!({"reason": "ssh_keys_registered", "keys": [registered(&added)]});
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        listed
    );
    // Re-adding a registered key overwrites its entry rather than duplicating it.
    assert_eq!(register_key(&run, &private_key_id), added);
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        listed
    );
    // The removed configuration surface changes nothing.
    assert_eq!(
        run.ok(run
            .admin_offline()
            .env("TURNKEY_PRIVATE_KEY_ID", "ignored")
            .env("TURNKEY_TK_CONFIG_PATH", run.home().join("missing.toml"))
            .args(["ssh", "keys", "list"])),
        listed
    );
    let printed = json!({
        "reason": "public_key_printed",
        "fingerprint": fingerprint,
        "publicKey": public_key,
    });
    assert_eq!(
        run.ok(run
            .admin_offline()
            .args(["ssh", "public-key", "--key", &fingerprint])),
        printed
    );
    // One registered key needs no name, and every name form selects it.
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "public-key"])),
        printed
    );
    for name in [&public_key, &private_key_id] {
        assert_eq!(
            run.ok(run
                .admin_offline()
                .args(["ssh", "public-key", "--key", name])),
            printed
        );
    }
    let mut human = bare_cli(run.home());
    assert_eq!(
        run.human_stdout(human.args(["ssh", "public-key"])),
        format!("{public_key}\n")
    );
    let unknown = run.err(run.admin_offline().args([
        "ssh",
        "public-key",
        "--key",
        "not-a-registered-private-key",
    ]));
    assert_eq!(unknown["code"], "invalid_input");
    assert_eq!(
        unknown["message"],
        "no registered SSH key matches not-a-registered-private-key; register it with tk ssh keys add --private-key-id ID"
    );
    let unknown_removal = run.err(run.admin_offline().args([
        "ssh",
        "keys",
        "remove",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]));
    assert_eq!(unknown_removal["code"], "invalid_input");
    assert_eq!(
        unknown_removal["message"],
        "no registered SSH key matches SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; register it with tk ssh keys add --private-key-id ID"
    );
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        listed
    );
    assert_eq!(
        fs::metadata(run.registry_path())
            .expect("registration should create the registry")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let removed = run.ok(run
        .admin_offline()
        .args(["ssh", "keys", "remove", &fingerprint]));
    assert_eq!(removed, registration_record("ssh_key_removed", &added));
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        json!({"reason": "ssh_keys_registered", "keys": []})
    );

    register_key(&run, &private_key_id);
    assert_eq!(
        run.ok(run
            .admin_offline()
            .args(["ssh", "keys", "remove", &public_key])),
        registration_record("ssh_key_removed", &added)
    );

    register_key(&run, &private_key_id);
    assert_eq!(
        run.ok(run
            .admin_offline()
            .args(["ssh", "keys", "remove", &private_key_id])),
        registration_record("ssh_key_removed", &added)
    );
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        json!({"reason": "ssh_keys_registered", "keys": []})
    );
}

#[test]
#[ignore]
fn ssh_key_registration_rejects_other_curves_and_unknown_ids() {
    let run = Run::new();

    let secp256k1_id = create_private_key(&run, "CURVE_SECP256K1");
    let wrong_curve =
        run.err(
            run.admin()
                .args(["ssh", "keys", "add", "--private-key-id", &secp256k1_id]),
        );
    assert_eq!(wrong_curve["code"], "invalid_input");
    assert_eq!(
        wrong_curve["message"],
        format!(
            "private key {secp256k1_id} has curve CURVE_SECP256K1; tk signs SSH payloads with CURVE_ED25519 keys"
        )
    );

    let missing_id = uuid::Uuid::new_v4().to_string();
    let missing =
        run.err(
            run.admin()
                .args(["ssh", "keys", "add", "--private-key-id", &missing_id]),
        );
    assert_eq!(missing["code"], "not_found", "{missing}");
    assert_eq!(missing["httpStatus"], 404);

    // Neither failure registered anything.
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "keys", "list"])),
        json!({"reason": "ssh_keys_registered", "keys": []})
    );
    assert!(!run.registry_path().exists());

    // Several keys and no name is the unnamed error for print and remove.
    let first_id = create_ed25519_key(&run);
    let second_id = create_ed25519_key(&run);
    register_key(&run, &first_id);
    register_key(&run, &second_id);
    let unnamed = run.err(run.admin_offline().args(["ssh", "public-key"]));
    assert_eq!(unnamed["code"], "invalid_input");
    assert_eq!(
        unnamed["message"],
        "the registry holds 2 SSH keys and none was named; name one with --key"
    );
}

#[test]
#[ignore]
fn git_signing_selects_the_public_key_git_names() {
    let (Some(git), Some(ssh_keygen)) = (locate("git"), locate("ssh-keygen")) else {
        eprintln!("skipping the SSH git-signing test: git or ssh-keygen is not on PATH");
        return;
    };
    let run = Run::new();
    let first_id = create_ed25519_key(&run);
    let first = run.ok(run
        .admin()
        .args(["ssh", "keys", "add", "--private-key-id", &first_id]));
    let second_id = create_ed25519_key(&run);
    let second = run.ok(run
        .admin()
        .args(["ssh", "keys", "add", "--private-key-id", &second_id]));

    let repository = run.home().join("ssh-git-repository");
    fs::create_dir(&repository).expect("the git repository directory should be creatable");
    let allowed_signers = run.home().join("allowed_signers");
    fs::write(
        &allowed_signers,
        format!(
            "tk-e2e@example.com {}\n",
            second["publicKey"].as_str().unwrap()
        ),
    )
    .expect("the allowed signers file should be writable");

    let git_command = |args: &[&str]| {
        let mut command = Command::new(&git);
        inherit_admin_environment(&run, &mut command);
        command
            .current_dir(&repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("XDG_CONFIG_HOME")
            .env("TK_SSH_KEYGEN_PROGRAM", &ssh_keygen)
            .args([
                "-c",
                "user.name=tk e2e",
                "-c",
                "user.email=tk-e2e@example.com",
            ])
            .args(["-c", "gpg.format=ssh"])
            .arg("-c")
            .arg(format!("gpg.ssh.program={}", env!("CARGO_BIN_EXE_tk")))
            .arg("-c")
            .arg(format!(
                "gpg.ssh.allowedSignersFile={}",
                allowed_signers.display()
            ))
            .arg("-c")
            .arg(format!(
                "user.signingkey=key::{}",
                second["publicKey"].as_str().unwrap()
            ))
            .args(args)
            .output()
            .expect("git should run")
    };

    let initialized = git_command(&["init", "--quiet"]);
    assert!(
        initialized.status.success(),
        "{}",
        run.redact(&initialized.stderr)
    );
    let committed = git_command(&[
        "commit",
        "-S",
        "--quiet",
        "--allow-empty",
        "-m",
        "signed by the second registered SSH key",
    ]);
    assert!(
        committed.status.success(),
        "{}",
        run.redact(&committed.stderr)
    );
    let verified = git_command(&["verify-commit", "HEAD"]);
    assert!(
        verified.status.success(),
        "{}",
        run.redact(&verified.stderr)
    );

    let verification = format!(
        "{}{}",
        String::from_utf8_lossy(&verified.stdout),
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(
        verification.contains(second["fingerprint"].as_str().unwrap()),
        "verification did not name the selected key: {verification}"
    );
    assert!(
        !verification.contains(first["fingerprint"].as_str().unwrap()),
        "verification unexpectedly named the first key: {verification}"
    );
}

#[test]
#[ignore]
fn passthrough_signing_errors_name_the_key_and_git_sign_signs() {
    let Some(ssh_keygen) = locate("ssh-keygen") else {
        eprintln!("skipping the SSH passthrough test: ssh-keygen is not on PATH");
        return;
    };
    let run = Run::new();
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed through the tk passthrough\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let unregistered = generate_local_key(
        &ssh_keygen,
        &run.home().join("unregistered_ed25519"),
        "ed25519",
    );
    let unregistered_fingerprint = local_fingerprint(&ssh_keygen, &unregistered);
    let rsa = generate_local_key(&ssh_keygen, &run.home().join("local_rsa"), "rsa");

    let shim = |args: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
        inherit_admin_environment(&run, &mut command);
        let output = command.args(args).output().expect("tk should run");
        assert!(output.stdout.is_empty(), "the shim wrote to stdout");
        (output.status.code(), run.redact(&output.stderr))
    };
    let sign = |public_key_path: &PathBuf| {
        let public_key_path = public_key_path.to_str().unwrap();
        let payload = payload.to_str().unwrap();
        shim(&["-Y", "sign", "-n", "git", "-f", public_key_path, payload])
    };
    let refused = |public_key_path: &PathBuf, expected: String| {
        let (code, stderr) = sign(public_key_path);
        assert_eq!(code, Some(1), "{stderr}");
        assert_eq!(stderr, format!("error: {expected}\n"));
        assert!(
            !signature.exists(),
            "a refused signature left {signature:?}"
        );
    };

    // An empty registry.
    refused(
        &unregistered,
        "the registry holds no SSH keys; register one with tk ssh keys add --private-key-id ID"
            .to_string(),
    );

    let private_key_id = create_ed25519_key(&run);
    let registered = register_key(&run, &private_key_id);
    let registered_public_key = run.home().join("registered.pub");
    fs::write(
        &registered_public_key,
        format!("{}\n", text(&registered["publicKey"])),
    )
    .unwrap();

    // A key git names that is not registered fails by fingerprint rather than
    // signing with the one registered key.
    refused(
        &unregistered,
        format!(
            "no registered SSH key matches {unregistered_fingerprint}; register it with tk ssh keys add --private-key-id <id>, or set user.signingkey to a registered key"
        ),
    );
    refused(
        &rsa,
        format!(
            "SSH key in {} is ssh-rsa; tk signs with ssh-ed25519 keys",
            rsa.display()
        ),
    );
    let missing = run.home().join("missing.pub");
    let (code, stderr) = sign(&missing);
    assert_eq!(code, Some(1));
    assert!(
        stderr.starts_with(&format!("error: read SSH key from {}", missing.display())),
        "{stderr}"
    );
    let (code, stderr) = shim(&[
        "-Y",
        "sign",
        "-n",
        "file",
        "-f",
        registered_public_key.to_str().unwrap(),
        payload.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(1));
    assert_eq!(stderr, "error: unsupported SSH signing namespace: file\n");

    // Verification operations run the real ssh-keygen, and a missing one is
    // reported rather than mistaken for a signing request.
    let mut passthrough = Command::new(env!("CARGO_BIN_EXE_tk"));
    inherit_admin_environment(&run, &mut passthrough);
    let output = passthrough
        .env(
            "TK_SSH_KEYGEN_PROGRAM",
            run.home().join("no-such-ssh-keygen"),
        )
        .args(["-Y", "verify", "-n", "git"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).starts_with(&format!(
            "error: cannot run {}",
            run.home().join("no-such-ssh-keygen").display()
        )),
        "{}",
        run.redact(&output.stderr)
    );

    // The registered key signs, and ssh-keygen accepts the signature.
    let (code, stderr) = sign(&registered_public_key);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let checked = check_signature(&ssh_keygen, &registered_public_key, &payload, &signature);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    fs::remove_file(&signature).unwrap();

    // The clap-fronted command runs the same signing and honors identity flags.
    let mismatched = run.err(
        run.admin()
            .args([
                "--organization-id",
                &uuid::Uuid::nil().to_string(),
                "ssh",
                "git-sign",
            ])
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&registered_public_key)
            .arg(&payload),
    );
    assert_eq!(mismatched["code"], "invalid_input");
    assert!(!signature.exists());
    let signed = run.ok(run
        .admin()
        .args(["ssh", "git-sign", "-Y", "sign", "-n", "git", "-f"])
        .arg(&registered_public_key)
        .arg(&payload));
    assert_eq!(signed, json!({"reason": "git_sign_completed"}));
    let checked = check_signature(&ssh_keygen, &registered_public_key, &payload, &signature);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
