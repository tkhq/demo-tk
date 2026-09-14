use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::ssh::Ed25519PublicKey;
use turnkey_auth::ssh::agent::{self, AgentIdentity, Keyring, SignError, SignFuture};
use turnkey_auth::ssh::protocol;
use turnkey_client::TurnkeyClient;
use uuid::Uuid;

use super::lock::{AgentLock, is_lock_held_by_other, resolve_lock_file};
use super::{
    AgentNotRunning, AgentRunning, AgentStopped, InternalRunArgs, StartArgs, StatusArgs, StopArgs,
    key_names,
};
use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::InvalidInput;
use crate::outcome::{MachineOnly, Outcome};
use crate::ssh::registry::{SelectError, SshKeyEntry, SshKeyName};
use crate::ssh::selection_error;
use crate::ssh::signer::TurnkeySigner;

const START_TIMEOUT: Duration = Duration::from_secs(4);
const STOP_TIMEOUT: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

struct RegistryKeyring {
    entries: BTreeMap<Ed25519PublicKey, SshKeyEntry>,
    clients: BTreeMap<Uuid, TurnkeyClient<TurnkeyP256ApiKey>>,
}

impl Keyring for RegistryKeyring {
    fn identities(&self) -> Vec<AgentIdentity> {
        self.entries
            .values()
            .map(|entry| AgentIdentity {
                public_key: entry.public_key,
                comment: format!("turnkey:{}", entry.private_key_id),
            })
            .collect()
    }

    fn sign<'a>(&'a self, public_key: &'a Ed25519PublicKey, data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async move {
            let entry = self.entries.get(public_key).ok_or(SignError::UnknownKey)?;
            let client = self.clients.get(&entry.organization_id).ok_or_else(|| {
                SignError::Signer(anyhow!(
                    "SSH agent has no credential client for organization {}",
                    entry.organization_id
                ))
            })?;
            TurnkeySigner::new(
                client,
                entry.organization_id.to_string(),
                &entry.private_key_id,
            )
            .sign_raw_payload(data)
            .await
            .map_err(SignError::Signer)
        })
    }
}

#[derive(Deserialize, Serialize)]
struct AgentMetadata {
    pid: u32,
    keys: Vec<String>,
}

struct SelectedKeys {
    entries: Vec<SshKeyEntry>,
    fingerprints: Vec<String>,
}

pub async fn start(args: StartArgs, options: &AuthOptions) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);
    let requested = key_names(args.key);
    let _selected = select_keys(options, &requested).await?;

    create_parent_dir(&socket).await?;
    create_parent_dir(&pid_file).await?;
    create_parent_dir(&lock_file).await?;

    if path_exists(&socket).await? {
        if probe_agent_socket(&socket).await.is_ok() || is_lock_held_by_other(lock_file).await? {
            return Err(anyhow!(
                "ssh-agent is already running on {}",
                socket.display()
            ));
        }
        remove_socket_if_present(&socket).await?;
    }
    remove_file_if_present(&pid_file).await?;

    let mut command = Command::new(env::current_exe()?);
    command.arg("ssh").arg("agent").arg("internal-run");
    for argument in forwarded_auth_arguments(options) {
        command.arg(argument);
    }
    command.arg("--socket").arg(&socket);
    command.arg("--pid-file").arg(&pid_file);
    for requested in requested {
        command.arg("--key").arg(requested.to_string());
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn background ssh-agent")?;

    let pid = child
        .id()
        .context("background ssh-agent pid was not available")?;

    match wait_for_startup(&socket, &mut child).await {
        Ok(()) => {
            let metadata = read_metadata(&pid_file)
                .await?
                .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;
            Ok(Outcome::AgentStarted(AgentRunning {
                pid,
                socket: socket.display().to_string(),
                keys: metadata.keys,
            }))
        }
        Err(error) => {
            let _ = fs::remove_file(&pid_file).await;
            let _ = child.start_kill();
            Err(error)
        }
    }
}

pub async fn stop(args: StopArgs) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(lock_file).await? {
        let _ = fs::remove_file(&pid_file).await;
        let _ = remove_socket_if_present(&socket).await;
        return Ok(Outcome::AgentNotRunning(AgentNotRunning {}));
    }

    let metadata = read_metadata(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;
    send_signal(metadata.pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal ssh-agent process {}", metadata.pid))?;
    wait_for_process_exit(metadata.pid).await?;
    let _ = fs::remove_file(&pid_file).await;
    wait_for_socket_removal(&socket).await?;
    Ok(Outcome::AgentStopped(AgentStopped {}))
}

pub async fn status(args: StatusArgs) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(args.pid_file)?;
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(lock_file).await? {
        return Err(anyhow!("ssh-agent is not running"));
    }

    let metadata = read_metadata(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;
    if !is_process_alive(metadata.pid) {
        return Err(anyhow!("ssh-agent pid {} is not running", metadata.pid));
    }
    if probe_agent_socket(&socket).await.is_err() {
        return Err(anyhow!(
            "ssh-agent pid {} is marked running but socket {} is not serving requests",
            metadata.pid,
            socket.display()
        ));
    }
    Ok(Outcome::AgentStatusReport(AgentRunning {
        pid: metadata.pid,
        socket: socket.display().to_string(),
        keys: metadata.keys,
    }))
}

pub async fn internal_run(args: InternalRunArgs, options: &AuthOptions) -> Result<Outcome> {
    let requested = key_names(args.key);
    let selected = select_keys(options, &requested).await?;
    let mut clients = BTreeMap::new();
    for organization_id in selected.entries.iter().map(|entry| entry.organization_id) {
        if clients.contains_key(&organization_id) {
            continue;
        }
        let auth = auth::resolve_for_organization(options, organization_id)
            .await
            .with_context(|| {
                format!("select a credential for SSH organization {organization_id}")
            })?;
        clients.insert(
            organization_id,
            build_turnkey_client(auth.stamper, &auth.api_base_url)?,
        );
    }
    let entries = selected
        .entries
        .into_iter()
        .map(|entry| (entry.public_key, entry))
        .collect();
    let keyring = Arc::new(RegistryKeyring { entries, clients });

    let lock_file = resolve_lock_file(&args.pid_file);
    let _lock = AgentLock::acquire(lock_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent is already running"))?;
    let metadata = AgentMetadata {
        pid: process::id(),
        keys: selected.fingerprints,
    };
    fs::write(&args.pid_file, serde_json::to_vec(&metadata)?)
        .await
        .with_context(|| format!("failed to write pid file at {}", args.pid_file.display()))?;

    let result = agent::run(args.socket, keyring).await;
    let _ = fs::remove_file(&args.pid_file).await;
    result.map(|()| Outcome::AgentDaemonExited(MachineOnly {}))
}

async fn select_keys(options: &AuthOptions, requested: &[SshKeyName]) -> Result<SelectedKeys> {
    let mut table = auth::load_ssh_keys(options).await?;
    if table.organizations().is_empty() {
        return Err(selection_error(SelectError::Empty, "name one with --key"));
    }
    if let Some((organization_id, source)) = auth::explicit_organization(options).await? {
        table.retain_organization(organization_id);
        if table.organizations().is_empty() {
            return Err(InvalidInput(format!(
                "organization {organization_id} selected by {source} has no registered SSH keys; register one with tk ssh keys add --private-key-id <id>, or drop the identity selection"
            ))
            .into());
        }
    }

    let entries = if requested.is_empty() {
        table.into_entries().collect()
    } else {
        requested
            .iter()
            .cloned()
            .map(|name| {
                table
                    .select_ref(name)
                    .cloned()
                    .map_err(|error| selection_error(error, "name one with --key"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut unique = BTreeMap::new();
    for entry in entries {
        unique.insert(entry.fingerprint(), entry);
    }
    let fingerprints = unique.keys().map(ToString::to_string).collect();
    Ok(SelectedKeys {
        entries: unique.into_values().collect(),
        fingerprints,
    })
}

fn forwarded_auth_arguments(options: &AuthOptions) -> Vec<OsString> {
    let mut forwarded = Vec::new();
    if let Some(path) = options.config() {
        forwarded.push(OsString::from("--config"));
        forwarded.push(path.as_os_str().to_owned());
    }
    if let Some(profile) = options.profile() {
        forwarded.push(OsString::from("--profile"));
        forwarded.push(profile.into());
    }
    if let Some(organization_id) = options.organization_id() {
        forwarded.push(OsString::from("--organization-id"));
        forwarded.push(organization_id.to_string().into());
    }
    if let Some(api_base_url) = options.api_base_url() {
        forwarded.push(OsString::from("--api-base-url"));
        forwarded.push(api_base_url.into());
    }
    forwarded
}

fn resolve_pid_file(pid_file: Option<PathBuf>) -> Result<PathBuf> {
    pid_file.map_or_else(default_pid_path, Ok)
}

fn resolve_socket_path(socket: Option<PathBuf>) -> Result<PathBuf> {
    socket.map_or_else(default_socket_path, Ok)
}

fn default_socket_path() -> Result<PathBuf> {
    Ok(default_agent_dir()?.join("ssh-agent.sock"))
}

fn default_pid_path() -> Result<PathBuf> {
    Ok(default_agent_dir()?.join("ssh-agent.pid"))
}

pub(super) async fn is_default_running() -> Result<bool> {
    let pid_file = default_pid_path()?;
    is_lock_held_by_other(resolve_lock_file(&pid_file)).await
}

fn default_agent_dir() -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .ok_or_else(|| anyhow!("missing HOME; use --socket and --pid-file to set paths"))?;
    Ok(Path::new(&home).join(".config/turnkey"))
}

async fn wait_for_startup(socket: &Path, child: &mut Child) -> Result<()> {
    let iterations = START_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if probe_agent_socket(socket).await.is_ok() {
            return Ok(());
        }
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_string(&mut stderr).await?;
                }
                let detail = stderr.trim();
                if detail.is_empty() {
                    return Err(anyhow!("background ssh-agent exited early: {status}"));
                }
                return Err(anyhow!(
                    "background ssh-agent exited early: {status}: {detail}"
                ));
            }
            Err(error) => {
                return Err(Error::new(error).context("failed to poll background ssh-agent status"));
            }
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!(
        "timed out waiting for ssh-agent socket at {}",
        socket.display()
    ))
}

async fn create_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    Ok(())
}

async fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

async fn read_metadata(path: &Path) -> Result<Option<AgentMetadata>> {
    let raw = match fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse pid file at {}", path.display()))
        .map(Some)
}

async fn path_exists(path: &Path) -> Result<bool> {
    fs::try_exists(path)
        .await
        .with_context(|| format!("failed to check {}", path.display()))
}

async fn remove_socket_if_present(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path)
                .await
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    Ok(())
}

async fn probe_agent_socket(socket: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("failed to connect to ssh-agent socket {}", socket.display()))?;
    let request = protocol::encode_agent_frame(protocol::SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    stream
        .write_all(&request)
        .await
        .context("failed to write readiness probe")?;
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .context("failed to read readiness probe length")?;
    let body_len = u32::from_be_bytes(length) as usize;
    let mut body = vec![0u8; body_len];
    stream
        .read_exact(&mut body)
        .await
        .context("failed to read readiness probe body")?;
    match body.first().copied() {
        Some(protocol::SSH_AGENT_IDENTITIES_ANSWER | protocol::SSH_AGENT_FAILURE) => Ok(()),
        Some(message_type) => Err(anyhow!(
            "unexpected ssh-agent readiness response: message_type={message_type}"
        )),
        None => Err(anyhow!("empty ssh-agent readiness response")),
    }
}

async fn wait_for_process_exit(pid: u32) -> Result<()> {
    let iterations = STOP_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if !is_process_alive(pid) {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!("timed out waiting for ssh-agent pid {pid} to exit"))
}

async fn wait_for_socket_removal(socket: &Path) -> Result<()> {
    let iterations = STOP_TIMEOUT.as_millis() / POLL_INTERVAL.as_millis();
    for _ in 0..iterations {
        if !path_exists(socket).await? {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!(
        "timed out waiting for ssh-agent socket {} to be removed",
        socket.display()
    ))
}

fn is_process_alive(pid: u32) -> bool {
    pid != 0
        && match send_signal(pid, 0) {
            Ok(()) => true,
            Err(error) => error.raw_os_error() != Some(libc::ESRCH),
        }
}

fn send_signal(pid: u32, signal: i32) -> io::Result<()> {
    // SAFETY: libc::kill is an FFI syscall wrapper and does not dereference
    // Rust pointers or access Rust-managed memory.
    let rc = unsafe { libc::kill(pid as i32, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Asserts on the classified error code.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::auth::ResolvedAuth;
    use crate::errors::{ErrorCode, classify};
    use crate::ssh::registry::PrivateKeyId;

    const ORG: &str = "00000000-0000-4000-8000-000000000001";

    /// The server is returned so it outlives the request; a dropped server
    /// goes back to wiremock's pool and answers another test.
    async fn keyring_against(
        response: ResponseTemplate,
    ) -> (MockServer, RegistryKeyring, Ed25519PublicKey) {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(response)
            .mount(&server)
            .await;
        let auth = ResolvedAuth::for_tests(ORG, &server.uri(), TurnkeyP256ApiKey::generate());
        let client = build_turnkey_client(auth.stamper, &auth.api_base_url).unwrap();
        let public_key = Ed25519PublicKey::from_bytes([1; 32]);
        let entry = SshKeyEntry {
            organization_id: auth.org_id,
            private_key_id: PrivateKeyId::from("private-key-id".to_string()),
            public_key,
        };
        let keyring = RegistryKeyring {
            entries: [(public_key, entry)].into(),
            clients: [(auth.org_id, client)].into(),
        };
        (server, keyring, public_key)
    }

    #[tokio::test]
    async fn a_signing_request_needing_approval_is_a_signer_error_classified_as_approval() {
        let (_server, keyring, public_key) =
            keyring_against(ResponseTemplate::new(200).set_body_json(json!({
                "activity": {
                    "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
                    "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED",
                    "id": "activity-1",
                    "organizationId": ORG,
                    "fingerprint": "sha256:example",
                }
            })))
            .await;
        let SignError::Signer(error) = keyring
            .sign(&public_key, b"payload")
            .await
            .expect_err("consensus should fail the signature")
        else {
            panic!("a refused signature must not be reported as an unknown key")
        };
        assert_eq!(classify(&error).code, ErrorCode::ApprovalRequired);
        assert_eq!(
            error.to_string(),
            "signing requires additional approval (activity id: activity-1)"
        );
    }

    #[tokio::test]
    async fn a_server_error_during_signing_is_a_signer_error_classified_as_api_error() {
        let (_server, keyring, public_key) =
            keyring_against(ResponseTemplate::new(500).set_body_string("unavailable")).await;
        let SignError::Signer(error) = keyring
            .sign(&public_key, b"payload")
            .await
            .expect_err("a server error should fail the signature")
        else {
            panic!("a server error must not be reported as an unknown key")
        };
        assert_eq!(classify(&error).code, ErrorCode::ApiError);
    }

    #[tokio::test]
    async fn registry_keyring_advertises_entries_and_rejects_unknown_keys() {
        let public_key = Ed25519PublicKey::from_bytes([1; 32]);
        let entry = SshKeyEntry {
            organization_id: Uuid::nil(),
            private_key_id: PrivateKeyId::from("private-key-id".to_string()),
            public_key,
        };
        let keyring = RegistryKeyring {
            entries: [(public_key, entry)].into(),
            clients: BTreeMap::new(),
        };
        assert_eq!(
            keyring.identities(),
            vec![AgentIdentity {
                public_key,
                comment: "turnkey:private-key-id".into(),
            }]
        );
        let error = keyring
            .sign(&Ed25519PublicKey::from_bytes([2; 32]), b"payload")
            .await
            .expect_err("an unregistered public key should be rejected");
        assert!(matches!(error, SignError::UnknownKey));
    }
}
