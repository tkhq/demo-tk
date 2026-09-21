//! Fixed-key `OpenPGP` signing over a Unix socket.

mod protocol;

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args as ClapArgs, Subcommand};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::fs;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;
use tracing::warn;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_auth::openpgp::entity::{ArmoredSignature, SigningKey, armored_detached_signature};
use turnkey_client::TurnkeyClient;
use uuid::Uuid;

use self::protocol::{Failure, SignRequest};
use super::registry::SigningKeyName;
use super::signer::TurnkeySigner;
use super::{select_registered, unix_now};
use crate::auth::AuthOptions;
use crate::outcome::{MachineOnly, Outcome};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SIGN_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 8;
pub(super) const SOCKET_ENV: &str = "TK_GPG_AGENT_SOCK";
pub(super) const MAX_PAYLOAD_LEN: usize = protocol::MAX_PAYLOAD_LEN;

#[derive(Debug, ClapArgs)]
#[command(
    about = "Serve a registered OpenPGP key over a Unix socket.",
    long_about = None
)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the agent in the foreground.
    Serve(ServeArgs),
}

#[derive(Debug, ClapArgs)]
struct ServeArgs {
    /// Serve this registered key and no other key.
    #[arg(long)]
    key: SigningKeyName,

    /// Unix socket path to bind for `OpenPGP` signing requests.
    #[arg(long, value_name = "path")]
    socket: Option<PathBuf>,

    /// Octal permissions for the socket. Access to it grants signing authority.
    #[arg(long, default_value = "600")]
    socket_mode: SocketMode,
}

struct State {
    signing_key: SigningKey,
    organization_id: Uuid,
    client: TurnkeyClient<TurnkeyP256ApiKey>,
}

#[derive(Clone, Copy, Debug)]
struct SocketMode(u32);

impl FromStr for SocketMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        u32::from_str_radix(value, 8)
            .ok()
            .filter(|mode| *mode <= 0o777)
            .map(Self)
            .ok_or_else(|| "socket mode must be an octal value from 000 through 777".to_string())
    }
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

struct CleanupSocketGuard {
    path: PathBuf,
    identity: SocketIdentity,
}

impl CleanupSocketGuard {
    fn remove(&self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket() && self.identity.matches(&metadata)
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for CleanupSocketGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

struct SocketGuard {
    // Field order cleans the path while its inode is pinned and the flock held.
    _cleanup: CleanupSocketGuard,
    _identity_pin: OwnedFd,
    _lock: File,
}

impl SocketIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &std::fs::Metadata) -> bool {
        metadata.dev() == self.device && metadata.ino() == self.inode
    }
}

pub(super) async fn run(args: Args, options: &AuthOptions) -> Result<Outcome> {
    match args.command {
        Command::Serve(args) => serve(args, options).await,
    }
}

async fn serve(args: ServeArgs, options: &AuthOptions) -> Result<Outcome> {
    let socket = match args.socket {
        Some(socket) => socket,
        None => default_socket_path()?,
    };
    let (entry, client) = select_registered(options, Some(args.key)).await?;
    let mut terminate = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("listen for SIGINT")?;
    let state = Arc::new(State {
        signing_key: entry.key.signing,
        organization_id: entry.organization_id,
        client,
    });

    let (listener, _socket_guard) = acquire_socket(&socket, args.socket_mode).await?;
    let shutdown = async {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = interrupt.recv() => {},
        }
    };
    run_accept_loop(
        &listener,
        move |stream| {
            let state = Arc::clone(&state);
            async move {
                if timeout(REQUEST_TIMEOUT + SIGN_TIMEOUT, handle(stream, state))
                    .await
                    .is_err()
                {
                    warn!("OpenPGP agent request timed out");
                }
            }
        },
        shutdown,
        MAX_CONNECTIONS,
    )
    .await?;
    Ok(Outcome::GpgAgentExited(MachineOnly {}))
}

trait ConnectionListener {
    type Connection: Send + 'static;

    fn accept(&self) -> impl Future<Output = io::Result<Self::Connection>> + Send;
}

impl ConnectionListener for UnixListener {
    type Connection = UnixStream;

    async fn accept(&self) -> io::Result<Self::Connection> {
        self.accept().await.map(|(stream, _address)| stream)
    }
}

async fn run_accept_loop<L, H, HF, S>(
    listener: &L,
    handler: H,
    shutdown: S,
    capacity: usize,
) -> Result<()>
where
    L: ConnectionListener,
    H: Fn(L::Connection) -> HF,
    HF: Future<Output = ()> + Send + 'static,
    S: Future<Output = ()>,
{
    debug_assert!(capacity > 0);
    let mut handlers = JoinSet::new();
    tokio::pin!(shutdown);

    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            Some(completed) = handlers.join_next(), if !handlers.is_empty() => {
                report_handler_completion(completed);
            }
            accepted = listener.accept(), if handlers.len() < capacity => match accepted {
                Ok(connection) => {
                    handlers.spawn(handler(connection));
                }
                Err(error) => {
                    break Err(error).context("accept an OpenPGP agent connection");
                }
            },
        }
    };

    handlers.abort_all();
    while let Some(completed) = handlers.join_next().await {
        report_handler_completion(completed);
    }
    result
}

fn report_handler_completion(completed: std::result::Result<(), JoinError>) {
    if let Err(error) = completed
        && !error.is_cancelled()
    {
        warn!("OpenPGP agent handler task failed");
    }
}

async fn acquire_socket(path: &Path, mode: SocketMode) -> Result<(UnixListener, SocketGuard)> {
    SockAddr::unix(path)
        .with_context(|| format!("invalid OpenPGP agent socket path {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let lock = acquire_socket_lock(path)?;
    remove_stale_socket(path).await?;
    let (staging, listener) = (|| -> io::Result<(PathBuf, Socket)> {
        let mut collision = io::Error::from(ErrorKind::AlreadyExists);
        for _ in 0..64 {
            let staging = staging_socket_path(path, Uuid::new_v4())?;
            let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            match listener.bind(&SockAddr::unix(&staging)?) {
                Ok(()) => return Ok((staging, listener)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => collision = error,
                Err(error) => return Err(error),
            }
        }
        Err(collision)
    })()
    .with_context(|| format!("failed to bind OpenPGP agent socket {}", path.display()))?;
    let metadata = match fs::symlink_metadata(&staging).await {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = fs::remove_file(&staging).await;
            return Err(error)
                .with_context(|| format!("failed to inspect agent socket {}", path.display()));
        }
    };
    let staging_guard = CleanupSocketGuard {
        path: staging,
        identity: SocketIdentity::from_metadata(&metadata),
    };
    fs::set_permissions(&staging_guard.path, std::fs::Permissions::from_mode(mode.0))
        .await
        .with_context(|| format!("failed to restrict OpenPGP agent socket {}", path.display()))?;
    listener
        .set_nonblocking(true)
        .with_context(|| format!("failed to bind OpenPGP agent socket {}", path.display()))?;
    listener
        .listen(128)
        .with_context(|| format!("failed to bind OpenPGP agent socket {}", path.display()))?;
    let listener = UnixListener::from_std(StdUnixListener::from(listener))
        .with_context(|| format!("failed to bind OpenPGP agent socket {}", path.display()))?;
    let identity_pin = listener
        .as_fd()
        .try_clone_to_owned()
        .with_context(|| format!("failed to pin OpenPGP agent socket {}", path.display()))?;
    match fs::hard_link(&staging_guard.path, path).await {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            return agent_already_running(path);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to bind OpenPGP agent socket {}", path.display())
            });
        }
    }
    let socket_guard = SocketGuard {
        _cleanup: CleanupSocketGuard {
            path: path.to_path_buf(),
            identity: staging_guard.identity,
        },
        _identity_pin: identity_pin,
        _lock: lock,
    };
    fs::remove_file(&staging_guard.path)
        .await
        .with_context(|| {
            format!(
                "failed to remove staging socket {}",
                staging_guard.path.display()
            )
        })?;
    Ok((listener, socket_guard))
}

fn staging_socket_path(path: &Path, nonce: Uuid) -> io::Result<PathBuf> {
    const MIN_NAME_LEN: usize = 16;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let path_capacity = unix_socket_path_capacity();
    let parent_len = parent.as_os_str().as_bytes().len();
    let separator_len = usize::from(parent_len > 0 && parent != Path::new("/"));
    let name_len = path_capacity
        .checked_sub(parent_len + separator_len)
        .filter(|length| *length >= MIN_NAME_LEN)
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                "Unix socket path leaves too little room for a secure staging name",
            )
        })?
        .min(32);
    let encoded = nonce.simple().to_string();
    let mut name = encoded[..name_len].to_string();
    let mut staging = parent.join(&name);
    if staging == path {
        name.replace_range(..1, if name.starts_with('0') { "1" } else { "0" });
        staging = parent.join(name);
    }
    debug_assert_ne!(staging, path);
    SockAddr::unix(&staging)?;
    Ok(staging)
}

fn unix_socket_path_capacity() -> usize {
    // SAFETY: The all-zero representation is valid for sockaddr_un and is only
    // used to inspect the platform-specific pathname array length.
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_path.len() - 1
}

fn acquire_socket_lock(path: &Path) -> Result<File> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| format!("failed to open agent lock {}", lock_path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect agent lock {}", lock_path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "refusing to use non-regular agent lock {}",
            lock_path.display()
        ));
    }
    // SAFETY: geteuid takes no arguments and has no memory-safety preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(anyhow!(
            "refusing to use agent lock {} owned by another user",
            lock_path.display()
        ));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict agent lock {}", lock_path.display()))?;

    // SAFETY: flock only observes the valid file descriptor owned by `file`.
    let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status == 0 {
        return Ok(file);
    }
    let error = io::Error::last_os_error();
    let raw_error = error.raw_os_error();
    if raw_error == Some(libc::EWOULDBLOCK) || raw_error == Some(libc::EAGAIN) {
        return agent_already_running(path);
    }
    Err(error).with_context(|| format!("failed to lock agent socket {}", path.display()))
}

async fn handle(mut stream: UnixStream, state: Arc<State>) {
    let request = match timeout(REQUEST_TIMEOUT, protocol::read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            warn!(?error, "OpenPGP agent rejected a malformed request");
            let _ = protocol::write_failure(&mut stream, Failure::InvalidRequest).await;
            return;
        }
        Err(_) => {
            warn!("OpenPGP agent request body timed out");
            let _ = protocol::write_failure(&mut stream, Failure::InvalidRequest).await;
            return;
        }
    };
    let SignRequest { key, payload } = request;
    let fingerprint = state.signing_key.fingerprint();
    if key.is_some_and(|key| !key.matches_fingerprint(&fingerprint)) {
        let _ = protocol::write_failure(&mut stream, Failure::KeyNotServed).await;
        return;
    }
    let created = match unix_now() {
        Ok(created) => created,
        Err(_) => {
            warn!("OpenPGP agent could not read the system clock");
            let _ = protocol::write_failure(&mut stream, Failure::SigningFailed).await;
            return;
        }
    };
    let signer = TurnkeySigner::new(&state.client, state.organization_id);
    let armored = match timeout(
        SIGN_TIMEOUT,
        armored_detached_signature(state.signing_key, &payload, &signer, created),
    )
    .await
    {
        Ok(Ok(armored)) => armored,
        Ok(Err(_)) => {
            warn!("OpenPGP agent signing failed");
            let _ = protocol::write_failure(&mut stream, Failure::SigningFailed).await;
            return;
        }
        Err(_) => {
            warn!("OpenPGP agent signing timed out");
            let _ = protocol::write_failure(&mut stream, Failure::SigningFailed).await;
            return;
        }
    };
    if let Err(error) = protocol::write_signature(&mut stream, &armored).await {
        warn!(?error, "OpenPGP agent could not write its response");
    }
}

pub(super) async fn sign(
    socket: &Path,
    key: Option<&str>,
    payload: &[u8],
) -> Result<ArmoredSignature> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(anyhow!(
            "payload exceeds the OpenPGP agent limit of {MAX_PAYLOAD_LEN} bytes"
        ));
    }
    let key = key
        .map(str::parse::<SigningKeyName>)
        .transpose()
        .map_err(|_error| anyhow!("OpenPGP agent does not serve the requested key"))?;
    let mut stream = send_request(socket, key.as_ref(), payload, REQUEST_TIMEOUT).await?;
    match timeout(
        REQUEST_TIMEOUT + SIGN_TIMEOUT,
        protocol::read_response(&mut stream),
    )
    .await
    .context("OpenPGP agent response timed out")??
    {
        Ok(signature) => {
            if key
                .as_ref()
                .is_some_and(|key| !key.matches_fingerprint(signature.fingerprint()))
            {
                Err(anyhow!("invalid OpenPGP agent signature response"))
            } else {
                Ok(signature)
            }
        }
        Err(Failure::InvalidRequest) => Err(anyhow!("OpenPGP agent rejected the request")),
        Err(Failure::KeyNotServed) => {
            Err(anyhow!("OpenPGP agent does not serve the requested key"))
        }
        Err(Failure::SigningFailed) => Err(anyhow!("OpenPGP agent could not sign the payload")),
    }
}

async fn send_request(
    socket: &Path,
    key: Option<&SigningKeyName>,
    payload: &[u8],
    deadline: Duration,
) -> Result<UnixStream> {
    timeout(deadline, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connect to OpenPGP agent socket {}", socket.display()))?;
        protocol::write_request(&mut stream, key, payload)
            .await
            .context("write the OpenPGP agent request")?;
        Ok(stream)
    })
    .await
    .context("OpenPGP agent request send timed out")?
}

fn default_socket_path() -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .ok_or_else(|| anyhow!("missing HOME; use --socket to set the OpenPGP agent path"))?;
    Ok(Path::new(&home)
        .join(".config/turnkey")
        .join("gpg-agent.sock"))
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(anyhow!(
                    "OpenPGP agent is already running on {}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                let identity = SocketIdentity::from_metadata(&metadata);
                match fs::symlink_metadata(path).await {
                    Ok(metadata)
                        if metadata.file_type().is_socket() && identity.matches(&metadata) =>
                    {
                        fs::remove_file(path).await.with_context(|| {
                            format!("failed to remove stale socket {}", path.display())
                        })?;
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Ok(_) => return agent_already_running(path),
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("failed to inspect {}", path.display()));
                    }
                }
            }
            Err(_) => return agent_already_running(path),
        },
        Ok(_) => {
            return Err(anyhow!(
                "refusing to replace non-socket path {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }
    Ok(())
}

fn agent_already_running<T>(path: &Path) -> Result<T> {
    Err(anyhow!(
        "OpenPGP agent is already running on {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::net::UnixListener as TestUnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use clap::Parser;
    use tempfile::tempdir;
    use tokio::sync::Notify;

    use super::*;

    #[derive(Debug, Parser)]
    struct AgentParser {
        #[command(flatten)]
        args: Args,
    }

    const KEY: &str = "0123456789ABCDEF";

    struct FakeListener {
        accepted: AtomicUsize,
    }

    impl ConnectionListener for FakeListener {
        type Connection = ();

        async fn accept(&self) -> io::Result<Self::Connection> {
            self.accepted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn socket_mode_defaults_to_owner_read_write_during_cli_parsing() {
        let parsed = AgentParser::try_parse_from(["agent", "serve", "--key", KEY]).unwrap();
        let Command::Serve(args) = parsed.args.command;

        assert_eq!(args.socket_mode.0, 0o600);
    }

    #[test]
    fn socket_mode_accepts_octal_permissions_during_cli_parsing() {
        let parsed =
            AgentParser::try_parse_from(["agent", "serve", "--key", KEY, "--socket-mode", "640"])
                .unwrap();
        let Command::Serve(args) = parsed.args.command;

        assert_eq!(args.socket_mode.0, 0o640);
    }

    #[test]
    fn socket_mode_rejects_invalid_values_during_cli_parsing() {
        let error =
            AgentParser::try_parse_from(["agent", "serve", "--key", KEY, "--socket-mode", "888"])
                .unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn staging_socket_path_uses_path_budget_and_never_matches_destination() {
        let path_capacity = unix_socket_path_capacity();
        let parent = Path::new("/").join("p".repeat(path_capacity - 18));
        let destination = parent.join("d");

        let staging = staging_socket_path(&destination, Uuid::nil()).unwrap();

        assert_eq!(staging.parent(), Some(parent.as_path()));
        assert_eq!(staging.file_name().unwrap().as_bytes().len(), 16);
        assert_ne!(staging, destination);

        let colliding_destination = Path::new("00000000000000000000000000000000");
        let staging = staging_socket_path(colliding_destination, Uuid::nil()).unwrap();
        assert_ne!(staging, colliding_destination);
        assert_eq!(staging.file_name().unwrap().as_bytes().len(), 32);

        let cramped_parent = Path::new("/").join("p".repeat(path_capacity - 17));
        let error = staging_socket_path(&cramped_parent.join("d"), Uuid::nil()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn accept_loop_applies_capacity_before_accept_and_drains_on_shutdown() {
        const CAPACITY: usize = 2;
        let listener = Arc::new(FakeListener {
            accepted: AtomicUsize::new(0),
        });
        let started = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        let task = {
            let listener = Arc::clone(&listener);
            let started = Arc::clone(&started);
            let dropped = Arc::clone(&dropped);
            let starts = Arc::clone(&starts);
            let shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move {
                run_accept_loop(
                    listener.as_ref(),
                    move |()| {
                        let started = Arc::clone(&started);
                        let dropped = Arc::clone(&dropped);
                        let starts = Arc::clone(&starts);
                        async move {
                            let _guard = DropCounter(dropped);
                            started.fetch_add(1, Ordering::SeqCst);
                            starts.notify_one();
                            pending::<()>().await;
                        }
                    },
                    shutdown.notified(),
                    CAPACITY,
                )
                .await
            })
        };

        while started.load(Ordering::SeqCst) < CAPACITY {
            starts.notified().await;
        }
        tokio::task::yield_now().await;
        assert_eq!(listener.accepted.load(Ordering::SeqCst), CAPACITY);

        shutdown.notify_one();
        task.await.unwrap().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), CAPACITY);
    }

    #[tokio::test]
    async fn accept_loop_resumes_accepting_after_a_handler_completes() {
        let listener = Arc::new(FakeListener {
            accepted: AtomicUsize::new(0),
        });
        let started = Arc::new(AtomicUsize::new(0));
        let starts = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let shutdown = Arc::new(Notify::new());

        let task = {
            let listener = Arc::clone(&listener);
            let started = Arc::clone(&started);
            let starts = Arc::clone(&starts);
            let release = Arc::clone(&release);
            let shutdown = Arc::clone(&shutdown);
            tokio::spawn(async move {
                run_accept_loop(
                    listener.as_ref(),
                    move |()| {
                        let started = Arc::clone(&started);
                        let starts = Arc::clone(&starts);
                        let release = Arc::clone(&release);
                        async move {
                            started.fetch_add(1, Ordering::SeqCst);
                            starts.notify_one();
                            release.notified().await;
                        }
                    },
                    shutdown.notified(),
                    1,
                )
                .await
            })
        };

        while started.load(Ordering::SeqCst) < 1 {
            starts.notified().await;
        }
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 1);

        release.notify_one();
        while started.load(Ordering::SeqCst) < 2 {
            starts.notified().await;
        }
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 2);

        shutdown.notify_one();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_send_deadline_bounds_a_peer_that_accepts_without_reading() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let (listener, _guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();
        let accepted = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            pending::<()>().await;
            drop(stream);
        });

        let error = send_request(
            &path,
            None,
            &vec![0_u8; MAX_PAYLOAD_LEN],
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();

        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == "OpenPGP agent request send timed out")
        );
        accepted.abort();
        accepted.await.unwrap_err();
    }

    #[tokio::test]
    async fn removes_only_connection_refused_stale_socket() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        drop(TestUnixListener::bind(&path).unwrap());

        remove_stale_socket(&path).await.unwrap();

        assert!(!path.exists());
    }

    #[tokio::test]
    async fn acquired_socket_is_ready_has_requested_mode_and_lives_with_guard() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");

        let (listener, guard) = acquire_socket(&path, SocketMode(0o640)).await.unwrap();

        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        let lock_metadata =
            std::fs::symlink_metadata(directory.path().join("agent.sock.lock")).unwrap();
        assert!(lock_metadata.file_type().is_file());
        assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);
        let connected = UnixStream::connect(&path).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop((connected, accepted, guard));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn short_named_socket_can_connect_and_is_cleaned_up() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("s");

        let (listener, guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();
        let connected = UnixStream::connect(&path).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();

        drop((connected, accepted, listener, guard));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn overlong_destination_is_rejected_before_creating_socket_resources() {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let parent = directory.path().join("not-created");
        let parent_len = parent.as_os_str().as_bytes().len();
        let name_len = unix_socket_path_capacity() + 1 - parent_len - 1;
        let path = parent.join("s".repeat(name_len));
        staging_socket_path(&path, Uuid::nil()).unwrap();

        let error = acquire_socket(&path, SocketMode(0o600))
            .await
            .err()
            .expect("an overlong destination must be rejected");

        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(ErrorKind::InvalidInput)
        );
        assert!(
            error
                .to_string()
                .contains("invalid OpenPGP agent socket path")
        );
        assert!(!path.exists());
        assert!(!parent.exists());
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        assert!(!PathBuf::from(lock_name).exists());
    }

    #[tokio::test]
    async fn maximum_length_destination_can_connect_and_is_cleaned_up() {
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let parent_len = directory.path().as_os_str().as_bytes().len();
        let name_len = unix_socket_path_capacity() - parent_len - 1;
        let path = directory.path().join("s".repeat(name_len));
        assert_eq!(
            path.as_os_str().as_bytes().len(),
            unix_socket_path_capacity()
        );

        let (listener, guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();
        let connected = UnixStream::connect(&path).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();

        drop((connected, accepted, listener, guard));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn socket_lock_blocks_until_published_guard_is_dropped() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let (listener, guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();

        let error = acquire_socket(&path, SocketMode(0o600))
            .await
            .err()
            .expect("the published guard must retain the lifecycle lock");
        assert!(error.to_string().contains("already running"));

        drop((listener, guard));
        let (_listener, replacement_guard) =
            acquire_socket(&path, SocketMode(0o600)).await.unwrap();
        drop(replacement_guard);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn concurrent_acquisition_from_stale_socket_has_one_connectable_owner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        drop(TestUnixListener::bind(&path).unwrap());

        let (first, second) = tokio::join!(
            acquire_socket(&path, SocketMode(0o600)),
            acquire_socket(&path, SocketMode(0o600))
        );

        let (listener, guard, error) = match (first, second) {
            (Ok(acquired), Err(error)) | (Err(error), Ok(acquired)) => {
                (acquired.0, acquired.1, error)
            }
            _ => panic!("expected exactly one socket owner"),
        };
        assert!(error.to_string().contains("already running"));
        let connected = UnixStream::connect(&path).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop((connected, accepted));
        drop((listener, guard));
        assert!(!path.exists());
        assert!(directory.path().join("agent.sock.lock").is_file());
    }

    #[test]
    fn socket_lock_does_not_follow_symlinks() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let target = directory.path().join("target");
        std::fs::write(&target, []).unwrap();
        symlink(&target, directory.path().join("agent.sock.lock")).unwrap();

        let error = acquire_socket_lock(&path).unwrap_err();

        assert!(error.to_string().contains("failed to open agent lock"));
        assert_eq!(std::fs::read(&target).unwrap(), Vec::<u8>::new());
    }

    #[tokio::test]
    async fn failed_socket_acquisition_releases_path_lock() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        std::fs::write(&path, []).unwrap();

        acquire_socket(&path, SocketMode(0o600))
            .await
            .err()
            .expect("non-socket path must be rejected");
        std::fs::remove_file(&path).unwrap();
        let (_listener, _guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_socket_guard_preserves_a_replacement_at_the_same_path() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let (listener, guard) = acquire_socket(&path, SocketMode(0o600)).await.unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        let _replacement = TestUnixListener::bind(&path).unwrap();

        drop(guard);
        assert!(path.exists());
    }
}
