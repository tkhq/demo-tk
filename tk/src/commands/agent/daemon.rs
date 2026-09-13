use std::env;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use turnkey_auth::config::default_config_dir_from_home;
use turnkey_auth::ssh::{agent, protocol};

use super::lock::{AgentLock, is_lock_held_by_other, resolve_lock_file};
use super::{
    AgentNotRunning, AgentRunning, AgentStopped, InternalRunArgs, StartArgs, StatusArgs, StopArgs,
};
use crate::outcome::{MachineOnly, Outcome};

const START_TIMEOUT: Duration = Duration::from_secs(4);
const STOP_TIMEOUT: Duration = Duration::from_secs(4);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub async fn start(args: StartArgs) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file);
    let lock_file = resolve_lock_file(&pid_file);
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

    let mut child = Command::new(env::current_exe()?)
        .arg("ssh")
        .arg("agent")
        .arg("internal-run")
        .arg("--socket")
        .arg(&socket)
        .arg("--pid-file")
        .arg(&pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn background ssh-agent")?;

    let pid = child
        .id()
        .context("background ssh-agent pid was not available")?;

    match wait_for_startup(&socket, &mut child).await {
        Ok(()) => Ok(Outcome::AgentStarted(AgentRunning {
            pid,
            socket: socket.display().to_string(),
        })),
        Err(error) => {
            let _ = fs::remove_file(&pid_file).await;
            let _ = child.start_kill();
            Err(error)
        }
    }
}

pub async fn stop(args: StopArgs) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file);
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(lock_file).await? {
        let _ = fs::remove_file(&pid_file).await;
        let _ = remove_socket_if_present(&socket).await;
        return Ok(Outcome::AgentNotRunning(AgentNotRunning {}));
    }

    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;

    send_signal(pid, libc::SIGTERM)
        .with_context(|| format!("failed to signal ssh-agent process {pid}"))?;
    wait_for_process_exit(pid).await?;
    let _ = fs::remove_file(&pid_file).await;
    wait_for_socket_removal(&socket).await?;
    Ok(Outcome::AgentStopped(AgentStopped {}))
}

pub async fn status(args: StatusArgs) -> Result<Outcome> {
    let socket = resolve_socket_path(args.socket)?;
    let pid_file = resolve_pid_file(&socket, args.pid_file);
    let lock_file = resolve_lock_file(&pid_file);

    if !is_lock_held_by_other(lock_file).await? {
        return Err(anyhow!("ssh-agent is not running"));
    }

    let pid = read_pid_file(&pid_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent pid file not found at {}", pid_file.display()))?;

    if !is_process_alive(pid) {
        return Err(anyhow!("ssh-agent pid {pid} is not running"));
    }

    if probe_agent_socket(&socket).await.is_err() {
        return Err(anyhow!(
            "ssh-agent pid {pid} is marked running but socket {} is not serving requests",
            socket.display()
        ));
    }

    Ok(Outcome::AgentStatusReport(AgentRunning {
        pid,
        socket: socket.display().to_string(),
    }))
}

pub async fn internal_run(args: InternalRunArgs) -> Result<Outcome> {
    let lock_file = resolve_lock_file(&args.pid_file);
    let _lock = AgentLock::acquire(lock_file)
        .await?
        .ok_or_else(|| anyhow!("ssh-agent is already running"))?;
    fs::write(&args.pid_file, format!("{}\n", process::id()))
        .await
        .with_context(|| format!("failed to write pid file at {}", args.pid_file.display()))?;

    let result = agent::run(args.socket).await;

    let _ = fs::remove_file(&args.pid_file).await;
    result.map(|()| Outcome::AgentDaemonExited(MachineOnly {}))
}

fn resolve_pid_file(socket: &Path, pid_file: Option<PathBuf>) -> PathBuf {
    pid_file.unwrap_or_else(|| PathBuf::from(format!("{}.pid", socket.display())))
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
                return Err(anyhow!("background ssh-agent exited early: {status}"));
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

fn resolve_socket_path(socket: Option<PathBuf>) -> Result<PathBuf> {
    match socket {
        Some(socket) => Ok(socket),
        None => default_socket_path(),
    }
}

fn default_socket_path() -> Result<PathBuf> {
    let home =
        env::var_os("HOME").ok_or_else(|| anyhow!("missing HOME; use --socket to set a path"))?;
    Ok(default_config_dir_from_home(Path::new(&home)).join("ssh-agent.sock"))
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

async fn read_pid_file(path: &Path) -> Result<Option<u32>> {
    let raw = match fs::read_to_string(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    let pid = raw
        .trim()
        .parse::<u32>()
        .with_context(|| format!("failed to parse pid file at {}", path.display()))?;
    Ok(Some(pid))
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

fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    match send_signal(pid, 0) {
        Ok(()) => true,
        Err(error) => error.raw_os_error() != Some(libc::ESRCH),
    }
}

fn send_signal(pid: u32, signal: i32) -> io::Result<()> {
    // SAFETY: libc::kill is an FFI syscall wrapper and does not dereference
    // Rust pointers or access Rust managed memory
    let rc = unsafe { libc::kill(pid as i32, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
