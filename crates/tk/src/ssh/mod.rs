//! SSH key registration, selection, signing, and agent commands.

use std::fmt::{self, Display, Formatter};

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::{self, AuthOptions, build_turnkey_client};
use crate::errors::InvalidInput;
use crate::outcome::{MachineOnly, Outcome};

use registry::{PrivateKeyId, SelectError, SshKeyEntry, SshKeyName};

pub mod agent;
pub mod keys;
pub mod registry;
pub mod shim;
pub mod signer;

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// Manage registered Ed25519 private keys.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Print a registered SSH public key.
    PublicKey(KeyArgs),
    /// Sign a payload using the Git SSH signer interface.
    GitSign(GitSignArgs),
    /// Manage a background SSH agent over a Unix socket.
    Agent(agent::Args),
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// Fetch and register an Ed25519 private key.
    Add(AddArgs),
    /// List all registered SSH keys without contacting Turnkey.
    List,
    /// Forget a registered key without changing the Turnkey private key.
    Remove(RemoveArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Turnkey private key to register.
    #[arg(long)]
    private_key_id: PrivateKeyId,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Fingerprint, public key line, or Turnkey private key ID.
    key: SshKeyName,
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    /// Fingerprint, public key line, or Turnkey private key ID.
    #[arg(long)]
    key: Option<SshKeyName>,
}

#[derive(Debug, Args)]
pub struct GitSignArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    ssh_keygen_args: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKey {
    pub(crate) fingerprint: String,
    public_key: String,
    organization_id: Uuid,
    private_key_id: String,
    #[serde(skip)]
    pub(crate) agent_running: bool,
}

impl From<SshKeyEntry> for RegisteredKey {
    fn from(entry: SshKeyEntry) -> Self {
        let fingerprint = entry.fingerprint().to_string();
        let SshKeyEntry {
            organization_id,
            private_key_id,
            public_key,
        } = entry;
        Self {
            fingerprint,
            public_key: public_key.line(),
            organization_id,
            private_key_id: private_key_id.into_string(),
            agent_running: false,
        }
    }
}

impl RegisteredKey {
    pub(crate) fn write_restart_hint(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.agent_running {
            f.write_str("; restart tk ssh agent to pick this up")?;
        }
        Ok(())
    }
}

impl Display for RegisteredKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {}  {}",
            self.fingerprint, self.organization_id, self.private_key_id
        )?;
        self.write_restart_hint(f)
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct RegisteredKeys {
    keys: Vec<RegisteredKey>,
}

impl Display for RegisteredKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Some((last, rest)) = self.keys.split_last() else {
            return f.write_str("no SSH keys registered");
        };
        for key in rest {
            writeln!(f, "{key}")?;
        }
        last.fmt(f)
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyPrinted {
    fingerprint: String,
    public_key: String,
}

impl Display for PublicKeyPrinted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.public_key)
    }
}

fn selection_error(error: SelectError, unnamed_remedy: &str) -> anyhow::Error {
    match &error {
        SelectError::Empty => InvalidInput(format!(
            "{error}; register one with tk ssh keys add --private-key-id ID"
        ))
        .into(),
        SelectError::Unnamed { .. } => InvalidInput(format!("{error}; {unnamed_remedy}")).into(),
        SelectError::NoMatch { .. } => InvalidInput(format!(
            "{error}; register it with tk ssh keys add --private-key-id ID"
        ))
        .into(),
        SelectError::Ambiguous { .. } => {
            InvalidInput(format!("{error}; name the key by its SHA256: fingerprint")).into()
        }
    }
}

pub async fn run(command: SshCommand, options: &AuthOptions) -> Result<Outcome> {
    match command {
        SshCommand::Keys {
            command: KeysCommand::List,
        } => Ok(Outcome::SshKeysRegistered(RegisteredKeys {
            keys: auth::load_ssh_keys()
                .await?
                .into_entries()
                .map(RegisteredKey::from)
                .collect(),
        })),
        SshCommand::Keys {
            command: KeysCommand::Add(AddArgs { private_key_id }),
        } => {
            let resolved = auth::resolve(options).await?;
            let client = build_turnkey_client(resolved.stamper, &resolved.api_base_url)?;
            let public_key =
                keys::get_private_key(&client, resolved.org_id, &private_key_id).await?;
            let entry = SshKeyEntry {
                organization_id: resolved.org_id,
                private_key_id,
                public_key,
            };
            let mut record = RegisteredKey::from(entry.clone());
            auth::register_ssh_key(entry).await?;
            record.agent_running = agent::is_default_running().await;
            Ok(Outcome::SshKeyRegistered(record))
        }
        SshCommand::Keys {
            command: KeysCommand::Remove(RemoveArgs { key }),
        } => {
            let removed = auth::remove_ssh_key(key)
                .await?
                .map_err(|error| selection_error(error, "name the key positionally"))?;
            let mut record = RegisteredKey::from(removed);
            record.agent_running = agent::is_default_running().await;
            Ok(Outcome::SshKeyRemoved(record))
        }
        SshCommand::PublicKey(KeyArgs { key }) => {
            let entry = auth::load_ssh_keys()
                .await?
                .select(key)
                .map_err(|error| selection_error(error, "name one with --key"))?;
            Ok(Outcome::PublicKeyPrinted(PublicKeyPrinted {
                fingerprint: entry.fingerprint().to_string(),
                public_key: entry.public_key.line(),
            }))
        }
        SshCommand::GitSign(GitSignArgs { ssh_keygen_args }) => {
            shim::sign(ssh_keygen_args, options).await?;
            Ok(Outcome::GitSignCompleted(MachineOnly {}))
        }
        SshCommand::Agent(args) => agent::run(args, options).await,
    }
}
