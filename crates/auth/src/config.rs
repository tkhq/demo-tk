//! Auth configuration resolution and persistence helpers.

use std::collections::BTreeMap;
use std::env;
use std::fmt::{self, Display, Formatter};
use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

const DEFAULT_API_BASE_URL: &str = "https://api.turnkey.com";
const CONFIG_PATH_ENV: &str = "TURNKEY_TK_CONFIG_PATH";
/// Display path for the default `tk` config directory.
pub const DEFAULT_CONFIG_DIR_DISPLAY: &str = "~/.config/turnkey/tk";

const ORGANIZATION_ID_ENV: &str = "TURNKEY_ORGANIZATION_ID";
const API_PUBLIC_KEY_ENV: &str = "TURNKEY_API_PUBLIC_KEY";
const API_PRIVATE_KEY_ENV: &str = "TURNKEY_API_PRIVATE_KEY";
const PRIVATE_KEY_ID_ENV: &str = "TURNKEY_PRIVATE_KEY_ID";
const API_BASE_URL_ENV: &str = "TURNKEY_API_BASE_URL";
const REDACTED_VALUE: &str = "<redacted>";

#[derive(Debug, PartialEq)]
/// Fully resolved Turnkey auth configuration.
pub struct Config {
    /// Turnkey organization identifier.
    pub organization_id: Uuid,
    /// Turnkey API public key used for request stamping.
    pub api_public_key: String,
    /// Turnkey API private key used for request stamping.
    pub api_private_key: String,
    /// Turnkey Ed25519 private key identifier, if configured.
    pub private_key_id: Option<String>,
    /// Base URL for the Turnkey API.
    pub api_base_url: String,
}

/// Effective config, with missing required fields left `None`.
struct ResolvedConfig {
    organization_id: Option<String>,
    api_public_key: Option<String>,
    api_private_key: Option<String>,
    private_key_id: Option<String>,
    api_base_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supported config keys exposed through the CLI.
pub enum ConfigKey {
    /// `turnkey.organizationId`
    OrganizationId,
    /// `turnkey.apiPublicKey`
    ApiPublicKey,
    /// `turnkey.apiPrivateKey`
    ApiPrivateKey,
    /// `turnkey.privateKeyId`
    PrivateKeyId,
    /// `turnkey.apiBaseUrl`
    ApiBaseUrl,
}

impl Config {
    /// Resolves a complete config from the process environment and config file.
    pub(crate) async fn resolve() -> Result<Self> {
        ResolvedConfig::resolve()
            .await
            .and_then(ResolvedConfig::into_complete)
    }

    /// Resolves a complete config from an explicit path and environment map.
    pub async fn resolve_from_map(path: &Path, env: &BTreeMap<String, String>) -> Result<Self> {
        ResolvedConfig::resolve_from_map(path, env)
            .await
            .and_then(ResolvedConfig::into_complete)
    }
}

impl ResolvedConfig {
    async fn resolve() -> Result<Self> {
        let path = global_config_path()?;
        let env = env::vars().collect::<BTreeMap<_, _>>();
        Self::resolve_from_map(&path, &env).await
    }

    async fn resolve_from_map(path: &Path, env: &BTreeMap<String, String>) -> Result<Self> {
        let persisted = load_persisted_config(path).await?;
        Ok(Self {
            organization_id: resolve_value(
                env,
                ORGANIZATION_ID_ENV,
                persisted.turnkey.organization_id.as_deref(),
            ),
            api_public_key: resolve_value(
                env,
                API_PUBLIC_KEY_ENV,
                persisted.turnkey.api_public_key.as_deref(),
            ),
            api_private_key: resolve_value(
                env,
                API_PRIVATE_KEY_ENV,
                persisted.turnkey.api_private_key.as_deref(),
            ),
            private_key_id: resolve_value(
                env,
                PRIVATE_KEY_ID_ENV,
                persisted.turnkey.private_key_id.as_deref(),
            ),
            api_base_url: resolve_value(
                env,
                API_BASE_URL_ENV,
                persisted.turnkey.api_base_url.as_deref(),
            )
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string()),
        })
    }

    fn into_complete(self) -> Result<Config> {
        let Self {
            organization_id,
            api_public_key,
            api_private_key,
            private_key_id,
            api_base_url,
        } = self;
        let organization_id = required_value(ConfigKey::OrganizationId, organization_id)?;
        let organization_id = Uuid::parse_str(&organization_id).with_context(|| {
            format!(
                "config value {} is not a UUID: {organization_id}",
                ConfigKey::OrganizationId
            )
        })?;
        Ok(Config {
            organization_id,
            api_public_key: required_value(ConfigKey::ApiPublicKey, api_public_key)?,
            api_private_key: required_value(ConfigKey::ApiPrivateKey, api_private_key)?,
            private_key_id,
            api_base_url,
        })
    }

    fn redacted(self) -> RedactedConfig {
        let Self {
            organization_id,
            api_public_key,
            api_private_key,
            private_key_id,
            api_base_url,
        } = self;
        let display = |key: ConfigKey, value: Option<String>| {
            value
                .map(|value| key.display_value(value))
                .unwrap_or_default()
        };
        RedactedConfig {
            turnkey: RedactedTurnkeyConfig {
                organization_id: display(ConfigKey::OrganizationId, organization_id),
                api_public_key: display(ConfigKey::ApiPublicKey, api_public_key),
                api_private_key: display(ConfigKey::ApiPrivateKey, api_private_key),
                private_key_id: display(ConfigKey::PrivateKeyId, private_key_id),
                api_base_url: ConfigKey::ApiBaseUrl.display_value(api_base_url),
            },
        }
    }
}

impl ConfigKey {
    /// Every supported config key, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::OrganizationId,
        Self::ApiPublicKey,
        Self::ApiPrivateKey,
        Self::PrivateKeyId,
        Self::ApiBaseUrl,
    ];

    /// The dotted name this key is written as, both on the command line and in
    /// the persisted config file.
    const fn name(self) -> &'static str {
        match self {
            Self::OrganizationId => "turnkey.organizationId",
            Self::ApiPublicKey => "turnkey.apiPublicKey",
            Self::ApiPrivateKey => "turnkey.apiPrivateKey",
            Self::PrivateKeyId => "turnkey.privateKeyId",
            Self::ApiBaseUrl => "turnkey.apiBaseUrl",
        }
    }

    /// The value as it may be shown to a user: secrets are replaced with a
    /// redaction marker, everything else passes through unchanged.
    fn display_value(self, value: String) -> String {
        match self {
            Self::ApiPrivateKey => REDACTED_VALUE.to_string(),
            Self::OrganizationId | Self::ApiPublicKey | Self::PrivateKeyId | Self::ApiBaseUrl => {
                value
            }
        }
    }
}

impl Display for ConfigKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ConfigKey {
    type Err = UnsupportedConfigKey;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|key| key.name() == value)
            .ok_or_else(|| UnsupportedConfigKey {
                key: value.to_string(),
            })
    }
}

/// A config key name that matches no supported [`ConfigKey`].
#[derive(Debug, thiserror::Error)]
#[error(
    "unsupported config key: {key}; supported keys: {}",
    ConfigKey::ALL.map(ConfigKey::name).join(", ")
)]
pub struct UnsupportedConfigKey {
    key: String,
}

/// Returns the global tk config path, honoring `TURNKEY_TK_CONFIG_PATH` when set.
fn global_config_path() -> Result<PathBuf> {
    if let Some(path) = read_value_from_process_env(CONFIG_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }

    let home = read_value_from_process_env("HOME")
        .ok_or_else(|| anyhow!("missing HOME; set {CONFIG_PATH_ENV} to choose a config path"))?;
    Ok(default_config_file_from_home(Path::new(&home)))
}

/// Returns the default `tk` config directory for a given home directory.
pub fn default_config_dir_from_home(home: &Path) -> PathBuf {
    home.join(".config").join("turnkey").join("tk")
}

/// Returns the default `tk` config file path for a given home directory.
pub fn default_config_file_from_home(home: &Path) -> PathBuf {
    default_config_dir_from_home(home).join("tk.toml")
}

/// Returns one resolved config value, redacting the private key when requested.
pub async fn get_resolved_config_value(key: ConfigKey) -> Result<String> {
    let resolved = ResolvedConfig::resolve().await?;
    let value = match key {
        ConfigKey::OrganizationId => resolved.organization_id,
        ConfigKey::ApiPublicKey => resolved.api_public_key,
        ConfigKey::ApiPrivateKey => resolved.api_private_key,
        ConfigKey::PrivateKeyId => resolved.private_key_id,
        ConfigKey::ApiBaseUrl => Some(resolved.api_base_url),
    }
    .ok_or_else(|| anyhow!("config value is not set"))?;

    Ok(key.display_value(value))
}

/// Resolves the effective config with sensitive values redacted.
pub async fn redacted_config() -> Result<RedactedConfig> {
    Ok(ResolvedConfig::resolve().await?.redacted())
}

/// Persists one config value to the global config file.
pub async fn set_config_value(key: ConfigKey, value: String) -> Result<()> {
    let path = global_config_path()?;
    let mut persisted = load_persisted_config(&path).await?;
    persisted.turnkey.set(key, value);
    save_persisted_config(&path, &persisted).await
}

async fn save_persisted_config(path: &Path, config: &PersistedConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let serialized = toml::to_string_pretty(config).context("failed to serialize config file")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.set_permissions(Permissions::from_mode(0o600)).await?;
    file.write_all(serialized.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}

async fn load_persisted_config(path: &Path) -> Result<PersistedConfigFile> {
    match fs::read_to_string(path).await {
        Ok(contents) => toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file at {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PersistedConfigFile::default()),
        Err(error) => Err(error.into()),
    }
}

fn resolve_value(
    env: &BTreeMap<String, String>,
    env_key: &str,
    persisted: Option<&str>,
) -> Option<String> {
    env.get(env_key)
        .and_then(|value| normalize_value(value))
        .or_else(|| persisted.and_then(normalize_value))
}

fn read_value_from_process_env(key: &str) -> Option<String> {
    env::var(key).ok().and_then(|value| normalize_value(&value))
}

fn normalize_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn required_value(key: ConfigKey, value: Option<String>) -> Result<String> {
    value.ok_or_else(|| anyhow!("missing required config value: {key}"))
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedConfigFile {
    #[serde(default)]
    turnkey: PersistedTurnkeyConfig,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedTurnkeyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_base_url: Option<String>,
}

impl PersistedTurnkeyConfig {
    fn set(&mut self, key: ConfigKey, value: String) {
        match key {
            ConfigKey::OrganizationId => self.organization_id = Some(value),
            ConfigKey::ApiPublicKey => self.api_public_key = Some(value),
            ConfigKey::ApiPrivateKey => self.api_private_key = Some(value),
            ConfigKey::PrivateKeyId => self.private_key_id = Some(value),
            ConfigKey::ApiBaseUrl => self.api_base_url = Some(value),
        }
    }
}

/// The effective config with sensitive values redacted.
#[derive(Default, Serialize)]
pub struct RedactedConfig {
    turnkey: RedactedTurnkeyConfig,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct RedactedTurnkeyConfig {
    organization_id: String,
    api_public_key: String,
    api_private_key: String,
    private_key_id: String,
    api_base_url: String,
}
