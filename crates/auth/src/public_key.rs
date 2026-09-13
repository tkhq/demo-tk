//! Public-key helpers backed by Turnkey.

use anyhow::Result;

use crate::config::Config;
use crate::ssh::encode_public_key_line;
use crate::turnkey::{self, TurnkeySigner};

/// Fetches the configured Turnkey public key and renders it in OpenSSH format.
pub async fn get_public_key_line() -> Result<String> {
    let config = Config::resolve().await?;
    let signer = TurnkeySigner::new(turnkey::build_client(&config)?, config);
    let public_key = signer.get_public_key().await?;
    Ok(encode_public_key_line(&public_key))
}
