//! Short-lived agent credentials: request, provision, activate, and inspect.
//!
//! The agent generates its keypair with `request` and hands only the public
//! key to a provisioner, which registers it with `provision`. The agent then
//! switches to it with `activate` and watches its expiry with `status`.

mod activate;
pub(crate) mod duration;
mod pending;
mod provision;
mod request;
mod status;

use anyhow::Result;
use clap::Subcommand;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::TurnkeyClientError;
use turnkey_client::generated::{GetWhoamiRequest, GetWhoamiResponse};
use uuid::Uuid;

use provision::ProvisionArgs;
pub(crate) use provision::{CompressedPublicKey, parse_public_key};
use status::StatusArgs;

use crate::auth::{self, ApiBaseUrl, AuthOptions, build_turnkey_client};
use crate::operations::OperationOutput;

/// Asks Turnkey who `key` belongs to within `organization_id`. The outer
/// error is a client construction failure; the inner one is the whoami call,
/// left unwrapped so each caller applies its own handling.
async fn whoami(
    key: TurnkeyP256ApiKey,
    api_base_url: &ApiBaseUrl,
    organization_id: Uuid,
) -> Result<Result<GetWhoamiResponse, TurnkeyClientError>> {
    Ok(build_turnkey_client(key, api_base_url)?
        .get_whoami(GetWhoamiRequest {
            organization_id: organization_id.to_string(),
        })
        .await)
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Generate a new credential for a saved profile and print its public key
    /// for a provisioner to register. The private key stays on this machine.
    Request {
        /// Saved profile that will use the new credential.
        #[arg(long = "profile-name")]
        name: String,
        /// Discard an unregistered pending request and start over.
        #[arg(long)]
        replace: bool,
    },
    /// Register a public key on a user as an expiring API key. Run with the
    /// provisioner's identity; re-run after approval.
    Provision(ProvisionArgs),
    /// Switch a saved profile to its pending credential once it is registered.
    Activate {
        /// Saved profile with a pending session request.
        #[arg(long = "profile-name")]
        name: String,
    },
    /// Report when a saved profile's credential expires; exits with
    /// `session_expiring` when less than `--warn-before` remains.
    Status(StatusArgs),
}

pub async fn run(command: SessionCommand, options: &AuthOptions) -> Result<OperationOutput> {
    match command {
        SessionCommand::Request { name, replace } => request::run(name, replace).await,
        SessionCommand::Provision(args) => {
            provision::run(auth::resolve(options).await?, args).await
        }
        SessionCommand::Activate { name } => activate::run(name).await,
        SessionCommand::Status(args) => status::run(args).await,
    }
}
