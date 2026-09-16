//! Short-lived agent credentials: request, provision, activate, and inspect.
//!
//! The agent generates its keypair with `request` and hands only the public
//! key to a provisioner, which registers it with `provision`. The agent then
//! switches to it with `activate` and watches its expiry with `status`.

pub(crate) mod duration;
pub(crate) mod pending;
mod provision;
mod request;

use anyhow::Result;
use clap::Subcommand;

pub use provision::ProvisionArgs;

use crate::auth::{self, AuthOptions};
use crate::operations::OperationOutput;

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
}

pub async fn run(command: SessionCommand, options: &AuthOptions) -> Result<OperationOutput> {
    match command {
        SessionCommand::Request { name, replace } => request::run(name, replace).await,
        SessionCommand::Provision(args) => {
            provision::run(auth::resolve(options).await?, args).await
        }
    }
}
