use anyhow::Result;
use clap::Args as ClapArgs;
use turnkey_auth::git_sign::run_git_sign;

use crate::outcome::{MachineOnly, Outcome};

#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    ssh_keygen_args: Vec<String>,
}

pub async fn run(args: Args) -> Result<Outcome> {
    run_git_sign(&args.ssh_keygen_args).await?;
    Ok(Outcome::GitSignCompleted(MachineOnly {}))
}
