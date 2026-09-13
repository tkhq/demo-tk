use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Serialize;
use std::fmt::{self, Display, Formatter};
use turnkey_auth::public_key::get_public_key_line;

use crate::outcome::Outcome;

#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyPrinted {
    public_key: String,
}

impl Display for PublicKeyPrinted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.public_key)
    }
}

pub async fn run(_args: Args) -> Result<Outcome> {
    Ok(Outcome::PublicKeyPrinted(PublicKeyPrinted {
        public_key: get_public_key_line().await?,
    }))
}
