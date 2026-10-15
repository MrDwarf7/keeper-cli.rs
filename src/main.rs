mod auth;
mod config;
mod crypto;
mod error;
mod prelude;
mod proto;
mod rest;
mod vault;

pub use crate::error::{Error, Result};

fn main() -> Result<()> {
    let mut config = config::Config::load(config::Config::resolve_path(None))?;
    let session = auth::login(&mut config, None, None)?;
    println!("{}", session.user);
    Ok(())
}
