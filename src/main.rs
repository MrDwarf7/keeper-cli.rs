mod attachment;
mod auth;
mod cli;
mod commands;
mod config;
mod crypto;
mod error;
mod generator;
mod prelude;
mod proto;
mod rest;
mod totp;
mod vault;

use std::io::{BufRead, Write};
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, ShellLine};
use crate::commands::App;
pub use crate::error::{Error, Result};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Cancelled) => ExitCode::from(130),
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let mut config = config::Config::load(cli.config)?;
    if let Some(server) = cli.server {
        config.set("server", Some(server));
    }
    let mut app = App::new(config, cli.user, cli.password);
    match cli.command {
        None | Some(Command::Shell) => shell(&mut app),
        Some(command) => app.run(command),
    }
}

fn shell(app: &mut App) -> Result<()> {
    eprintln!("Keeper CLI shell. Type \"help\" for commands, \"exit\" to leave.");
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        eprint!("{}", app.prompt());
        std::io::stderr().flush()?;
        line.clear();
        if stdin.lock().read_line(&mut line)? == 0 {
            eprintln!();
            return Ok(());
        }
        let Some(words) = shlex::split(line.trim()) else {
            eprintln!("Unbalanced quotes");
            continue;
        };
        if words.is_empty() {
            continue;
        }
        let parsed = match ShellLine::try_parse_from(&words) {
            Ok(parsed) => parsed,
            Err(e) => {
                // Covers --help/help output as well as genuine usage errors.
                let _ = e.print();
                continue;
            }
        };
        match parsed.command {
            Command::Exit => return Ok(()),
            Command::Shell => {}
            command => {
                if let Err(e) = app.run(command) {
                    eprintln!("Error: {e}");
                }
            }
        }
    }
}
