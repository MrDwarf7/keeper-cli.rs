mod attachment;
mod auth;
mod cli;
mod clipboard;
mod commands;
mod crypto;
mod diagnostics;
mod error;
mod folder_edit;
mod generator;
mod prelude;
mod proto;
mod record_edit;
mod rest;
mod settings;
mod totp;
mod uid;
mod vault;

use std::io::{BufRead, Write};
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, ShellLine};
use crate::commands::App;
use crate::diagnostics::{Report, Verbosity};
pub use crate::error::{Error, Result};

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_args(std::env::args_os()));
    let verbosity = Verbosity::from(cli.debug || cfg!(debug_assertions));
    if let Err(error) = diagnostics::init(verbosity) {
        eprintln!(
            "{}",
            Report {
                error: &error,
                verbosity
            }
        );
        return ExitCode::FAILURE;
    }
    match run(cli, verbosity) {
        Ok(()) => {
            tracing::debug!(event = "cli_run_succeeded", "CLI run succeeded");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::debug!(error_kind = diagnostics::error_kind(&error), event = "cli_run_failed", "CLI run failed");
            if !matches!(error, Error::Cancelled) || verbosity == Verbosity::Debug {
                eprintln!(
                    "{}",
                    Report {
                        error: &error,
                        verbosity
                    }
                );
            }
            if matches!(error, Error::Cancelled) {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli, verbosity: Verbosity) -> Result<()> {
    let mut config = settings::Settings::load(cli.config)?;
    if cli.server.is_some() {
        config.server = cli.server;
    }
    let mut app = App {
        settings: config,
        user:     cli.user,
        password: cli.password.into(),
        account:  None,
    };
    match cli.command {
        None | Some(Command::Shell) => shell(&mut app, verbosity),
        Some(command) => app.run(command),
    }
}

fn shell(app: &mut App, verbosity: Verbosity) -> Result<()> {
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
        let parsed = match ShellLine::try_parse_from(normalize_args(words.into_iter().map(Into::into))) {
            Ok(parsed) => parsed,
            Err(error) => {
                error.print()?;
                continue;
            }
        };
        match parsed.command {
            Command::Exit => return Ok(()),
            Command::Shell => {}
            command => {
                match app.run(command) {
                    Ok(()) => {}
                    Err(Error::Cancelled) => return Err(Error::Cancelled),
                    Err(error) => {
                        eprintln!(
                            "{}",
                            Report {
                                error: &error,
                                verbosity
                            }
                        );
                    }
                }
            }
        }
    }
}

fn normalize_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let mut args = args.into_iter();
    let mut normalized = Vec::new();
    while let Some(arg) = args.next() {
        let text = arg.to_str().unwrap_or_default();
        if text == "--" {
            normalized.push(arg);
            normalized.extend(args);
            break;
        }
        let takes_value = matches!(
            text,
            "--password"
                | "--user"
                | "--server"
                | "--config"
                | "--title"
                | "--record"
                | "--notes"
                | "--name"
                | "--folder"
                | "--field"
                | "--file"
                | "--out-dir"
                | "--username"
                | "--output"
                | "--record-type"
                | "-rt"
                | "--format"
                | "--color"
        );
        normalized.push(match text {
            "-rt" => "--record-type".into(),
            value if let Some(value) = value.strip_prefix("-rt=") => format!("--record-type={value}").into(),
            "-sf" => "--shared-folder".into(),
            "-uf" => "--user-folder".into(),
            "-cu" => "--copy-uid".into(),
            _ => arg,
        });
        if takes_value && let Some(value) = args.next() {
            normalized.push(value);
        }
    }
    normalized
}
