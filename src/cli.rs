//! Command-line surface. Names, aliases and flags follow Commander so muscle memory carries
//! over; only the read-only vault subset is implemented.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "keeper-cli",
    version,
    about = "Keeper Password Manager CLI (Rust port of Keeper Commander's core)"
)]
pub struct Cli {
    /// Config file
    #[arg(long, global = true, env = "KEEPER_CONFIG_FILE", default_value_os_t = crate::config::default_path())]
    pub config: PathBuf,

    /// Account email
    #[arg(long, global = true)]
    pub user: Option<String>,

    /// Master password (prompted for when omitted)
    #[arg(long, global = true, env = "KEEPER_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Keeper region host, e.g. keepersecurity.eu
    #[arg(long, global = true)]
    pub server: Option<String>,

    /// Command to run; starts the interactive shell when omitted
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Parser, Debug)]
#[command(
    no_binary_name = true,
    disable_version_flag = true,
    name = "",
    about = "Shell commands"
)]
pub struct ShellLine {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Log in (and remember the account in the config)
    Login { email: Option<String> },
    /// End the session and forget this device's persistent login
    Logout,
    /// Show the logged-in account
    Whoami {
        #[arg(short, long)]
        verbose: bool,
    },
    /// Download and decrypt the vault again
    SyncDown,
    /// List folder contents
    Ls {
        /// Show a detailed table
        #[arg(short = 'l', long = "list")]
        detail:       bool,
        #[arg(short = 'f', long = "folders")]
        folders_only: bool,
        #[arg(short = 'r', long = "records")]
        records_only: bool,
        /// Include subfolders
        #[arg(short = 'R', long)]
        recursive:    bool,
        /// Folder path or UID, or a name filter for the current folder
        #[arg(default_value_t, hide_default_value = true)]
        pattern:      String,
    },
    /// Change current folder (shell only)
    Cd {
        #[arg(default_value = "/")]
        folder: String,
    },
    /// Display the folder structure
    Tree {
        /// Include records
        #[arg(short, long)]
        records: bool,
        /// Show UIDs
        #[arg(short, long)]
        verbose: bool,
        #[arg(default_value = "/")]
        folder:  String,
    },
    /// List records
    #[command(visible_alias = "l")]
    List {
        /// Filter by record type (repeatable)
        #[arg(short = 't', long = "type")]
        record_type: Vec<String>,
        #[arg(short, long)]
        verbose:     bool,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format:      Format,
        /// Search terms; every term must match
        pattern:     Vec<String>,
    },
    /// Search records, shared folders and teams
    #[command(visible_alias = "s")]
    Search {
        #[arg(short, long)]
        verbose: bool,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format:  Format,
        pattern: Vec<String>,
    },
    /// Show a record, folder, shared folder or team
    #[command(visible_alias = "g")]
    Get {
        /// Show hidden field values
        #[arg(long)]
        unmask: bool,
        #[arg(long, value_enum, default_value_t = DetailFormat::Detail)]
        format: DetailFormat,
        /// UID, or record path/title
        uid:    String,
    },
    /// List shared folders
    #[command(name = "list-sf", visible_alias = "lsf")]
    ListSf {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format:  Format,
        pattern: Vec<String>,
    },
    /// List teams
    #[command(name = "list-team", visible_alias = "lt")]
    ListTeam {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// Show the current TOTP code of a record, or list records that have one
    Totp {
        #[arg(long)]
        details: bool,
        record:  Option<String>,
    },
    /// Generate passwords
    Generate {
        /// Password length [default: 20, or the length given in --rules]
        #[arg(short = 'c', long = "count")]
        length:    Option<usize>,
        /// Number of passwords
        #[arg(short, long, default_value_t = 1)]
        number:    usize,
        /// "[length,] upper, lower, digits, symbols" minimum counts
        #[arg(short, long)]
        rules:     Option<String>,
        /// Minimum symbols, 0 for none
        #[arg(short, long, allow_negative_numbers = true)]
        symbols:   Option<i32>,
        /// Minimum digits, 0 for none
        #[arg(short, long, allow_negative_numbers = true)]
        digits:    Option<i32>,
        /// Minimum uppercase letters, 0 for none
        #[arg(short, long, allow_negative_numbers = true)]
        uppercase: Option<i32>,
        /// Minimum lowercase letters, 0 for none
        #[arg(short, long, allow_negative_numbers = true)]
        lowercase: Option<i32>,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format:    Format,
    },
    /// Show this device's login settings, or change them
    #[command(name = "this-device")]
    ThisDevice {
        #[command(subcommand)]
        action: Option<DeviceAction>,
    },
    /// Start the interactive shell
    Shell,
    /// Leave the shell
    #[command(visible_alias = "quit", hide = true)]
    Exit,
}

#[derive(Subcommand, Debug)]
pub enum DeviceAction {
    /// Store an encrypted copy of the data key for this device
    Register,
    /// Turn "Stay Logged In" on or off; "on" lets commands run without the master password
    #[command(name = "persistent-login", visible_alias = "pl")]
    PersistentLogin { state: Toggle },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toggle {
    On,
    Off,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DetailFormat {
    Detail,
    Json,
}
