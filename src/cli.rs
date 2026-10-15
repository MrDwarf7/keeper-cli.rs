//! Command-line surface. Names, aliases and flags follow Commander so muscle memory carries
//! over; each subcommand's arguments are their own struct in `commands`.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::commands::folders::{Cd, Ls, Tree};
use crate::commands::generate::Generate;
use crate::commands::records::{Get, List, ListSf, ListTeam, Search, Totp};
use crate::commands::session::{Login, Logout, SyncDown, ThisDevice, Whoami};

#[derive(Parser, Debug)]
#[command(
    name = "keeper-cli",
    version,
    about = "Keeper Password Manager CLI (Rust port of Keeper Commander's core)"
)]
pub struct Cli {
    /// Config file
    #[arg(long, global = true, env = "KEEPER_CONFIG_FILE", default_value_os_t = crate::settings::default_path())]
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
    Login(Login),
    /// End the session and forget this device's persistent login
    Logout(Logout),
    /// Show the logged-in account
    Whoami(Whoami),
    /// Download and decrypt the vault again
    SyncDown(SyncDown),
    /// List folder contents
    Ls(Ls),
    /// Change current folder (shell only)
    Cd(Cd),
    /// Display the folder structure
    Tree(Tree),
    /// List records
    #[command(visible_alias = "l")]
    List(List),
    /// Search records, shared folders and teams
    #[command(visible_alias = "s")]
    Search(Search),
    /// Show a record, folder, shared folder or team
    #[command(visible_alias = "g")]
    Get(Get),
    /// List shared folders
    #[command(name = "list-sf", visible_alias = "lsf")]
    ListSf(ListSf),
    /// List teams
    #[command(name = "list-team", visible_alias = "lt")]
    ListTeam(ListTeam),
    /// Show the current TOTP code of a record, or list records that have one
    Totp(Totp),
    /// Generate passwords
    Generate(Generate),
    /// Create a typed vault record
    #[command(name = "record-add", visible_alias = "ra")]
    RecordAdd(crate::record_edit::RecordAdd),
    /// Edit a typed vault record
    #[command(name = "record-update", visible_alias = "ru")]
    RecordUpdate(crate::record_edit::RecordUpdate),
    /// Append notes to a record
    #[command(name = "append-notes", visible_alias = "an")]
    AppendNotes(crate::record_edit::AppendNotes),
    /// Remove records or their folder links
    Rm(crate::record_edit::Rm),
    /// Create a private or shared folder
    Mkdir(crate::folder_edit::Mkdir),
    /// Remove folders
    Rmdir(crate::folder_edit::Rmdir),
    /// Rename a folder
    Rndir(crate::folder_edit::Rndir),
    /// Move records or folders
    Mv(crate::folder_edit::Mv),
    /// Download record attachments
    #[command(name = "download-attachment", visible_alias = "da")]
    DownloadAttachment(crate::attachment::DownloadAttachment),
    /// Upload attachments to a typed record
    #[command(name = "upload-attachment", visible_alias = "ua")]
    UploadAttachment(crate::attachment::UploadAttachment),
    /// Copy a record field to the clipboard or stdout
    #[command(name = "clipboard-copy", visible_alias = "cc")]
    ClipboardCopy(crate::clipboard::ClipboardCopy),
    /// Print a record password to stdout
    #[command(name = "find-password")]
    FindPassword(crate::clipboard::FindPassword),
    /// Show this device's login settings, or change them
    #[command(name = "this-device")]
    ThisDevice(ThisDevice),
    /// Start the interactive shell
    Shell,
    /// Leave the shell
    #[command(visible_alias = "quit", hide = true)]
    Exit,
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
