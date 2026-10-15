//! Command implementations. Each command is its clap argument struct plus a [`Run`] impl; the
//! [`App`] carries settings and an authenticated account with its session, vault and current folder.

pub mod folders;
pub mod generate;
pub mod records;
pub mod session;

use serde_json::Value;

use crate::auth::{self, Password, Session};
use crate::cli::{Command, Format};
use crate::prelude::*;
use crate::settings::Settings;
use crate::vault::{self, Location, Vault};

pub trait Run {
    fn run(self, app: &mut App) -> Result<()>;
}

pub struct App {
    pub(crate) settings: Settings,
    /// `--user`, which beats the account remembered in the settings.
    pub(crate) user:     Option<String>,
    pub(crate) password: Password,
    pub(crate) account:  Option<Account>,
}

pub(crate) struct Account {
    pub(crate) session: Session,
    pub(crate) vault:   Option<Vault>,
    pub(crate) cwd:     Location,
}

impl From<Session> for Account {
    fn from(session: Session) -> Self {
        Self {
            session,
            vault: None,
            cwd: Location::Root,
        }
    }
}

/// The synced vault together with the current folder, borrowed at once.
pub struct View<'a> {
    pub vault: &'a Vault,
    pub cwd:   &'a Location,
}

impl App {
    pub fn run(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Login(c) => c.run(self),
            Command::Logout(c) => c.run(self),
            Command::Whoami(c) => c.run(self),
            Command::SyncDown(c) => c.run(self),
            Command::Ls(c) => c.run(self),
            Command::Cd(c) => c.run(self),
            Command::Tree(c) => c.run(self),
            Command::List(c) => c.run(self),
            Command::Search(c) => c.run(self),
            Command::Get(c) => c.run(self),
            Command::ListSf(c) => c.run(self),
            Command::ListTeam(c) => c.run(self),
            Command::Totp(c) => c.run(self),
            Command::Generate(c) => c.run(self),
            Command::RecordAdd(c) => c.run(self),
            Command::RecordUpdate(c) => c.run(self),
            Command::AppendNotes(c) => c.run(self),
            Command::Rm(c) => c.run(self),
            Command::Mkdir(c) => c.run(self),
            Command::Rmdir(c) => c.run(self),
            Command::Rndir(c) => c.run(self),
            Command::Mv(c) => c.run(self),
            Command::DownloadAttachment(c) => c.run(self),
            Command::UploadAttachment(c) => c.run(self),
            Command::ClipboardCopy(c) => c.run(self),
            Command::FindPassword(c) => c.run(self),
            Command::ThisDevice(c) => c.run(self),
            Command::Shell | Command::Exit => Ok(()),
        }
    }

    pub fn prompt(&self) -> String {
        let name = self
            .account
            .as_ref()
            .and_then(|account| account.vault.as_ref().map(|vault| vault.name_of(&account.cwd)))
            .unwrap_or("My Vault");
        format!("{name}> ")
    }

    /// `--user`, else the remembered account, else ask.
    pub(crate) fn default_user(&self) -> Result<String> {
        match self.user.clone().or_else(|| self.settings.user.clone()) {
            Some(user) => Ok(user),
            None => {
                match auth::prompt("Email: ")? {
                    user if user.is_empty() => Err(Error::Cancelled),
                    user => Ok(user),
                }
            }
        }
    }

    pub(crate) fn login(&mut self, user: String) -> Result<()> {
        let password = std::mem::replace(&mut self.password, Password::Prompt);
        let session = auth::login(&mut self.settings, user, password)?;
        eprintln!("Logged in as {}", session.user);
        self.account = Some(session.into());
        self.sync()
    }

    pub(crate) fn sync(&mut self) -> Result<()> {
        let account = self.account.as_mut().ok_or(Error::NotLoggedIn)?;
        account.vault = None;
        let vault = vault::sync_down(&mut account.session)?;
        eprintln!("Decrypted {} records.", vault.records.len());
        if vault.folder(&account.cwd).is_none() {
            account.cwd = Location::Root;
        }
        account.vault = Some(vault);
        Ok(())
    }

    pub(crate) fn ensure_synced(&mut self) -> Result<()> {
        match self.account.as_ref() {
            None => {
                let user = self.default_user()?;
                self.login(user)
            }
            Some(Account { vault: None, .. }) => self.sync(),
            Some(Account { vault: Some(_), .. }) => Ok(()),
        }
    }

    pub fn view(&mut self) -> Result<View<'_>> {
        self.ensure_synced()?;
        let account = self.account.as_ref().ok_or(Error::NotLoggedIn)?;
        Ok(View {
            vault: account.vault.as_ref().ok_or(Error::NotLoggedIn)?,
            cwd:   &account.cwd,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    Compact,
    Full,
}

impl From<bool> for Detail {
    fn from(verbose: bool) -> Self {
        if verbose { Self::Full } else { Self::Compact }
    }
}
/// Rows with snake_case column keys: JSON objects keyed by them, or a numbered text table
/// titled from them.
pub struct Table {
    columns: &'static [&'static str],
    rows:    Vec<Vec<String>>,
}

impl Table {
    pub fn new(columns: &'static [&'static str]) -> Self {
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    pub fn push(&mut self, row: Vec<String>) {
        debug_assert_eq!(row.len(), self.columns.len());
        self.rows.push(row);
    }

    pub fn print(&self, format: Format) {
        match format {
            Format::Table => print!("{self}"),
            Format::Json => println!("{}", Value::from(self)),
        }
    }
}

impl From<&Table> for Value {
    fn from(table: &Table) -> Self {
        Value::Array(
            table
                .rows
                .iter()
                .map(|row| {
                    Value::Object(
                        table
                            .columns
                            .iter()
                            .zip(row)
                            .map(|(column, value)| ((*column).to_owned(), Value::String(value.clone())))
                            .collect(),
                    )
                })
                .collect(),
        )
    }
}

impl Extend<Vec<String>> for Table {
    fn extend<I: IntoIterator<Item = Vec<String>>>(&mut self, rows: I) {
        for row in rows {
            debug_assert_eq!(row.len(), self.columns.len());
            self.rows.push(row);
        }
    }
}

impl std::fmt::Display for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rows.is_empty() {
            return writeln!(f, "No results");
        }
        let headers: Vec<String> = self
            .columns
            .iter()
            .map(|column| ColumnTitle(column).to_string())
            .collect();
        let widths: Vec<usize> = headers
            .iter()
            .enumerate()
            .map(|(column, header)| {
                self.rows
                    .iter()
                    .map(|row| row[column].chars().count())
                    .chain([header.chars().count()])
                    .max()
                    .unwrap_or_default()
            })
            .collect();
        let number_width = self.rows.len().to_string().len();
        write!(f, "{:<number_width$}", "#")?;
        for (column, header) in headers.iter().enumerate() {
            if column + 1 == headers.len() {
                write!(f, "  {header}")?;
            } else {
                write!(f, "  {header:<width$}", width = widths[column])?;
            }
        }
        writeln!(f)?;
        write!(f, "{:-<number_width$}", "")?;
        for width in &widths {
            write!(f, "  {:-<width$}", "")?;
        }
        writeln!(f)?;
        for (index, row) in self.rows.iter().enumerate() {
            write!(f, "{:<number_width$}", index + 1)?;
            for (column, cell) in row.iter().enumerate() {
                if column + 1 == row.len() {
                    write!(f, "  {cell}")?;
                } else {
                    write!(f, "  {cell:<width$}", width = widths[column])?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

/// `shared_folder_uid` renders as `Shared Folder UID`.
struct ColumnTitle<'a>(&'a str);

impl std::fmt::Display for ColumnTitle<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let words: Vec<String> = self
            .0
            .split('_')
            .map(|w| {
                match w {
                    "uid" => "UID".to_owned(),
                    w => {
                        let mut c = w.chars();
                        c.next()
                            .map(|first| first.to_uppercase().chain(c).collect())
                            .unwrap_or_default()
                    }
                }
            })
            .collect();
        f.write_str(&words.join(" "))
    }
}

/// Right-aligned `label: value`, continuing multi-line values under the value column.
pub struct DetailLine<'a>(pub &'a str, pub &'a str);

impl std::fmt::Display for DetailLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lines = self.1.lines();
        writeln!(f, "{:>20}: {}", self.0, lines.next().unwrap_or_default())?;
        for line in lines {
            writeln!(f, "{:>20}  {line}", "")?;
        }
        Ok(())
    }
}

/// Truncates to `width` characters with a trailing ellipsis, as Commander's tables do.
pub struct Clipped<'a>(pub &'a str, pub usize);

impl std::fmt::Display for Clipped<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(text, width) = *self;
        if text.chars().count() <= width {
            f.write_str(text)
        } else {
            let kept: String = text.chars().take(width.saturating_sub(3)).collect();
            write!(f, "{kept}...")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipped_counts_characters_not_bytes() {
        assert_eq!(Clipped("héllo wörld", 8).to_string(), "héllo...");
        assert_eq!(Clipped("short", 8).to_string(), "short");
    }
}
