//! Folder write commands: `mkdir`, `rmdir`, `rndir` and `mv`.
//!
//! Keeper still takes these as legacy JSON ("v2") commands, so the key work happens here: a new
//! folder gets a random key wrapped by the data key (or by its shared folder's key), its name and
//! data are encrypted with that key, and a move carries `transition_keys` that re-wrap whatever
//! crosses between the data key and a shared folder.

use std::ffi::OsString;
use std::fmt;
use std::str::FromStr;

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{self, Session};
use crate::commands::{App, Run, resolve_folder};
use crate::crypto;
use crate::prelude::*;
use crate::vault::{Folder, FolderKind, Record, Vault};

/// Commander puts at most this many items in one `move` and asks for the command to be repeated.
const MOVE_LIMIT: usize = 991;

/// Create a folder
#[derive(Args, Debug)]
pub struct Mkdir {
    /// Create a shared folder (Commander's -sf)
    #[arg(long)]
    shared_folder: bool,
    /// Create a user folder (Commander's -uf)
    #[arg(long)]
    user_folder:   bool,
    #[command(flatten)]
    grant:         Grant,
    /// Folder color
    #[arg(long, value_enum)]
    color:         Option<Color>,
    /// Folder path
    folder:        Option<String>,
}

/// Remove a folder and its contents
#[derive(Args, Debug)]
pub struct Rmdir {
    /// Remove without prompting
    #[arg(short, long)]
    force:   bool,
    /// With --force, remove without showing folder info
    #[arg(short, long)]
    quiet:   bool,
    /// Folder paths, UIDs or name patterns
    pattern: Vec<String>,
}

/// Rename a folder or change its color
#[derive(Args, Debug)]
pub struct Rndir {
    /// New folder name
    #[arg(short, long)]
    name:   Option<String>,
    /// Folder color
    #[arg(long, value_enum)]
    color:  Option<Color>,
    /// Rename without showing folder info
    #[arg(short, long)]
    quiet:  bool,
    /// Folder path or UID
    folder: Option<String>,
}

/// Move a record or folder to another folder
#[derive(Args, Debug)]
pub struct Mv {
    /// Accepted for Commander compatibility; moving never prompts
    #[arg(short = 'f', long = "force")]
    _force:        bool,
    #[command(flatten)]
    share:         Share,
    /// Apply the name pattern to shared folders
    #[arg(long, conflicts_with = "user_folder")]
    shared_folder: bool,
    /// Apply the name pattern to user folders
    #[arg(long)]
    user_folder:   bool,
    /// Record or folder: path, UID or name pattern
    src:           String,
    /// Destination folder: path or UID
    dst:           String,
}

/// Default permissions of a new shared folder.
#[derive(Args, Clone, Copy, Debug)]
struct Grant {
    /// Anyone has all permissions by default
    #[arg(short = 'a', long)]
    all:            bool,
    /// Anyone can manage users by default
    #[arg(short = 'u', long)]
    manage_users:   bool,
    /// Anyone can manage records by default
    #[arg(short = 'r', long)]
    manage_records: bool,
    /// Anyone can share records by default
    #[arg(short = 's', long)]
    can_share:      bool,
    /// Anyone can edit records by default
    #[arg(short = 'e', long)]
    can_edit:       bool,
}

/// What `mv` lets everyone do with records it moves into a shared folder.
#[derive(Args, Clone, Copy, Debug, Default, Serialize)]
struct Share {
    /// Anyone can re-share the records
    #[arg(short = 's', long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_reshare: bool,
    /// Anyone can edit the records
    #[arg(short = 'e', long)]
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_edit:    bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Color {
    /// Remove the color
    #[value(name = "none")]
    Off,
    Red,
    Green,
    Blue,
    Orange,
    Yellow,
    Gray,
}

impl Run for Mkdir {
    fn run(self, app: &mut App) -> Result<()> {
        let Self {
            shared_folder,
            user_folder,
            grant,
            color,
            folder,
        } = self;
        let wanted = match (shared_folder, user_folder) {
            (true, _) => Wanted::Shared(grant.into()),
            (false, true) => Wanted::User,
            (false, false) => Wanted::Unspecified,
        };
        let tint = Tint::from(color);
        let (session, vault, cwd) = connect(app)?;

        let (parent, mut name) = match folder.as_deref().filter(|f| !f.trim().is_empty()) {
            // A blank name is asked for once the kind of folder is settled, as Commander does.
            None => (cwd.to_owned(), String::new()),
            Some(path) => {
                match locate(vault, cwd, path) {
                    Target::Folder(_) => {
                        eprintln!("mkdir: Folder \"{path}\" already exists");
                        return Ok(());
                    }
                    Target::Within { parent, name } => (parent, name),
                    Target::Missing => {
                        return Err(Error::Generic(format!("mkdir: The folder part of \"{path}\" does not exist")));
                    }
                }
            }
        };
        let base = Place::from(vault.folders.get(&parent));
        let home = Realm::try_from((vault, base))?;
        let kind = match (wanted, home) {
            (Wanted::Shared(_), Realm::Shared { .. }) => {
                return Err(Error::Generic("mkdir: Shared folders cannot be nested".into()));
            }
            (Wanted::Shared(perms), Realm::Private) => Kind::Shared(perms),
            (Wanted::User | Wanted::Unspecified, Realm::Shared { uid, .. }) => Kind::Nested { shared_folder: uid },
            (Wanted::User, Realm::Private) => Kind::User,
            (Wanted::Unspecified, Realm::Private) => {
                if ask::<Answer>("Do you want to create a shared folder? [y/n]: ")? == Answer::Yes {
                    Kind::Shared(ask(
                        "Default user permissions: (A)ll | Manage (U)sers / (R)ecords; Can (E)dit / (S)hare records? \
                         [a/u/r/e/s]: ",
                    )?)
                } else {
                    Kind::User
                }
            }
        };

        while name.trim().is_empty() {
            name = ask::<FolderName>("... Folder Name: ")?.0;
        }
        let name = name.trim();
        let uid = b64_encode(&crypto::random_bytes(16));
        let key = crypto::random_bytes(32);
        let wrapper = match home {
            Realm::Private => session.data_key.as_slice(),
            Realm::Shared { key, .. } => key,
        };
        let request = Request::try_from(&NewFolder {
            uid: &uid,
            key: &key,
            wrapper,
            name,
            tint,
            kind,
            parent: base,
        })?;
        session.execute_v2(serde_json::to_value(request)?)?;

        let path = format!("{}{name}", Trail(vault, &parent));
        println!("{}", json!({ "folder_uid": uid, "name": name, "path": path }));
        app.vault = None;
        Ok(())
    }
}

impl Run for Rmdir {
    fn run(self, app: &mut App) -> Result<()> {
        let Self { force, quiet, pattern } = self;
        let confirm = Confirm::from(force);
        // Commander only stays quiet when it is also told not to ask.
        let report = Report::from(force && quiet);
        let (session, vault, cwd) = connect(app)?;

        let mut doomed: Vec<&Folder> = Vec::new();
        for pattern in &pattern {
            let found: Vec<&Folder> = match locate(vault, cwd, pattern) {
                Target::Folder(uid) => {
                    match vault.folders.get(&uid) {
                        Some(folder) => vec![folder],
                        None => return Err(Error::Generic("rmdir: The root folder cannot be removed".into())),
                    }
                }
                Target::Within { parent, name } => {
                    let glob = Glob::new(&name, Case::Exact);
                    vault
                        .subfolders_of(&parent)
                        .iter()
                        .filter_map(|uid| vault.folders.get(uid))
                        .filter(|f| glob.is_match(&f.name) || glob.is_match(&f.uid))
                        .collect()
                }
                Target::Missing => Vec::new(),
            };
            if found.is_empty() {
                eprintln!("Folder \"{pattern}\" was not found.");
            }
            for folder in found {
                if doomed.iter().all(|d| d.uid != folder.uid) {
                    doomed.push(folder);
                }
            }
        }
        if doomed.is_empty() {
            return Err(Error::Generic("rmdir: Enter name of an existing folder.".into()));
        }

        if report == Report::Show {
            let names: Vec<String> = doomed.iter().map(|f| Trail(vault, &f.uid).to_string()).collect();
            println!("\nThe following user folder(s) will be removed:\n{}", names.join(", "));
        }
        let objects = doomed.iter().map(|&f| Deletion::from((vault, f))).collect();
        let pre_delete = session.execute_v2(serde_json::to_value(Request::PreDelete { objects })?)?;
        let PreDeleted {
            pre_delete_response: Pending {
                pre_delete_token,
                would_delete,
            },
        } = serde_json::from_value(pre_delete)?;
        if report == Report::Show {
            for line in &would_delete.deletion_summary {
                println!("{line}");
            }
        }
        if confirm == Confirm::Ask
            && ask::<Answer>("\nDo you want to proceed with the user folder deletion? [y/n]: ")? == Answer::No
        {
            return Ok(());
        }
        session.execute_v2(serde_json::to_value(Request::Delete { pre_delete_token })?)?;
        app.vault = None;
        Ok(())
    }
}

impl Run for Rndir {
    fn run(self, app: &mut App) -> Result<()> {
        let Self {
            name,
            color,
            quiet,
            folder,
        } = self;
        let edit = Edit {
            name: name.into(),
            tint: color.into(),
        };
        if edit == Edit::default() {
            return Err(Error::Generic("New folder name and/or color parameters are required.".into()));
        }
        let Some(path) = folder else {
            return Err(Error::Generic("Enter the path or UID of existing folder.".into()));
        };
        let report = Report::from(quiet);
        let (session, vault, cwd) = connect(app)?;

        let Target::Folder(uid) = locate(vault, cwd, &path) else {
            return Err(Error::Generic(format!("Folder {path} not found")));
        };
        let Some(folder) = vault.folders.get(&uid) else {
            return Err(Error::Generic("rndir: The root folder cannot be renamed".into()));
        };
        let request = Request::try_from((folder, &edit))?;
        session.execute_v2(serde_json::to_value(request)?)?;
        if report == Report::Show
            && let Rename::To(new) = &edit.name
        {
            eprintln!("Folder \"{}\" has been renamed to \"{new}\"", folder.name);
        }
        app.vault = None;
        Ok(())
    }
}

impl Run for Mv {
    fn run(self, app: &mut App) -> Result<()> {
        let Self {
            share,
            shared_folder,
            user_folder,
            src,
            dst,
            ..
        } = self;
        let matching = match (shared_folder, user_folder) {
            (true, _) => Match::SharedFolders,
            (false, true) => Match::UserFolders,
            (false, false) => Match::Records,
        };
        let (session, vault, cwd) = connect(app)?;

        let Some(dst) = resolve_folder(vault, cwd, &dst) else {
            return Err(Error::Generic("mv: Destination path should be existing folder".into()));
        };
        let mut sources = selected(vault, cwd, &src, &dst, matching)?;
        if sources.len() > MOVE_LIMIT {
            eprintln!("The command limit has been reached. Please repeat this command to resume operation.");
            sources.truncate(MOVE_LIMIT);
        }
        let request = Request::try_from(&Relocation {
            vault,
            data_key: &session.data_key,
            dst: Place::from(vault.folders.get(&dst)),
            sources: &sources,
            share,
        })?;
        session.execute_v2(serde_json::to_value(request)?)?;
        app.vault = None;
        Ok(())
    }
}

/// Clap has no multi-letter short options, so Commander's `mkdir -sf` and `-uf` are rewritten to
/// their long forms before parsing.
pub fn expand_legacy_flags<T: Into<OsString>>(args: impl IntoIterator<Item = T>) -> Vec<OsString> {
    let mut in_mkdir = false;
    args.into_iter()
        .map(|arg| {
            let arg = arg.into();
            match arg.to_str() {
                Some("mkdir") => in_mkdir = true,
                Some("-sf") if in_mkdir => return "--shared-folder".into(),
                Some("-uf") if in_mkdir => return "--user-folder".into(),
                _ => {}
            }
            arg
        })
        .collect()
}

/// The logged-in session, a synced vault and the shell's current folder. Commands that change
/// the vault set `app.vault = None` afterwards so the next one downloads the result, as
/// Commander syncs after every write.
fn connect(app: &mut App) -> Result<(&mut Session, &Vault, &str)> {
    app.vault()?;
    match (app.session.as_mut(), app.vault.as_ref()) {
        (Some(session), Some(vault)) => Ok((session, vault, &app.cwd)),
        _ => Err(Error::NotLoggedIn),
    }
}

/// What `mkdir` was asked to create.
#[derive(Clone, Copy, Debug)]
enum Wanted {
    Shared(Perms),
    User,
    /// Neither flag: inside a shared folder this is a subfolder, elsewhere the user is asked.
    Unspecified,
}

/// What `mkdir` will create.
#[derive(Clone, Copy, Debug)]
enum Kind<'a> {
    User,
    Shared(Perms),
    /// A folder inside the shared folder with this UID.
    Nested {
        shared_folder: &'a str,
    },
}

/// Default permissions of a shared folder; only the granted ones go on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct Perms {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    manage_users:   bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    manage_records: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_share:      bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    can_edit:       bool,
}

impl Perms {
    const ALL: Self = Self {
        manage_users:   true,
        manage_records: true,
        can_share:      true,
        can_edit:       true,
    };
}

impl From<Grant> for Perms {
    fn from(grant: Grant) -> Self {
        Self {
            manage_users:   grant.all || grant.manage_users,
            manage_records: grant.all || grant.manage_records,
            can_share:      grant.all || grant.can_share,
            can_edit:       grant.all || grant.can_edit,
        }
    }
}

/// The letters of Commander's prompt: (A)ll, manage (U)sers / (R)ecords, can (E)dit / (S)hare.
impl FromStr for Perms {
    type Err = Error;

    fn from_str(letters: &str) -> Result<Self> {
        let mut perms = Self::default();
        for letter in letters.trim().chars() {
            match letter.to_ascii_lowercase() {
                'a' => perms = Self::ALL,
                'u' => perms.manage_users = true,
                'r' => perms.manage_records = true,
                'e' => perms.can_edit = true,
                's' => perms.can_share = true,
                _ => return Err(Error::Generic("invalid input".into())),
            }
        }
        Ok(perms)
    }
}

/// A folder name typed at the prompt: `//` is a literal slash, a lone `/` is reserved for paths.
struct FolderName(String);

impl FromStr for FolderName {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let masked = text.trim().replace("//", "\0");
        if masked.contains('/') {
            return Err(Error::Generic("mkdir: Character \"/\" is reserved. Use \"//\" inside folder name".into()));
        }
        Ok(Self(masked.replace('\0', "/")))
    }
}

/// A `[y/n]` reply; nothing means no.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
}

impl FromStr for Answer {
    type Err = Error;

    fn from_str(reply: &str) -> Result<Self> {
        match reply.trim().to_ascii_lowercase().as_str() {
            "y" => Ok(Self::Yes),
            "" | "n" => Ok(Self::No),
            _ => Err(Error::Generic("invalid input".into())),
        }
    }
}

/// Prompts until the reply parses.
fn ask<T>(question: &str) -> Result<T>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    loop {
        match auth::prompt(question)?.parse() {
            Ok(answer) => return Ok(answer),
            Err(e) => eprintln!("Error: {e}"),
        }
    }
}

/// A folder about to be created.
struct NewFolder<'a> {
    uid:     &'a str,
    /// The folder's own key.
    key:     &'a [u8],
    /// Wraps `key`: the data key, or the key of the shared folder it goes into.
    wrapper: &'a [u8],
    name:    &'a str,
    tint:    Tint,
    kind:    Kind<'a>,
    parent:  Place<'a>,
}

impl TryFrom<&NewFolder<'_>> for Request {
    type Error = Error;

    fn try_from(new: &NewFolder<'_>) -> Result<Self> {
        let mut data = json!({ "name": new.name });
        new.tint.apply(&mut data);
        let (folder_type, name, shared_folder_uid, perms) = match new.kind {
            Kind::User => (Node::UserFolder, None, None, Perms::default()),
            // A shared folder also carries its name apart from its data.
            Kind::Shared(perms) => (Node::SharedFolder, Some(Sealed::cbc(new.name.as_bytes(), new.key)?), None, perms),
            Kind::Nested { shared_folder } => {
                (Node::SharedFolderFolder, None, Some(shared_folder.to_owned()), Perms::default())
            }
        };
        Ok(Self::FolderAdd {
            folder_uid: new.uid.to_owned(),
            folder_type,
            key: Sealed::cbc(new.key, new.wrapper)?,
            data: Sealed::cbc(data.to_string().as_bytes(), new.key)?,
            name,
            // A shared folder's direct children name it through `shared_folder_uid` instead.
            parent_uid: match new.parent {
                Place::In(parent) if parent.kind != FolderKind::SharedFolder => Some(parent.uid.clone()),
                Place::In(_) | Place::Root => None,
            },
            shared_folder_uid,
            perms,
        })
    }
}

/// Whether to ask before deleting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Confirm {
    Ask,
    Skip,
}

impl From<bool> for Confirm {
    fn from(force: bool) -> Self {
        if force { Self::Skip } else { Self::Ask }
    }
}

/// Whether to print what a command is about to do or has done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Report {
    Show,
    Hide,
}

impl From<bool> for Report {
    fn from(quiet: bool) -> Self {
        if quiet { Self::Hide } else { Self::Show }
    }
}

/// How a deleted object is handled; Commander only ever unlinks.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Resolution {
    Unlink,
}

#[derive(Debug, Serialize)]
struct Deletion {
    delete_resolution: Resolution,
    object_uid:        String,
    object_type:       Node,
    #[serde(flatten)]
    origin:            Origin,
}

impl From<(&Vault, &Folder)> for Deletion {
    fn from((vault, folder): (&Vault, &Folder)) -> Self {
        let mut origin = Origin::from(Place::from(folder.parent.as_deref().and_then(|uid| vault.folders.get(uid))));
        // Unlike `mv`, a delete files the direct children of a shared folder under their own type.
        if origin.from_type == Node::SharedFolder {
            origin.from_type = Node::SharedFolderFolder;
        }
        Self {
            delete_resolution: Resolution::Unlink,
            object_uid: folder.uid.clone(),
            object_type: folder.kind.into(),
            origin,
        }
    }
}

/// The server's answer to `pre_delete`: what would go, and the token that confirms it.
#[derive(Deserialize)]
struct PreDeleted {
    pre_delete_response: Pending,
}

#[derive(Deserialize)]
struct Pending {
    pre_delete_token: String,
    #[serde(default)]
    would_delete:     WouldDelete,
}

#[derive(Default, Deserialize)]
struct WouldDelete {
    #[serde(default)]
    deletion_summary: Vec<String>,
}

/// A new name for a folder, or none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Rename {
    #[default]
    Keep,
    To(String),
}

impl From<Option<String>> for Rename {
    fn from(name: Option<String>) -> Self {
        name.map_or(Self::Keep, Self::To)
    }
}

/// What to do with a folder's `color`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Tint {
    #[default]
    Keep,
    Clear,
    Paint(Color),
}

impl From<Option<Color>> for Tint {
    fn from(color: Option<Color>) -> Self {
        match color {
            None => Self::Keep,
            Some(Color::Off) => Self::Clear,
            Some(color) => Self::Paint(color),
        }
    }
}

impl Tint {
    fn apply(self, data: &mut Value) {
        match self {
            Self::Keep => {}
            Self::Clear => {
                if let Some(fields) = data.as_object_mut() {
                    fields.remove("color");
                }
            }
            Self::Paint(color) => data["color"] = json!(color),
        }
    }
}

/// A change to a folder's data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Edit {
    name: Rename,
    tint: Tint,
}

impl TryFrom<(&Folder, &Edit)> for Request {
    type Error = Error;

    fn try_from((folder, edit): (&Folder, &Edit)) -> Result<Self> {
        if folder.key.is_empty() {
            return Err(Error::Generic(format!(
                "The key of folder {} is not available, so it cannot be changed",
                folder.uid
            )));
        }
        // Everything else in the folder's data (a color set elsewhere, say) must survive.
        let mut data = if folder.data.is_object() {
            folder.data.clone()
        } else {
            json!({})
        };
        if let Rename::To(name) = &edit.name {
            data["name"] = json!(name);
        }
        edit.tint.apply(&mut data);

        let (name, shared_folder_uid) = match folder.kind {
            FolderKind::User => (None, None),
            FolderKind::SharedFolder => {
                let name = match &edit.name {
                    Rename::To(name) => name,
                    Rename::Keep => &folder.name,
                };
                (Some(Sealed::cbc(name.as_bytes(), &folder.key)?), Some(folder.uid.clone()))
            }
            FolderKind::SharedFolderFolder => (None, folder.shared_folder_uid.clone()),
        };
        Ok(Self::FolderUpdate {
            folder_uid: folder.uid.clone(),
            folder_type: folder.kind.into(),
            data: Sealed::cbc(data.to_string().as_bytes(), &folder.key)?,
            name,
            shared_folder_uid,
        })
    }
}

/// What a name pattern given to `mv` selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Match {
    Records,
    SharedFolders,
    UserFolders,
}

/// One thing to move.
#[derive(Debug, PartialEq, Eq)]
enum Source {
    Folder(String),
    Record {
        uid:  String,
        /// The folder the record is taken out of (`""` is the root).
        from: String,
    },
}

/// Resolves what `mv` was told to move, the way Commander does: a record UID, a folder UID or
/// path, or a name pattern that selects records (or folders, when asked) inside a folder.
fn selected(vault: &Vault, cwd: &str, src: &str, dst: &str, matching: Match) -> Result<Vec<Source>> {
    let same = || Error::Generic("mv: Source and Destination folders are the same".into());
    if vault.records.contains_key(src) {
        let from = home_of(vault, cwd, src);
        if from == dst {
            return Err(same());
        }
        return Ok(vec![Source::Record {
            uid: src.to_owned(),
            from,
        }]);
    }
    match locate(vault, cwd, src) {
        Target::Folder(uid) if uid == dst => Err(same()),
        Target::Folder(uid) => Ok(vec![Source::Folder(uid)]),
        Target::Missing => Err(Error::Generic("mv: Source path should be existing record or folder".into())),
        Target::Within { parent, .. } if parent == dst => Err(same()),
        Target::Within { parent, name } => {
            let glob = Glob::new(&name, Case::Ignore);
            let found: Vec<Source> = match matching {
                Match::Records => {
                    vault
                        .records_in(&parent)
                        // Only password and typed records are matched by title, like Commander.
                        .filter(|r| r.uid == name || (matches!(r.version, 2 | 3) && glob.is_match(r.title())))
                        .map(|r| {
                            Source::Record {
                                uid:  r.uid.clone(),
                                from: parent.clone(),
                            }
                        })
                        .collect()
                }
                Match::SharedFolders | Match::UserFolders => {
                    let shared = matching == Match::SharedFolders;
                    vault
                        .subfolders_of(&parent)
                        .iter()
                        .filter_map(|uid| vault.folders.get(uid))
                        .filter(|f| (f.kind == FolderKind::SharedFolder) == shared && glob.is_match(&f.name))
                        .map(|f| Source::Folder(f.uid.clone()))
                        .collect()
                }
            };
            if found.is_empty() {
                Err(Error::Generic(format!("mv: Record \"{name}\" not found")))
            } else {
                Ok(found)
            }
        }
    }
}

/// The folder `mv` takes a record from when it is named by UID: the current folder if it holds
/// the record, else the first other folder that does, else the root.
fn home_of(vault: &Vault, cwd: &str, record: &str) -> String {
    let holds = |folder: &str| vault.folder_records.get(folder).is_some_and(|set| set.contains(record));
    if holds(cwd) {
        return cwd.to_owned();
    }
    vault
        .folder_records
        .iter()
        .filter(|(folder, set)| !folder.is_empty() && set.contains(record))
        .map(|(folder, _)| folder.clone())
        .min()
        .unwrap_or_default()
}

/// Everything `move` needs to know to build the request.
#[derive(Clone, Copy)]
struct Relocation<'a> {
    vault:    &'a Vault,
    data_key: &'a [u8],
    dst:      Place<'a>,
    sources:  &'a [Source],
    share:    Share,
}

impl TryFrom<&Relocation<'_>> for Request {
    type Error = Error;

    fn try_from(plan: &Relocation<'_>) -> Result<Self> {
        let Relocation {
            vault,
            data_key,
            dst,
            sources,
            share,
        } = *plan;
        let into = Realm::try_from((vault, dst))?;
        // Sharing flags only mean something for records landing in a shared folder.
        let share = match into {
            Realm::Shared { .. } => share,
            Realm::Private => Share::default(),
        };
        let (mut items, mut transition_keys) = (Vec::new(), Vec::new());
        for source in sources {
            match source {
                Source::Folder(uid) => {
                    let Some(folder) = vault.folders.get(uid) else {
                        return Err(Error::Generic("mv: Root folder cannot be a source folder".into()));
                    };
                    if is_within(vault, dst, uid) {
                        return Err(Error::Generic("mv: Cannot move/link folder to self or a child".into()));
                    }
                    items.push(MoveItem {
                        uid:     uid.clone(),
                        kind:    folder.kind.into(),
                        cascade: true,
                        origin:  Place::from(folder.parent.as_deref().and_then(|p| vault.folders.get(p))).into(),
                        share:   Share::default(),
                    });
                    // A shared folder keeps its own key wherever it is filed.
                    if folder.kind != FolderKind::SharedFolder
                        && let Some(wrapper) = Realm::try_from((vault, Place::In(folder)))?.rewrap(into, data_key)
                    {
                        for member in PostOrder::new(vault, folder) {
                            if member.kind == FolderKind::SharedFolder {
                                return Err(Error::Generic(
                                    "mv: A folder containing shared folders cannot be moved into a shared folder"
                                        .into(),
                                ));
                            }
                            transition_keys.push(TransitionKey::try_from((member, wrapper))?);
                            for record in vault.records_in(&member.uid) {
                                transition_keys.push(TransitionKey::try_from((record, wrapper))?);
                            }
                        }
                    }
                }
                Source::Record { uid, from } => {
                    let Some(record) = vault.records.get(uid) else {
                        return Err(Error::Generic(format!("mv: Record {uid} not found")));
                    };
                    let from = Place::from(vault.folders.get(from));
                    items.push(MoveItem {
                        uid: uid.clone(),
                        kind: Node::Record,
                        cascade: false,
                        origin: from.into(),
                        share,
                    });
                    if let Some(wrapper) = Realm::try_from((vault, from))?.rewrap(into, data_key) {
                        transition_keys.push(TransitionKey::try_from((record, wrapper))?);
                    }
                }
            }
        }
        let (to_type, to_uid) = match dst {
            Place::Root => (Node::UserFolder, None),
            Place::In(folder) => (folder.kind.into(), Some(folder.uid.clone())),
        };
        Ok(Self::Move {
            link: false,
            to_type,
            to_uid,
            items,
            transition_keys,
        })
    }
}

#[derive(Debug, Serialize)]
struct MoveItem {
    uid:     String,
    #[serde(rename = "type")]
    kind:    Node,
    cascade: bool,
    #[serde(flatten)]
    origin:  Origin,
    #[serde(flatten)]
    share:   Share,
}

/// The key of a record or folder re-wrapped for its new home.
#[derive(Debug, Serialize)]
struct TransitionKey {
    uid: String,
    key: Sealed,
}

impl TryFrom<(&Folder, &[u8])> for TransitionKey {
    type Error = Error;

    fn try_from((folder, wrapper): (&Folder, &[u8])) -> Result<Self> {
        // An unknown key would be wrapped as if it were empty, and the folder lost for good.
        if folder.key.is_empty() {
            return Err(Error::Generic(format!(
                "The key of folder {} is not available, so it cannot be moved",
                folder.uid
            )));
        }
        Ok(Self {
            uid: folder.uid.clone(),
            key: Sealed::cbc(&folder.key, wrapper)?,
        })
    }
}

impl TryFrom<(&Record, &[u8])> for TransitionKey {
    type Error = Error;

    fn try_from((record, wrapper): (&Record, &[u8])) -> Result<Self> {
        // The cipher follows the record's own format: GCM from v3 on.
        let key = if record.version >= 3 {
            Sealed::gcm(&record.key, wrapper)
        } else {
            Sealed::cbc(&record.key, wrapper)
        };
        Ok(Self {
            uid: record.uid.clone(),
            key: key?,
        })
    }
}

/// A folder and everything below it, children before their parent: the order Commander lists
/// transition keys in.
struct PostOrder<'a> {
    vault: &'a Vault,
    /// Folders on the path to the one being visited, each with how many children are done.
    stack: Vec<(&'a Folder, usize)>,
}

impl<'a> PostOrder<'a> {
    fn new(vault: &'a Vault, root: &'a Folder) -> Self {
        Self {
            vault,
            stack: vec![(root, 0)],
        }
    }
}

impl<'a> Iterator for PostOrder<'a> {
    type Item = &'a Folder;

    fn next(&mut self) -> Option<&'a Folder> {
        loop {
            let &mut (folder, ref mut done) = self.stack.last_mut()?;
            let Some(child) = folder.subfolders.get(*done) else {
                return self.stack.pop().map(|(folder, _)| folder);
            };
            *done += 1;
            if let Some(child) = self.vault.folders.get(child) {
                self.stack.push((child, 0));
            }
        }
    }
}

/// Whether `place` is the folder `ancestor` or lies below it.
fn is_within(vault: &Vault, place: Place<'_>, ancestor: &str) -> bool {
    let Place::In(folder) = place else { return false };
    std::iter::successors(Some(folder), |f| f.parent.as_deref().and_then(|p| vault.folders.get(p)))
        .any(|f| f.uid == ancestor)
}

/// A spot in the folder tree.
#[derive(Clone, Copy, Debug)]
enum Place<'a> {
    Root,
    In(&'a Folder),
}

impl<'a> From<Option<&'a Folder>> for Place<'a> {
    fn from(folder: Option<&'a Folder>) -> Self {
        folder.map_or(Self::Root, Self::In)
    }
}

/// Which key protects what lives in a folder.
#[derive(Clone, Copy, Debug)]
enum Realm<'a> {
    /// The account's data key.
    Private,
    /// A shared folder's key, which every folder inside it shares.
    Shared { uid: &'a str, key: &'a [u8] },
}

impl<'a> TryFrom<(&'a Vault, Place<'a>)> for Realm<'a> {
    type Error = Error;

    fn try_from((vault, place): (&'a Vault, Place<'a>)) -> Result<Self> {
        let Place::In(folder) = place else {
            return Ok(Self::Private);
        };
        if folder.kind == FolderKind::User {
            return Ok(Self::Private);
        }
        let uid = folder.shared_folder_uid.as_deref().unwrap_or(&folder.uid);
        match vault.shared_folders.get(uid) {
            Some(shared) if !shared.key.is_empty() => {
                Ok(Self::Shared {
                    uid: &shared.uid,
                    key: &shared.key,
                })
            }
            _ => Err(Error::Generic(format!("The key of shared folder {uid} is not available"))),
        }
    }
}

impl Realm<'_> {
    /// The key that keys moving from here into `into` must be re-wrapped with, if any.
    fn rewrap<'k>(self, into: Realm<'k>, data_key: &'k [u8]) -> Option<&'k [u8]> {
        match (self, into) {
            (Self::Private, Realm::Private) => None,
            (Self::Shared { uid: from, .. }, Realm::Shared { uid: to, .. }) if from == to => None,
            (_, Realm::Shared { key, .. }) => Some(key),
            (Self::Shared { .. }, Realm::Private) => Some(data_key),
        }
    }
}

/// Commander's folder path: names from the root, each followed by `/`; nothing for the root.
struct Trail<'a>(&'a Vault, &'a str);

impl fmt::Display for Trail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(folder) = self.0.folders.get(self.1) else {
            return Ok(());
        };
        if let Some(parent) = &folder.parent {
            write!(f, "{}", Trail(self.0, parent))?;
        }
        write!(f, "{}/", folder.name)
    }
}

/// What a path argument points at.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// An existing folder (`""` is the root).
    Folder(String),
    /// A name to look for inside an existing folder.
    Within { parent: String, name: String },
    /// Not even the folder part exists.
    Missing,
}

fn locate(vault: &Vault, cwd: &str, path: &str) -> Target {
    if let Some(uid) = resolve_folder(vault, cwd, path) {
        return Target::Folder(uid);
    }
    let PathTail { parent, name } = path.into();
    match resolve_folder(vault, cwd, &parent) {
        Some(parent) if !name.is_empty() => Target::Within { parent, name },
        _ => Target::Missing,
    }
}

/// A path cut at its last unescaped `/` (`//` is a literal slash inside a name).
#[derive(Debug, PartialEq, Eq)]
struct PathTail {
    /// Everything before the cut, still escaped so `resolve_folder` can read it.
    parent: String,
    /// The final name, unescaped.
    name:   String,
}

impl From<&str> for PathTail {
    fn from(path: &str) -> Self {
        let masked = path.replace("//", "\0");
        let trimmed = masked.trim_end_matches('/');
        let (parent, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some(cut) => cut,
            None => ("", trimmed),
        };
        Self {
            parent: parent.replace('\0', "//"),
            name:   name.replace('\0', "/"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Exact,
    Ignore,
}

impl Case {
    fn fold(self, text: &str) -> Vec<char> {
        match self {
            Self::Exact => text.chars().collect(),
            Self::Ignore => text.chars().flat_map(char::to_lowercase).collect(),
        }
    }
}

/// An `fnmatch`-style pattern that has to match a whole name.
// ponytail: `*` and `?` only; `[seq]` classes match literally. Add them if a real pattern needs them.
struct Glob {
    pattern: Vec<char>,
    case:    Case,
}

impl Glob {
    fn new(pattern: &str, case: Case) -> Self {
        Self {
            pattern: case.fold(pattern),
            case,
        }
    }

    fn is_match(&self, text: &str) -> bool {
        glob_match(&self.pattern, &self.case.fold(text))
    }
}

fn glob_match(pattern: &[char], text: &[char]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some(('*', rest)) => (0..=text.len()).any(|skip| glob_match(rest, &text[skip..])),
        Some((&wanted, rest)) => {
            text.split_first()
                .is_some_and(|(&got, tail)| (wanted == '?' || wanted == got) && glob_match(rest, tail))
        }
    }
}

/// A legacy JSON command, tagged with its `command` name.
#[derive(Debug, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum Request {
    FolderAdd {
        folder_uid:        String,
        folder_type:       Node,
        key:               Sealed,
        data:              Sealed,
        #[serde(skip_serializing_if = "Option::is_none")]
        name:              Option<Sealed>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parent_uid:        Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        shared_folder_uid: Option<String>,
        #[serde(flatten)]
        perms:             Perms,
    },
    FolderUpdate {
        folder_uid:        String,
        folder_type:       Node,
        data:              Sealed,
        #[serde(skip_serializing_if = "Option::is_none")]
        name:              Option<Sealed>,
        #[serde(skip_serializing_if = "Option::is_none")]
        shared_folder_uid: Option<String>,
    },
    PreDelete {
        objects: Vec<Deletion>,
    },
    Delete {
        pre_delete_token: String,
    },
    Move {
        link:            bool,
        to_type:         Node,
        #[serde(skip_serializing_if = "Option::is_none")]
        to_uid:          Option<String>,
        #[serde(rename = "move")]
        items:           Vec<MoveItem>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        transition_keys: Vec<TransitionKey>,
    },
}

/// The `*_type` strings of the legacy commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Node {
    UserFolder,
    SharedFolder,
    SharedFolderFolder,
    Record,
}

impl From<FolderKind> for Node {
    fn from(kind: FolderKind) -> Self {
        match kind {
            FolderKind::User => Self::UserFolder,
            FolderKind::SharedFolder => Self::SharedFolder,
            FolderKind::SharedFolderFolder => Self::SharedFolderFolder,
        }
    }
}

/// Where an object is taken from; the root has no UID and counts as a user folder.
#[derive(Debug, Serialize)]
struct Origin {
    from_type: Node,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_uid:  Option<String>,
}

impl From<Place<'_>> for Origin {
    fn from(place: Place<'_>) -> Self {
        match place {
            Place::Root => {
                Self {
                    from_type: Node::UserFolder,
                    from_uid:  None,
                }
            }
            Place::In(folder) => {
                Self {
                    from_type: folder.kind.into(),
                    from_uid:  Some(folder.uid.clone()),
                }
            }
        }
    }
}

/// Base64url ciphertext as the legacy commands carry it.
#[derive(Debug, Serialize)]
struct Sealed(String);

impl Sealed {
    /// AES-CBC: folder keys, names and data, and the keys of records before v3.
    fn cbc(plain: &[u8], key: &[u8]) -> Result<Self> {
        crypto::encrypt_aes_v1(plain, key).map(|sealed| Self(b64_encode(&sealed)))
    }

    /// AES-GCM: the keys of v3+ records.
    fn gcm(plain: &[u8], key: &[u8]) -> Result<Self> {
        crypto::encrypt_aes_v2(plain, key).map(|sealed| Self(b64_encode(&sealed)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command};
    use crate::vault::SharedFolder;

    /// A private tree (`P` ⊃ `Q`), two shared folders (`S` ⊃ `F` ⊃ `G`, and `T`), a few records,
    /// and every key in it.
    struct Fx {
        vault:    Vault,
        data_key: Vec<u8>,
        keys:     HashMap<&'static str, Vec<u8>>,
    }

    impl Fx {
        fn new() -> Self {
            let data_key = crypto::random_bytes(32);
            let keys: HashMap<&'static str, Vec<u8>> = ["P", "Q", "S", "F", "G", "T", "R3", "R2", "RS", "RR"]
                .into_iter()
                .map(|uid| (uid, crypto::random_bytes(32)))
                .collect();
            let folder =
                |uid: &'static str, name: &str, kind, parent: Option<&str>, shared: Option<&str>, kids: &[&str]| {
                    (
                        uid.to_owned(),
                        Folder {
                            uid: uid.into(),
                            kind,
                            name: name.into(),
                            parent: parent.map(Into::into),
                            subfolders: kids.iter().map(|k| (*k).into()).collect(),
                            key: keys[uid].clone(),
                            shared_folder_uid: shared.map(Into::into),
                            data: json!({ "name": name }),
                        },
                    )
                };
            let record = |uid: &'static str, version, title: &str| {
                (
                    uid.to_owned(),
                    Record {
                        uid: uid.into(),
                        version,
                        key: keys[uid].clone(),
                        data: json!({ "title": title }),
                        ..Record::default()
                    },
                )
            };
            let shared = |uid: &'static str, name: &str| {
                (
                    uid.to_owned(),
                    SharedFolder {
                        uid:                    uid.into(),
                        name:                   name.into(),
                        record_uids:            vec![],
                        users:                  vec![],
                        teams:                  vec![],
                        default_manage_records: false,
                        default_manage_users:   false,
                        default_can_edit:       false,
                        default_can_share:      false,
                        key:                    keys[uid].clone(),
                    },
                )
            };
            let holds = |folder: &str, uids: &[&str]| {
                (folder.to_owned(), uids.iter().map(|u| (*u).to_owned()).collect::<BTreeSet<_>>())
            };
            let mut vault = Vault {
                records: BTreeMap::from([
                    record("R3", 3, "Router"),
                    record("R2", 2, "router old"),
                    record("RS", 3, "Shared doc"),
                    record("RR", 3, "Root note"),
                ]),
                shared_folders: BTreeMap::from([shared("S", "Team"), shared("T", "Other")]),
                folders: HashMap::from([
                    folder("P", "Personal", FolderKind::User, None, None, &["Q"]),
                    folder("Q", "Sub", FolderKind::User, Some("P"), None, &[]),
                    folder("S", "Team", FolderKind::SharedFolder, None, Some("S"), &["F"]),
                    folder("F", "Docs", FolderKind::SharedFolderFolder, Some("S"), Some("S"), &["G"]),
                    folder("G", "Deep", FolderKind::SharedFolderFolder, Some("F"), Some("S"), &[]),
                    folder("T", "Other", FolderKind::SharedFolder, None, Some("T"), &[]),
                ]),
                root_folders: vec!["P".into(), "S".into(), "T".into()],
                folder_records: HashMap::from([holds("Q", &["R3", "R2"]), holds("F", &["RS"]), holds("", &["RR"])]),
                ..Vault::default()
            };
            vault.folders.get_mut("P").unwrap().data = json!({ "name": "Personal", "color": "red" });
            Self { vault, data_key, keys }
        }

        fn key(&self, uid: &str) -> &[u8] {
            &self.keys[uid]
        }

        fn at(&self, uid: &str) -> Place<'_> {
            Place::from(self.vault.folders.get(uid))
        }

        fn relocate(&self, dst: &str, sources: Vec<Source>, share: Share) -> Result<Value> {
            let request = Request::try_from(&Relocation {
                vault: &self.vault,
                data_key: &self.data_key,
                dst: self.at(dst),
                sources: &sources,
                share,
            })?;
            Ok(serde_json::to_value(request).unwrap())
        }
    }

    fn open_cbc(sealed: &Value, key: &[u8]) -> Vec<u8> {
        crypto::decrypt_aes_v1(&b64_decode(sealed.as_str().unwrap()).unwrap(), key).unwrap()
    }

    fn open_gcm(sealed: &Value, key: &[u8]) -> Vec<u8> {
        crypto::decrypt_aes_v2(&b64_decode(sealed.as_str().unwrap()).unwrap(), key).unwrap()
    }

    fn record_from(uid: &str, from: &str) -> Source {
        Source::Record {
            uid:  uid.into(),
            from: from.into(),
        }
    }

    fn new_folder(fx: &Fx, kind: Kind<'_>, wrapper: &[u8], parent: &str, folder_key: &[u8]) -> Value {
        let request = Request::try_from(&NewFolder {
            uid: "N",
            key: folder_key,
            wrapper,
            name: "Reports",
            tint: Tint::Paint(Color::Blue),
            kind,
            parent: fx.at(parent),
        })
        .unwrap();
        serde_json::to_value(request).unwrap()
    }

    #[test]
    fn user_folder_key_is_wrapped_by_the_data_key_and_data_by_the_folder_key() {
        let fx = Fx::new();
        let folder_key = crypto::random_bytes(32);
        let v = new_folder(&fx, Kind::User, &fx.data_key, "P", &folder_key);

        assert_eq!(v["command"], "folder_add");
        assert_eq!(v["folder_type"], "user_folder");
        assert_eq!(v["folder_uid"], "N");
        assert_eq!(v["parent_uid"], "P");
        assert!(v.get("name").is_none() && v.get("shared_folder_uid").is_none());
        assert_eq!(open_cbc(&v["key"], &fx.data_key), folder_key);
        let data: Value = serde_json::from_slice(&open_cbc(&v["data"], &folder_key)).unwrap();
        assert_eq!(data, json!({ "name": "Reports", "color": "blue" }));

        let at_root = new_folder(&fx, Kind::User, &fx.data_key, "", &folder_key);
        assert!(at_root.get("parent_uid").is_none());
    }

    #[test]
    fn shared_folder_name_is_encrypted_apart_and_only_granted_permissions_are_sent() {
        let fx = Fx::new();
        let folder_key = crypto::random_bytes(32);
        let perms = Perms {
            manage_records: true,
            can_edit: true,
            ..Perms::default()
        };
        let v = new_folder(&fx, Kind::Shared(perms), &fx.data_key, "", &folder_key);

        assert_eq!(v["folder_type"], "shared_folder");
        assert!(v.get("parent_uid").is_none() && v.get("shared_folder_uid").is_none());
        assert_eq!(open_cbc(&v["key"], &fx.data_key), folder_key);
        assert_eq!(open_cbc(&v["name"], &folder_key), b"Reports");
        assert_eq!((&v["manage_records"], &v["can_edit"]), (&json!(true), &json!(true)));
        assert!(v.get("manage_users").is_none() && v.get("can_share").is_none());
    }

    #[test]
    fn folder_inside_a_shared_folder_is_wrapped_by_that_shared_folder_key() {
        let fx = Fx::new();
        let folder_key = crypto::random_bytes(32);
        for (parent, parent_uid) in [("F", Some("F")), ("S", None)] {
            let kind = Kind::Nested { shared_folder: "S" };
            let v = new_folder(&fx, kind, fx.key("S"), parent, &folder_key);

            assert_eq!(v["folder_type"], "shared_folder_folder");
            assert_eq!(v["shared_folder_uid"], "S");
            assert_eq!(v.get("parent_uid").and_then(Value::as_str), parent_uid, "under {parent}");
            assert!(v.get("name").is_none());
            assert_eq!(open_cbc(&v["key"], fx.key("S")), folder_key);
            let under_data_key = crypto::decrypt_aes_v1(&b64_decode(v["key"].as_str().unwrap()).unwrap(), &fx.data_key);
            assert_ne!(under_data_key.ok(), Some(folder_key.clone()));
        }
    }

    #[test]
    fn rename_keeps_the_rest_of_the_folder_data() {
        let fx = Fx::new();
        let data = |edit: Edit| -> Value {
            let v = serde_json::to_value(Request::try_from((&fx.vault.folders["P"], &edit)).unwrap()).unwrap();
            assert_eq!(v["command"], "folder_update");
            assert_eq!(v["folder_type"], "user_folder");
            assert!(v.get("name").is_none() && v.get("shared_folder_uid").is_none());
            serde_json::from_slice(&open_cbc(&v["data"], fx.key("P"))).unwrap()
        };
        let rename = Edit {
            name: Rename::To("Home".into()),
            tint: Tint::Keep,
        };
        assert_eq!(data(rename), json!({ "name": "Home", "color": "red" }));
        let clear = Edit {
            name: Rename::Keep,
            tint: Tint::Clear,
        };
        assert_eq!(data(clear), json!({ "name": "Personal" }));
        let paint = Edit {
            name: Rename::Keep,
            tint: Tint::Paint(Color::Gray),
        };
        assert_eq!(data(paint), json!({ "name": "Personal", "color": "gray" }));
    }

    #[test]
    fn shared_folders_rename_with_their_own_name_field_and_subfolders_name_their_shared_folder() {
        let fx = Fx::new();
        let update = |uid: &str, edit: Edit| {
            serde_json::to_value(Request::try_from((&fx.vault.folders[uid], &edit)).unwrap()).unwrap()
        };
        let rename = |name: &str| {
            Edit {
                name: Rename::To(name.into()),
                tint: Tint::Keep,
            }
        };

        let v = update("S", rename("Squad"));
        assert_eq!((&v["folder_type"], &v["shared_folder_uid"]), (&json!("shared_folder"), &json!("S")));
        assert_eq!(open_cbc(&v["name"], fx.key("S")), b"Squad");
        assert_eq!(open_cbc(&v["data"], fx.key("S")), br#"{"name":"Squad"}"#);

        // A color-only change still has to send the current name.
        let v = update(
            "S",
            Edit {
                name: Rename::Keep,
                tint: Tint::Paint(Color::Red),
            },
        );
        assert_eq!(open_cbc(&v["name"], fx.key("S")), b"Team");

        let v = update("F", rename("Papers"));
        assert_eq!((&v["folder_type"], &v["shared_folder_uid"]), (&json!("shared_folder_folder"), &json!("S")));
        assert!(v.get("name").is_none());
        assert_eq!(open_cbc(&v["data"], fx.key("F")), br#"{"name":"Papers"}"#);
    }

    #[test]
    fn a_folder_whose_key_is_unknown_cannot_be_changed() {
        let folder = Folder {
            uid: "X".into(),
            ..Folder::default()
        };
        let edit = Edit {
            name: Rename::To("a".into()),
            tint: Tint::Keep,
        };
        assert!(Request::try_from((&folder, &edit)).is_err());
    }

    #[test]
    fn records_moving_into_a_shared_folder_get_their_key_re_wrapped_for_it() {
        let fx = Fx::new();
        let share = Share {
            can_reshare: true,
            can_edit:    false,
        };
        let v = fx
            .relocate("S", vec![record_from("R3", "Q"), record_from("R2", "Q")], share)
            .unwrap();

        assert_eq!((&v["command"], &v["link"]), (&json!("move"), &json!(false)));
        assert_eq!((&v["to_type"], &v["to_uid"]), (&json!("shared_folder"), &json!("S")));
        assert_eq!(
            v["move"][0],
            json!({ "uid": "R3", "type": "record", "cascade": false, "from_type": "user_folder", "from_uid": "Q", "can_reshare": true })
        );
        let keys = v["transition_keys"].as_array().unwrap();
        assert_eq!(keys[0]["uid"], "R3");
        assert_eq!(open_gcm(&keys[0]["key"], fx.key("S")), fx.key("R3"), "v3 records are GCM");
        assert_eq!(keys[1]["uid"], "R2");
        assert_eq!(open_cbc(&keys[1]["key"], fx.key("S")), fx.key("R2"), "older records are CBC");
    }

    #[test]
    fn moves_that_stay_under_one_key_carry_no_transition_keys() {
        let fx = Fx::new();
        let share = Share {
            can_reshare: true,
            can_edit:    true,
        };
        for (dst, source) in [
            ("P", record_from("R3", "Q")),
            ("G", record_from("RS", "F")),
            ("S", Source::Folder("F".into())),
        ] {
            let v = fx.relocate(dst, vec![source], share).unwrap();
            assert!(v.get("transition_keys").is_none(), "into {dst}");
        }
        // Sharing flags only apply to records landing in a shared folder.
        let v = fx.relocate("P", vec![record_from("R3", "Q")], share).unwrap();
        assert!(v["move"][0].get("can_edit").is_none());
    }

    #[test]
    fn leaving_or_switching_shared_folders_re_wraps_for_the_destination() {
        let fx = Fx::new();
        let out = fx.relocate("", vec![record_from("RS", "F")], Share::default()).unwrap();
        assert_eq!(out["to_type"], "user_folder");
        assert!(out.get("to_uid").is_none());
        assert_eq!(out["move"][0]["from_type"], "shared_folder_folder");
        assert_eq!(out["move"][0]["from_uid"], "F");
        assert_eq!(open_gcm(&out["transition_keys"][0]["key"], &fx.data_key), fx.key("RS"));

        let across = fx
            .relocate("T", vec![record_from("RS", "F")], Share::default())
            .unwrap();
        assert_eq!(open_gcm(&across["transition_keys"][0]["key"], fx.key("T")), fx.key("RS"));
    }

    #[test]
    fn a_folder_tree_entering_a_shared_folder_lists_children_before_parents() {
        let fx = Fx::new();
        let v = fx
            .relocate("S", vec![Source::Folder("P".into())], Share::default())
            .unwrap();

        assert_eq!(
            v["move"][0],
            json!({ "uid": "P", "type": "user_folder", "cascade": true, "from_type": "user_folder" })
        );
        let keys = v["transition_keys"].as_array().unwrap();
        let order: Vec<&str> = keys.iter().map(|k| k["uid"].as_str().unwrap()).collect();
        assert_eq!(order, ["Q", "R2", "R3", "P"]);
        assert_eq!(open_cbc(&keys[0]["key"], fx.key("S")), fx.key("Q"));
        assert_eq!(open_cbc(&keys[1]["key"], fx.key("S")), fx.key("R2"));
        assert_eq!(open_gcm(&keys[2]["key"], fx.key("S")), fx.key("R3"));
        assert_eq!(open_cbc(&keys[3]["key"], fx.key("S")), fx.key("P"));
    }

    #[test]
    fn a_shared_subfolder_moved_out_is_re_wrapped_with_the_data_key() {
        let fx = Fx::new();
        let v = fx
            .relocate("P", vec![Source::Folder("F".into())], Share::default())
            .unwrap();

        assert_eq!(
            v["move"][0],
            json!({ "uid": "F", "type": "shared_folder_folder", "cascade": true, "from_type": "shared_folder", "from_uid": "S" })
        );
        let keys = v["transition_keys"].as_array().unwrap();
        let order: Vec<&str> = keys.iter().map(|k| k["uid"].as_str().unwrap()).collect();
        assert_eq!(order, ["G", "F", "RS"]);
        assert_eq!(open_cbc(&keys[0]["key"], &fx.data_key), fx.key("G"));
        assert_eq!(open_cbc(&keys[1]["key"], &fx.data_key), fx.key("F"));
        assert_eq!(open_gcm(&keys[2]["key"], &fx.data_key), fx.key("RS"));
    }

    #[test]
    fn a_shared_folder_keeps_its_key_when_refiled() {
        let fx = Fx::new();
        let v = fx
            .relocate("P", vec![Source::Folder("S".into())], Share::default())
            .unwrap();
        assert_eq!(v["move"][0]["type"], "shared_folder");
        assert_eq!(v["move"][0]["from_type"], "user_folder");
        assert!(v.get("transition_keys").is_none());
    }

    #[test]
    fn impossible_folder_moves_are_refused() {
        let fx = Fx::new();
        for (dst, src) in [("Q", "P"), ("P", "P"), ("G", "F")] {
            let e = fx
                .relocate(dst, vec![Source::Folder(src.into())], Share::default())
                .unwrap_err();
            assert!(e.to_string().contains("self or a child"), "{src} into {dst}: {e}");
        }
        let e = fx
            .relocate("P", vec![Source::Folder(String::new())], Share::default())
            .unwrap_err();
        assert!(e.to_string().contains("Root folder"), "{e}");

        // Shared folders cannot nest, so a tree holding one cannot enter a shared folder.
        let mut fx = Fx::new();
        fx.vault.folders.get_mut("P").unwrap().subfolders.push("T".into());
        fx.vault.folders.get_mut("T").unwrap().parent = Some("P".into());
        let e = fx
            .relocate("S", vec![Source::Folder("P".into())], Share::default())
            .unwrap_err();
        assert!(e.to_string().contains("shared folders"), "{e}");
    }

    #[test]
    fn a_folder_whose_key_is_unknown_is_not_re_wrapped() {
        let mut fx = Fx::new();
        fx.vault.folders.get_mut("Q").unwrap().key.clear();
        let e = fx
            .relocate("S", vec![Source::Folder("P".into())], Share::default())
            .unwrap_err();
        assert!(e.to_string().contains("key of folder Q"), "{e}");

        // Under one key nothing is re-wrapped, so nothing is in the way.
        assert!(
            fx.relocate("", vec![Source::Folder("Q".into())], Share::default())
                .is_ok()
        );
    }

    #[test]
    fn deletions_name_their_parent_the_way_commander_does() {
        let fx = Fx::new();
        let del = |uid: &str| serde_json::to_value(Deletion::from((&fx.vault, &fx.vault.folders[uid]))).unwrap();

        assert_eq!(
            del("P"),
            json!({ "delete_resolution": "unlink", "object_uid": "P", "object_type": "user_folder", "from_type": "user_folder" })
        );
        assert_eq!((&del("Q")["from_type"], &del("Q")["from_uid"]), (&json!("user_folder"), &json!("P")));
        // Unlike `mv`, a delete files a shared folder's direct children under their own type.
        assert_eq!((&del("F")["from_type"], &del("F")["from_uid"]), (&json!("shared_folder_folder"), &json!("S")));
        assert_eq!((&del("G")["from_type"], &del("G")["from_uid"]), (&json!("shared_folder_folder"), &json!("F")));
        assert_eq!(del("S")["object_type"], "shared_folder");
    }

    #[test]
    fn delete_requests_and_the_pre_delete_answer_match_the_wire_format() {
        let delete = Request::Delete {
            pre_delete_token: "t".into(),
        };
        assert_eq!(serde_json::to_value(delete).unwrap(), json!({ "command": "delete", "pre_delete_token": "t" }));
        let pre = Request::PreDelete { objects: vec![] };
        assert_eq!(serde_json::to_value(pre).unwrap(), json!({ "command": "pre_delete", "objects": [] }));

        let answer = json!({
            "result": "success",
            "pre_delete_response": {
                "pre_delete_token": "abc",
                "would_delete": { "deletion_summary": ["1 folder", "2 records"] }
            }
        });
        let PreDeleted { pre_delete_response } = serde_json::from_value(answer).unwrap();
        assert_eq!(pre_delete_response.pre_delete_token, "abc");
        assert_eq!(pre_delete_response.would_delete.deletion_summary, ["1 folder", "2 records"]);
    }

    #[test]
    fn paths_split_at_the_last_unescaped_slash() {
        let tail = |path: &str| {
            let PathTail { parent, name } = path.into();
            (parent, name)
        };
        assert_eq!(tail("New"), (String::new(), "New".into()));
        assert_eq!(tail("A/B/New"), ("A/B".into(), "New".into()));
        assert_eq!(tail("/New"), ("/".into(), "New".into()));
        assert_eq!(tail("/A/New/"), ("/A".into(), "New".into()));
        assert_eq!(tail("A/a//b"), ("A".into(), "a/b".into()));
        assert_eq!(tail("a//b"), (String::new(), "a/b".into()));
        assert_eq!(tail("A//B/New"), ("A//B".into(), "New".into()));
    }

    #[test]
    fn paths_are_located_as_folders_or_names_inside_folders() {
        let fx = Fx::new();
        let at = |cwd: &str, path: &str| locate(&fx.vault, cwd, path);
        let within = |parent: &str, name: &str| {
            Target::Within {
                parent: parent.into(),
                name:   name.into(),
            }
        };
        assert_eq!(at("", "Personal"), Target::Folder("P".into()));
        assert_eq!(at("P", "Sub"), Target::Folder("Q".into()));
        assert_eq!(at("", "/Team/Docs"), Target::Folder("F".into()));
        assert_eq!(at("", "Personal/New"), within("P", "New"));
        assert_eq!(at("", "/New"), within("", "New"));
        assert_eq!(at("Q", "New"), within("Q", "New"));
        assert_eq!(at("", "Nope/New"), Target::Missing);
    }

    #[test]
    fn globs_match_whole_names() {
        let hit = |pattern: &str, text: &str, case| Glob::new(pattern, case).is_match(text);
        assert!(hit("Old*", "Old Stuff", Case::Exact));
        assert!(!hit("Old*", "Bold", Case::Exact));
        assert!(hit("*", "", Case::Exact));
        assert!(hit("a?c", "abc", Case::Exact));
        assert!(!hit("a?c", "ac", Case::Exact));
        assert!(!hit("abc", "abcd", Case::Exact));
        assert!(hit("*prod*db", "My prod DB", Case::Ignore));
        assert!(!hit("old*", "Old Stuff", Case::Exact));
        assert!(hit("old*", "Old Stuff", Case::Ignore));
    }

    #[test]
    fn move_sources_resolve_like_commander() {
        let fx = Fx::new();
        let pick = |cwd: &str, src: &str, dst: &str, matching| selected(&fx.vault, cwd, src, dst, matching);
        let message = |result: Result<Vec<Source>>| result.unwrap_err().to_string();

        // A record UID is taken from the current folder, else from the first folder holding it.
        assert_eq!(pick("Q", "R3", "P", Match::Records).unwrap(), [record_from("R3", "Q")]);
        assert_eq!(pick("", "R3", "P", Match::Records).unwrap(), [record_from("R3", "Q")]);
        assert_eq!(pick("", "RR", "P", Match::Records).unwrap(), [record_from("RR", "")]);

        // Names are patterns over record titles, ignoring case; a folder path moves the folder.
        assert_eq!(
            pick("", "Personal/Sub/rout*", "S", Match::Records).unwrap(),
            [record_from("R2", "Q"), record_from("R3", "Q")]
        );
        assert_eq!(pick("", "Personal/Sub", "S", Match::Records).unwrap(), [Source::Folder("Q".into())]);

        // The folder flags make the pattern select folders of that kind instead.
        assert_eq!(pick("", "*", "Q", Match::UserFolders).unwrap(), [Source::Folder("P".into())]);
        assert_eq!(
            pick("", "*", "Q", Match::SharedFolders).unwrap(),
            [Source::Folder("S".into()), Source::Folder("T".into())]
        );

        assert!(message(pick("Q", "R3", "Q", Match::Records)).contains("are the same"));
        assert!(message(pick("", "Personal/Sub", "Q", Match::Records)).contains("are the same"));
        assert!(message(pick("", "Nope/x", "P", Match::Records)).contains("existing record or folder"));
        assert!(message(pick("", "Personal/zzz*", "S", Match::Records)).contains("not found"));
    }

    #[test]
    fn prompt_replies_parse_like_commanders() {
        assert_eq!("a".parse::<Perms>().unwrap(), Perms::ALL);
        let edit_users = Perms {
            manage_users: true,
            can_edit: true,
            ..Perms::default()
        };
        assert_eq!("UE".parse::<Perms>().unwrap(), edit_users);
        assert_eq!("".parse::<Perms>().unwrap(), Perms::default());
        assert!("x".parse::<Perms>().is_err());

        assert_eq!("Y".parse::<Answer>().unwrap(), Answer::Yes);
        assert_eq!("".parse::<Answer>().unwrap(), Answer::No);
        assert!("maybe".parse::<Answer>().is_err());

        assert_eq!("Dev//Ops".parse::<FolderName>().unwrap().0, "Dev/Ops");
        assert!("a/b".parse::<FolderName>().is_err());
    }

    #[test]
    fn folder_paths_print_the_way_commander_prints_them() {
        let fx = Fx::new();
        assert_eq!(Trail(&fx.vault, "Q").to_string(), "Personal/Sub/");
        assert_eq!(Trail(&fx.vault, "").to_string(), "");
    }

    #[test]
    fn commanders_multi_letter_flags_reach_clap_as_long_flags() {
        let args = ["keeper-cli", "mkdir", "-sf", "-a", "Team"];
        let command = Cli::try_parse_from(expand_legacy_flags(args)).unwrap().command;
        let Some(Command::Mkdir(mkdir)) = command else {
            panic!("not mkdir: {command:?}");
        };
        assert!(mkdir.shared_folder && mkdir.grant.all && !mkdir.user_folder);
        assert_eq!(mkdir.folder.as_deref(), Some("Team"));

        assert_eq!(expand_legacy_flags(["ls", "-sf"]), ["ls", "-sf"]);
    }
}
