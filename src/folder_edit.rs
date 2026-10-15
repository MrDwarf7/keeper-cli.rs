//! Folder write commands: `mkdir`, `rmdir`, `rndir` and `mv`.
//!
//! These are legacy JSON commands: new folder keys, names and data use CBC, and moves re-wrap
//! keys only when an object crosses between private and shared-folder encryption realms.

use std::fmt::Display;
use std::str::FromStr;

use aes::cipher::block_padding::Pkcs7;
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth;
use crate::commands::{App, Run};
use crate::crypto::{self, AesKey};
use crate::prelude::*;
use crate::uid::Uid;
use crate::vault::{Folder, FolderKind, Location, PathResolution, Record, Vault};

/// Commander puts at most this many items in one `move` and asks for the command to be repeated.
const MOVE_LIMIT: usize = 991;

/// Create a folder.
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

/// Remove a folder and its contents.
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

/// Rename a folder or change its color.
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

/// Move a record or folder to another folder.
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
    /// Remove the color.
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
        {
            app.ensure_synced()?;
            let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
            let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
            let session = &mut account.session;
            let cwd = &account.cwd;
            let (parent, mut name) = match folder.as_deref().filter(|f| !f.trim().is_empty()) {
                None => (None, String::new()),
                Some(path) => {
                    match locate(vault, cwd, path) {
                        Target::Folder(_) => {
                            eprintln!("mkdir: Folder \"{path}\" already exists");
                            return Ok(());
                        }
                        Target::Within { parent, name } => (Some(parent), name),
                        Target::Missing => {
                            return Err(Error::Generic(format!("mkdir: The folder part of \"{path}\" does not exist")));
                        }
                    }
                }
            };
            let parent = parent.as_ref().unwrap_or(cwd);
            let base = Place::from(vault.folder(parent));
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
            let uid = Uid::from(crypto::random_bytes(16).as_slice());
            let key = AesKey::try_from(crypto::random_bytes(32))?;
            let wrapper = match home {
                Realm::Private => &session.data_key,
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
            let path = format!("{}{name}", Trail(vault, parent));
            println!("{}", serde_json::json!({ "folder_uid": uid.to_string(), "name": name, "path": path }));
        };
        app.account.as_mut().ok_or(Error::NotLoggedIn)?.vault = None;
        Ok(())
    }
}

impl Run for Rmdir {
    fn run(self, app: &mut App) -> Result<()> {
        let Self { force, quiet, pattern } = self;
        let confirm = match force {
            true => Confirm::Skip,
            false => Confirm::Ask,
        };
        let report = match (force, quiet) {
            (true, true) => Report::Hide,
            _ => Report::Show,
        };
        {
            app.ensure_synced()?;
            let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
            let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
            let session = &mut account.session;
            let cwd = &account.cwd;
            let mut doomed: Vec<&Folder> = Vec::new();
            for pattern in &pattern {
                let found: Vec<&Folder> = match locate(vault, cwd, pattern) {
                    Target::Folder(Location::Root) => {
                        return Err(Error::Generic("rmdir: The root folder cannot be removed".into()));
                    }
                    Target::Folder(Location::Folder(uid)) => {
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
                            .filter(|folder| glob.is_match(&folder.name) || glob.is_match(folder.uid.as_ref()))
                            .collect()
                    }
                    Target::Missing => Vec::new(),
                };
                if found.is_empty() {
                    eprintln!("Folder \"{pattern}\" was not found.");
                }
                for folder in found {
                    if doomed.iter().all(|doomed| doomed.uid != folder.uid) {
                        doomed.push(folder);
                    }
                }
            }
            if doomed.is_empty() {
                return Err(Error::Generic("rmdir: Enter name of an existing folder.".into()));
            }
            if report == Report::Show {
                let names: Vec<String> = doomed
                    .iter()
                    .map(|folder| Trail(vault, &Location::Folder(folder.uid.clone())).to_string())
                    .collect();
                println!("\nThe following user folder(s) will be removed:\n{}", names.join(", "));
            }
            let objects = doomed.iter().map(|&folder| Deletion::from((vault, folder))).collect();
            let pre_delete = session.execute_v2(serde_json::to_value(Request::PreDelete { objects })?)?;
            let PreDeleted {
                pre_delete_response:
                    Pending {
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
        }
        app.account.as_mut().ok_or(Error::NotLoggedIn)?.vault = None;
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
        let path = folder.ok_or_else(|| Error::Generic("Enter the path or UID of existing folder.".into()))?;
        let report = match quiet {
            true => Report::Hide,
            false => Report::Show,
        };
        {
            app.ensure_synced()?;
            let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
            let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
            let session = &mut account.session;
            let cwd = &account.cwd;
            let uid = match locate(vault, cwd, &path) {
                Target::Folder(Location::Folder(uid)) => uid,
                Target::Folder(Location::Root) => {
                    return Err(Error::Generic("rndir: The root folder cannot be renamed".into()));
                }
                _ => return Err(Error::Generic(format!("Folder {path} not found"))),
            };
            let folder = vault
                .folders
                .get(&uid)
                .ok_or_else(|| Error::Generic("rndir: The root folder cannot be renamed".into()))?;
            let request = Request::try_from((folder, &edit))?;
            session.execute_v2(serde_json::to_value(request)?)?;
            if report == Report::Show
                && let Rename::To(new) = &edit.name
            {
                eprintln!("Folder \"{}\" has been renamed to \"{new}\"", folder.name);
            }
        }
        app.account.as_mut().ok_or(Error::NotLoggedIn)?.vault = None;
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
        {
            app.ensure_synced()?;
            let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
            let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
            let session = &mut account.session;
            let cwd = &account.cwd;
            let dst = Location::try_from(vault.resolve_path(cwd, &dst))
                .map_err(|_| Error::Generic("mv: Destination path should be existing folder".into()))?;
            let mut sources = selected(vault, cwd, &src, &dst, matching)?;
            if sources.len() > MOVE_LIMIT {
                eprintln!("The command limit has been reached. Please repeat this command to resume operation.");
                sources.truncate(MOVE_LIMIT);
            }
            let request = Request::try_from(&Relocation {
                vault,
                data_key: &session.data_key,
                dst: Place::from(vault.folder(&dst)),
                sources: &sources,
                share,
            })?;
            session.execute_v2(serde_json::to_value(request)?)?;
        }
        app.account.as_mut().ok_or(Error::NotLoggedIn)?.vault = None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Wanted {
    Shared(Perms),
    User,
    Unspecified,
}

#[derive(Clone, Copy, Debug)]
enum Kind<'a> {
    User,
    Shared(Perms),
    Nested { shared_folder: &'a Uid },
}

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

fn ask<T>(question: &str) -> Result<T>
where
    T: FromStr,
    T::Err: Display,
{
    loop {
        match auth::prompt(question)?.parse() {
            Ok(answer) => return Ok(answer),
            Err(error) => eprintln!("Error: {error}"),
        }
    }
}

struct NewFolder<'a> {
    uid:     &'a Uid,
    key:     &'a AesKey,
    wrapper: &'a [u8],
    name:    &'a str,
    tint:    Tint,
    kind:    Kind<'a>,
    parent:  Place<'a>,
}

impl TryFrom<&NewFolder<'_>> for Request {
    type Error = Error;

    fn try_from(new: &NewFolder<'_>) -> Result<Self> {
        let mut data = serde_json::json!({ "name": new.name });
        new.tint.apply(&mut data);
        let (folder_type, name, shared_folder_uid, perms) = match new.kind {
            Kind::User => (Node::UserFolder, None, None, Perms::default()),
            Kind::Shared(perms) => (Node::SharedFolder, Some(Sealed::cbc(new.name.as_bytes(), new.key)?), None, perms),
            Kind::Nested { shared_folder } => {
                (Node::SharedFolderFolder, None, Some(shared_folder.to_string()), Perms::default())
            }
        };
        Ok(Self::FolderAdd {
            folder_uid: new.uid.to_string(),
            folder_type,
            key: Sealed::cbc(new.key, new.wrapper)?,
            data: Sealed::cbc(data.to_string().as_bytes(), new.key)?,
            name,
            parent_uid: match new.parent {
                Place::In(parent) if !matches!(&parent.kind, FolderKind::SharedFolder) => Some(parent.uid.to_string()),
                Place::In(_) | Place::Root => None,
            },
            shared_folder_uid,
            perms,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Confirm {
    Ask,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Report {
    Show,
    Hide,
}

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
        let mut origin = Origin::from(Place::from(vault.folder(&folder.parent)));
        if origin.from_type == Node::SharedFolder {
            origin.from_type = Node::SharedFolderFolder;
        }
        Self {
            delete_resolution: Resolution::Unlink,
            object_uid: folder.uid.to_string(),
            object_type: (&folder.kind).into(),
            origin,
        }
    }
}

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
            Self::Paint(color) => data["color"] = serde_json::json!(color),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Edit {
    name: Rename,
    tint: Tint,
}

impl TryFrom<(&Folder, &Edit)> for Request {
    type Error = Error;

    fn try_from((folder, edit): (&Folder, &Edit)) -> Result<Self> {
        let key = folder.key.as_ref().ok_or_else(|| {
            Error::Generic(format!("The key of folder {} is not available, so it cannot be changed", folder.uid))
        })?;
        let mut data = if folder.data.is_object() {
            folder.data.clone()
        } else {
            serde_json::json!({})
        };
        if let Rename::To(name) = &edit.name {
            data["name"] = serde_json::json!(name);
        }
        edit.tint.apply(&mut data);
        let (name, shared_folder_uid) = match &folder.kind {
            FolderKind::User => (None, None),
            FolderKind::SharedFolder => {
                let name = match &edit.name {
                    Rename::To(name) => name,
                    Rename::Keep => &folder.name,
                };
                (Some(Sealed::cbc(name.as_bytes(), key)?), Some(folder.uid.to_string()))
            }
            FolderKind::SharedFolderFolder { shared_folder } => (None, Some(shared_folder.to_string())),
        };
        Ok(Self::FolderUpdate {
            folder_uid: folder.uid.to_string(),
            folder_type: (&folder.kind).into(),
            data: Sealed::cbc(data.to_string().as_bytes(), key)?,
            name,
            shared_folder_uid,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Match {
    Records,
    SharedFolders,
    UserFolders,
}

#[derive(Debug, PartialEq, Eq)]
enum Source {
    Folder(Location),
    Record { uid: Uid, from: Location },
}

fn selected(vault: &Vault, cwd: &Location, src: &str, dst: &Location, matching: Match) -> Result<Vec<Source>> {
    let same = || Error::Generic("mv: Source and Destination folders are the same".into());
    if let Ok(uid) = src.parse::<Uid>()
        && vault.records.contains_key(&uid)
    {
        let from = home_of(vault, cwd, &uid);
        if &from == dst {
            return Err(same());
        }
        return Ok(vec![Source::Record { uid, from }]);
    }
    match locate(vault, cwd, src) {
        Target::Folder(folder) if &folder == dst => Err(same()),
        Target::Folder(folder) => Ok(vec![Source::Folder(folder)]),
        Target::Missing => Err(Error::Generic("mv: Source path should be existing record or folder".into())),
        Target::Within { parent, .. } if &parent == dst => Err(same()),
        Target::Within { parent, name } => {
            let glob = Glob::new(&name, Case::Ignore);
            let found: Vec<Source> = match matching {
                Match::Records => {
                    vault
                        .records_in(&parent)
                        .filter(|record| {
                            record.uid.as_ref() == name.as_str()
                                || (matches!(i32::from(&record.kind), 2 | 3) && glob.is_match(record.title()))
                        })
                        .map(|record| {
                            Source::Record {
                                uid:  record.uid.clone(),
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
                        .filter(|folder| {
                            matches!(&folder.kind, FolderKind::SharedFolder) == shared && glob.is_match(&folder.name)
                        })
                        .map(|folder| Source::Folder(Location::Folder(folder.uid.clone())))
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

fn home_of(vault: &Vault, cwd: &Location, record: &Uid) -> Location {
    if vault.records_in(cwd).any(|candidate| &candidate.uid == record) {
        return cwd.clone();
    }
    vault
        .locations_of(record)
        .filter_map(|location| {
            match location {
                Location::Root => None,
                Location::Folder(uid) => Some((uid, Location::Folder(uid.clone()))),
            }
        })
        .min_by(|(a, _), (b, _)| a.cmp(b))
        .map_or(Location::Root, |(_, location)| location)
}

#[derive(Clone, Copy)]
struct Relocation<'a> {
    vault:    &'a Vault,
    data_key: &'a AesKey,
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
        let share = match into {
            Realm::Shared { .. } => share,
            Realm::Private => Share::default(),
        };
        let (mut items, mut transition_keys) = (Vec::new(), Vec::new());
        for source in sources {
            match source {
                Source::Folder(Location::Root) => {
                    return Err(Error::Generic("mv: Root folder cannot be a source folder".into()));
                }
                Source::Folder(Location::Folder(uid)) => {
                    let folder = vault
                        .folders
                        .get(uid)
                        .ok_or_else(|| Error::Generic("mv: Root folder cannot be a source folder".into()))?;
                    if is_within(vault, dst, uid) {
                        return Err(Error::Generic("mv: Cannot move/link folder to self or a child".into()));
                    }
                    items.push(MoveItem {
                        uid:     uid.to_string(),
                        kind:    (&folder.kind).into(),
                        cascade: true,
                        origin:  Place::from(vault.folder(&folder.parent)).into(),
                        share:   Share::default(),
                    });
                    if !matches!(&folder.kind, FolderKind::SharedFolder)
                        && let Some(wrapper) = Realm::try_from((vault, Place::In(folder)))?.rewrap(into, data_key)
                    {
                        for member in PostOrder::new(vault, folder) {
                            if matches!(&member.kind, FolderKind::SharedFolder) {
                                return Err(Error::Generic(
                                    "mv: A folder containing shared folders cannot be moved into a shared folder"
                                        .into(),
                                ));
                            }
                            transition_keys.push(TransitionKey::try_from((member, wrapper))?);
                            let at = Location::Folder(member.uid.clone());
                            for record in vault.records_in(&at) {
                                transition_keys.push(TransitionKey::try_from((record, wrapper))?);
                            }
                        }
                    }
                }
                Source::Record { uid, from } => {
                    let record = vault
                        .records
                        .get(uid)
                        .ok_or_else(|| Error::Generic(format!("mv: Record {uid} not found")))?;
                    let origin = Place::from(vault.folder(from));
                    items.push(MoveItem {
                        uid: uid.to_string(),
                        kind: Node::Record,
                        cascade: false,
                        origin: origin.into(),
                        share,
                    });
                    if let Some(wrapper) = Realm::try_from((vault, origin))?.rewrap(into, data_key) {
                        transition_keys.push(TransitionKey::try_from((record, wrapper))?);
                    }
                }
            }
        }
        let (to_type, to_uid) = match dst {
            Place::Root => (Node::UserFolder, None),
            Place::In(folder) => ((&folder.kind).into(), Some(folder.uid.to_string())),
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

#[derive(Debug, Serialize)]
struct TransitionKey {
    uid: String,
    key: Sealed,
}

impl TryFrom<(&Folder, &[u8])> for TransitionKey {
    type Error = Error;

    fn try_from((folder, wrapper): (&Folder, &[u8])) -> Result<Self> {
        let key = folder.key.as_ref().ok_or_else(|| {
            Error::Generic(format!("The key of folder {} is not available, so it cannot be moved", folder.uid))
        })?;
        Ok(Self {
            uid: folder.uid.to_string(),
            key: Sealed::cbc(key, wrapper)?,
        })
    }
}

impl TryFrom<(&Record, &[u8])> for TransitionKey {
    type Error = Error;

    fn try_from((record, wrapper): (&Record, &[u8])) -> Result<Self> {
        let key = if i32::from(&record.kind) >= 3 {
            Sealed::gcm(&record.key, wrapper)
        } else {
            Sealed::cbc(&record.key, wrapper)
        }?;
        Ok(Self {
            uid: record.uid.to_string(),
            key,
        })
    }
}

struct PostOrder<'a> {
    vault: &'a Vault,
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

fn is_within(vault: &Vault, place: Place<'_>, ancestor: &Uid) -> bool {
    let Place::In(mut folder) = place else { return false };
    loop {
        if &folder.uid == ancestor {
            return true;
        }
        let Some(parent) = vault.folder(&folder.parent) else {
            return false;
        };
        folder = parent;
    }
}

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

#[derive(Clone, Copy, Debug)]
enum Realm<'a> {
    Private,
    Shared { uid: &'a Uid, key: &'a AesKey },
}

impl<'a> TryFrom<(&'a Vault, Place<'a>)> for Realm<'a> {
    type Error = Error;

    fn try_from((vault, place): (&'a Vault, Place<'a>)) -> Result<Self> {
        let Place::In(folder) = place else {
            return Ok(Self::Private);
        };
        let Some(uid) = folder.shared_folder() else {
            return Ok(Self::Private);
        };
        let shared = vault
            .shared_folders
            .get(uid)
            .ok_or_else(|| Error::Generic(format!("The key of shared folder {uid} is not available")))?;
        Ok(Self::Shared {
            uid: &shared.uid,
            key: &shared.key,
        })
    }
}

impl Realm<'_> {
    /// Key to wrap moved objects with, if their source and destination realms differ.
    fn rewrap<'a>(self, into: Realm<'a>, data_key: &'a AesKey) -> Option<&'a [u8]> {
        match (self, into) {
            (Self::Private, Realm::Private) => None,
            (Self::Shared { uid: from, .. }, Realm::Shared { uid: to, .. }) if from == to => None,
            (_, Realm::Shared { key, .. }) => Some(key),
            (Self::Shared { .. }, Realm::Private) => Some(data_key),
        }
    }
}

struct Trail<'a>(&'a Vault, &'a Location);

impl std::fmt::Display for Trail<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Location::Folder(_) = self.1 {
            let path = self.0.path_of(self.1);
            write!(f, "{}/", path.trim_start_matches('/'))?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Target {
    Folder(Location),
    Within { parent: Location, name: String },
    Missing,
}

fn locate(vault: &Vault, cwd: &Location, path: &str) -> Target {
    match vault.resolve_path(cwd, path) {
        PathResolution::Full(folder) => Target::Folder(folder),
        PathResolution::Partial { parent, tail } => {
            let mut components = tail.components.into_iter();
            match (components.next(), components.next()) {
                (Some(name), None) => Target::Within { parent, name },
                _ => Target::Missing,
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
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

pub(crate) struct Glob {
    pattern: Vec<char>,
    case:    Case,
}

impl Glob {
    pub(crate) fn new(pattern: &str, case: Case) -> Self {
        Self {
            pattern: case.fold(pattern),
            case,
        }
    }

    pub(crate) fn is_match(&self, text: &str) -> bool {
        let text = self.case.fold(text);
        let (mut pattern_index, mut text_index, mut star, mut retry) = (0, 0, None, 0);
        while text_index < text.len() {
            match self.pattern.get(pattern_index) {
                Some(&'*') => {
                    pattern_index += 1;
                    star = Some(pattern_index);
                    retry = text_index;
                }
                Some(&'?') => {
                    pattern_index += 1;
                    text_index += 1;
                }
                Some(&expected) if expected == text[text_index] => {
                    pattern_index += 1;
                    text_index += 1;
                }
                _ => {
                    match star {
                        Some(after_star) if retry < text.len() => {
                            retry += 1;
                            text_index = retry;
                            pattern_index = after_star;
                        }
                        _ => return false,
                    }
                }
            }
        }
        while self.pattern.get(pattern_index) == Some(&'*') {
            pattern_index += 1;
        }
        pattern_index == self.pattern.len()
    }
}

// ponytail: star backtracking is O(pattern × name); memoize if larger workloads need it.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Node {
    UserFolder,
    SharedFolder,
    SharedFolderFolder,
    Record,
}

impl From<&FolderKind> for Node {
    fn from(kind: &FolderKind) -> Self {
        match kind {
            FolderKind::User => Self::UserFolder,
            FolderKind::SharedFolder => Self::SharedFolder,
            FolderKind::SharedFolderFolder { .. } => Self::SharedFolderFolder,
        }
    }
}

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
                    from_type: (&folder.kind).into(),
                    from_uid:  Some(folder.uid.to_string()),
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct Sealed(String);

impl Sealed {
    fn cbc(plain: &[u8], key: &[u8]) -> Result<Self> {
        crypto::encrypt_cbc::<Pkcs7>(plain, key).map(|sealed| Self(b64_encode(&sealed)))
    }

    fn gcm(plain: &[u8], key: &[u8]) -> Result<Self> {
        crypto::encrypt_aes_v2(plain, key).map(|sealed| Self(b64_encode(&sealed)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use clap::Parser;
    use serde_json::json;

    use super::*;
    use crate::cli::{Cli, Command};
    use crate::vault::{RecordKind, SharedFolder};

    struct Fx {
        vault:    Vault,
        data_key: AesKey,
        keys:     HashMap<&'static str, AesKey>,
    }

    impl Fx {
        fn new() -> Self {
            let mut vault = crate::vault::tests::sample();
            let labels = ["P", "Q", "S", "F", "G", "T", "U", "V", "R3", "R2", "RS"];
            let keys: HashMap<_, _> = labels.into_iter().map(|label| (label, AesKey::random())).collect();
            let uid = test_uid;
            let p = uid("P");
            let q = uid("Q");
            let r3 = uid("R3");
            let p_folder = vault.folders.get_mut(&p).unwrap();
            p_folder.name = "Personal".into();
            p_folder.key = Some(keys["P"].clone());
            p_folder.data = json!({ "name": "Personal", "color": "red" });
            let q_folder = vault.folders.get_mut(&q).unwrap();
            q_folder.name = "Sub".into();
            q_folder.key = Some(keys["Q"].clone());
            q_folder.data = json!({ "name": "Sub" });
            let record = vault.records.get_mut(&r3).unwrap();
            record.kind = RecordKind::Typed;
            record.data = json!({ "title": "Router", "type": "login" });
            record.key = keys["R3"].clone();
            let r2 = uid("R2");
            vault.records.insert(
                r2.clone(),
                Record {
                    uid:                  r2,
                    kind:                 RecordKind::Legacy { extra: None },
                    data:                 json!({ "title": "router old" }),
                    revision:             1,
                    shared:               false,
                    client_modified_time: 0,
                    key:                  keys["R2"].clone(),
                    owner:                true,
                    udata:                None,
                },
            );

            let add_folder = |uid: Uid, name: &str, kind: FolderKind, parent: Location, key: &str| {
                (
                    uid.clone(),
                    Folder {
                        uid,
                        name: name.into(),
                        kind,
                        parent,
                        subfolders: Vec::new(),
                        key: Some(keys[key].clone()),
                        data: json!({ "name": name }),
                    },
                )
            };
            let s = uid("S");
            let f = uid("F");
            let g = uid("G");
            let t = uid("T");
            let u = uid("U");
            let v = uid("V");
            vault.folders.extend([
                add_folder(s.clone(), "Team", FolderKind::SharedFolder, Location::Folder(p.clone()), "S"),
                add_folder(
                    f.clone(),
                    "Docs",
                    FolderKind::SharedFolderFolder {
                        shared_folder: s.clone(),
                    },
                    Location::Folder(s.clone()),
                    "F",
                ),
                add_folder(
                    g.clone(),
                    "Deep",
                    FolderKind::SharedFolderFolder {
                        shared_folder: s.clone(),
                    },
                    Location::Folder(f.clone()),
                    "G",
                ),
                add_folder(t.clone(), "Other", FolderKind::SharedFolder, Location::Folder(p.clone()), "T"),
                add_folder(u.clone(), "Tree", FolderKind::User, Location::Folder(q.clone()), "U"),
                add_folder(v.clone(), "Leaf", FolderKind::User, Location::Folder(u.clone()), "V"),
            ]);
            vault
                .folders
                .get_mut(&p)
                .unwrap()
                .subfolders
                .extend([s.clone(), t.clone()]);
            vault.folders.get_mut(&q).unwrap().subfolders.push(u.clone());
            vault.folders.get_mut(&s).unwrap().subfolders.push(f.clone());
            vault.folders.get_mut(&f).unwrap().subfolders.push(g);
            vault.folders.get_mut(&u).unwrap().subfolders.push(v);
            vault.shared_folders.extend([
                (s.clone(), shared(&s, "Team", keys["S"].clone())),
                (t.clone(), shared(&t, "Other", keys["T"].clone())),
            ]);
            Self {
                vault,
                data_key: AesKey::random(),
                keys,
            }
        }

        fn key(&self, label: &str) -> &AesKey {
            &self.keys[label]
        }

        fn at(&self, label: &str) -> Place<'_> {
            if label.is_empty() {
                Place::Root
            } else {
                Place::from(self.vault.folder(&Location::Folder(test_uid(label))))
            }
        }

        fn relocate(&self, dst: &str, sources: Vec<Source>, share: Share) -> Result<Value> {
            let request = Request::try_from(&Relocation {
                vault: &self.vault,
                data_key: &self.data_key,
                dst: self.at(dst),
                sources: &sources,
                share,
            })?;
            Ok(serde_json::to_value(request)?)
        }
    }

    fn test_uid(label: &str) -> Uid {
        match label {
            "P" => "AAAA".parse().unwrap(),
            "Q" => "BBBB".parse().unwrap(),
            "R3" => "RRRR".parse().unwrap(),
            _ => Uid::from(label.as_bytes()),
        }
    }

    fn shared(uid: &Uid, name: &str, key: AesKey) -> SharedFolder {
        SharedFolder {
            uid: uid.clone(),
            name: name.into(),
            key,
            record_uids: Vec::new(),
            users: Vec::new(),
            teams: Vec::new(),
            default_manage_records: false,
            default_manage_users: false,
            default_can_edit: false,
            default_can_share: false,
        }
    }

    fn open_cbc(sealed: &Value, key: &[u8]) -> Vec<u8> {
        crypto::decrypt_cbc::<Pkcs7>(&b64_decode(sealed.as_str().unwrap()).unwrap(), key).unwrap()
    }

    fn open_gcm(sealed: &Value, key: &[u8]) -> Vec<u8> {
        crypto::decrypt_aes_v2(&b64_decode(sealed.as_str().unwrap()).unwrap(), key).unwrap()
    }

    fn record_from(uid: &str, from: &str) -> Source {
        Source::Record {
            uid:  test_uid(uid),
            from: if from.is_empty() {
                Location::Root
            } else {
                Location::Folder(test_uid(from))
            },
        }
    }

    fn new_folder(fx: &Fx, kind: Kind<'_>, wrapper: &[u8], parent: &str, folder_key: &AesKey) -> Value {
        let request = Request::try_from(&NewFolder {
            uid: &test_uid("N"),
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
    fn user_folder_key_and_data_are_wrapped_by_the_expected_keys() {
        let fx = Fx::new();
        let folder_key = AesKey::random();
        let v = new_folder(&fx, Kind::User, &fx.data_key, "P", &folder_key);
        assert_eq!(v["command"], "folder_add");
        assert_eq!(v["folder_type"], "user_folder");
        assert_eq!(v["parent_uid"], test_uid("P").to_string());
        assert!(v.get("name").is_none() && v.get("shared_folder_uid").is_none());
        assert_eq!(open_cbc(&v["key"], &fx.data_key), folder_key.to_vec());
        let data: Value = serde_json::from_slice(&open_cbc(&v["data"], &folder_key)).unwrap();
        assert_eq!(data, json!({ "name": "Reports", "color": "blue" }));
        let root = new_folder(&fx, Kind::User, &fx.data_key, "", &folder_key);
        assert!(root.get("parent_uid").is_none());
    }

    #[test]
    fn shared_folder_permissions_and_nested_folder_wrapping_match_wire_format() {
        let fx = Fx::new();
        let folder_key = AesKey::random();
        let perms = Perms {
            manage_records: true,
            can_edit: true,
            ..Perms::default()
        };
        let shared = new_folder(&fx, Kind::Shared(perms), &fx.data_key, "", &folder_key);
        assert_eq!(shared["folder_type"], "shared_folder");
        assert_eq!(open_cbc(&shared["name"], &folder_key), b"Reports");
        assert_eq!((&shared["manage_records"], &shared["can_edit"]), (&json!(true), &json!(true)));
        assert!(shared.get("manage_users").is_none() && shared.get("can_share").is_none());
        let shared_uid = test_uid("S");
        let nested = new_folder(
            &fx,
            Kind::Nested {
                shared_folder: &shared_uid,
            },
            fx.key("S"),
            "S",
            &folder_key,
        );
        assert_eq!(nested["folder_type"], "shared_folder_folder");
        assert_eq!(nested["shared_folder_uid"], shared_uid.to_string());
        assert_eq!(open_cbc(&nested["key"], fx.key("S")), folder_key.to_vec());
    }

    #[test]
    fn rename_preserves_folder_data_and_rejects_an_unavailable_key() {
        let fx = Fx::new();
        let folder = &fx.vault.folders[&test_uid("P")];
        let request = |edit: Edit| Request::try_from((folder, &edit)).unwrap();
        let rename = Edit {
            name: Rename::To("Home".into()),
            tint: Tint::Keep,
        };
        let data: Value =
            serde_json::from_slice(&open_cbc(&serde_json::to_value(request(rename)).unwrap()["data"], fx.key("P")))
                .unwrap();
        assert_eq!(data, json!({ "name": "Home", "color": "red" }));
        let clear = Edit {
            name: Rename::Keep,
            tint: Tint::Clear,
        };
        let data: Value =
            serde_json::from_slice(&open_cbc(&serde_json::to_value(request(clear)).unwrap()["data"], fx.key("P")))
                .unwrap();
        assert_eq!(data, json!({ "name": "Personal" }));
        let locked = Folder {
            uid:        test_uid("X"),
            name:       String::new(),
            kind:       FolderKind::User,
            parent:     Location::Root,
            subfolders: Vec::new(),
            key:        None,
            data:       Value::Null,
        };
        assert!(
            Request::try_from((
                &locked,
                &Edit {
                    name: Rename::To("x".into()),
                    tint: Tint::Keep,
                }
            ))
            .is_err()
        );
    }

    #[test]
    fn records_rewrap_only_when_crossing_realms_and_preserve_record_cipher() {
        let fx = Fx::new();
        let shared = fx
            .relocate(
                "S",
                vec![record_from("R3", "Q")],
                Share {
                    can_reshare: true,
                    can_edit:    false,
                },
            )
            .unwrap();
        assert_eq!(shared["command"], "move");
        assert_eq!(shared["move"][0]["can_reshare"], true);
        assert_eq!(shared["transition_keys"][0]["uid"], test_uid("R3").to_string());
        assert_eq!(open_gcm(&shared["transition_keys"][0]["key"], fx.key("S")), fx.key("R3").to_vec());

        let legacy = fx
            .relocate("S", vec![record_from("R2", "Q")], Share::default())
            .unwrap();
        assert_eq!(open_cbc(&legacy["transition_keys"][0]["key"], fx.key("S")), fx.key("R2").to_vec());

        let same = fx
            .relocate(
                "P",
                vec![record_from("R3", "Q")],
                Share {
                    can_reshare: true,
                    can_edit:    true,
                },
            )
            .unwrap();
        assert!(same.get("transition_keys").is_none());
        assert!(same["move"][0].get("can_edit").is_none());

        let leaving = fx.relocate("", vec![record_from("R3", "F")], Share::default()).unwrap();
        assert_eq!(leaving["move"][0]["from_type"], "shared_folder_folder");
        assert_eq!(open_gcm(&leaving["transition_keys"][0]["key"], &fx.data_key), fx.key("R3").to_vec());
        let switching = fx
            .relocate("T", vec![record_from("R3", "F")], Share::default())
            .unwrap();
        assert_eq!(open_gcm(&switching["transition_keys"][0]["key"], fx.key("T")), fx.key("R3").to_vec());
    }

    #[test]
    fn folder_trees_move_postorder_and_locked_keys_only_block_rewrapping() {
        let fx = Fx::new();
        let moved = fx
            .relocate("S", vec![Source::Folder(Location::Folder(test_uid("Q")))], Share::default())
            .unwrap();
        let order: Vec<_> = moved["transition_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["uid"].as_str().unwrap().to_owned())
            .collect();
        let position = |uid: &Uid| {
            order
                .iter()
                .position(|candidate| candidate == &uid.to_string())
                .unwrap()
        };
        assert!(position(&test_uid("V")) < position(&test_uid("U")));
        assert!(position(&test_uid("U")) < position(&test_uid("Q")));
        let record_key = moved["transition_keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["uid"] == test_uid("R3").to_string())
            .unwrap();
        assert_eq!(open_gcm(&record_key["key"], fx.key("S")), fx.key("R3").to_vec());

        let shared = fx
            .relocate("P", vec![Source::Folder(Location::Folder(test_uid("S")))], Share::default())
            .unwrap();
        assert_eq!(shared["move"][0]["type"], "shared_folder");
        assert!(shared.get("transition_keys").is_none());
        assert!(
            fx.relocate("V", vec![Source::Folder(Location::Folder(test_uid("U")))], Share::default())
                .unwrap_err()
                .to_string()
                .contains("self or a child")
        );
        assert!(
            fx.relocate("P", vec![Source::Folder(Location::Root)], Share::default())
                .unwrap_err()
                .to_string()
                .contains("Root folder")
        );

        let mut fx = Fx::new();
        fx.vault.folders.get_mut(&test_uid("V")).unwrap().key = None;
        assert!(
            fx.relocate("S", vec![Source::Folder(Location::Folder(test_uid("U")))], Share::default())
                .unwrap_err()
                .to_string()
                .contains("key of folder")
        );
        assert!(
            fx.relocate("P", vec![Source::Folder(Location::Folder(test_uid("U")))], Share::default())
                .is_ok()
        );
        let leaf_key = fx.key("V").clone();
        fx.vault.folders.get_mut(&test_uid("V")).unwrap().key = Some(leaf_key);
        let shared_uid = test_uid("T");
        fx.vault
            .folders
            .get_mut(&test_uid("U"))
            .unwrap()
            .subfolders
            .push(shared_uid.clone());
        fx.vault.folders.get_mut(&shared_uid).unwrap().parent = Location::Folder(test_uid("U"));
        assert!(
            fx.relocate("S", vec![Source::Folder(Location::Folder(test_uid("U")))], Share::default())
                .unwrap_err()
                .to_string()
                .contains("shared folders")
        );
    }

    #[test]
    fn shared_folder_renames_use_their_name_field_and_keep_folder_data() {
        let fx = Fx::new();
        let rename = Edit {
            name: Rename::To("Squad".into()),
            tint: Tint::Keep,
        };
        let shared =
            serde_json::to_value(Request::try_from((&fx.vault.folders[&test_uid("S")], &rename)).unwrap()).unwrap();
        assert_eq!(shared["folder_type"], "shared_folder");
        assert_eq!(shared["shared_folder_uid"], test_uid("S").to_string());
        assert_eq!(open_cbc(&shared["name"], fx.key("S")), b"Squad");
        assert_eq!(open_cbc(&shared["data"], fx.key("S")), br#"{"name":"Squad"}"#);

        let nested =
            serde_json::to_value(Request::try_from((&fx.vault.folders[&test_uid("F")], &rename)).unwrap()).unwrap();
        assert_eq!(nested["folder_type"], "shared_folder_folder");
        assert!(nested.get("name").is_none());
        assert_eq!(nested["shared_folder_uid"], test_uid("S").to_string());
        assert_eq!(open_cbc(&nested["data"], fx.key("F")), br#"{"name":"Squad"}"#);
    }

    #[test]
    fn move_selection_and_folder_paths_follow_commander_resolution() {
        let fx = Fx::new();
        let root = Location::Root;
        let folder = |uid: &str| Target::Folder(Location::Folder(test_uid(uid)));
        assert_eq!(locate(&fx.vault, &root, "Personal"), folder("P"));
        assert_eq!(locate(&fx.vault, &Location::Folder(test_uid("P")), "Sub"), folder("Q"));
        assert_eq!(locate(&fx.vault, &root, "/Personal/Sub"), folder("Q"));
        assert_eq!(
            locate(&fx.vault, &root, "/Personal/New"),
            Target::Within {
                parent: Location::Folder(test_uid("P")),
                name:   "New".into(),
            }
        );
        assert_eq!(
            locate(&fx.vault, &root, "/Personal/a//b/New/"),
            Target::Within {
                parent: Location::Folder("CCCC".parse::<Uid>().unwrap()),
                name:   "New".into(),
            }
        );
        assert_eq!(
            locate(&fx.vault, &root, "/New"),
            Target::Within {
                parent: root.clone(),
                name:   "New".into(),
            }
        );
        assert_eq!(locate(&fx.vault, &root, "Nope/New"), Target::Missing);

        let selected_record =
            selected(&fx.vault, &root, test_uid("R3").as_ref(), &Location::Folder(test_uid("P")), Match::Records)
                .unwrap();
        assert_eq!(selected_record, [record_from("R3", "Q")]);
        let by_title =
            selected(&fx.vault, &root, "Personal/Sub/Rou*", &Location::Folder(test_uid("S")), Match::Records).unwrap();
        assert_eq!(by_title, [record_from("R3", "Q")]);
        let shared =
            selected(&fx.vault, &root, "Personal/*", &Location::Folder(test_uid("Q")), Match::SharedFolders).unwrap();
        assert_eq!(
            shared,
            [
                Source::Folder(Location::Folder(test_uid("S"))),
                Source::Folder(Location::Folder(test_uid("T")))
            ]
        );
        assert!(
            selected(
                &fx.vault,
                &Location::Folder(test_uid("Q")),
                test_uid("R3").as_ref(),
                &Location::Folder(test_uid("Q")),
                Match::Records
            )
            .unwrap_err()
            .to_string()
            .contains("are the same")
        );
        assert_eq!(Trail(&fx.vault, &Location::Folder(test_uid("Q"))).to_string(), "Personal/Sub/");
        assert_eq!(Trail(&fx.vault, &root).to_string(), "");
    }

    #[test]
    fn delete_requests_and_predelete_answers_match_wire_format() {
        assert_eq!(
            serde_json::to_value(Request::Delete {
                pre_delete_token: "t".into(),
            })
            .unwrap(),
            json!({ "command": "delete", "pre_delete_token": "t" })
        );
        assert_eq!(
            serde_json::to_value(Request::PreDelete { objects: Vec::new() }).unwrap(),
            json!({ "command": "pre_delete", "objects": [] })
        );
        let answer = json!({ "result": "success", "pre_delete_response": {
            "pre_delete_token": "abc", "would_delete": { "deletion_summary": ["1 folder", "2 records"] }
        }});
        let parsed: PreDeleted = serde_json::from_value(answer).unwrap();
        assert_eq!(parsed.pre_delete_response.pre_delete_token, "abc");
        assert_eq!(parsed.pre_delete_response.would_delete.deletion_summary, ["1 folder", "2 records"]);
    }

    #[test]
    fn deletion_origin_and_paths_match_commander() {
        let fx = Fx::new();
        let folder = &fx.vault.folders[&test_uid("F")];
        let deletion = serde_json::to_value(Deletion::from((&fx.vault, folder))).unwrap();
        assert_eq!(deletion["delete_resolution"], "unlink");
        assert_eq!(deletion["from_type"], "shared_folder_folder");
        assert!(Glob::new("*prod*db", Case::Ignore).is_match("My prod DB"));
        assert!(!Glob::new("Old*", Case::Exact).is_match("Bold"));
        assert!(Glob::new("a?c", Case::Exact).is_match("abc"));
        assert!(!Glob::new("a?c", Case::Exact).is_match("ac"));
        assert!(Glob::new("h?llo", Case::Ignore).is_match("HÉLLO"));
        assert!(Glob::new("*", Case::Exact).is_match(""));
    }

    #[test]
    fn prompts_and_legacy_flags_parse_like_commander() {
        assert_eq!("a".parse::<Perms>().unwrap(), Perms::ALL);
        assert_eq!(
            "UE".parse::<Perms>().unwrap(),
            Perms {
                manage_users: true,
                can_edit: true,
                ..Perms::default()
            }
        );
        assert_eq!("Y".parse::<Answer>().unwrap(), Answer::Yes);
        assert_eq!("".parse::<Answer>().unwrap(), Answer::No);
        assert_eq!("Dev//Ops".parse::<FolderName>().unwrap().0, "Dev/Ops");
        assert!("a/b".parse::<FolderName>().is_err());
        let args = ["keeper-cli", "mkdir", "-sf", "-a", "Team"];
        let command = Cli::try_parse_from(crate::normalize_args(args.into_iter().map(Into::into)))
            .unwrap()
            .command;
        let Some(Command::Mkdir(mkdir)) = command else {
            panic!("not mkdir: {command:?}")
        };
        assert!(mkdir.shared_folder && mkdir.grant.all && !mkdir.user_folder);
        assert_eq!(mkdir.folder.as_deref(), Some("Team"));
    }
}
