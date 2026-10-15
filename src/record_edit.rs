//! `record-add`, `record-update`, `append-notes` and `rm`: Commander's everyday record write
//! commands.
//!
//! As in Commander only typed (v3/v6) records are created and edited; legacy records are refused
//! with the same advice. Edits are encrypted client-side (AES-GCM) and sent through the protobuf
//! `vault/records_add` and `vault/records_update` endpoints; deletion still goes through the
//! legacy JSON `pre_delete`/`delete` commands, as in Commander.
//!
//! Not carried over from Commander: file attachments (`file=@path`), `--self-destruct` share
//! links and onboarding e-mail, `--pam-config` password sync, enterprise password-complexity
//! and record-type enforcement, master-password re-entry, and the audit/security-score blobs
//! enterprise accounts attach to records.

mod field;

use std::collections::BTreeSet;
use std::str::FromStr;
use std::time;

use clap::{Args, ValueEnum};
use field::{Body, Findings, Labels, NotesEdit, Spec, TypeDef};
use prost::Message;
use serde::Serialize;
use serde_json::Value;

use crate::auth::{self, Session};
use crate::commands::{App, Run};
use crate::crypto::AesKey;
use crate::prelude::*;
use crate::proto::account_summary::AccountSummaryElements;
use crate::proto::records as pb;
use crate::uid::Uid;
use crate::vault::{FolderKind, Location, RecordKind, Vault};

/// Commander removes at most this many records per `pre_delete`/`record_update` request.
const REMOVE_CHUNK: usize = 999;

/// Add a record to a folder.
#[derive(Args, Debug)]
pub struct RecordAdd {
    /// Display help on field parameters.
    #[arg(long)]
    syntax_help: bool,
    /// Ignore warnings.
    #[arg(short, long)]
    force:       bool,
    /// Record title.
    #[arg(short, long, allow_hyphen_values = true)]
    title:       Option<String>,
    /// Record type, e.g. login (also spelled -rt).
    #[arg(long)]
    record_type: Option<String>,
    /// Label fields of the record type: "on" (default) labels unlabelled ones with their type,
    /// "off" leaves them unlabelled.
    #[arg(long, value_enum, default_value_t)]
    labels:      Labels,
    /// Record notes.
    #[arg(short, long, allow_hyphen_values = true)]
    notes:       Option<String>,
    /// Folder path or UID to store the record in (default: the vault root).
    #[arg(long)]
    folder:      Option<String>,
    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    format:      OutputFormat,
    /// Fields as [f.|c.][type.][label]=value; see --syntax-help.
    #[arg(value_name = "FIELD=VALUE", allow_hyphen_values = true)]
    fields:      Vec<String>,
}

/// Update a record.
#[derive(Args, Debug)]
pub struct RecordUpdate {
    /// Display help on field parameters.
    #[arg(long)]
    syntax_help: bool,
    /// Ignore warnings.
    #[arg(short, long)]
    force:       bool,
    /// New record title.
    #[arg(short, long, allow_hyphen_values = true)]
    title:       Option<String>,
    /// Change the record type (also spelled -rt); fields of the new type are added, others kept
    /// as custom fields.
    #[arg(long)]
    record_type: Option<String>,
    /// New notes; a leading "+" appends to the existing notes.
    #[arg(short, long, allow_hyphen_values = true)]
    notes:       Option<String>,
    /// Record path or UID.
    #[arg(short = 'r', long)]
    record:      Option<String>,
    /// Fields as [f.|c.][type.][label]=value (empty value deletes); see --syntax-help.
    #[arg(value_name = "FIELD=VALUE", allow_hyphen_values = true)]
    fields:      Vec<String>,
}

/// Append text to a record's notes.
#[derive(Args, Debug)]
pub struct AppendNotes {
    /// Text to append (prompted for when omitted).
    #[arg(long, allow_hyphen_values = true)]
    notes:  Option<String>,
    /// Record path or UID.
    record: Option<String>,
}

/// Remove records from your vault, or delete them for everyone with --purge.
#[derive(Args, Debug)]
pub struct Rm {
    /// Do not prompt.
    #[arg(short, long)]
    force:   bool,
    /// Permanently delete the records for ALL users (default: remove only from your vault).
    #[arg(long)]
    purge:   bool,
    /// Record paths or UIDs; may be repeated.
    records: Vec<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// What to do about warnings collected while editing (`-f/--force` ignores them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Warnings {
    #[default]
    Heed,
    Ignore,
}

/// Whether to ask before removing (`rm -f` doesn't).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Confirm {
    Ask,
    Skip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Removal {
    /// Take the record out of the folders named, leaving it for other users.
    Unlink,
    /// Delete it for every user (owner only).
    Purge,
}

/// A validated `record-add`.
struct Add {
    title:       String,
    record_type: String,
    notes:       String,
    destination: Destination,
    specs:       Vec<Spec>,
    warnings:    Warnings,
    labels:      Labels,
    format:      OutputFormat,
}

enum Destination {
    Root,
    /// A folder path or UID.
    Folder(String),
}

/// A validated `record-update` (or `append-notes`).
#[derive(Default)]
struct Edit {
    record:      String,
    title:       Option<String>,
    notes:       Option<NotesEdit>,
    record_type: Option<String>,
    specs:       Vec<Spec>,
    warnings:    Warnings,
}

/// Parses `field=value` arguments; attachments (`file=...`) aren't supported.
fn parse_specs(fields: &[String]) -> Result<Vec<Spec>> {
    let specs = fields
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
        .map(str::parse::<Spec>)
        .collect::<Result<Vec<_>>>()?;
    match specs.iter().find(|s| s.ty == "file") {
        Some(_) => Err(Error::Generic("File attachments (file=@path) are not supported yet".into())),
        None => Ok(specs),
    }
}

impl TryFrom<RecordAdd> for Add {
    type Error = Error;

    fn try_from(opts: RecordAdd) -> Result<Self> {
        let title = opts
            .title
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::Generic("Title parameter is required.".into()))?;
        let record_type = opts
            .record_type
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::Generic("Record type parameter is required.".into()))?;
        if matches!(record_type.as_str(), "legacy" | "general") {
            return Err(Error::Generic("Legacy record type is not supported.".into()));
        }
        Ok(Self {
            title,
            record_type,
            notes: field::Notes::from(opts.notes.unwrap_or_default().as_str()).0,
            destination: opts
                .folder
                .filter(|f| !f.is_empty())
                .map_or(Destination::Root, Destination::Folder),
            specs: parse_specs(&opts.fields)?,
            warnings: if opts.force { Warnings::Ignore } else { Warnings::Heed },
            labels: opts.labels,
            format: opts.format,
        })
    }
}

impl TryFrom<RecordUpdate> for Edit {
    type Error = Error;

    fn try_from(opts: RecordUpdate) -> Result<Self> {
        Ok(Self {
            record:      opts
                .record
                .filter(|r| !r.is_empty())
                .ok_or_else(|| Error::Generic("Record parameter is required.".into()))?,
            title:       opts.title.filter(|t| !t.is_empty()),
            notes:       opts.notes.as_deref().map(NotesEdit::from),
            record_type: opts.record_type.filter(|t| !t.is_empty()),
            specs:       parse_specs(&opts.fields)?,
            warnings:    if opts.force { Warnings::Ignore } else { Warnings::Heed },
        })
    }
}

impl Run for RecordAdd {
    fn run(self, app: &mut App) -> Result<()> {
        if self.syntax_help {
            println!("{SYNTAX_HELP}");
            return Ok(());
        }
        let add = Add::try_from(self)?;
        with_vault(app, |ctx| create(ctx, &add))
    }
}

impl Run for RecordUpdate {
    fn run(self, app: &mut App) -> Result<()> {
        if self.syntax_help {
            println!("{SYNTAX_HELP}");
            return Ok(());
        }
        let edit = Edit::try_from(self)?;
        with_vault(app, |ctx| update(ctx, &edit))
    }
}

impl Run for AppendNotes {
    fn run(self, app: &mut App) -> Result<()> {
        let notes = match self.notes.filter(|n| !n.is_empty()) {
            Some(notes) => notes,
            None => {
                loop {
                    let typed = auth::prompt("... Notes to append: ")?;
                    if !typed.is_empty() {
                        break typed;
                    }
                }
            }
        };
        let record = self
            .record
            .filter(|r| !r.is_empty())
            .ok_or_else(|| Error::Generic("Record parameter is required.".into()))?;
        let edit = Edit {
            record,
            notes: Some(NotesEdit::from(format!("+{notes}").as_str())),
            ..Edit::default()
        };
        with_vault(app, |ctx| update(ctx, &edit))
    }
}

impl Run for Rm {
    fn run(self, app: &mut App) -> Result<()> {
        with_vault(app, |ctx| {
            let mut filings = Vec::new();
            for name in &self.records {
                filings.extend(find(ctx.vault, ctx.cwd, name)?);
            }
            let confirm = if self.force { Confirm::Skip } else { Confirm::Ask };
            match if self.purge { Removal::Purge } else { Removal::Unlink } {
                Removal::Unlink => unlink(ctx.session, &filings, confirm),
                Removal::Purge => purge(ctx, &filings, confirm),
            }
        })
    }
}

/// A logged-in session with the vault it last synced and the shell's current folder.
struct Ctx<'a> {
    session: &'a mut Session,
    vault:   &'a Vault,
    cwd:     &'a Location,
}

/// Runs a write against the synced vault. Commander re-syncs after every write, so the cached
/// vault is dropped afterwards and the next command downloads it again.
fn with_vault<T>(app: &mut App, job: impl FnOnce(&mut Ctx<'_>) -> Result<T>) -> Result<T> {
    app.ensure_synced()?;
    let cwd = app.cwd.clone();
    let outcome = {
        let session = app.session.as_mut().ok_or(Error::NotLoggedIn)?;
        let vault = app.vault.as_ref().ok_or(Error::NotLoggedIn)?;
        job(&mut Ctx {
            session,
            vault,
            cwd: &cwd,
        })
    };
    app.vault = None;
    outcome
}

// --- ids and time ------------------------------------------------------------------------------

/// Keeper UIDs are 16 random bytes, shown as unpadded URL-safe base64. Keep the first character
/// away from `-` and `_` so a UID never looks like an option.
fn random_uid() -> Uid {
    let mut bytes = crate::crypto::random_bytes(16);
    if bytes[0] & 0xf8 == 0xf8 {
        bytes[0] &= 0x7f;
    }
    Uid::from(bytes.as_slice())
}

fn now_millis() -> i64 {
    time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// --- adding and updating -----------------------------------------------------------------------

fn create(ctx: &mut Ctx<'_>, add: &Add) -> Result<()> {
    let place = match &add.destination {
        Destination::Root => Placement::Root,
        Destination::Folder(path) => placement(ctx.vault, ctx.cwd, path)?,
    };
    let def = record_type(ctx.session, &add.record_type)?;
    let mut body = Body {
        type_name: add.record_type.clone(),
        title: add.title.clone(),
        notes: add.notes.clone(),
        fields: def
            .fields
            .iter()
            .filter(|f| !f.reference.is_empty())
            .map(|f| f.blank(add.labels))
            .collect(),
        ..Body::default()
    };
    let mut found = Findings::default();
    field::apply(&mut body, &add.specs, &mut found);
    settle(found, add.warnings)?;

    let new = New {
        uid: random_uid(),
        key: AesKey::random(),
        body,
    };
    let now = now_millis();
    let links = links(ctx.vault, &new.key, &field::refs(&new.body))?;
    let rq = pb::RecordsAddRequest {
        records:                vec![record_add(&ctx.session.data_key, &new, &place, links, now)?],
        client_time:            now,
        security_data_key_type: pb::RecordKeyType::from(&ctx.session.summary) as i32,
    };
    let bytes = ctx
        .session
        .rest
        .execute("vault/records_add", &ctx.session.session_token, &rq)?;
    let rs = pb::RecordsModifyResponse::decode(bytes.as_slice())?;
    verdict(&rs, &new.uid)?;
    match add.format {
        OutputFormat::Text => println!("{}", new.uid),
        OutputFormat::Json => println!("{}", serde_json::json!({ "record_uid": new.uid.to_string() })),
    }
    Ok(())
}

fn update(ctx: &mut Ctx<'_>, edit: &Edit) -> Result<()> {
    let mut old = existing(ctx.vault, ctx.cwd, &edit.record)?;
    let mut body = old.body.clone();
    if let Some(title) = &edit.title {
        body.title.clone_from(title);
    }
    if let Some(notes) = edit.notes.clone() {
        notes.apply(&mut body.notes);
    }
    if let Some(name) = &edit.record_type {
        let def = record_type(ctx.session, name)?;
        body.type_name.clone_from(name);
        field::adjust(&mut body, &def.fields);
    }
    let mut found = Findings::default();
    field::apply(&mut body, &edit.specs, &mut found);
    settle(found, edit.warnings)?;

    let (before, after) = (field::refs(&old.body), field::refs(&body));
    old.body = body;
    let now = now_millis();
    let added = links(ctx.vault, &old.key, &after.difference(&before).cloned().collect())?;
    let removed = before
        .difference(&after)
        .map(|r| Ok(Vec::from(&r.parse::<Uid>()?)))
        .collect::<Result<Vec<Vec<u8>>>>()?;
    let rq = pb::RecordsUpdateRequest {
        records:                vec![record_update(&old, added, removed, now)?],
        client_time:            now,
        security_data_key_type: pb::RecordKeyType::from(&ctx.session.summary) as i32,
    };
    let bytes = ctx
        .session
        .rest
        .execute("vault/records_update", &ctx.session.session_token, &rq)?;
    let rs = pb::RecordsModifyResponse::decode(bytes.as_slice())?;
    verdict(&rs, &old.uid)
}

/// Errors stop the command; warnings do too unless ignored, in which case the edits that did
/// apply are saved.
fn settle(found: Findings, warnings: Warnings) -> Result<()> {
    if !found.errors.is_empty() {
        return Err(Error::Generic(found.errors.join("\n")));
    }
    for warning in &found.warnings {
        eprintln!("{warning}");
    }
    if !found.warnings.is_empty() && warnings == Warnings::Heed {
        return Err(Error::Generic(
            "Nothing was saved. Fix the warnings above, or use --force to save the edits that applied.".into(),
        ));
    }
    Ok(())
}

/// The definition of a record type by name or numeric ID, from the server.
fn record_type(session: &mut Session, name: &str) -> Result<TypeDef> {
    let rq = pb::RecordTypesRequest {
        standard:   true,
        user:       true,
        enterprise: true,
        pam:        true,
    };
    let bytes = session
        .rest
        .execute("vault/get_record_types", &session.session_token, &rq)?;
    let rs = pb::RecordTypesResponse::decode(bytes.as_slice())?;
    let wanted_id = name.parse::<i64>().ok();
    rs.record_types
        .iter()
        .find_map(|rt| {
            let def: TypeDef = serde_json::from_str(&rt.content).ok()?;
            // User, enterprise and PAM types are numbered in blocks of a million by scope.
            let id = i64::from(rt.record_type_id) + i64::from(rt.scope) * 1_000_000;
            let hit = wanted_id.map_or(def.id == name, |wanted| wanted == id);
            (hit && !def.fields.is_empty()).then_some(def)
        })
        .ok_or_else(|| Error::Generic(format!("Record type \"{name}\" cannot be found.")))
}

/// A record about to be created.
struct New {
    uid:  Uid,
    key:  AesKey,
    body: Body,
}

/// A record about to be changed, as the vault holds it.
#[derive(Debug)]
struct Existing {
    uid:      Uid,
    key:      AesKey,
    revision: i64,
    body:     Body,
}

/// Where a new record is filed, with the key that makes it readable through a shared folder.
#[derive(Debug, PartialEq)]
enum Placement {
    Root,
    Private(Uid),
    Shared {
        folder: Uid,
        kind:   pb::RecordFolderType,
        key:    AesKey,
    },
}

/// A record's JSON, padded with spaces to a multiple of 16 bytes and at least 384, as Commander
/// does, so the ciphertext length doesn't give the content away.
impl TryFrom<&Body> for Vec<u8> {
    type Error = Error;

    fn try_from(body: &Body) -> Result<Self> {
        let mut json = serde_json::to_vec(body)?;
        json.resize(json.len().max(384).next_multiple_of(16), b' ');
        Ok(json)
    }
}

fn record_add(
    data_key: &AesKey,
    new: &New,
    place: &Placement,
    links: Vec<pb::RecordLink>,
    now: i64,
) -> Result<pb::RecordAdd> {
    let (folder_type, folder_uid, folder_key) = match place {
        Placement::Root => (pb::RecordFolderType::UserFolder, Vec::new(), Vec::new()),
        Placement::Private(folder) => (pb::RecordFolderType::UserFolder, folder.into(), Vec::new()),
        Placement::Shared { folder, kind, key } => {
            (*kind, folder.into(), crate::crypto::encrypt_aes_v2(&new.key, key)?)
        }
    };
    Ok(pb::RecordAdd {
        record_uid: (&new.uid).into(),
        record_key: crate::crypto::encrypt_aes_v2(&new.key, data_key)?,
        client_modified_time: now,
        data: crate::crypto::encrypt_aes_v2(&Vec::<u8>::try_from(&new.body)?, &new.key)?,
        folder_type: folder_type as i32,
        folder_uid,
        folder_key,
        record_links: links,
        ..pb::RecordAdd::default()
    })
}

fn record_update(
    old: &Existing,
    added: Vec<pb::RecordLink>,
    removed: Vec<Vec<u8>>,
    now: i64,
) -> Result<pb::RecordUpdate> {
    Ok(pb::RecordUpdate {
        record_uid: (&old.uid).into(),
        client_modified_time: now,
        revision: old.revision,
        data: crate::crypto::encrypt_aes_v2(&Vec::<u8>::try_from(&old.body)?, &old.key)?,
        record_links_add: added,
        record_links_remove: removed,
        ..pb::RecordUpdate::default()
    })
}

impl From<&AccountSummaryElements> for pb::RecordKeyType {
    /// Which enterprise key the security data of a record is encrypted to.
    fn from(summary: &AccountSummaryElements) -> Self {
        if summary.forbid_key_type2 {
            Self::EncryptedByPublicKeyEcc
        } else {
            Self::EncryptedByPublicKey
        }
    }
}

/// Reports the server's verdict on one record. Like Commander, a response that doesn't mention
/// the record counts as success.
fn verdict(rs: &pb::RecordsModifyResponse, uid: &Uid) -> Result<()> {
    let Some(status) = rs.records.iter().find(|s| s.record_uid == Vec::from(uid)) else {
        return Ok(());
    };
    match pb::RecordModifyResult::try_from(status.status) {
        Ok(pb::RecordModifyResult::RsSuccess) => Ok(()),
        Ok(failure) => Err(Error::api(failure.as_str_name(), status.message.as_str())),
        Err(_) => Err(Error::api(status.status.to_string(), status.message.as_str())),
    }
}

// --- vault lookups -----------------------------------------------------------------------------
//
// Everything the write commands need to know about the synced vault is read here.

/// Resolves `--folder` (a path or UID) to where a record is filed. A typo must not put credentials
/// at the root.
fn placement(vault: &Vault, cwd: &Location, path: &str) -> Result<Placement> {
    let at = vault
        .resolve_folder(cwd, path)
        .ok_or_else(|| Error::Generic(format!("Folder not found: {path}")))?;
    let Some(folder) = vault.folder(&at) else {
        return Ok(Placement::Root);
    };
    let folder_uid = folder.uid.clone();
    let kind = match &folder.kind {
        FolderKind::User => return Ok(Placement::Private(folder_uid)),
        FolderKind::SharedFolder => pb::RecordFolderType::SharedFolder,
        FolderKind::SharedFolderFolder { .. } => pb::RecordFolderType::SharedFolderFolder,
    };
    let shared = folder
        .shared_folder()
        .and_then(|uid| vault.shared_folders.get(uid))
        .ok_or_else(|| Error::Generic(format!("The key of the shared folder containing {path} is not available")))?;
    Ok(Placement::Shared {
        folder: folder_uid,
        kind,
        key: shared.key.clone(),
    })
}

/// Finds the record to edit by UID or path/title, if it is a typed record.
fn existing(vault: &Vault, cwd: &Location, spec: &str) -> Result<Existing> {
    let record = vault
        .resolve_record(cwd, spec)
        .ok_or_else(|| Error::Generic(format!("Record \"{spec}\" not found.")))?;
    match &record.kind {
        RecordKind::Typed | RecordKind::PamConfiguration => {}
        RecordKind::Legacy { .. } => {
            return Err(Error::Generic(
                "Legacy record type is not supported. Convert the record to login record type.".into(),
            ));
        }
        _ => return Err(Error::Generic(format!("Record \"{spec}\" can not be edited."))),
    }
    Ok(Existing {
        uid:      record.uid.clone(),
        key:      record.key.clone(),
        revision: record.revision,
        body:     serde_json::from_value(record.data.clone())?,
    })
}

/// A `RecordLink` for each referenced record this account can read, which is how Commander
/// attaches linked records (a reference to a record this account doesn't hold is left unlinked).
fn links(vault: &Vault, record_key: &AesKey, refs: &BTreeSet<String>) -> Result<Vec<pb::RecordLink>> {
    refs.iter()
        .filter_map(|uid| vault.records.get(uid.as_str()))
        .map(|target| {
            Ok(pb::RecordLink {
                record_uid: Vec::from(&target.uid),
                record_key: crate::crypto::encrypt_aes_v2(&target.key, record_key)?,
            })
        })
        .collect()
}

// --- removing ----------------------------------------------------------------------------------

/// The folder a record is filed in, as `pre_delete` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Origin {
    Root,
    Private(String),
    Shared(String),
}

/// A record in one of the folders it is filed in.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Filing {
    record: String,
    origin: Origin,
}

/// One entry of the `pre_delete` request.
#[derive(Serialize)]
struct Doomed<'a> {
    delete_resolution: &'static str,
    object_uid:        &'a str,
    object_type:       &'static str,
    from_type:         &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_uid:          Option<&'a str>,
}

impl<'a> From<&'a Filing> for Doomed<'a> {
    fn from(filing: &'a Filing) -> Self {
        let (from_type, from_uid) = match &filing.origin {
            Origin::Root => ("user_folder", None),
            Origin::Private(folder) => ("user_folder", Some(folder.as_str())),
            // Commander names shared folders themselves "shared_folder_folder" here too.
            Origin::Shared(folder) => ("shared_folder_folder", Some(folder.as_str())),
        };
        Self {
            delete_resolution: "unlink",
            object_uid: &filing.record,
            object_type: "record",
            from_type,
            from_uid,
        }
    }
}

/// What `pre_delete` calls a folder; `None` for one this vault doesn't know.
fn origin(vault: &Vault, at: &Location) -> Option<Origin> {
    Some(match at {
        Location::Root => Origin::Root,
        Location::Folder(uid) => {
            match &vault.folders.get(uid)?.kind {
                FolderKind::User => Origin::Private(uid.to_string()),
                FolderKind::SharedFolder | FolderKind::SharedFolderFolder { .. } => Origin::Shared(uid.to_string()),
            }
        }
    })
}

/// Everything a name given to `rm` stands for: a UID (every folder holding the record), or a
/// path/title (that folder only), falling back to a title match anywhere in the vault.
fn find(vault: &Vault, cwd: &Location, name: &str) -> Result<Vec<Filing>> {
    // The folders a record is filed in, in a stable order.
    let filed = |uid: &Uid| -> Vec<Filing> {
        let mut locations: Vec<_> = vault.locations_of(uid).collect();
        locations.sort_by_key(|at| {
            match at {
                Location::Root => String::new(),
                Location::Folder(folder) => folder.to_string(),
            }
        });
        locations
            .into_iter()
            .filter_map(|at| {
                Some(Filing {
                    record: uid.to_string(),
                    origin: origin(vault, at)?,
                })
            })
            .collect()
    };

    if let Some(record) = name.parse::<Uid>().ok().and_then(|uid| vault.records.get(&uid)) {
        let filings = filed(&record.uid);
        return Ok(if filings.is_empty() {
            vec![Filing {
                record: record.uid.to_string(),
                origin: Origin::Root,
            }]
        } else {
            filings
        });
    }

    // ponytail: duplicate same-named folders resolve to the first; Commander searches all of them.
    // Walk every match if the vault model gains a duplicate-aware path resolver.
    let Name { folder: dir, title } = Name::from(name);
    let lower = title.to_lowercase();
    let mut found = Vec::new();
    if let Some(folder) = vault.resolve_folder(cwd, &dir) {
        let here = origin(vault, &folder);
        for record in vault
            .records_in(&folder)
            .filter(|r| r.uid.as_ref() == title || r.title().to_lowercase() == lower)
        {
            found.extend(here.clone().map(|origin| {
                Filing {
                    record: record.uid.to_string(),
                    origin,
                }
            }));
        }
    }
    if found.is_empty() {
        let lower = name.to_lowercase();
        found = vault
            .records
            .values()
            .filter(|r| r.title().to_lowercase() == lower)
            .flat_map(|r| filed(&r.uid))
            .collect();
    }
    let uids: BTreeSet<&str> = found.iter().map(|f| f.record.as_str()).collect();
    match uids.len() {
        0 => {
            Err(Error::Generic(format!(
                "No record found matching \"{name}\". Provide a valid record title, path, or UID."
            )))
        }
        1 => Ok(found),
        n => {
            let list: String = uids.iter().map(|uid| format!("\n  {uid}")).collect();
            Err(Error::Generic(format!("\"{name}\" matches {n} records. Use a UID to identify the record:{list}")))
        }
    }
}

/// A name given to `rm`: `folder/title`, split at the last `/` that isn't half of an escaped `//`.
struct Name {
    folder: String,
    title:  String,
}

impl From<&str> for Name {
    fn from(name: &str) -> Self {
        let masked = name.replace("//", "\0");
        let (folder, title) = match masked.rsplit_once('/') {
            Some(("", title)) => ("/".to_owned(), title),
            Some((dir, title)) => (dir.replace('\0', "//"), title),
            None => (String::new(), masked.as_str()),
        };
        Self {
            folder,
            title: title.replace('\0', "/"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
}

impl FromStr for Answer {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        match typed.to_lowercase().as_str() {
            "y" => Ok(Self::Yes),
            "" | "n" => Ok(Self::No),
            _ => Err(Error::Generic("invalid input".into())),
        }
    }
}

fn ask(question: &str) -> Result<Answer> {
    loop {
        match auth::prompt(&format!("{question} [y/n]: "))?.parse() {
            Ok(answer) => return Ok(answer),
            Err(_) => eprintln!("Error: invalid input"),
        }
    }
}

/// Takes records out of the folders they were found in; the server first reports what that
/// would delete, which is shown before asking.
fn unlink(session: &mut Session, filings: &[Filing], confirm: Confirm) -> Result<()> {
    for chunk in filings.chunks(REMOVE_CHUNK) {
        let objects = chunk
            .iter()
            .map(|f| serde_json::to_value(Doomed::from(f)))
            .collect::<Result<Vec<_>, _>>()?;
        let rs = session.execute_v2(serde_json::json!({ "command": "pre_delete", "objects": objects }))?;
        let pre = &rs["pre_delete_response"];
        if confirm == Confirm::Ask {
            for line in pre["would_delete"]["deletion_summary"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                println!("{line}");
            }
            if ask("Do you want to proceed with removal?")? == Answer::No {
                continue;
            }
        }
        session.execute_v2(serde_json::json!({ "command": "delete", "pre_delete_token": pre["pre_delete_token"] }))?;
    }
    Ok(())
}

/// Deletes records for every user; only the owner of a record may.
fn purge(ctx: &mut Ctx<'_>, filings: &[Filing], confirm: Confirm) -> Result<()> {
    let uids: BTreeSet<&str> = filings.iter().map(|f| f.record.as_str()).collect();
    let (owned, foreign): (Vec<&str>, Vec<&str>) = uids
        .into_iter()
        .partition(|uid| ctx.vault.records.get(*uid).is_some_and(|r| r.owner));
    for uid in foreign {
        let title = ctx.vault.records.get(uid).map_or(uid, |r| r.title());
        eprintln!("Cannot permanently delete \"{title}\": you are not the record owner.");
    }
    if owned.is_empty() {
        return Ok(());
    }
    if confirm == Confirm::Ask {
        println!("This will permanently delete {} record(s) for ALL users.", owned.len());
        if ask("Do you want to proceed?")? == Answer::No {
            return Ok(());
        }
    }
    let mut deleted = 0;
    for chunk in owned.chunks(REMOVE_CHUNK) {
        let rs = ctx
            .session
            .execute_v2(serde_json::json!({ "command": "record_update", "delete_records": chunk }))?;
        for status in rs["delete_records"].as_array().into_iter().flatten() {
            if status["status"] == "success" {
                deleted += 1;
            } else {
                eprintln!(
                    "Failed to delete record {}: {}",
                    status["uid"].as_str().unwrap_or_default(),
                    status["status"].as_str().unwrap_or_default()
                );
            }
        }
    }
    if deleted > 0 {
        eprintln!("{deleted} record(s) permanently deleted for all users.");
    }
    Ok(())
}

const SYNTAX_HELP: &str = r#"
There are two types of records:
1. Typed
2. Legacy (not editable here; convert the record to a typed one in the Vault)

The content of a Typed record is defined by its record type, which names the fields it starts
with (login, password, url, ...). Use a type name, or its numeric ID, with -rt.

Record fields are written as
  [<FIELD_SET>.][<FIELD_TYPE>.][<FIELD_LABEL>]=[<FIELD_VALUE>]
1. FIELD_SET:   Optional. "f" or "c". "f." only looks at the fields of the record type.
2. FIELD_TYPE:  Mandatory for the fields of the record type, optional for custom fields. When
                omitted, "text" is assumed.
3. FIELD_LABEL: Optional. When adding several custom fields of the same type make the label unique.
4. FIELD_VALUE: Optional. If empty, the field is deleted (or cleared, for fields of the record type).
Example:   "url.Web URL=https://google.com"

Field types are case sensitive. Field labels are case insensitive.

Use the full <FIELD_TYPE>.<FIELD_LABEL> syntax when a label collides with a field type:
  "password"          the "password" field
  "text.password"     a "text" field labelled "password"
  "Password"          a "text" field labelled "Password"

Use the full syntax too when a field label contains a dot (.):
  "google.com"        would be field type "google"
  "text.google.com"   field type "text", label "google.com"

If a field label contains an equal sign (=) double it. If a value starts with an equal sign
prepend it with a space:
  text.aaa==bbb=" =ccc"   sets the custom field labelled "aaa=bbb" to "=ccc"

Notes (-n) can contain \n for a new line. With record-update, a leading + appends to the notes.

Field Type        Description            Value Type     Examples
===========       ==================     ==========     =====================================
date              Unix epoch time        integer        1668639533 | 2022-11-16T10:58:53Z | 2022-11-16
checkbox          Yes/No                 boolean        yes | no | true | false
host              host name / port       object         192.168.1.2:4321
address           Address                object         123 Main St, SmallTown, CA 12345, USA
phone             Phone                  object         Mobile: US (555)555-1234
name              Person name            object         Doe, John Jr. | Jane Doe
securityQuestion  Security Q & A         array          What city you were ...? city; What is the name of ...? name
paymentCard       Payment Card           object         4111111111111111 04/2026 123
bankAccount       Bank Account           object         Checking: 123456789 987654321
keyPair           Key Pair               object         private key, with \n for new lines
oneTimeCode       TOTP URL               string         otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Keeper
note, multiline   Multiline text         string
secret            Masked text            string
login, email      Login, e-mail          string
password          Password               string
url               URL                    string         https://google.com/
text              Free form text         string         This field type generally has a label

$<ACTION>[:<PARAMS>, <PARAMS>]   computes a field value

Value                   Field type         Description                      Example
====================    ===============    ===================              ==============
$GEN:[alg],[n]          password           Generates a random password      $GEN:rand,16
                                           alg: rand (default); n: length
$GEN                    oneTimeCode        Generates a TOTP URL
$BASE64:<BASE64>        any string field   Decodes a base64 value           password=$BASE64:ZmpzemRmaGtkZg==
                                           Useful for passwords with        Decodes to: fjszdfhkdf
$JSON:<JSON TEXT>       any object         Sets a field value as JSON       phone.Cell=$JSON:'{"number": "(555) 555-1234", "type": "Mobile"}'

Not supported: file attachments (file=@path), $GEN for key pairs, and the dice, crypto and
passphrase $GEN algorithms.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> AesKey {
        AesKey::try_from(vec![byte; 32]).unwrap()
    }

    #[test]
    fn add_encrypts_keys_and_padded_record_body() {
        let new = New {
            uid:  Uid::from(&[1; 16][..]),
            key:  key(2),
            body: Body {
                type_name: "login".into(),
                title: "test".into(),
                ..Body::default()
            },
        };
        let data_key = key(3);
        let request = record_add(&data_key, &new, &Placement::Root, Vec::new(), 17).unwrap();
        assert_eq!(crate::crypto::decrypt_aes_v2(&request.record_key, &data_key).unwrap(), new.key.to_vec());
        let plaintext = crate::crypto::decrypt_aes_v2(&request.data, &new.key).unwrap();
        assert!(plaintext.len() >= 384 && plaintext.len().is_multiple_of(16));
        assert_eq!(serde_json::from_slice::<Body>(&plaintext).unwrap().title, "test");
        assert_eq!(request.client_modified_time, 17);
    }
    #[test]
    fn shared_subfolder_placement_uses_its_shared_folder_key() {
        let shared_uid = Uid::from(&[7; 16][..]);
        let folder_uid = Uid::from(&[8; 16][..]);
        let shared_key = key(9);
        let mut vault = Vault::default();
        vault.shared_folders.insert(
            shared_uid.clone(),
            crate::vault::SharedFolder {
                uid:                    shared_uid.clone(),
                name:                   "shared".into(),
                key:                    shared_key.clone(),
                record_uids:            Vec::new(),
                users:                  Vec::new(),
                teams:                  Vec::new(),
                default_manage_records: false,
                default_manage_users:   false,
                default_can_edit:       false,
                default_can_share:      false,
            },
        );
        vault.folders.insert(
            folder_uid.clone(),
            crate::vault::Folder {
                uid:        folder_uid.clone(),
                name:       "nested".into(),
                data:       Value::Null,
                kind:       FolderKind::SharedFolderFolder {
                    shared_folder: shared_uid,
                },
                parent:     Location::Root,
                subfolders: Vec::new(),
                key:        Some(shared_key.clone()),
            },
        );

        assert_eq!(
            placement(&vault, &Location::Root, folder_uid.as_ref()).unwrap(),
            Placement::Shared {
                folder: folder_uid,
                kind:   pb::RecordFolderType::SharedFolderFolder,
                key:    shared_key,
            }
        );
    }

    #[test]
    fn update_preserves_record_revision_and_link_changes() {
        let old = Existing {
            uid:      Uid::from(&[4; 16][..]),
            key:      key(5),
            revision: 8,
            body:     Body {
                title: "updated".into(),
                ..Body::default()
            },
        };
        let request = record_update(&old, Vec::new(), vec![vec![9; 16]], 23).unwrap();
        assert_eq!(request.record_uid, Vec::<u8>::from(&old.uid));
        assert_eq!(request.revision, 8);
        assert_eq!(request.client_modified_time, 23);
        assert_eq!(request.record_links_remove, vec![vec![9; 16]]);
        let plaintext = crate::crypto::decrypt_aes_v2(&request.data, &old.key).unwrap();
        assert_eq!(serde_json::from_slice::<Body>(&plaintext).unwrap().title, "updated");
    }

    #[test]
    fn rm_names_split_at_the_last_unescaped_slash() {
        let name = Name::from("/team/a//b/record/title");
        assert_eq!(name.folder, "/team/a//b/record");
        assert_eq!(name.title, "title");
        let root = Name::from("/title");
        assert_eq!(root.folder, "/");
        assert_eq!(root.title, "title");
        let local = Name::from("name");
        assert_eq!(local.folder, "");
        assert_eq!(local.title, "name");
    }
    #[test]
    fn rm_accepts_padded_record_uids() {
        let uid = Uid::from(&[10; 16][..]);
        let mut vault = Vault::default();
        vault.records.insert(
            uid.clone(),
            crate::vault::Record {
                uid:                  uid.clone(),
                kind:                 RecordKind::Typed,
                data:                 serde_json::json!({ "title": "item" }),
                revision:             0,
                shared:               false,
                client_modified_time: 0,
                key:                  key(11),
                owner:                true,
                udata:                None,
            },
        );
        let filings = find(&vault, &Location::Root, &format!("{uid}==")).unwrap();
        assert_eq!(
            filings,
            vec![Filing {
                record: uid.to_string(),
                origin: Origin::Root,
            }]
        );
    }
}
