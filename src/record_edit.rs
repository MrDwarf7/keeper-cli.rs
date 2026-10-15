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
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, ValueEnum};
use field::{Body, Findings, Labels, NotesEdit, Spec, TypeDef};
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::{self, Session};
use crate::commands::{App, Run, resolve_folder, resolve_record};
use crate::crypto;
use crate::prelude::*;
use crate::proto::account_summary::AccountSummaryElements;
use crate::proto::records as pb;
use crate::vault::{FolderKind, Vault};

/// Commander removes at most this many records per `pre_delete`/`record_update` request.
const REMOVE_CHUNK: usize = 999;

// --- command line ------------------------------------------------------------------------------

// clap has no multi-letter short options, so Commander's `-rt` can't be declared as a flag.
// `record-add` and `record-update` therefore take their arguments raw and hand them to a second
// parser (`AddOpts`/`UpdateOpts`) after spelling `-rt` as `--record-type`.

/// Add a record to a folder
#[derive(Args, Debug)]
#[command(disable_help_flag = true, override_usage = "record-add [OPTIONS] [FIELD=VALUE]...")]
pub struct RecordAdd {
    /// Options and field=value arguments; `record-add --help` lists them
    #[arg(allow_hyphen_values = true, trailing_var_arg = true, value_name = "ARGS")]
    args: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(name = "record-add", no_binary_name = true, about = "Add a record to a folder")]
struct AddOpts {
    /// Display help on field parameters
    #[arg(long)]
    syntax_help: bool,
    /// Ignore warnings
    #[arg(short, long)]
    force:       bool,
    /// Record title
    #[arg(short, long, allow_hyphen_values = true)]
    title:       Option<String>,
    /// Record type, e.g. login (also spelled -rt)
    #[arg(long)]
    record_type: Option<String>,
    /// Label fields of the record type: "on" (default) labels unlabelled ones with their type,
    /// "off" leaves them unlabelled
    #[arg(long, value_enum, default_value_t)]
    labels:      Labels,
    /// Record notes
    #[arg(short, long, allow_hyphen_values = true)]
    notes:       Option<String>,
    /// Folder path or UID to store the record in (default: the vault root)
    #[arg(long)]
    folder:      Option<String>,
    /// Output format
    #[arg(long, value_enum, default_value_t)]
    format:      OutputFormat,
    /// Fields as [f.|c.][type.][label]=value; see --syntax-help
    fields:      Vec<String>,
}

/// Update a record
#[derive(Args, Debug)]
#[command(
    disable_help_flag = true,
    override_usage = "record-update -r RECORD [OPTIONS] [FIELD=VALUE]..."
)]
pub struct RecordUpdate {
    /// Options and field=value arguments; `record-update --help` lists them
    #[arg(allow_hyphen_values = true, trailing_var_arg = true, value_name = "ARGS")]
    args: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(name = "record-update", no_binary_name = true, about = "Update a record")]
struct UpdateOpts {
    /// Display help on field parameters
    #[arg(long)]
    syntax_help: bool,
    /// Ignore warnings
    #[arg(short, long)]
    force:       bool,
    /// New record title
    #[arg(short, long, allow_hyphen_values = true)]
    title:       Option<String>,
    /// Change the record type (also spelled -rt); fields of the new type are added, others kept
    /// as custom fields
    #[arg(long)]
    record_type: Option<String>,
    /// New notes; a leading "+" appends to the existing notes
    #[arg(short, long, allow_hyphen_values = true)]
    notes:       Option<String>,
    /// Record path or UID
    #[arg(short, long)]
    record:      Option<String>,
    /// Fields as [f.|c.][type.][label]=value (empty value deletes); see --syntax-help
    fields:      Vec<String>,
}

/// Append text to a record's notes
#[derive(Args, Debug)]
pub struct AppendNotes {
    /// Text to append (prompted for when omitted)
    #[arg(long, allow_hyphen_values = true)]
    notes:  Option<String>,
    /// Record path or UID
    record: Option<String>,
}

/// Remove records from your vault, or delete them for everyone with --purge
#[derive(Args, Debug)]
pub struct Rm {
    /// Do not prompt
    #[arg(short, long)]
    force:   bool,
    /// Permanently delete the records for ALL users (default: remove only from your vault)
    #[arg(long)]
    purge:   bool,
    /// Record paths or UIDs; may be repeated
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

impl From<bool> for Warnings {
    fn from(force: bool) -> Self {
        if force { Self::Ignore } else { Self::Heed }
    }
}

/// Whether to ask before removing (`rm -f` doesn't).
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Removal {
    /// Take the record out of the folders named, leaving it for other users.
    Unlink,
    /// Delete it for every user (owner only).
    Purge,
}

impl From<bool> for Removal {
    fn from(purge: bool) -> Self {
        if purge { Self::Purge } else { Self::Unlink }
    }
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

impl TryFrom<AddOpts> for Add {
    type Error = Error;

    fn try_from(opts: AddOpts) -> Result<Self> {
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
            warnings: opts.force.into(),
            labels: opts.labels,
            format: opts.format,
        })
    }
}

impl TryFrom<UpdateOpts> for Edit {
    type Error = Error;

    fn try_from(opts: UpdateOpts) -> Result<Self> {
        Ok(Self {
            record:      opts
                .record
                .filter(|r| !r.is_empty())
                .ok_or_else(|| Error::Generic("Record parameter is required.".into()))?,
            title:       opts.title.filter(|t| !t.is_empty()),
            notes:       opts.notes.as_deref().map(NotesEdit::from),
            record_type: opts.record_type.filter(|t| !t.is_empty()),
            specs:       parse_specs(&opts.fields)?,
            warnings:    opts.force.into(),
        })
    }
}

/// Parses a command's raw arguments, spelling Commander's `-rt` the way clap understands.
/// `None` means help was printed instead.
fn parse<P: Parser>(args: &[String]) -> Result<Option<P>> {
    let args = args.iter().map(|arg| {
        match arg.strip_prefix("-rt") {
            Some("") => "--record-type".to_owned(),
            Some(value) if value.starts_with('=') => format!("--record-type{value}"),
            _ => arg.clone(),
        }
    });
    match P::try_parse_from(args) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(e) if !e.use_stderr() => {
            e.print()?;
            Ok(None)
        }
        Err(e) => Err(Error::Generic(e.to_string().trim_start_matches("error: ").trim_end().to_owned())),
    }
}

impl Run for RecordAdd {
    fn run(self, app: &mut App) -> Result<()> {
        let Some(opts) = parse::<AddOpts>(&self.args)? else {
            return Ok(());
        };
        if opts.syntax_help {
            println!("{SYNTAX_HELP}");
            return Ok(());
        }
        let add = Add::try_from(opts)?;
        with_vault(app, |ctx| create(ctx, &add))
    }
}

impl Run for RecordUpdate {
    fn run(self, app: &mut App) -> Result<()> {
        let Some(opts) = parse::<UpdateOpts>(&self.args)? else {
            return Ok(());
        };
        if opts.syntax_help {
            println!("{SYNTAX_HELP}");
            return Ok(());
        }
        let edit = Edit::try_from(opts)?;
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
            match Removal::from(self.purge) {
                Removal::Unlink => unlink(ctx.session, &filings, self.force.into()),
                Removal::Purge => purge(ctx, &filings, self.force.into()),
            }
        })
    }
}

/// A logged-in session with the vault it last synced and the shell's current folder.
struct Ctx<'a> {
    session: &'a mut Session,
    vault:   &'a Vault,
    cwd:     &'a str,
}

/// Runs a write against the synced vault. Commander re-syncs after every write, so the cached
/// vault is dropped afterwards and the next command downloads it again.
fn with_vault<T>(app: &mut App, job: impl FnOnce(&mut Ctx) -> Result<T>) -> Result<T> {
    let cwd = app.cwd.clone();
    app.vault()?;
    let (Some(session), Some(vault)) = (app.session.as_mut(), app.vault.as_ref()) else {
        return Err(Error::NotLoggedIn);
    };
    let outcome = job(&mut Ctx {
        session,
        vault,
        cwd: &cwd,
    });
    app.vault = None;
    outcome
}

// --- ids and time ------------------------------------------------------------------------------

/// A Keeper UID: 16 bytes, shown as unpadded URL-safe base64.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Uid([u8; 16]);

impl Uid {
    fn random() -> Self {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&crypto::random_bytes(16));
        // Keeper keeps the first character away from '-' and '_' so a UID never looks like an option.
        if bytes[0] & 0xf8 == 0xf8 {
            bytes[0] &= 0x7f;
        }
        Self(bytes)
    }
}

impl std::fmt::Display for Uid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b64_encode(&self.0))
    }
}

impl std::str::FromStr for Uid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = b64_decode(s)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| Error::Generic(format!("invalid UID '{s}'")))?,
        ))
    }
}

impl From<&Uid> for Vec<u8> {
    fn from(uid: &Uid) -> Self {
        uid.0.to_vec()
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// --- adding and updating -----------------------------------------------------------------------

fn create(ctx: &mut Ctx, add: &Add) -> Result<()> {
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
        uid: Uid::random(),
        key: crypto::random_bytes(32),
        body,
    };
    let now = now_millis();
    let links = links(ctx.vault, &new.key, &field::refs(&new.body))?;
    let rq = pb::RecordsAddRequest {
        records:                vec![record_add(&ctx.session.data_key, &new, &place, links, now)?],
        client_time:            now,
        security_data_key_type: pb::RecordKeyType::from(&ctx.session.summary) as i32,
    };
    let rs: pb::RecordsModifyResponse = ctx.session.call_typed("vault/records_add", &rq)?;
    verdict(&rs, &new.uid)?;
    match add.format {
        OutputFormat::Text => println!("{}", new.uid),
        OutputFormat::Json => println!("{}", json!({ "record_uid": new.uid.to_string() })),
    }
    Ok(())
}

fn update(ctx: &mut Ctx, edit: &Edit) -> Result<()> {
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
    let rs: pb::RecordsModifyResponse = ctx.session.call_typed("vault/records_update", &rq)?;
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
    let rs: pb::RecordTypesResponse = session.call_typed("vault/get_record_types", &rq)?;
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
    key:  Vec<u8>,
    body: Body,
}

/// A record about to be changed, as the vault holds it.
#[derive(Debug)]
struct Existing {
    uid:      Uid,
    key:      Vec<u8>,
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
        key:    Vec<u8>,
    },
}

/// Commander pads record JSON to a multiple of 16 bytes, at least 384, so the ciphertext length
/// doesn't give the content away.
fn padded_json(body: &Body) -> Result<Vec<u8>> {
    let mut json = serde_json::to_vec(body)?;
    json.resize(json.len().max(384).next_multiple_of(16), b' ');
    Ok(json)
}

fn record_add(
    data_key: &[u8],
    new: &New,
    place: &Placement,
    links: Vec<pb::RecordLink>,
    now: i64,
) -> Result<pb::RecordAdd> {
    let (folder_type, folder_uid, folder_key) = match place {
        Placement::Root => (pb::RecordFolderType::UserFolder, Vec::new(), Vec::new()),
        Placement::Private(folder) => (pb::RecordFolderType::UserFolder, folder.into(), Vec::new()),
        Placement::Shared { folder, kind, key } => (*kind, folder.into(), crypto::encrypt_aes_v2(&new.key, key)?),
    };
    Ok(pb::RecordAdd {
        record_uid: (&new.uid).into(),
        record_key: crypto::encrypt_aes_v2(&new.key, data_key)?,
        client_modified_time: now,
        data: crypto::encrypt_aes_v2(&padded_json(&new.body)?, &new.key)?,
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
        data: crypto::encrypt_aes_v2(&padded_json(&old.body)?, &old.key)?,
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

/// Resolves `--folder` (a path or UID) to where a record is filed.
fn placement(vault: &Vault, cwd: &str, path: &str) -> Result<Placement> {
    let uid = resolve_folder(vault, cwd, path).ok_or_else(|| Error::Generic(format!("Folder not found: {path}")))?;
    let Some(folder) = vault.folders.get(&uid) else {
        return Ok(Placement::Root);
    };
    let kind = match folder.kind {
        FolderKind::User => return Ok(Placement::Private(uid.parse()?)),
        FolderKind::SharedFolder => pb::RecordFolderType::SharedFolder,
        FolderKind::SharedFolderFolder => pb::RecordFolderType::SharedFolderFolder,
    };
    let shared = folder
        .shared_folder_uid
        .as_ref()
        .and_then(|sf| vault.shared_folders.get(sf))
        .ok_or_else(|| Error::Generic(format!("The key of the shared folder containing {path} is not available")))?;
    Ok(Placement::Shared {
        folder: uid.parse()?,
        kind,
        key: shared.key.clone(),
    })
}

/// Finds the record to edit by UID or path/title, if it is a typed record.
fn existing(vault: &Vault, cwd: &str, spec: &str) -> Result<Existing> {
    let record =
        resolve_record(vault, cwd, spec).ok_or_else(|| Error::Generic(format!("Record \"{spec}\" not found.")))?;
    match record.version {
        3 | 6 => {}
        2 => {
            return Err(Error::Generic(
                "Legacy record type is not supported. Convert the record to login record type.".into(),
            ));
        }
        _ => return Err(Error::Generic(format!("Record \"{spec}\" can not be edited."))),
    }
    Ok(Existing {
        uid:      record.uid.parse()?,
        key:      record.key.clone(),
        revision: record.revision,
        body:     serde_json::from_value(record.data.clone())?,
    })
}

/// A `RecordLink` for each referenced record this account can read, which is how Commander
/// attaches linked records (a reference to a record this account doesn't hold is left unlinked).
fn links(vault: &Vault, record_key: &[u8], refs: &BTreeSet<String>) -> Result<Vec<pb::RecordLink>> {
    refs.iter()
        .filter_map(|uid| vault.records.get(uid))
        .map(|target| {
            Ok(pb::RecordLink {
                record_uid: Vec::from(&target.uid.parse::<Uid>()?),
                record_key: crypto::encrypt_aes_v2(&target.key, record_key)?,
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
fn origin(vault: &Vault, folder: &str) -> Option<Origin> {
    if folder.is_empty() {
        return Some(Origin::Root);
    }
    Some(match vault.folders.get(folder)?.kind {
        FolderKind::User => Origin::Private(folder.to_owned()),
        FolderKind::SharedFolder | FolderKind::SharedFolderFolder => Origin::Shared(folder.to_owned()),
    })
}

/// Everything a name given to `rm` stands for: a UID (every folder holding the record), or a
/// path/title (that folder only), falling back to a title match anywhere in the vault.
fn find(vault: &Vault, cwd: &str, name: &str) -> Result<Vec<Filing>> {
    // The folders a record is filed in, in a stable order.
    let filed = |uid: &str| -> Vec<Filing> {
        let mut folders: Vec<&String> = vault
            .folder_records
            .iter()
            .filter(|(_, records)| records.contains(uid))
            .map(|(folder, _)| folder)
            .collect();
        folders.sort();
        folders
            .into_iter()
            .filter_map(|folder| {
                Some(Filing {
                    record: uid.to_owned(),
                    origin: origin(vault, folder)?,
                })
            })
            .collect()
    };

    if vault.records.contains_key(name) {
        let filings = filed(name);
        return Ok(if filings.is_empty() {
            vec![Filing {
                record: name.to_owned(),
                origin: Origin::Root,
            }]
        } else {
            filings
        });
    }

    let (dir, title) = split_name(name);
    let lower = title.to_lowercase();
    let mut found = Vec::new();
    if let Some(folder) = resolve_folder(vault, cwd, &dir) {
        let here = origin(vault, &folder);
        for record in vault
            .records_in(&folder)
            .filter(|r| r.uid == title || r.title().to_lowercase() == lower)
        {
            found.extend(here.clone().map(|origin| {
                Filing {
                    record: record.uid.clone(),
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

/// Splits `folder/title` at the last `/` that isn't half of an escaped `//`.
fn split_name(name: &str) -> (String, String) {
    let masked = name.replace("//", "\0");
    match masked.rsplit_once('/') {
        Some(("", title)) => ("/".to_owned(), title.replace('\0', "/")),
        Some((dir, title)) => (dir.replace('\0', "//"), title.replace('\0', "/")),
        None => (String::new(), masked.replace('\0', "/")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
}

fn ask(question: &str) -> Result<Answer> {
    loop {
        match auth::prompt(&format!("{question} [y/n]: "))?.to_lowercase().as_str() {
            "y" => return Ok(Answer::Yes),
            "" | "n" => return Ok(Answer::No),
            _ => eprintln!("Error: invalid input"),
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
        let rs = session.execute_v2(json!({ "command": "pre_delete", "objects": objects }))?;
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
        session.execute_v2(json!({ "command": "delete", "pre_delete_token": pre["pre_delete_token"] }))?;
    }
    Ok(())
}

/// Deletes records for every user; only the owner of a record may.
fn purge(ctx: &mut Ctx, filings: &[Filing], confirm: Confirm) -> Result<()> {
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
            .execute_v2(json!({ "command": "record_update", "delete_records": chunk }))?;
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
Commander supports two types of records:
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

Use the full syntax too when a label contains a dot (.):
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
                                           special characters
$JSON:<JSON TEXT>       any object         Sets a field value as JSON       phone.Cell=$JSON:'{"number": "(555) 555-1234", "type": "Mobile"}'

Not supported: file attachments (file=@path), $GEN for key pairs, and the dice, crypto and
passphrase $GEN algorithms.
"#;

#[cfg(test)]
mod tests;
