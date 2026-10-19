//! Download and upload files attached to Keeper records.
//!
//! Typed records point to v4 file records through `fileRef`; legacy records keep files in
//! `extra.files`. GCM tags and legacy CBC padding are checked before output files are created; CBC
//! has no MAC in its legacy framing.

use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::str::FromStr;

use aes::cipher::block_padding::Pkcs7;
use clap::Args;
use prost::Message;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use crate::auth::Session;
use crate::commands::{App, Run};
use crate::crypto::{self, AesKey};
use crate::prelude::*;
use crate::proto::records::{
    File as FileEntry,
    FileAddResult,
    FileAddStatus,
    FileGetResult,
    FilesAddRequest,
    FilesAddResponse,
    FilesGetRequest,
    FilesGetResponse,
    RecordKeyType,
    RecordLink,
    RecordModifyResult,
    RecordUpdate,
    RecordsModifyResponse,
    RecordsUpdateRequest,
};
use crate::vault::{LegacyFile, Location, Record, RecordField, RecordKind, TypedRecord, Vault};
const TRANSFER_WORKERS: usize = 4;
const TRANSFER_BUFFER_BUDGET: usize = 64 * 1024 * 1024;

struct TransferBudget {
    state: std::sync::Mutex<crate::error::TransferAdmissionState>,
    ready: std::sync::Condvar,
}

#[derive(Clone, Copy)]
enum BufferDemand {
    Known(usize),
    Unknown,
}

#[derive(Clone, Copy)]
enum PermitKind {
    Shared(usize),
    Exclusive,
}

impl TransferBudget {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(crate::error::TransferAdmissionState::Shared(0)),
            ready: std::sync::Condvar::new(),
        }
    }

    fn owned_poison(
        &self,
        error: std::sync::PoisonError<std::sync::MutexGuard<'_, crate::error::TransferAdmissionState>>,
    ) -> Error {
        let snapshot = **error.get_ref();
        drop(error.into_inner());
        self.ready.notify_all();
        Error::TransferBudgetPoisoned {
            source: std::sync::PoisonError::new(snapshot),
        }
    }

    fn acquire(&self, demand: BufferDemand) -> Result<BufferPermit<'_>> {
        let mut state = self.state.lock().map_err(|error| self.owned_poison(error))?;
        loop {
            match (demand, *state) {
                (BufferDemand::Known(bytes), crate::error::TransferAdmissionState::Shared(used))
                    if bytes <= TRANSFER_BUFFER_BUDGET && used.saturating_add(bytes) <= TRANSFER_BUFFER_BUDGET =>
                {
                    *state = crate::error::TransferAdmissionState::Shared(used + bytes);
                    return Ok(BufferPermit {
                        budget: self,
                        kind:   PermitKind::Shared(bytes),
                    });
                }
                (BufferDemand::Unknown | BufferDemand::Known(_), crate::error::TransferAdmissionState::Shared(0)) => {
                    *state = crate::error::TransferAdmissionState::Exclusive;
                    return Ok(BufferPermit {
                        budget: self,
                        kind:   PermitKind::Exclusive,
                    });
                }
                _ => {
                    state = self.ready.wait(state).map_err(|error| self.owned_poison(error))?;
                }
            }
        }
    }

    fn finish(self) -> Result<()> {
        self.state
            .into_inner()
            .map(|_| ())
            .map_err(|source| Error::TransferBudgetPoisoned { source })
    }
}

struct BufferPermit<'a> {
    budget: &'a TransferBudget,
    kind:   PermitKind,
}

impl Drop for BufferPermit<'_> {
    fn drop(&mut self) {
        let mut state = match self.budget.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        match (self.kind, *state) {
            (PermitKind::Shared(bytes), crate::error::TransferAdmissionState::Shared(used)) => {
                let Some(remaining) = used.checked_sub(bytes) else {
                    unreachable!("attachment transfer permit exceeds admitted buffer bytes");
                };
                *state = crate::error::TransferAdmissionState::Shared(remaining);
            }
            (PermitKind::Exclusive, crate::error::TransferAdmissionState::Exclusive) => {
                *state = crate::error::TransferAdmissionState::Shared(0);
            }
            _ => unreachable!("attachment transfer permit/state invariant broken"),
        }
        self.budget.ready.notify_all();
    }
}

fn parallel_each<T: Sync>(items: &[T], work: impl Fn(&T) -> Result<()> + Sync) -> Vec<Error> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let next = AtomicUsize::new(0);
    let workers = TRANSFER_WORKERS.min(items.len());
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut failures = Vec::new();
        for _ in 0..workers {
            let next = &next;
            let work = &work;
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                let mut failures = Vec::new();
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        break failures;
                    };
                    if let Err(error) = work(item) {
                        failures.push(error);
                    }
                }
            }) {
                Ok(handle) => handles.push(handle),
                Err(error) => failures.push(Error::Io(error)),
            }
        }
        for handle in handles {
            match handle.join() {
                Ok(worker_failures) => failures.extend(worker_failures),
                Err(payload) => failures.push(Error::WorkerPanic(payload.into())),
            }
        }
        failures
    })
}

/// Download attachments from one or more records or folders.
#[derive(Args, Debug)]
pub struct DownloadAttachment {
    /// Record or folder UID or path; a folder downloads the attachments of every record in it.
    #[arg(required = true)]
    records:      Vec<String>,
    /// Descend into subfolders.
    #[arg(short, long)]
    recursive:    bool,
    /// Local folder for downloaded files (defaults to the current folder).
    #[arg(long)]
    out_dir:      Option<UserPath>,
    /// Recreate the vault folder structure below the output folder.
    #[arg(long)]
    preserve_dir: bool,
    /// Prefix file names with the record title.
    #[arg(long)]
    record_title: bool,
    /// Only attachments with this name, title or ID (repeatable).
    #[arg(long = "name")]
    names:        Vec<String>,
}

/// A path typed on the command line. A leading `~` means the user's home directory.
#[derive(Clone, Debug)]
pub struct UserPath(PathBuf);

impl FromStr for UserPath {
    type Err = Infallible;

    fn from_str(typed: &str) -> Result<Self, Self::Err> {
        let separators = ['/', MAIN_SEPARATOR];
        let below_home = typed
            .strip_prefix('~')
            .filter(|rest| rest.is_empty() || rest.starts_with(separators));
        Ok(Self(match (below_home, dirs::home_dir()) {
            (Some(rest), Some(home)) => home.join(rest.trim_start_matches(separators)),
            _ => PathBuf::from(typed),
        }))
    }
}

impl AsRef<Path> for UserPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Flat,
    ByFolder,
}

#[derive(Clone, Copy)]
enum Naming {
    Stored,
    WithRecordTitle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    Folder,
    Subtree,
}

/// A file attached to a record, with the key that decrypts its content.
#[derive(Debug, PartialEq, Eq)]
struct Attachment {
    /// A v2 attachment ID, or the UID of a v4 file record.
    id:    String,
    name:  String,
    title: String,
    key:   AesKey,
}

impl TryFrom<&LegacyFile> for Attachment {
    type Error = Error;

    fn try_from(file: &LegacyFile) -> Result<Self> {
        Ok(Self {
            id:    file.id.as_deref().unwrap_or_default().to_owned(),
            name:  file.name.as_deref().unwrap_or_default().to_owned(),
            title: file.title.as_deref().unwrap_or_default().to_owned(),
            key:   AesKey::try_from(b64_decode(file.key.as_deref().unwrap_or_default())?)?,
        })
    }
}

impl TryFrom<&Record> for Attachment {
    type Error = Error;

    fn try_from(file: &Record) -> Result<Self> {
        if !matches!(&file.kind, RecordKind::File { .. }) {
            return Err(Error::Generic(format!("record {} is not a file", file.uid)));
        }
        let text = |field: &str| {
            let value = match field {
                "name" => file.data.name.as_deref(),
                "title" => Some(file.data.title.as_str()),
                "type" => Some(file.data.type_name.as_str()),
                _ => file.data.extra.get(field).and_then(Value::as_str),
            };
            value.unwrap_or_default().trim().to_owned()
        };
        Ok(Self {
            id:    file.uid.to_string(),
            name:  text("name"),
            title: text("title"),
            key:   file.key.clone(),
        })
    }
}

impl Attachment {
    /// A legacy record's `extra.files`, a typed record's linked file records, or a file record itself.
    fn of(vault: &Vault, record: &Record) -> Result<Vec<Self>> {
        match &record.kind {
            RecordKind::Legacy { extra } => {
                extra
                    .as_ref()
                    .map_or(Ok(Vec::new()), |extra| extra.files.iter().map(Self::try_from).collect())
            }
            RecordKind::Typed | RecordKind::PamConfiguration => {
                let mut attachments = Vec::new();
                for uid in record
                    .typed_fields()
                    .find(|field| field.field_type() == "fileRef")
                    .into_iter()
                    .flat_map(|field| field.values())
                    .filter_map(Value::as_str)
                {
                    let file = vault.records.get(uid.trim_end_matches('='));
                    if let Some(file) = file {
                        attachments.push(Self::try_from(file)?);
                    }
                }
                Ok(attachments)
            }
            RecordKind::File { .. } => Ok(vec![Self::try_from(record)?]),
            RecordKind::Application => Ok(Vec::new()),
        }
    }

    fn is_named(&self, wanted: &str) -> bool {
        let same = |text: &str| text.to_lowercase() == wanted.to_lowercase();
        self.id == wanted || same(&self.title) || same(&self.name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cipher {
    Cbc,
    Gcm,
}

impl From<i32> for Cipher {
    fn from(file_key_type: i32) -> Self {
        if file_key_type == RecordKeyType::EncryptedByDataKeyGcm as i32 {
            Self::Gcm
        } else {
            Self::Cbc
        }
    }
}

impl Cipher {
    fn open<'a>(self, body: &'a mut [u8], key: &[u8]) -> Result<&'a [u8]> {
        match self {
            Self::Cbc => crypto::decrypt_cbc_in_place::<Pkcs7>(body, key),
            Self::Gcm => crypto::decrypt_aes_v2_in_place(body, key),
        }
    }
}

struct Ticket {
    url:    String,
    cipher: Cipher,
}

struct DownloadJob<'a> {
    attachment: &'a Attachment,
    ticket:     Ticket,
    path:       PathBuf,
}

/// Large attachments can legitimately take minutes; only the connection is time-limited.
fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(None::<std::time::Duration>)
        .build()?)
}

struct DownloadOperation<'a> {
    session:  &'a mut Session,
    vault:    &'a Vault,
    http:     &'a reqwest::blocking::Client,
    budget:   &'a TransferBudget,
    out_dir:  &'a Path,
    layout:   Layout,
    naming:   Naming,
    names:    &'a [String],
    saved:    usize,
    failures: Vec<Error>,
}

impl DownloadOperation<'_> {
    fn download_record(&mut self, record: &Record) -> Result<()> {
        let mut attachments = Attachment::of(self.vault, record)?;
        attachments
            .retain(|attachment| self.names.is_empty() || self.names.iter().any(|name| attachment.is_named(name)));
        if attachments.is_empty() {
            return Ok(());
        }

        let dir = destination(self.vault, self.out_dir, self.layout, record);
        std::fs::create_dir_all(&dir)?;
        let response = if matches!(&record.kind, RecordKind::Legacy { .. }) {
            legacy_tickets(self.session, self.vault, record, &attachments)?
        } else {
            file_tickets(self.session, &attachments)?
        };
        let mut jobs = Vec::with_capacity(attachments.len());
        let mut reserved = HashSet::new();
        for (index, attachment) in attachments.iter().enumerate() {
            let ticket = match response.ticket(attachment, index) {
                Ok(ticket) => ticket,
                Err(error) => {
                    self.failures.push(error);
                    continue;
                }
            };
            let name = local_name(attachment, record, self.naming);
            let path = free_path(&dir, &name, record.uid.as_ref(), &attachment.id, &mut reserved);
            eprintln!("Downloading '{}'", path.display());
            jobs.push(DownloadJob {
                attachment,
                ticket,
                path,
            });
        }
        let saved = std::sync::atomic::AtomicUsize::new(0);
        self.failures.extend(parallel_each(&jobs, |job| {
            download_buffered(self.http, self.budget, &job.ticket, &job.attachment.key, &job.path).map_err(
                |error| {
                    Error::Context {
                        context: format!("downloading attachment {} to {}", job.attachment.id, job.path.display()),
                        source:  Box::new(error),
                    }
                },
            )?;
            saved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }));
        self.saved += saved.load(std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn finish(mut self, terminal: Result<()>) -> Result<()> {
        if let Err(error) = terminal {
            self.failures.push(error);
        }
        if !self.failures.is_empty() {
            return Err(Error::DownloadBatch {
                failures: self.failures,
            });
        }
        if self.saved == 0 {
            eprintln!("No attachments found");
        }
        Ok(())
    }
}

impl Run for DownloadAttachment {
    fn run(self, app: &mut App) -> Result<()> {
        let out_dir = match self.out_dir {
            Some(UserPath(dir)) => dir,
            None => std::env::current_dir()?,
        };
        let layout = if self.preserve_dir {
            Layout::ByFolder
        } else {
            Layout::Flat
        };
        let naming = if self.record_title {
            Naming::WithRecordTitle
        } else {
            Naming::Stored
        };
        let depth = if self.recursive { Depth::Subtree } else { Depth::Folder };
        let view = app.view()?;
        let session = &mut *view.session;
        let vault = view.vault;
        let records = select_records(vault, view.cwd, &self.records, depth);
        if records.is_empty() {
            return Err(Error::Generic(format!("Record(s) \"{}\" not found", self.records.join(", "))));
        }
        std::fs::create_dir_all(&out_dir)?;
        let http = http_client()?;
        let budget = TransferBudget::new();
        let mut operation = DownloadOperation {
            session,
            vault,
            http: &http,
            budget: &budget,
            out_dir: &out_dir,
            layout,
            naming,
            names: &self.names,
            saved: 0,
            failures: Vec::new(),
        };
        let result = records
            .into_iter()
            .try_for_each(|record| operation.download_record(record));
        let result = operation.finish(result);
        match budget.finish() {
            Ok(()) => result,
            Err(error) => {
                match result {
                    Err(Error::DownloadBatch { mut failures }) => {
                        failures.push(error);
                        Err(Error::DownloadBatch { failures })
                    }
                    Err(failure) => {
                        Err(Error::DownloadBatch {
                            failures: vec![failure, error],
                        })
                    }
                    Ok(()) => Err(error),
                }
            }
        }
    }
}

fn select_records<'v>(vault: &'v Vault, cwd: &Location, specs: &[String], depth: Depth) -> Vec<&'v Record> {
    let mut found: BTreeMap<_, _> = BTreeMap::new();
    for spec in specs {
        if let Some(record) = vault.records.get(spec.as_str()) {
            found.insert(&record.uid, record);
        } else if let crate::vault::PathResolution::Full(folder) = vault.resolve_path(cwd, spec) {
            for location in folder_tree(vault, folder, depth) {
                for record in vault.records_in(&location) {
                    found.insert(&record.uid, record);
                }
            }
        } else if let Some(record) = vault.resolve_record(cwd, spec) {
            found.insert(&record.uid, record);
        }
    }
    found.into_values().collect()
}

fn folder_tree(vault: &Vault, root: Location, depth: Depth) -> Vec<Location> {
    let mut locations = vec![root];
    if depth == Depth::Subtree {
        let mut next = 0;
        while let Some(location) = locations.get(next) {
            let children = vault
                .subfolders_of(location)
                .iter()
                .cloned()
                .map(Location::Folder)
                .collect::<Vec<_>>();
            locations.extend(children);
            next += 1;
        }
    }
    locations
}

fn destination(vault: &Vault, out_dir: &Path, layout: Layout, record: &Record) -> PathBuf {
    match layout {
        Layout::Flat => out_dir.to_path_buf(),
        Layout::ByFolder => {
            let folder = vault
                .locations_of(&record.uid)
                .filter_map(|location| {
                    match location {
                        Location::Root => None,
                        Location::Folder(uid) => Some(uid),
                    }
                })
                .min();
            let mut names = Vec::new();
            if let Some(uid) = folder {
                let mut location = Location::Folder(uid.clone());
                while let Some(folder) = vault.folder(&location) {
                    names.push(
                        folder
                            .name
                            .chars()
                            .filter(|character| character.is_alphanumeric())
                            .collect::<String>(),
                    );
                    location = folder.parent.clone();
                }
            }
            names.reverse();
            names
                .into_iter()
                .filter(|name| !name.is_empty())
                .fold(out_dir.to_path_buf(), |dir, name| dir.join(name))
        }
    }
}

fn last_component(text: &str) -> Option<&str> {
    Path::new(text)
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
}

/// Only a stored path's final component is allowed to become a local filename.
fn local_name(attachment: &Attachment, record: &Record, naming: Naming) -> String {
    let stored = last_component(&attachment.name)
        .or_else(|| last_component(&attachment.id))
        .unwrap_or("attachment");
    match naming {
        Naming::Stored => stored.to_owned(),
        Naming::WithRecordTitle => {
            let title: String = record
                .title()
                .chars()
                .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                .collect();
            if title.is_empty() {
                stored.to_owned()
            } else {
                format!("{title}-{stored}")
            }
        }
    }
}

/// Avoid replacing an existing download; use record and file UIDs to disambiguate collisions.
fn free_path(dir: &Path, name: &str, record_uid: &str, file_id: &str, reserved: &mut HashSet<PathBuf>) -> PathBuf {
    let path = dir.join(name);
    if !path.exists() && reserved.insert(path.clone()) {
        return path;
    }
    let stem = Path::new(name).file_stem().and_then(OsStr::to_str).unwrap_or(name);
    let extension = Path::new(name)
        .extension()
        .and_then(OsStr::to_str)
        .map_or_else(String::new, |extension| format!(".{extension}"));
    let file_id = last_component(file_id).unwrap_or("file");
    let candidates = [record_uid, file_id];
    for suffix in candidates {
        let candidate = dir.join(format!("{stem}({suffix}){extension}"));
        if !candidate.exists() && reserved.insert(candidate.clone()) {
            return candidate;
        }
    }
    let mut suffix = 2u64;
    loop {
        let candidate = dir.join(format!("{stem}({file_id}-{suffix}){extension}"));
        if !candidate.exists() && reserved.insert(candidate.clone()) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

enum DownloadResponse {
    Files(FilesGetResponse),
    Legacy(Value),
}

impl DownloadResponse {
    fn ticket(&self, attachment: &Attachment, index: usize) -> Result<Ticket> {
        let context = |detail: &str| format!("attachment {} {detail}", attachment.id);
        let invalid = |detail: &str| Error::Generic(context(detail));
        match self {
            Self::Files(response) => {
                let uid = b64_decode(&attachment.id).map_err(|error| {
                    Error::Context {
                        context: context("has an invalid file UID"),
                        source:  Box::new(error),
                    }
                })?;
                let file = response
                    .files
                    .iter()
                    .find(|file| file.record_uid == uid)
                    .ok_or_else(|| invalid("is missing from the download response"))?;
                if file.status != FileGetResult::FgSuccess as i32 {
                    return Err(invalid(&format!("was refused with status {}", file.status)));
                }
                if file.url.is_empty() {
                    return Err(invalid(&format!("has malformed grant data (status {})", file.status)));
                }

                Ok(Ticket {
                    url:    file.url.clone(),
                    cipher: file.file_key_type.into(),
                })
            }
            Self::Legacy(response) => {
                let grant = response
                    .get("downloads")
                    .and_then(Value::as_array)
                    .and_then(|downloads| downloads.get(index))
                    .ok_or_else(|| invalid("is missing from the positional download response"))?;
                let url = grant
                    .get("url")
                    .and_then(Value::as_str)
                    .filter(|url| !url.is_empty())
                    .ok_or_else(|| invalid("was refused or has malformed positional grant data"))?;
                Ok(Ticket {
                    url:    url.to_owned(),
                    cipher: Cipher::Cbc,
                })
            }
        }
    }
}

fn file_tickets(session: &mut Session, attachments: &[Attachment]) -> Result<DownloadResponse> {
    let rq = FilesGetRequest {
        record_uids: attachments
            .iter()
            .map(|attachment| {
                b64_decode(&attachment.id).map_err(|error| {
                    Error::Context {
                        context: format!("decoding file UID {}", attachment.id),
                        source:  Box::new(error),
                    }
                })
            })
            .collect::<Result<_>>()?,
        ..Default::default()
    };
    let body = session
        .rest
        .execute("vault/files_download", &session.session_token, &rq)?;
    Ok(DownloadResponse::Files(FilesGetResponse::decode(body.as_slice())?))
}

fn legacy_tickets(
    session: &mut Session,
    vault: &Vault,
    record: &Record,
    attachments: &[Attachment],
) -> Result<DownloadResponse> {
    let mut rq = serde_json::json!({
        "command": "request_download",
        "file_ids": attachments.iter().map(|attachment| attachment.id.as_str()).collect::<Vec<_>>(),
    });
    if let Some(folder) = access_folder(vault, record) {
        rq.as_object_mut()
            .ok_or_else(|| Error::Generic("malformed download request".into()))?
            .entry("shared_folder_uid")
            .or_insert_with(|| Value::from(folder));
    }
    Ok(DownloadResponse::Legacy(session.execute_v2(rq)?))
}

fn access_folder<'v>(vault: &'v Vault, record: &Record) -> Option<&'v str> {
    if record.owner {
        return None;
    }
    vault
        .shared_folders
        .values()
        .find(|folder| folder.record_uids.contains(&record.uid))
        .map(|folder| folder.uid.as_ref())
}

/// Fetch and decrypt before creating an output file; GCM authenticates, while legacy CBC only checks padding.
fn download_buffered(
    http: &reqwest::blocking::Client,
    budget: &TransferBudget,
    ticket: &Ticket,
    key: &[u8],
    path: &Path,
) -> Result<()> {
    let mut response = http.get(&ticket.url).send()?;
    if !response.status().is_success() {
        return Err(Error::Generic(format!("HTTP status code {}", response.status().as_u16())));
    }
    let expected = response
        .content_length()
        .map(usize::try_from)
        .transpose()
        .map_err(Error::Integer)?;
    // Length headers are untrusted: read at most one extra byte and reject mismatches.
    // ponytail: unknown or oversized bodies run alone, but a single encrypted file still buffers fully; streaming is the upgrade path.
    let demand = match expected {
        Some(length) => {
            BufferDemand::Known(
                length
                    .checked_add(1 + 32)
                    .ok_or_else(|| Error::Generic("download size overflow".into()))?,
            )
        }
        None => BufferDemand::Unknown,
    };
    let _permit = budget.acquire(demand)?;
    let mut body = Vec::new();
    if let Some(length) = expected {
        body.try_reserve_exact(length.saturating_add(1))
            .map_err(Error::Allocation)?;
        response
            .take(u64::try_from(length.saturating_add(1))?)
            .read_to_end(&mut body)?;
        if body.len() != length {
            return Err(Error::Generic(format!("download length changed for {}", path.display())));
        }
    } else {
        response.read_to_end(&mut body)?;
    }
    let plain = ticket.cipher.open(&mut body, key)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Error::Context {
                context: format!("creating {}", path.display()),
                source:  Box::new(error.into()),
            }
        })?;
    if let Err(error) = file.write_all(plain) {
        return Err(Error::Context {
            context: format!("writing {} (partial file may remain)", path.display()),
            source:  Box::new(error.into()),
        });
    }
    Ok(())
}

/// Upload local files to a typed record.
#[derive(Args, Debug)]
pub struct UploadAttachment {
    /// File to upload (repeatable).
    #[arg(long = "file", required = true)]
    files:  Vec<UserPath>,
    /// Typed record path or UID.
    record: String,
}

struct UploadFile {
    local: LocalFile,
    uid:   Vec<u8>,
    key:   AesKey,
}

struct UploadTarget<'a> {
    file:                &'a UploadFile,
    url:                 &'a str,
    success_status_code: i32,
    boundary:            String,
    head:                std::sync::Arc<[u8]>,
    tail:                std::sync::Arc<[u8]>,
    metadata_bytes:      usize,
}

struct LocalFile {
    path: PathBuf,
    name: String,
    size: usize,
    mime: MimeType,
}

impl From<LocalFile> for UploadFile {
    fn from(local: LocalFile) -> Self {
        Self {
            local,
            uid: Vec::from(crate::uid::random_bytes(&mut rand::rngs::OsRng)),
            key: AesKey::random(),
        }
    }
}

impl TryFrom<&UploadFile> for Vec<u8> {
    type Error = Error;

    fn try_from(file: &UploadFile) -> Result<Self> {
        let reserve = file
            .local
            .size
            .checked_add(16)
            .ok_or_else(|| Error::Generic(format!("{} does not fit in memory", file.local.name)))?;
        let mut frame = vec![0; 12];
        frame.try_reserve_exact(reserve).map_err(|error| {
            Error::Context {
                context: format!("reserving upload data for {}", file.local.path.display()),
                source:  Box::new(Error::Allocation(error)),
            }
        })?;
        let expected = file
            .local
            .size
            .checked_add(1)
            .ok_or_else(|| Error::Generic(format!("{} does not fit in memory", file.local.name)))?;
        std::fs::File::open(&file.local.path)?
            .take(u64::try_from(expected)?)
            .read_to_end(&mut frame)?;
        if frame.len() != file.local.size.saturating_add(12) {
            return Err(Error::Generic(format!("File {} changed size while uploading", file.local.name)));
        }
        frame.extend_from_slice(&[0; 16]);
        crypto::encrypt_aes_v2_in_place(&mut frame, &file.key)?;
        Ok(frame)
    }
}

impl TryFrom<&UserPath> for LocalFile {
    type Error = Error;

    fn try_from(typed: &UserPath) -> Result<Self> {
        let path = std::path::absolute(typed)?;
        let metadata = path.metadata().map_err(|error| {
            Error::Context {
                context: format!("reading metadata for {}", typed.0.display()),
                source:  Box::new(error.into()),
            }
        })?;
        if !metadata.is_file() {
            return Err(Error::Generic(format!("File \"{}\" is not a regular file", typed.0.display())));
        }
        let size = usize::try_from(metadata.len()).map_err(|error| {
            Error::Context {
                context: format!("file size for {}", typed.0.display()),
                source:  Box::new(Error::Integer(error)),
            }
        })?;
        Ok(Self {
            name: path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
            mime: MimeType::from(path.as_path()),
            path,
            size,
        })
    }
}

struct MimeType(&'static str);

impl From<&Path> for MimeType {
    fn from(path: &Path) -> Self {
        let extension = path
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        Self(match extension.as_str() {
            "txt" | "text" => "text/plain",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "csv" => "text/csv",
            "xml" => "text/xml",
            "json" => "application/json",
            "pdf" => "application/pdf",
            "zip" => "application/zip",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "doc" => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls" => "application/vnd.ms-excel",
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _ => "",
        })
    }
}

impl std::fmt::Display for MimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl Run for UploadAttachment {
    fn run(self, app: &mut App) -> Result<()> {
        let view = app.view()?;
        let session = &mut *view.session;
        let vault = view.vault;
        let cwd = view.cwd;
        let record = vault
            .resolve_record(cwd, &self.record)
            .ok_or_else(|| Error::Generic(format!("Record UID not found for record \"{}\"", self.record)))?;
        let typed_record = TypedRecord::try_from(record)?;
        let record = typed_record.as_ref();
        let files = self.files.iter().map(LocalFile::try_from).collect::<Result<Vec<_>>>()?;
        let files: Vec<UploadFile> = files.into_iter().map(UploadFile::from).collect();
        let add = add_request(&files, &session.data_key)?;
        let body = session.rest.execute("vault/files_add", &session.session_token, &add)?;
        let added = FilesAddResponse::decode(body.as_slice())?;
        let http = http_client()?;
        upload_files(&http, &files, &added.files)?;

        let key_type = if session.summary.forbid_key_type2 {
            RecordKeyType::EncryptedByPublicKeyEcc
        } else {
            RecordKeyType::EncryptedByPublicKey
        };
        let rq = link_request(typed_record, &files, key_type)?;
        let body = session
            .rest
            .execute("vault/records_update", &session.session_token, &rq)?;
        let updated = RecordsModifyResponse::decode(body.as_slice())?;
        let status = updated
            .records
            .iter()
            .find(|status| rq.records.iter().any(|request| request.record_uid == status.record_uid))
            .ok_or_else(|| Error::Generic(format!("Updating record {}: missing response status.", record.uid)))?;
        if status.status != RecordModifyResult::RsSuccess as i32 {
            let result = RecordModifyResult::try_from(status.status).map_err(|source| {
                Error::Context {
                    context: format!("updating record {}: invalid response status", record.uid),
                    source:  Box::new(Error::UnknownEnum(source)),
                }
            })?;
            return Err(Error::api(result.as_str_name(), status.message.clone()));
        }
        eprintln!("Uploaded {} file(s) to \"{}\"", files.len(), record.title());
        app.account.as_mut().ok_or(Error::NotLoggedIn)?.vault = None;
        Ok(())
    }
}

fn add_request(files: &[UploadFile], data_key: &[u8]) -> Result<FilesAddRequest> {
    Ok(FilesAddRequest {
        files:       files
            .iter()
            .map(|file| -> Result<FileEntry> {
                let metadata = serde_json::json!({
                    "title": file.local.name,
                    "name": file.local.name,
                    "type": file.local.mime.to_string(),
                    "size": file.local.size,
                });
                Ok(FileEntry {
                    record_uid: file.uid.clone(),
                    record_key: crypto::encrypt_aes_v2(&file.key, data_key)?,
                    data: crypto::encrypt_aes_v2(metadata.to_string().as_bytes(), &file.key)?,
                    file_size: i64::try_from(file.local.size).unwrap_or(i64::MAX).saturating_add(100),
                    ..Default::default()
                })
            })
            .collect::<Result<_>>()?,
        client_time: now_millis(),
    })
}

fn value_heap_bytes(value: &Value) -> usize {
    match value {
        Value::String(value) => value.capacity(),
        Value::Array(values) => {
            values
                .capacity()
                .saturating_mul(std::mem::size_of::<Value>())
                .saturating_add(values.iter().map(value_heap_bytes).fold(0usize, usize::saturating_add))
        }
        Value::Object(fields) => {
            fields
                .iter()
                .map(|(name, value)| {
                    name.capacity()
                        .saturating_add(value_heap_bytes(value))
                        .saturating_add(256)
                })
                .fold(0usize, usize::saturating_add)
        }
        _ => 0,
    }
}

fn prepare_upload<'a>(file: &'a UploadFile, status: &'a FileAddStatus) -> Result<UploadTarget<'a>> {
    let fields: serde_json::Map<String, Value> = serde_json::from_str(&status.parameters).map_err(|source| {
        Error::Context {
            context: format!("uploading file {}: malformed upload parameters", file.local.name),
            source:  Box::new(Error::Json(source)),
        }
    })?;
    let boundary = data_encoding::HEXLOWER.encode(&crypto::random_bytes(16));
    let mut head = String::new();
    for (name, value) in &fields {
        let value = value.as_str().map_or_else(|| value.to_string(), str::to_owned);
        write!(&mut head, "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
            .expect("writing multipart framing to a String cannot fail");
    }
    let file_ref = b64_encode(&file.uid);
    write!(
        &mut head,
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_ref}\"\r\nContent-Type: \
         application/octet-stream\r\n\r\n"
    )
    .expect("writing multipart framing to a String cannot fail");
    let tail = format!("\r\n--{boundary}--\r\n");
    let parsed_metadata = fields
        .iter()
        .map(|(name, value)| {
            name.capacity()
                .saturating_add(value_heap_bytes(value))
                .saturating_add(256)
        })
        .fold(0usize, usize::saturating_add);
    let metadata_bytes = status
        .parameters
        .capacity()
        .saturating_add(status.url.capacity())
        .saturating_add(head.capacity())
        .saturating_add(tail.capacity())
        .saturating_add(boundary.capacity())
        .saturating_add(32)
        .saturating_add(parsed_metadata);
    Ok(UploadTarget {
        file,
        url: &status.url,
        success_status_code: status.success_status_code,
        boundary,
        head: std::sync::Arc::from(head.into_bytes()),
        tail: std::sync::Arc::from(tail.into_bytes()),
        metadata_bytes,
    })
}

fn send(http: &reqwest::blocking::Client, target: &UploadTarget<'_>) -> Result<()> {
    let frame = Vec::try_from(target.file)?;
    let length = target
        .head
        .len()
        .checked_add(frame.len())
        .and_then(|length| length.checked_add(target.tail.len()))
        .ok_or_else(|| Error::Generic(format!("multipart upload {} is too large", target.file.local.name)))?;
    let body = reqwest::blocking::Body::sized(
        std::io::Cursor::new(std::sync::Arc::clone(&target.head))
            .chain(std::io::Cursor::new(frame))
            .chain(std::io::Cursor::new(std::sync::Arc::clone(&target.tail))),
        u64::try_from(length)?,
    );
    let response = http
        .post(target.url)
        .header("Content-Type", format!("multipart/form-data; boundary={}", target.boundary))
        .body(body)
        .send()?;
    let status = response.status().as_u16();
    if i32::from(status) != target.success_status_code {
        return Err(Error::Generic(format!("Uploading file {}: HTTP status code {status}", target.file.local.name)));
    }
    Ok(())
}

fn upload_files(http: &reqwest::blocking::Client, files: &[UploadFile], statuses: &[FileAddStatus]) -> Result<()> {
    let mut targets = Vec::with_capacity(files.len());
    let mut failures = Vec::new();
    for file in files {
        let mut matching = statuses.iter().filter(|status| status.record_uid == file.uid);
        match (matching.next(), matching.next()) {
            (Some(status), None) if status.status == FileAddResult::FaSuccess as i32 && !status.url.is_empty() => {
                if !(200..300).contains(&status.success_status_code) {
                    failures.push(Error::Generic(format!(
                        "Uploading file {}: invalid expected success status {}.",
                        file.local.name, status.success_status_code
                    )));
                } else if let Err(error) = http.post(&status.url).build() {
                    failures.push(Error::Context {
                        context: format!("uploading file {}: malformed upload URL", file.local.name),
                        source:  Box::new(Error::Http(error)),
                    });
                } else {
                    match prepare_upload(file, status) {
                        Ok(target) => targets.push(target),
                        Err(error) => failures.push(error),
                    }
                }
            }
            (Some(status), None) => {
                failures.push(Error::Generic(format!(
                    "Uploading file {}: refused with status {} or missing upload URL.",
                    file.local.name, status.status
                )))
            }
            (None, _) => {
                failures.push(Error::Generic(format!("Uploading file {}: missing upload status.", file.local.name)))
            }
            (Some(_), Some(_)) => {
                failures.push(Error::Generic(format!("Uploading file {}: duplicate upload statuses.", file.local.name)))
            }
        }
    }
    for status in statuses {
        if !files.iter().any(|file| file.uid == status.record_uid) {
            failures.push(Error::Generic("files_add response contains an unrequested file status.".into()));
        }
    }
    if !failures.is_empty() {
        return Err(Error::AttachmentBatch { failures });
    }

    let metadata_bytes = targets
        .iter()
        .map(|target| target.metadata_bytes)
        .fold(0usize, usize::saturating_add)
        .saturating_add(
            targets
                .capacity()
                .saturating_mul(std::mem::size_of::<UploadTarget<'_>>()),
        );
    let mut start = 0;
    while start < targets.len() {
        let mut end = start;
        let mut reserved = metadata_bytes;
        while let Some(target) = targets.get(end) {
            // ponytail: if total metadata or one file exceeds budget, uploads run one at a time; whole-file buffers may exceed 64 MiB. Streaming is the upgrade path.
            let estimate = target.file.local.size.saturating_add(28);
            if end > start && reserved.saturating_add(estimate) > TRANSFER_BUFFER_BUDGET {
                break;
            }
            reserved = reserved.saturating_add(estimate);
            end += 1;
            if reserved > TRANSFER_BUFFER_BUDGET {
                break;
            }
        }
        let batch = targets
            .get(start..end)
            .ok_or_else(|| Error::Generic("invalid upload batch range".into()))?;
        failures.extend(parallel_each(batch, |target| {
            send(http, target).map_err(|error| {
                Error::Context {
                    context: format!("uploading {}", target.file.local.name),
                    source:  Box::new(error),
                }
            })
        }));
        start = end;
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::AttachmentBatch { failures })
    }
}

fn link_request(
    record: TypedRecord<'_>,
    files: &[UploadFile],
    key_type: RecordKeyType,
) -> Result<RecordsUpdateRequest> {
    let record = record.as_ref();
    let mut data = record.data.clone();
    let refs: Vec<Value> = files.iter().map(|file| Value::from(b64_encode(&file.uid))).collect();
    let listed = data
        .fields
        .iter_mut()
        .find(|field| field.ty == "fileRef")
        .and_then(|field| field.value.as_mut())
        .and_then(Value::as_array_mut);
    match listed {
        Some(listed) => listed.extend(refs),
        None => {
            data.fields.push(RecordField {
                ty: "fileRef".into(),
                value: Some(Value::Array(refs)),
                ..RecordField::default()
            })
        }
    }
    let mut json = serde_json::to_vec(&data)?;
    json.resize(json.len().max(384).next_multiple_of(16), b' ');
    let now = now_millis();
    Ok(RecordsUpdateRequest {
        records:                vec![RecordUpdate {
            record_uid: Vec::from(&record.uid),
            client_modified_time: now,
            revision: record.revision,
            data: crypto::encrypt_aes_v2(&json, &record.key)?,
            record_links_add: files
                .iter()
                .map(|file| -> Result<RecordLink> {
                    Ok(RecordLink {
                        record_uid: file.uid.clone(),
                        record_key: crypto::encrypt_aes_v2(&file.key, &record.key)?,
                    })
                })
                .collect::<Result<_>>()?,
            ..Default::default()
        }],
        client_time:            now,
        security_data_key_type: key_type as i32,
    })
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::uid::Uid;

    fn key(byte: u8) -> AesKey {
        AesKey::try_from(vec![byte; 32]).unwrap()
    }

    fn record(uid: &str, kind: RecordKind, data: Value, key_byte: u8) -> Record {
        Record {
            uid: Uid::from(uid.as_bytes()),
            kind,
            data: serde_json::from_value(data).unwrap(),
            revision: 0,
            shared: false,
            client_modified_time: 0,
            key: key(key_byte),
            owner: true,
            udata: None,
        }
    }

    fn vault_of(records: impl IntoIterator<Item = Record>) -> Vault {
        Vault {
            records: records.into_iter().map(|record| (record.uid.clone(), record)).collect(),
            ..Vault::default()
        }
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keeper-cli-test-{}", b64_encode(&crypto::random_bytes(8))));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn transfer_budget_waits_for_shared_permits_before_exclusive_work() {
        let budget = std::sync::Arc::new(TransferBudget::new());
        let half = TRANSFER_BUFFER_BUDGET / 2;
        let first = budget.acquire(BufferDemand::Known(half)).unwrap();
        let second = budget.acquire(BufferDemand::Known(half)).unwrap();
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (acquired_sender, acquired_receiver) = std::sync::mpsc::channel();
        let worker_budget = std::sync::Arc::clone(&budget);
        let worker = std::thread::spawn(move || {
            started_sender.send(()).unwrap();
            let permit = worker_budget.acquire(BufferDemand::Unknown).unwrap();
            acquired_sender.send(()).unwrap();
            drop(permit);
        });
        started_receiver.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(matches!(acquired_receiver.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        drop(first);
        drop(second);
        acquired_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        worker.join().unwrap();
        assert!(matches!(*budget.state.lock().unwrap(), crate::error::TransferAdmissionState::Shared(0)));
    }

    #[test]
    fn transfer_budget_poison_errors_retain_owned_sources() {
        let budget = std::sync::Arc::new(TransferBudget::new());
        let poisoner = std::sync::Arc::clone(&budget);
        assert!(
            std::thread::spawn(move || {
                let _state = poisoner.state.lock().unwrap();
                panic!("poison transfer budget in regression test");
            })
            .join()
            .is_err()
        );

        let acquire_error = match budget.acquire(BufferDemand::Known(1)) {
            Ok(_) => panic!("poisoned admission lock must fail"),
            Err(error) => error,
        };
        assert!(matches!(&acquire_error, Error::TransferBudgetPoisoned { .. }));
        assert!(
            std::error::Error::source(&acquire_error)
                .and_then(|source| {
                    source.downcast_ref::<std::sync::PoisonError<crate::error::TransferAdmissionState>>()
                })
                .is_some()
        );

        let budget = std::sync::Arc::try_unwrap(budget).unwrap_or_else(|_| panic!("budget still shared"));
        let finish_error = budget.finish().expect_err("final budget check retains mutex poison");
        assert!(
            std::error::Error::source(&finish_error)
                .and_then(|source| {
                    source.downcast_ref::<std::sync::PoisonError<crate::error::TransferAdmissionState>>()
                })
                .is_some()
        );
    }

    fn attachment(name: &str) -> Attachment {
        // Legacy attachment IDs are opaque strings; file-record IDs are typed UIDs.
        Attachment {
            id:    "FILEID".into(),
            name:  name.into(),
            title: String::new(),
            key:   key(0),
        }
    }

    #[test]
    fn legacy_typed_and_file_record_attachments_resolve_their_keys() {
        let parent_uid = Uid::from(b"PARENT".as_slice());
        let f1 = record("F1", RecordKind::File { size: 5 }, json!({"name": " a.txt ", "title": "Notes"}), 2);
        let f2 = record("F2", RecordKind::File { size: 0 }, json!({"name": "b.bin"}), 3);
        let other = record("NOTAFILE", RecordKind::Typed, json!({"title": "x"}), 4);
        let mut parent = record(
            "PARENT",
            RecordKind::Typed,
            json!({"title": "Server", "fields": [{"type": "fileRef", "value": [f1.uid.to_string(), "GONE", f2.uid.to_string()]}]}),
            1,
        );
        parent.uid = parent_uid.clone();
        let malformed_ref = record(
            "BADREF",
            RecordKind::Typed,
            json!({"fields": [{"type": "fileRef", "value": [other.uid.to_string()]}]}),
            1,
        );
        let vault = vault_of([parent, f1, f2, other]);
        let parent = vault.records.get(&parent_uid).expect("parent fixture exists");
        let found = Attachment::of(&vault, parent).unwrap();
        let [first, _] = found.as_slice() else {
            panic!("expected two parent attachments");
        };
        assert_eq!(found.iter().map(|file| file.name.as_str()).collect::<Vec<_>>(), ["a.txt", "b.bin"]);
        assert_eq!(first.key, key(2));

        assert!(Attachment::of(&vault, &malformed_ref).is_err());
        assert_eq!(
            Attachment::of(
                &vault,
                vault
                    .records
                    .get(&Uid::from(b"F2".as_slice()))
                    .expect("file fixture exists")
            )
            .unwrap()
            .len(),
            1
        );

        let legacy_key = [9u8; 32];
        let legacy = record(
            "OLD",
            RecordKind::Legacy {
                extra: Some(
                    serde_json::from_value(json!({
                        "files": [{"id": "ATT1", "name": "scan.pdf", "title": "Scan", "key": b64_encode(&legacy_key)}]
                    }))
                    .unwrap(),
                ),
            },
            json!({"title": "Legacy"}),
            1,
        );
        let legacy_attachments = Attachment::of(&Vault::default(), &legacy).unwrap();
        let [legacy_attachment] = legacy_attachments.as_slice() else {
            panic!("expected one legacy attachment");
        };
        assert_eq!(legacy_attachment.key, key(9));
        let malformed = record(
            "BAD",
            RecordKind::Legacy {
                extra: Some(serde_json::from_value(json!({"files": [{"id": "ATT2", "key": "***"}]})).unwrap()),
            },
            json!({}),
            1,
        );
        assert!(Attachment::of(&Vault::default(), &malformed).is_err());
    }

    #[test]
    fn content_decrypts_only_with_its_attachment_key_and_key_type_selects_cipher() {
        let key = [8u8; 32];
        let gcm = crypto::encrypt_aes_v2(b"file body", &key).unwrap();
        assert_eq!(Cipher::Gcm.open(&mut gcm.clone(), &key).unwrap(), b"file body");
        assert!(Cipher::Gcm.open(&mut gcm.clone(), &[1; 32]).is_err());
        let cbc = crypto::encrypt_cbc::<Pkcs7>(b"legacy body", &key).unwrap();
        assert_eq!(Cipher::Cbc.open(&mut cbc.clone(), &key).unwrap(), b"legacy body");
        assert_eq!(Cipher::from(RecordKeyType::EncryptedByDataKeyGcm as i32), Cipher::Gcm);
        assert_eq!(Cipher::from(RecordKeyType::EncryptedByDataKey as i32), Cipher::Cbc);
    }

    #[test]
    fn only_attachment_names_and_ids_match_case_insensitively_where_expected() {
        let file = Attachment {
            id:    "F1".into(),
            name:  "Report.PDF".into(),
            title: "Q3 Report".into(),
            key:   key(0),
        };
        assert!(file.is_named("F1"));
        assert!(!file.is_named("f1"));
        assert!(file.is_named("report.pdf"));
        assert!(file.is_named("q3 REPORT"));
        assert!(!file.is_named("report"));
    }

    #[test]
    fn filenames_stay_in_output_folder_and_collisions_do_not_overwrite() {
        let record = record("R", RecordKind::Typed, json!({"title": "My: Server/1"}), 1);
        let safe_name = |attachment: &Attachment| {
            let name = local_name(attachment, &record, Naming::Stored);
            let path = Path::new(&name);
            assert!(!path.is_absolute());
            assert_eq!(path.components().count(), 1);
            assert_eq!(path.file_name().and_then(OsStr::to_str), Some(name.as_str()));
            name
        };
        assert_eq!(safe_name(&attachment("../../etc/passwd")), "passwd");
        assert_eq!(safe_name(&attachment("..")), "FILEID");
        assert_eq!(safe_name(&attachment("")), "FILEID");
        let hostile_id = Attachment {
            id: "../../etc/shadow".into(),
            ..attachment("")
        };
        assert_eq!(safe_name(&hostile_id), "shadow");
        assert_eq!(local_name(&attachment("key.pem"), &record, Naming::WithRecordTitle), "My Server1-key.pem");

        let dir = temp_dir();
        let record_uid = Uid::from(b"REC".as_slice()).to_string();
        let file_uid = Uid::from(b"FILE".as_slice()).to_string();
        let mut reserved = HashSet::new();
        let mut saved = Vec::new();
        for marker in 0..4u8 {
            let path = free_path(&dir, "a.tar.gz", &record_uid, &file_uid, &mut reserved);
            assert_eq!(path.parent(), Some(dir.as_path()));
            assert!(!saved.contains(&path));
            std::fs::write(&path, [marker]).unwrap();
            saved.push(path);
        }
        for (marker, path) in (0..4u8).zip(&saved) {
            assert_eq!(std::fs::read(path).unwrap(), [marker]);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn record_and_folder_specs_select_records_in_a_subtree() {
        let vault = crate::vault::tests::sample();
        let uid = vault.records.values().next().unwrap().uid.to_string();
        let cwd = Location::Root;
        assert_eq!(select_records(&vault, &cwd, std::slice::from_ref(&uid), Depth::Folder).len(), 1);
        assert_eq!(select_records(&vault, &cwd, &["Work".into()], Depth::Folder).len(), 0);
        assert_eq!(select_records(&vault, &cwd, &["Work".into()], Depth::Subtree).len(), 1);
        assert_eq!(select_records(&vault, &cwd, &["/Work/Infra/DB Admin".into()], Depth::Folder).len(), 1);
        assert_eq!(select_records(&vault, &cwd, &[uid, "Work".into()], Depth::Subtree).len(), 1);
    }

    #[test]
    fn download_responses_resolve_mixed_grants_and_keep_attachment_ids() {
        let ids = ["ONE", "TWO", "THREE"].map(|bytes| Uid::from(bytes.as_bytes()).to_string());
        let [first_id, second_id, _third_id] = ids.as_slice() else {
            panic!("expected three attachment IDs");
        };
        let attachments = ids.each_ref().map(|id| {
            Attachment {
                id:    id.as_str().to_owned(),
                name:  String::new(),
                title: String::new(),
                key:   key(0),
            }
        });
        let [first, second, third] = attachments.as_slice() else {
            panic!("expected three attachments");
        };
        let files = DownloadResponse::Files(FilesGetResponse {
            files: vec![
                crate::proto::records::FileGetStatus {
                    record_uid: b64_decode(second_id).unwrap(),
                    status: 91,
                    ..Default::default()
                },
                crate::proto::records::FileGetStatus {
                    record_uid: b64_decode(first_id).unwrap(),
                    status: FileGetResult::FgSuccess as i32,
                    url: "https://example.invalid/one".into(),
                    file_key_type: RecordKeyType::EncryptedByDataKey as i32,
                    ..Default::default()
                },
            ],
        });
        assert_eq!(files.ticket(first, 0).unwrap().url, "https://example.invalid/one");
        for attachment in [second, third] {
            let message = format!("{:?}", files.ticket(attachment, 1).err().unwrap());
            assert!(message.contains(&attachment.id), "{message}");
        }

        let legacy = DownloadResponse::Legacy(json!({
            "downloads": [{"url": "https://example.invalid/one"}, {"url": ""}]
        }));
        assert_eq!(legacy.ticket(first, 0).unwrap().url, "https://example.invalid/one");
        for (index, attachment) in [(1, second), (2, third)] {
            let message = format!("{:?}", legacy.ticket(attachment, index).err().unwrap());
            assert!(message.contains(&attachment.id), "{message}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_file_preserves_symlink_loop_stat_error() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let loop_path = dir.join("loop");
        symlink(&loop_path, &loop_path).unwrap();
        let expected = std::fs::metadata(&loop_path).unwrap_err().kind();
        let error = LocalFile::try_from(&UserPath(loop_path)).err().unwrap();
        assert!(matches!(
            error,
            Error::Context { source, .. } if matches!(source.as_ref(), Error::Io(error) if error.kind() == expected)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tilde_expands_only_as_a_whole_leading_path_component() {
        let home = dirs::home_dir().unwrap();
        let path = |typed: &str| UserPath::from_str(typed).unwrap().0;
        assert_eq!(path("~"), home);
        assert_eq!(path("~/files"), home.join("files"));
        assert_eq!(path("~other/files"), PathBuf::from("~other/files"));
        assert_eq!(path("a/~"), PathBuf::from("a/~"));
    }

    #[test]
    fn local_file_reports_its_name_size_and_common_mime_type() {
        let dir = temp_dir();
        std::fs::write(dir.join("Notes.TXT"), b"hello world").unwrap();
        let file = LocalFile::try_from(&UserPath(dir.join("Notes.TXT"))).unwrap();
        assert_eq!((file.name.as_str(), file.size, file.mime.to_string().as_str()), ("Notes.TXT", 11, "text/plain"));
        std::fs::write(dir.join("archive.tar.gz"), b"").unwrap();
        assert_eq!(
            LocalFile::try_from(&UserPath(dir.join("archive.tar.gz")))
                .unwrap()
                .mime
                .to_string(),
            ""
        );
        assert!(matches!(
            LocalFile::try_from(&UserPath(dir.clone())),
            Err(Error::Generic(message)) if message.contains("not a regular file")
        ));
        assert!(matches!(
            LocalFile::try_from(&UserPath(dir.join("missing.bin"))),
            Err(Error::Context { source, .. }) if matches!(*source, Error::Io(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn add_and_link_requests_encrypt_keys_and_file_metadata() {
        let dir = temp_dir();
        std::fs::write(dir.join("notes.txt"), b"hello world").unwrap();
        std::fs::write(dir.join("report.pdf"), b"second file!").unwrap();
        let files = [
            UploadFile {
                local: LocalFile::try_from(&UserPath(dir.join("notes.txt"))).unwrap(),
                uid:   vec![1; 16],
                key:   key(6),
            },
            UploadFile {
                local: LocalFile::try_from(&UserPath(dir.join("report.pdf"))).unwrap(),
                uid:   vec![2; 16],
                key:   key(7),
            },
        ];
        let [file_one, file_two] = files.as_slice() else {
            panic!("expected two upload fixtures");
        };
        let add = add_request(&files, &[5; 32]).unwrap();
        let [entry_one, entry_two] = add.files.as_slice() else {
            panic!("expected two add response entries");
        };
        for (entry, file, expected_metadata, expected_size) in [
            (
                entry_one,
                file_one,
                json!({"title": "notes.txt", "name": "notes.txt", "type": "text/plain", "size": 11}),
                111i64,
            ),
            (
                entry_two,
                file_two,
                json!({"title": "report.pdf", "name": "report.pdf", "type": "application/pdf", "size": 12}),
                112i64,
            ),
        ] {
            assert_eq!(entry.record_uid, file.uid);
            let file_key = crypto::decrypt_aes_v2(&entry.record_key, &[5; 32]).unwrap();
            assert_eq!(file_key.as_slice(), &*file.key);
            let metadata: Value =
                serde_json::from_slice(&crypto::decrypt_aes_v2(&entry.data, &file.key).unwrap()).unwrap();
            assert_eq!(metadata, expected_metadata);
            assert_eq!(entry.file_size, expected_size);
        }

        let uid = Uid::from(b"PARENT".as_slice());
        let mut parent = record(
            "PARENT",
            RecordKind::Typed,
            json!({"title": "Server", "type": "login", "extension": {"keep": true}, "fields": [{"type": "text", "value": ["keep text"]}, {"type": "login", "value": ["root"]}, {"type": "fileRef", "value": ["OLD"]}]}),
            1,
        );
        parent.uid = uid;
        parent.revision = 41;
        let update =
            link_request(TypedRecord::try_from(&parent).unwrap(), &files, RecordKeyType::EncryptedByPublicKeyEcc)
                .unwrap();
        assert_eq!(update.security_data_key_type, RecordKeyType::EncryptedByPublicKeyEcc as i32);
        let [updated] = update.records.as_slice() else {
            panic!("expected one record update");
        };
        assert_eq!(updated.record_uid, Vec::<u8>::from(&parent.uid));
        assert_eq!(updated.revision, 41);
        let plain = crypto::decrypt_aes_v2(&updated.data, &parent.key).unwrap();
        assert!(plain.len() >= 384 && plain.len().is_multiple_of(16));
        let data: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(data.get("type").and_then(Value::as_str), Some("login"));
        assert_eq!(data.get("extension"), Some(&json!({"keep": true})));
        let fields = data
            .get("fields")
            .and_then(Value::as_array)
            .expect("updated fields are an array");
        let parent_fields = parent.data.fields.as_slice();
        let [text_field, login_field, file_field] = fields.as_slice() else {
            panic!("expected text, login, and file-reference fields");
        };
        let [parent_text_field, parent_login_field, _parent_file_field] = parent_fields else {
            panic!("expected text, login, and file-reference fixture fields");
        };
        assert_eq!(text_field, &serde_json::to_value(parent_text_field).unwrap());
        assert_eq!(text_field.get("type").and_then(Value::as_str), Some("text"));
        assert_eq!(login_field, &serde_json::to_value(parent_login_field).unwrap());
        assert_eq!(
            file_field.get("value"),
            Some(&json!(["OLD", b64_encode(&file_one.uid), b64_encode(&file_two.uid)]))
        );
        assert_eq!(updated.record_links_add.len(), files.len());
        for (link, file) in updated.record_links_add.iter().zip(&files) {
            assert_eq!(link.record_uid, file.uid);
            let linked_key = crypto::decrypt_aes_v2(&link.record_key, &parent.key).unwrap();
            assert_eq!(linked_key.as_slice(), &*file.key);
        }
        let no_fields = record("P2", RecordKind::Typed, json!({"title": "A"}), 1);
        let no_fields_update = link_request(
            TypedRecord::try_from(&no_fields).unwrap(),
            std::slice::from_ref(file_two),
            RecordKeyType::EncryptedByPublicKey,
        )
        .unwrap();
        let [no_fields_record] = no_fields_update.records.as_slice() else {
            panic!("expected one empty-record update");
        };
        let no_fields_data = crypto::decrypt_aes_v2(&no_fields_record.data, &no_fields.key).unwrap();
        let no_fields_data: Value = serde_json::from_slice(&no_fields_data).unwrap();
        let [file_ref_field] = no_fields_data
            .get("fields")
            .and_then(Value::as_array)
            .expect("new fields are an array")
            .as_slice()
        else {
            panic!("expected one file-reference field");
        };
        assert_eq!(file_ref_field.get("type").and_then(Value::as_str), Some("fileRef"));
        assert_eq!(file_ref_field.get("value"), Some(&json!([b64_encode(&file_two.uid)])));
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct TestServer {
        url:    String,
        worker: std::thread::JoinHandle<Vec<u8>>,
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 16 * 1024];
        let mut total = None;
        while total.is_none_or(|total| request.len() < total) {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "client hung up mid-request");
            request.extend_from_slice(chunk.get(..read).expect("read count fits chunk buffer"));
            if total.is_none()
                && let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            {
                let (head_bytes, _) = request.split_at_checked(head_end).expect("delimiter is in request");
                let head = String::from_utf8_lossy(head_bytes).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .map_or(0, |length| length.trim().parse().unwrap());
                total = Some(
                    head_end
                        .checked_add(4)
                        .and_then(|head| head.checked_add(length))
                        .expect("request length fits usize"),
                );
            }
        }
        request
    }

    fn serve_once(status: &'static str, reply: Vec<u8>) -> TestServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(error) => panic!("no client connected: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let request = read_http_request(&mut stream);
            write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len())
                .unwrap();
            stream.write_all(&reply).unwrap();
            request
        });
        TestServer { url, worker }
    }
    struct RestFixture {
        url:    String,
        worker: std::thread::JoinHandle<Vec<String>>,
        stop:   std::sync::mpsc::Sender<()>,
    }

    fn rest_fixture(transmission_key: [u8; 32], upload_url: String) -> RestFixture {
        use crate::proto::authentication::{ApiRequest, ApiRequestPayload};
        use crate::proto::records::{FilesAddRequest, FilesAddResponse, RecordsModifyResponse, RecordsUpdateRequest};

        fn serve_rest_request(
            stream: &mut std::net::TcpStream,
            transmission_key: &[u8; 32],
            upload_url: &str,
            file_keys: &mut Vec<(Vec<u8>, Vec<u8>)>,
            paths: &mut Vec<String>,
        ) {
            let request = read_http_request(stream);
            let head_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("REST request contains a header delimiter");
            let (headers, frame) = request
                .split_at_checked(head_end)
                .expect("header delimiter is in request");
            let path = String::from_utf8_lossy(headers)
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .expect("REST request line has a path")
                .to_owned();
            let body = frame.strip_prefix(b"\r\n\r\n").expect("header delimiter was found");
            let request = ApiRequest::decode(body).unwrap();
            let decrypted = crypto::decrypt_aes_v2(&request.encrypted_payload, transmission_key).unwrap();
            let payload = ApiRequestPayload::decode(decrypted.as_slice()).unwrap();
            let response = match path.as_str() {
                "/api/rest/vault/files_add" => {
                    let added = FilesAddRequest::decode(payload.payload.as_slice()).unwrap();
                    FilesAddResponse {
                        files: added
                            .files
                            .iter()
                            .map(|file| {
                                file_keys.push((
                                    file.record_uid.clone(),
                                    crypto::decrypt_aes_v2(&file.record_key, &[9; 32]).unwrap(),
                                ));
                                FileAddStatus {
                                    record_uid: file.record_uid.clone(),
                                    url: upload_url.to_owned(),
                                    parameters: "{}".into(),
                                    success_status_code: 201,
                                    status: FileAddResult::FaSuccess as i32,
                                    ..Default::default()
                                }
                            })
                            .collect(),
                        ..Default::default()
                    }
                    .encode_to_vec()
                }
                "/api/rest/vault/records_update" => {
                    let update = RecordsUpdateRequest::decode(payload.payload.as_slice()).unwrap();
                    let Some(update_record) = update.records.first() else {
                        panic!("records_update fixture received no record");
                    };
                    assert_eq!(update_record.record_links_add.len(), 1);
                    let Some(link) = update_record.record_links_add.first() else {
                        panic!("records_update fixture received no file link");
                    };
                    let Some((file_uid, file_key)) = file_keys.iter().find(|(uid, _)| uid == &link.record_uid) else {
                        panic!("records_update fixture linked an unregistered file");
                    };
                    assert_eq!(&link.record_uid, file_uid);
                    assert_eq!(
                        crypto::decrypt_aes_v2(&link.record_key, &[1; 32]).unwrap().as_slice(),
                        file_key.as_slice()
                    );
                    let data = crypto::decrypt_aes_v2(&update_record.data, &[1; 32]).unwrap();
                    let data: Value = serde_json::from_slice(&data).unwrap();
                    let fields = data
                        .get("fields")
                        .and_then(Value::as_array)
                        .expect("updated record fields");
                    let file_ref = Value::String(b64_encode(file_uid));
                    assert!(fields.iter().any(|field| {
                        field.get("type").and_then(Value::as_str) == Some("fileRef")
                            && field
                                .get("value")
                                .and_then(Value::as_array)
                                .is_some_and(|values| values.contains(&file_ref))
                    }));
                    let mut response = RecordsModifyResponse::default();
                    response.records.push(Default::default());
                    let Some(status) = response.records.first_mut() else {
                        panic!("records_update response fixture missing its status");
                    };
                    status.record_uid = update_record.record_uid.clone();
                    status.status = RecordModifyResult::RsSuccess as i32;
                    response.encode_to_vec()
                }
                _ => panic!("unexpected REST endpoint: {path}"),
            };
            paths.push(path);
            let response = crypto::encrypt_aes_v2(&response, transmission_key).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let mut file_keys = Vec::new();
            let mut paths = Vec::new();
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        serve_rest_request(&mut stream, &transmission_key, &upload_url, &mut file_keys, &mut paths);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match stopped.recv_timeout(std::time::Duration::from_millis(10)) {
                            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                        }
                    }
                    Err(error) => panic!("accepting REST fixture request: {error}"),
                }
            }
            paths
        });
        RestFixture { url, worker, stop }
    }
    struct UploadRunOutcome {
        result:            Result<()>,
        routes:            Vec<String>,
        upload_request:    Vec<u8>,
        vault_invalidated: bool,
    }

    fn run_upload_fixture(upload_status: &'static str) -> UploadRunOutcome {
        let dir = temp_dir();
        let file_path = dir.join("run.txt");
        std::fs::write(&file_path, b"run-level payload").unwrap();
        let transmission_key = [7; 32];
        let upload_server = serve_once(upload_status, Vec::new());
        let rest = rest_fixture(transmission_key, upload_server.url.clone());
        let parent = record("UPLOAD_RECORD", RecordKind::Typed, json!({"title": "Server"}), 1);
        let record_selector = parent.uid.to_string();
        let session = crate::auth::Session {
            rest:          crate::rest::RestContext::for_test(
                reqwest::Url::parse(&rest.url).unwrap(),
                transmission_key,
            )
            .unwrap(),
            user:          "fixture@example.test".into(),
            session_token: vec![1, 2, 3],
            data_key:      key(9),
            rsa_key:       None,
            ecc_key:       None,
            summary:       Default::default(),
        };
        let mut app = App {
            settings: crate::settings::Settings::default(),
            user:     None,
            password: crate::auth::Password::Prompt,
            account:  Some(crate::commands::Account {
                session,
                vault: Some(vault_of([parent])),
                cwd: Location::Root,
            }),
        };
        let result = UploadAttachment {
            files:  vec![UserPath(file_path)],
            record: record_selector,
        }
        .run(&mut app);
        let vault_invalidated = app.account.as_ref().is_some_and(|account| account.vault.is_none());
        rest.stop.send(()).unwrap();
        let requests = rest.worker.join().unwrap();
        let upload_request = upload_server.worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        UploadRunOutcome {
            result,
            routes: requests,
            upload_request,
            vault_invalidated,
        }
    }

    fn serve_concurrent(
        status: &'static str,
        reply: Vec<u8>,
        requests: usize,
    ) -> (String, std::thread::JoinHandle<(usize, usize)>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let peak = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut handlers = Vec::with_capacity(requests);
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let reply = reply.clone();
                let active = std::sync::Arc::clone(&active);
                let peak = std::sync::Arc::clone(&peak);
                handlers.push(std::thread::spawn(move || {
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0; 16 * 1024];
                    let mut total = None;
                    while total.is_none_or(|total| request.len() < total) {
                        let read = stream.read(&mut chunk).unwrap();
                        assert!(read > 0, "client hung up mid-request");
                        request.extend_from_slice(chunk.get(..read).expect("read count fits chunk buffer"));
                        if total.is_none()
                            && let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let (head_bytes, _) = request.split_at_checked(head_end).expect("delimiter is in request");
                            let head = String::from_utf8_lossy(head_bytes).to_lowercase();
                            let length = head
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length: "))
                                .map_or(0, |length| length.trim().parse().unwrap());
                            total = Some(
                                head_end
                                    .checked_add(4)
                                    .and_then(|head| head.checked_add(length))
                                    .unwrap(),
                            );
                        }
                    }
                    let now = active.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    peak.fetch_max(now, std::sync::atomic::Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len())
                        .unwrap();
                    stream.write_all(&reply).unwrap();
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
            (active.load(std::sync::atomic::Ordering::Relaxed), peak.load(std::sync::atomic::Ordering::Relaxed))
        });
        (url, worker)
    }

    #[test]
    fn upload_worker_count_is_bounded_against_concurrent_local_http_requests() {
        let dir = temp_dir();
        let mut files = Vec::new();
        for index in 0..8u8 {
            let path = dir.join(format!("file-{index}.txt"));
            std::fs::write(&path, [index]).unwrap();
            files.push(UploadFile {
                local: LocalFile::try_from(&UserPath(path)).unwrap(),
                uid:   vec![index; 16],
                key:   key(index),
            });
        }
        let (url, server) = serve_concurrent("201 Created", Vec::new(), files.len());
        let statuses = files
            .iter()
            .map(|file| {
                FileAddStatus {
                    record_uid: file.uid.clone(),
                    url: url.clone(),
                    parameters: "{}".into(),
                    success_status_code: 201,
                    status: FileAddResult::FaSuccess as i32,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        upload_files(&http, &files, &statuses).unwrap();
        let (active, peak) = server.join().unwrap();
        assert_eq!(active, 0);
        assert!(peak > 1 && peak <= TRANSFER_WORKERS, "peak concurrent requests: {peak}");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn download_decrypts_before_writing_plaintext() {
        let dir = temp_dir();
        let path = dir.join("out.bin");
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let plain: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        for (cipher, sealed) in [
            (Cipher::Gcm, crypto::encrypt_aes_v2(&plain, &key).unwrap()),
            (Cipher::Cbc, crypto::encrypt_cbc::<Pkcs7>(&plain, &key).unwrap()),
        ] {
            let server = serve_once("200 OK", sealed);
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url: server.url.clone(),
                    cipher,
                },
                &key,
                &path,
            )
            .unwrap();
            let request = String::from_utf8(server.worker.join().unwrap()).unwrap();
            assert!(request.starts_with("GET /blob HTTP/1.1\r\n"));
            assert_eq!(std::fs::read(&path).unwrap(), plain);
            std::fs::remove_file(&path).unwrap();
        }
        let server = serve_once("403 Forbidden", b"denied".to_vec());
        assert!(
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url:    server.url.clone(),
                    cipher: Cipher::Gcm,
                },
                &key,
                &path
            )
            .unwrap_err()
            .to_string()
            .contains("403")
        );
        server.worker.join().unwrap();
        let mut forged = crypto::encrypt_aes_v2(&plain, &key).unwrap();
        *forged.get_mut(100).expect("GCM fixture is long enough") ^= 1;
        let server = serve_once("200 OK", forged);
        assert!(
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url:    server.url.clone(),
                    cipher: Cipher::Gcm,
                },
                &key,
                &path
            )
            .is_err()
        );
        server.worker.join().unwrap();
        assert!(!path.exists());
        // Legacy CBC rejects invalid padding before output creation, but has no MAC for data integrity.
        let mut bad_padding = crypto::encrypt_cbc::<Pkcs7>(b"15-byte-message", &key).unwrap();
        *bad_padding.get_mut(15).expect("CBC fixture contains a 16-byte IV") ^= 1;
        let server = serve_once("200 OK", bad_padding);
        assert!(
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url:    server.url.clone(),
                    cipher: Cipher::Cbc,
                },
                &key,
                &path
            )
            .is_err()
        );
        server.worker.join().unwrap();
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_length_chunked_download_uses_exclusive_admission() {
        let dir = temp_dir();
        let path = dir.join("chunked.bin");
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let plain = b"chunked attachment body";
        let sealed = crypto::encrypt_aes_v2(plain, &key).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let read = stream.read(&mut request).unwrap();
            assert!(
                request
                    .get(..read)
                    .expect("read count fits buffer")
                    .starts_with(b"GET /blob HTTP/1.1\r\n")
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n",
                sealed.len()
            )
            .unwrap();
            stream.write_all(&sealed).unwrap();
            stream.write_all(b"\r\n0\r\n\r\n").unwrap();
        });
        download_buffered(
            &http,
            &TransferBudget::new(),
            &Ticket {
                url,
                cipher: Cipher::Gcm,
            },
            &key,
            &path,
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), plain);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parallel_download_jobs_fetch_decrypt_and_write_real_http_bodies() {
        let dir = temp_dir();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let plain = b"parallel attachment";
        let attachments = [
            attachment("same.txt"),
            attachment("same.txt"),
            attachment("same.txt"),
            attachment("same.txt"),
        ];
        let sealed = crypto::encrypt_aes_v2(plain, &key).unwrap();
        let (url, server) = serve_concurrent("200 OK", sealed, attachments.len());
        let mut reserved = HashSet::new();
        let jobs = attachments
            .iter()
            .map(|attachment| {
                DownloadJob {
                    attachment,
                    ticket: Ticket {
                        url:    url.clone(),
                        cipher: Cipher::Gcm,
                    },
                    path: free_path(&dir, "same.txt", "record", &attachment.id, &mut reserved),
                }
            })
            .collect::<Vec<_>>();
        let budget = TransferBudget::new();
        let failures = parallel_each(&jobs, |job| download_buffered(&http, &budget, &job.ticket, &key, &job.path));
        assert!(failures.is_empty(), "{failures:?}");
        for job in &jobs {
            assert_eq!(std::fs::read(&job.path).unwrap(), plain);
        }
        let (active, peak) = server.join().unwrap();
        assert_eq!(active, 0);
        assert!(peak > 1 && peak <= TRANSFER_WORKERS, "peak concurrent downloads: {peak}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parallel_downloads_retain_every_independent_http_failure() {
        let dir = temp_dir();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let attachments = [attachment("first.txt"), attachment("second.txt")];
        let servers = [
            serve_once("403 Forbidden", Vec::new()),
            serve_once("503 Service Unavailable", Vec::new()),
        ];
        let jobs = attachments
            .iter()
            .zip(&servers)
            .enumerate()
            .map(|(index, (attachment, server))| {
                DownloadJob {
                    attachment,
                    ticket: Ticket {
                        url:    server.url.clone(),
                        cipher: Cipher::Gcm,
                    },
                    path: dir.join(format!("failure-{index}.txt")),
                }
            })
            .collect::<Vec<_>>();
        let budget = TransferBudget::new();
        let failure_key = key(8);
        let failures = parallel_each(&jobs, |job| {
            download_buffered(&http, &budget, &job.ticket, &failure_key, &job.path).map_err(|error| {
                Error::Context {
                    context: format!("downloading {}", job.attachment.name),
                    source:  Box::new(error),
                }
            })
        });
        assert_eq!(failures.len(), 2);
        for (server, job) in servers.into_iter().zip(&jobs) {
            let request = server.worker.join().unwrap();
            assert!(request.starts_with(b"GET /blob HTTP/1.1\r\n"));
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.to_string().contains(&job.attachment.name))
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn download_refuses_a_target_created_after_name_selection() {
        let dir = temp_dir();
        let path = free_path(&dir, "out.bin", "record", "file", &mut HashSet::new());
        let sentinel = b"keep this file";
        std::fs::write(&path, sentinel).unwrap();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let sealed = crypto::encrypt_aes_v2(b"downloaded plaintext", &key).unwrap();
        let server = serve_once("200 OK", sealed);
        assert!(
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url:    server.url.clone(),
                    cipher: Cipher::Gcm,
                },
                &key,
                &path
            )
            .is_err()
        );
        server.worker.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sentinel);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn download_refuses_a_symlink_target() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir();
        let target = dir.join("sentinel");
        let path = free_path(&dir, "out.bin", "record", "file", &mut HashSet::new());
        let sentinel = b"keep this file";
        std::fs::write(&target, sentinel).unwrap();
        symlink(&target, &path).unwrap();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let sealed = crypto::encrypt_aes_v2(b"downloaded plaintext", &key).unwrap();
        let server = serve_once("200 OK", sealed);
        assert!(
            download_buffered(
                &http,
                &TransferBudget::new(),
                &Ticket {
                    url:    server.url.clone(),
                    cipher: Cipher::Gcm,
                },
                &key,
                &path
            )
            .is_err()
        );
        server.worker.join().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), sentinel);
        assert!(path.is_symlink());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn upload_http_posts_a_framed_multipart_form_with_the_encrypted_file_last() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..=255u8).cycle().take(50_000).collect();
        std::fs::write(dir.join("report.pdf"), &content).unwrap();
        let file = UploadFile {
            local: LocalFile::try_from(&UserPath(dir.join("report.pdf"))).unwrap(),
            uid:   vec![5; 16],
            key:   key(9),
        };
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let server = serve_once("201 Created", Vec::new());
        let target = FileAddStatus {
            url: server.url.clone(),
            parameters: r#"{"key":"uploads/abc","policy":"p"}"#.into(),
            success_status_code: 201,
            ..Default::default()
        };
        let target = prepare_upload(&file, &target).unwrap();
        send(&http, &target).unwrap();
        let request = server.worker.join().unwrap();
        let head_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP header delimiter");
        let (head_bytes, frame) = request.split_at_checked(head_end).expect("delimiter is in request");
        let body = frame.strip_prefix(b"\r\n\r\n").expect("delimiter was found");
        let head = String::from_utf8(head_bytes.to_vec()).unwrap().to_lowercase();
        let header = |name: &str| {
            head.lines()
                .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                .map(str::to_owned)
                .unwrap()
        };
        let boundary = header("content-type")
            .strip_prefix("multipart/form-data; boundary=")
            .unwrap()
            .to_owned();
        assert!(head.starts_with("post /blob http/1.1\r\n"));
        assert_eq!(header("content-length"), body.len().to_string());

        let marker = format!("--{boundary}\r\n");
        let closing = format!("\r\n--{boundary}--\r\n");
        let mut remaining = body.strip_prefix(marker.as_bytes()).expect("form begins with boundary");
        assert!(body.ends_with(closing.as_bytes()));
        let mut fields = BTreeMap::new();
        let (file_headers, encrypted) = loop {
            let header_end = remaining
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("multipart header delimiter");
            let (header_bytes, frame) = remaining.split_at_checked(header_end).expect("delimiter is in part");
            let headers = std::str::from_utf8(header_bytes).unwrap().to_owned();
            let payload = frame
                .strip_prefix(b"\r\n\r\n")
                .expect("part header delimiter was found");
            if headers.starts_with("Content-Disposition: form-data; name=\"file\";") {
                let file_ref = b64_encode(&file.uid);
                assert_eq!(
                    headers,
                    format!(
                        "Content-Disposition: form-data; name=\"file\"; filename=\"{file_ref}\"\r\n\
                         Content-Type: application/octet-stream"
                    )
                );
                let encrypted = payload
                    .strip_suffix(closing.as_bytes())
                    .expect("file part closes the form");
                break (headers, encrypted);
            }
            let name = if headers == "Content-Disposition: form-data; name=\"key\"" {
                "key"
            } else if headers == "Content-Disposition: form-data; name=\"policy\"" {
                "policy"
            } else {
                panic!("unexpected multipart field header: {headers}");
            };
            let separator = format!("\r\n{marker}");
            let next = payload
                .windows(separator.len())
                .position(|window| window == separator.as_bytes())
                .expect("multipart field separator");
            let (value, rest) = payload.split_at_checked(next).expect("separator is in payload");
            assert!(fields.insert(name.to_owned(), value.to_vec()).is_none());
            remaining = rest.strip_prefix(separator.as_bytes()).expect("separator was found");
        };
        assert_eq!(file_headers.lines().count(), 2);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields.get("key").map(Vec::as_slice), Some(b"uploads/abc".as_slice()));
        assert_eq!(fields.get("policy").map(Vec::as_slice), Some(b"p".as_slice()));
        assert_eq!(crypto::decrypt_aes_v2(encrypted, &file.key).unwrap(), content);

        let server = serve_once("200 OK", Vec::new());
        let target = FileAddStatus {
            url: server.url.clone(),
            parameters: "{}".into(),
            success_status_code: 201,
            ..Default::default()
        };
        let target = prepare_upload(&file, &target).unwrap();
        assert!(send(&http, &target).is_err());
        server.worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn upload_files_sends_every_valid_target_and_reports_each_http_failure() {
        let dir = temp_dir();
        let paths = [dir.join("one.txt"), dir.join("two.txt")];
        for (path, body) in paths.iter().zip([b"one".as_slice(), b"two".as_slice()]) {
            std::fs::write(path, body).unwrap();
        }
        let files = paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                UploadFile {
                    local: LocalFile::try_from(&UserPath(path.clone())).unwrap(),
                    uid:   vec![u8::try_from(index + 1).unwrap(); 16],
                    key:   key(u8::try_from(index + 1).unwrap()),
                }
            })
            .collect::<Vec<_>>();
        let servers = [
            serve_once("500 Internal Server Error", Vec::new()),
            serve_once("503 Service Unavailable", Vec::new()),
        ];
        let statuses = files
            .iter()
            .zip(&servers)
            .map(|(file, server)| {
                FileAddStatus {
                    record_uid: file.uid.clone(),
                    url: server.url.clone(),
                    parameters: "{}".into(),
                    success_status_code: 201,
                    status: FileAddResult::FaSuccess as i32,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let error = upload_files(&http, &files, &statuses).unwrap_err();
        let Error::AttachmentBatch { failures } = error else {
            panic!("expected aggregated upload failures");
        };
        assert_eq!(failures.len(), 2);
        for (server, file) in servers.into_iter().zip(&files) {
            let request = server.worker.join().unwrap();
            assert!(request.starts_with(b"POST /blob HTTP/1.1\r\n"));
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.to_string().contains(&file.local.name))
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn upload_run_sends_real_link_request_after_local_upload_success() {
        let outcome = run_upload_fixture("201 Created");
        assert!(outcome.result.is_ok());
        assert!(outcome.vault_invalidated);
        assert_eq!(
            outcome.routes,
            [
                "/api/rest/vault/files_add".to_owned(),
                "/api/rest/vault/records_update".to_owned()
            ]
        );
        assert!(outcome.upload_request.starts_with(b"POST /blob HTTP/1.1\r\n"));
    }

    #[test]
    fn upload_run_never_sends_real_link_request_after_local_upload_failure() {
        let outcome = run_upload_fixture("500 Internal Server Error");
        assert!(matches!(outcome.result, Err(Error::AttachmentBatch { failures }) if failures.len() == 1));
        assert_eq!(outcome.routes, ["/api/rest/vault/files_add"]);
        assert!(outcome.upload_request.starts_with(b"POST /blob HTTP/1.1\r\n"));
    }
    #[test]
    fn rejected_registration_does_not_send_any_file_payload() {
        let dir = temp_dir();
        let path = dir.join("file.txt");
        std::fs::write(&path, b"payload").unwrap();
        let file = UploadFile {
            local: LocalFile::try_from(&UserPath(path)).unwrap(),
            uid:   vec![3; 16],
            key:   key(3),
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = FileAddStatus {
            record_uid: file.uid.clone(),
            url: format!("http://{}/blob", listener.local_addr().unwrap()),
            parameters: "{}".into(),
            success_status_code: 201,
            status: 91,
            ..Default::default()
        };
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let error = upload_files(&http, &[file], &[target]).unwrap_err();
        assert!(matches!(error, Error::AttachmentBatch { failures } if failures.len() == 1));
        assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
