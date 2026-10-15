//! Download and upload files attached to Keeper records.
//!
//! Typed records point to v4 file records through `fileRef`; legacy records keep files in
//! `extra.files`. File contents use signed URLs and are authenticated before a download is written.

use std::collections::BTreeMap;
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
use crate::vault::{Location, Record, RecordKind, Vault};

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

impl TryFrom<&Value> for Attachment {
    type Error = Error;

    fn try_from(file: &Value) -> Result<Self> {
        let text = |field: &str| file.get(field).and_then(Value::as_str).unwrap_or_default().to_owned();
        Ok(Self {
            id:    text("id"),
            name:  text("name"),
            title: text("title"),
            key:   AesKey::try_from(b64_decode(&text("key"))?)?,
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
            file.data
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim()
                .to_owned()
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
                    .and_then(|extra| extra.get("files"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(Self::try_from)
                    .collect()
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
        for (index, attachment) in attachments.iter().enumerate() {
            let ticket = match response.ticket(attachment, index) {
                Ok(ticket) => ticket,
                Err(error) => {
                    self.failures.push(error);
                    continue;
                }
            };
            let name = local_name(attachment, record, self.naming);
            let path = free_path(&dir, &name, record.uid.as_ref(), &attachment.id);
            eprintln!("Downloading '{}'", std::path::absolute(&path)?.display());
            download(self.http, &ticket, &attachment.key, &path)?;
            self.saved += 1;
        }
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
        app.ensure_synced()?;
        let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
        let session = &mut account.session;
        let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
        let records = select_records(vault, &account.cwd, &self.records, depth);
        if records.is_empty() {
            return Err(Error::Generic(format!("Record(s) \"{}\" not found", self.records.join(", "))));
        }
        std::fs::create_dir_all(&out_dir)?;
        let http = http_client()?;
        let mut operation = DownloadOperation {
            session,
            vault,
            http: &http,
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
        operation.finish(result)
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
fn free_path(dir: &Path, name: &str, record_uid: &str, file_id: &str) -> PathBuf {
    let path = dir.join(name);
    if !path.exists() {
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
        if !candidate.exists() {
            return candidate;
        }
    }
    let mut suffix = 2u64;
    loop {
        let candidate = dir.join(format!("{stem}({file_id}-{suffix}){extension}"));
        if !candidate.exists() {
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
                let grant = response["downloads"]
                    .as_array()
                    .and_then(|downloads| downloads.get(index))
                    .ok_or_else(|| invalid("is missing from the positional download response"))?;
                let Some(url) = grant.get("url").and_then(Value::as_str).filter(|url| !url.is_empty()) else {
                    return Err(invalid("was refused or has malformed positional grant data"));
                };
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
        rq["shared_folder_uid"] = folder.into();
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

/// Fetch and authenticate a signed download before writing any plaintext to disk.
fn download(http: &reqwest::blocking::Client, ticket: &Ticket, key: &[u8], path: &Path) -> Result<()> {
    let mut response = http.get(&ticket.url).send()?;
    if !response.status().is_success() {
        return Err(Error::Generic(format!("HTTP status code {}", response.status().as_u16())));
    }
    let mut body = Vec::new();
    if let Some(len) = response.content_length() {
        let len = usize::try_from(len).map_err(|error| {
            Error::Context {
                context: format!("download size for {}", path.display()),
                source:  Box::new(Error::Integer(error)),
            }
        })?;
        body.try_reserve_exact(len).map_err(|error| {
            Error::Context {
                context: format!("reserving {len} bytes for {}", path.display()),
                source:  Box::new(Error::Allocation(error)),
            }
        })?;
    }
    response.read_to_end(&mut body)?;
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
        std::fs::File::open(&file.local.path)?.read_to_end(&mut frame)?;
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
        let files = self.files.iter().map(LocalFile::try_from).collect::<Result<Vec<_>>>()?;
        app.ensure_synced()?;
        let account = app.account.as_mut().ok_or(Error::NotLoggedIn)?;
        let session = &mut account.session;
        let vault = account.vault.as_ref().ok_or(Error::NotLoggedIn)?;
        let cwd = &account.cwd;
        let record = vault
            .resolve_record(cwd, &self.record)
            .ok_or_else(|| Error::Generic(format!("Record UID not found for record \"{}\"", self.record)))?;
        if !matches!(&record.kind, RecordKind::Typed) {
            return Err(Error::Generic(format!(
                "Cannot attach files to \"{}\": only typed (v3) records are supported",
                record.title()
            )));
        }

        let files: Vec<UploadFile> = files.into_iter().map(UploadFile::from).collect();
        let add = add_request(&files, &session.data_key)?;
        let body = session.rest.execute("vault/files_add", &session.session_token, &add)?;
        let added = FilesAddResponse::decode(body.as_slice())?;
        let http = http_client()?;
        for file in &files {
            let target = added
                .files
                .iter()
                .find(|status| status.record_uid == file.uid && status.status == FileAddResult::FaSuccess as i32)
                .ok_or_else(|| Error::Generic(format!("Uploading file {}: Get upload URL error.", file.local.name)))?;
            send(&http, target, file)?;
        }

        let key_type = if session.summary.forbid_key_type2 {
            RecordKeyType::EncryptedByPublicKeyEcc
        } else {
            RecordKeyType::EncryptedByPublicKey
        };
        let rq = link_request(record, &files, key_type)?;
        let body = session
            .rest
            .execute("vault/records_update", &session.session_token, &rq)?;
        let updated = RecordsModifyResponse::decode(body.as_slice())?;
        if let Some(status) = updated
            .records
            .iter()
            .find(|status| status.record_uid == rq.records[0].record_uid)
            .filter(|status| status.status != RecordModifyResult::RsSuccess as i32)
        {
            let name = RecordModifyResult::try_from(status.status).map_or("UNKNOWN", |result| result.as_str_name());
            return Err(Error::api(name, status.message.clone()));
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

fn send(http: &reqwest::blocking::Client, target: &FileAddStatus, file: &UploadFile) -> Result<()> {
    let frame = Vec::try_from(file)?;
    let boundary = data_encoding::HEXLOWER.encode(&crypto::random_bytes(16));
    let fields: serde_json::Map<String, Value> = serde_json::from_str(&target.parameters)?;
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
    let len = (head.len() + frame.len() + tail.len()) as u64;
    let body = reqwest::blocking::Body::sized(
        std::io::Cursor::new(head.into_bytes())
            .chain(std::io::Cursor::new(frame))
            .chain(std::io::Cursor::new(tail.into_bytes())),
        len,
    );
    let response = http
        .post(&target.url)
        .header("Content-Type", format!("multipart/form-data; boundary={boundary}"))
        .body(body)
        .send()?;
    let status = response.status().as_u16();
    if i32::from(status) != target.success_status_code {
        return Err(Error::Generic(format!("Uploading file {}: HTTP status code {status}", file.local.name)));
    }
    Ok(())
}

fn link_request(record: &Record, files: &[UploadFile], key_type: RecordKeyType) -> Result<RecordsUpdateRequest> {
    let mut data = record.data.clone();
    let fields = data
        .as_object_mut()
        .map(|object| object.entry("fields").or_insert_with(|| serde_json::json!([])))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::Generic(format!("Record {} has malformed data", record.uid)))?;
    let refs = files.iter().map(|file| Value::from(b64_encode(&file.uid)));
    let listed = fields
        .iter_mut()
        .find(|field| field["type"] == "fileRef")
        .and_then(|field| field.get_mut("value"))
        .and_then(Value::as_array_mut);
    match listed {
        Some(listed) => listed.extend(refs),
        None => fields.push(serde_json::json!({"type": "fileRef", "value": refs.collect::<Vec<_>>()})),
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
            data,
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
        let found = Attachment::of(&vault, &vault.records[&parent_uid]).unwrap();
        assert_eq!(found.iter().map(|file| file.name.as_str()).collect::<Vec<_>>(), ["a.txt", "b.bin"]);
        assert_eq!(found[0].key, key(2));

        assert!(Attachment::of(&vault, &malformed_ref).is_err());
        assert_eq!(
            Attachment::of(&vault, &vault.records[&Uid::from(b"F2".as_slice())])
                .unwrap()
                .len(),
            1
        );

        let legacy_key = [9u8; 32];
        let legacy = record(
            "OLD",
            RecordKind::Legacy {
                extra: Some(
                    json!({"files": [{"id": "ATT1", "name": "scan.pdf", "title": "Scan", "key": b64_encode(&legacy_key)}]}),
                ),
            },
            json!({"title": "Legacy"}),
            1,
        );
        assert_eq!(Attachment::of(&Vault::default(), &legacy).unwrap()[0].key, key(9));
        let malformed = record(
            "BAD",
            RecordKind::Legacy {
                extra: Some(json!({"files": [{"id": "ATT2", "key": "***"}]})),
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
        let mut saved = Vec::new();
        for marker in 0..4u8 {
            let path = free_path(&dir, "a.tar.gz", &record_uid, &file_uid);
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
        let attachments = ids.each_ref().map(|id| {
            Attachment {
                id:    id.as_str().to_owned(),
                name:  String::new(),
                title: String::new(),
                key:   key(0),
            }
        });
        let files = DownloadResponse::Files(FilesGetResponse {
            files: vec![
                crate::proto::records::FileGetStatus {
                    record_uid: b64_decode(&ids[1]).unwrap(),
                    status: 91,
                    ..Default::default()
                },
                crate::proto::records::FileGetStatus {
                    record_uid: b64_decode(&ids[0]).unwrap(),
                    status: FileGetResult::FgSuccess as i32,
                    url: "https://example.invalid/one".into(),
                    file_key_type: RecordKeyType::EncryptedByDataKey as i32,
                    ..Default::default()
                },
            ],
        });
        assert_eq!(files.ticket(&attachments[0], 0).unwrap().url, "https://example.invalid/one");
        for attachment in &attachments[1..] {
            let message = format!("{:?}", files.ticket(attachment, 1).err().unwrap());
            assert!(message.contains(&attachment.id), "{message}");
        }

        let legacy = DownloadResponse::Legacy(json!({
            "downloads": [{"url": "https://example.invalid/one"}, {"url": ""}]
        }));
        assert_eq!(legacy.ticket(&attachments[0], 0).unwrap().url, "https://example.invalid/one");
        for (index, attachment) in attachments.iter().enumerate().skip(1) {
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
        let add = add_request(&files, &[5; 32]).unwrap();
        for (entry, file, expected_metadata, expected_size) in [
            (
                &add.files[0],
                &files[0],
                json!({"title": "notes.txt", "name": "notes.txt", "type": "text/plain", "size": 11}),
                111i64,
            ),
            (
                &add.files[1],
                &files[1],
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
            json!({"title": "Server", "fields": [{"type": "login", "value": ["root"]}, {"type": "fileRef", "value": ["OLD"]}]}),
            1,
        );
        parent.uid = uid;
        parent.revision = 41;
        let update = link_request(&parent, &files, RecordKeyType::EncryptedByPublicKeyEcc).unwrap();
        assert_eq!(update.security_data_key_type, RecordKeyType::EncryptedByPublicKeyEcc as i32);
        let updated = &update.records[0];
        assert_eq!(updated.record_uid, Vec::<u8>::from(&parent.uid));
        assert_eq!(updated.revision, 41);
        let plain = crypto::decrypt_aes_v2(&updated.data, &parent.key).unwrap();
        assert!(plain.len() >= 384 && plain.len().is_multiple_of(16));
        let data: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(data["fields"][0], parent.data["fields"][0]);
        assert_eq!(data["fields"][1]["value"], json!(["OLD", b64_encode(&files[0].uid), b64_encode(&files[1].uid)]));
        assert_eq!(updated.record_links_add.len(), files.len());
        for (link, file) in updated.record_links_add.iter().zip(&files) {
            assert_eq!(link.record_uid, file.uid);
            let linked_key = crypto::decrypt_aes_v2(&link.record_key, &parent.key).unwrap();
            assert_eq!(linked_key.as_slice(), &*file.key);
        }
        let no_fields = record("P2", RecordKind::Typed, json!({"title": "A"}), 1);
        let no_fields_update = link_request(&no_fields, &files[1..], RecordKeyType::EncryptedByPublicKey).unwrap();
        let no_fields_data = crypto::decrypt_aes_v2(&no_fields_update.records[0].data, &no_fields.key).unwrap();
        let no_fields_data: Value = serde_json::from_slice(&no_fields_data).unwrap();
        assert_eq!(no_fields_data["fields"], json!([{"type": "fileRef", "value": [b64_encode(&files[1].uid)]}]));
        let malformed = record("P3", RecordKind::Typed, json!(["not", "an", "object"]), 1);
        assert!(link_request(&malformed, &files[1..], RecordKeyType::EncryptedByPublicKey).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct TestServer {
        url:    String,
        worker: std::thread::JoinHandle<Vec<u8>>,
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
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 16 * 1024];
            let mut total = None;
            while total.is_none_or(|total| request.len() < total) {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "client hung up mid-request");
                request.extend_from_slice(&chunk[..read]);
                if total.is_none()
                    && let Some(head_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let head = String::from_utf8_lossy(&request[..head_end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .map_or(0, |length| length.trim().parse().unwrap());
                    total = Some(head_end + 4 + length);
                }
            }
            write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len())
                .unwrap();
            stream.write_all(&reply).unwrap();
            request
        });
        TestServer { url, worker }
    }
    #[test]
    fn download_http_authenticates_before_writing_plaintext() {
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
            download(
                &http,
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
            download(
                &http,
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
        forged[100] ^= 1;
        let server = serve_once("200 OK", forged);
        assert!(
            download(
                &http,
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
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn download_refuses_a_target_created_after_name_selection() {
        let dir = temp_dir();
        let path = free_path(&dir, "out.bin", "record", "file");
        let sentinel = b"keep this file";
        std::fs::write(&path, sentinel).unwrap();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let sealed = crypto::encrypt_aes_v2(b"downloaded plaintext", &key).unwrap();
        let server = serve_once("200 OK", sealed);
        assert!(
            download(
                &http,
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
        let path = free_path(&dir, "out.bin", "record", "file");
        let sentinel = b"keep this file";
        std::fs::write(&target, sentinel).unwrap();
        symlink(&target, &path).unwrap();
        let http = reqwest::blocking::Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let sealed = crypto::encrypt_aes_v2(b"downloaded plaintext", &key).unwrap();
        let server = serve_once("200 OK", sealed);
        assert!(
            download(
                &http,
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
        send(&http, &target, &file).unwrap();
        let request = server.worker.join().unwrap();
        let head_end = request.windows(4).position(|window| window == b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8(request[..head_end].to_vec()).unwrap().to_lowercase();
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
        let body = &request[head_end..];
        assert!(head.starts_with("post /blob http/1.1\r\n"));
        assert_eq!(header("content-length"), body.len().to_string());

        let marker = format!("--{boundary}\r\n");
        let closing = format!("\r\n--{boundary}--\r\n");
        assert!(body.starts_with(marker.as_bytes()));
        assert!(body.ends_with(closing.as_bytes()));
        let mut remaining = &body[marker.len()..];
        let mut fields = BTreeMap::new();
        let (file_headers, encrypted) = loop {
            let header_end = remaining.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
            let headers = std::str::from_utf8(&remaining[..header_end]).unwrap().to_owned();
            let payload = &remaining[header_end + 4..];
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
                .unwrap();
            let value = &payload[..next];
            assert!(fields.insert(name.to_owned(), value.to_vec()).is_none());
            remaining = &payload[next + separator.len()..];
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
        assert!(send(&http, &target, &file).is_err());
        server.worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
