//! `download-attachment` and `upload-attachment`: the files attached to records.
//!
//! A v3 record lists its files in a `fileRef` field. Each entry is the UID of a v4 *file record*
//! whose own key encrypts the content, stored behind a signed URL that `vault/files_download`
//! (`vault/files_add` for uploads) hands out. A legacy v2 record keeps its files in `extra.files`,
//! each with a key of its own, and gets the URL from the JSON `request_download` command. Content
//! is framed like every other Keeper blob: `iv|ciphertext` for CBC, `nonce|ciphertext|tag` for GCM.
//!
//! Uploading adds a file record per file (`files_add`), posts the encrypted content to the signed
//! form it returns, then rewrites the parent so its `fileRef` lists the new UIDs and
//! `record_links_add` carries each file key wrapped in the parent's key.
//!
//! ponytail: a file is held in memory whole (once, encrypted or decrypted in place). Stream it if
//! attachments beyond a few hundred MB matter; GCM can only be authenticated at the end anyway.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt;
use std::io::{Cursor, Read};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use reqwest::blocking::{Body, Client};
use serde_json::{Value, json};

use crate::auth::Session;
use crate::commands::{App, Run, resolve_folder, resolve_record};
use crate::crypto;
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
use crate::vault::{Record, Vault};

/// Download record attachments
#[derive(Args, Debug)]
pub struct DownloadAttachment {
    /// Record or folder UID or path; a folder downloads the attachments of every record in it
    #[arg(required = true)]
    records:      Vec<String>,
    /// Descend into subfolders
    #[arg(short, long)]
    recursive:    bool,
    /// Local folder for downloaded files [default: the current folder]
    #[arg(long)]
    out_dir:      Option<UserPath>,
    /// Recreate the vault folder structure below the output folder
    #[arg(long)]
    preserve_dir: bool,
    /// Prefix file names with the record title
    #[arg(long)]
    record_title: bool,
    /// Only the attachment with this name, title or ID (repeatable)
    #[arg(long = "name")]
    names:        Vec<String>,
}

/// A path typed on the command line. A leading `~` is the home folder, as in Commander: the shell
/// leaves it alone inside quotes and this program's own shell never expands it.
#[derive(Clone, Debug)]
pub struct UserPath(PathBuf);

impl FromStr for UserPath {
    type Err = Infallible;

    fn from_str(typed: &str) -> Result<Self, Infallible> {
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

/// Where a record's files go below the output folder.
#[derive(Clone, Copy)]
enum Layout {
    Flat,
    ByFolder,
}

impl From<bool> for Layout {
    fn from(preserve_dir: bool) -> Self {
        if preserve_dir { Self::ByFolder } else { Self::Flat }
    }
}

/// How saved files are named.
#[derive(Clone, Copy)]
enum Naming {
    Stored,
    WithRecordTitle,
}

impl From<bool> for Naming {
    fn from(record_title: bool) -> Self {
        if record_title {
            Self::WithRecordTitle
        } else {
            Self::Stored
        }
    }
}

/// Whether a folder argument stands for the folder alone or its whole subtree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth {
    Folder,
    Subtree,
}

impl From<bool> for Depth {
    fn from(recursive: bool) -> Self {
        if recursive { Self::Subtree } else { Self::Folder }
    }
}

/// A file attached to a record, with the key that decrypts its content.
#[derive(Debug, PartialEq)]
struct Attachment {
    /// A v2 attachment's id, or the UID of a v3 record's file record.
    id:    String,
    name:  String,
    title: String,
    key:   Vec<u8>,
}

impl TryFrom<&Value> for Attachment {
    type Error = Error;

    /// One entry of a legacy record's `extra.files`.
    fn try_from(file: &Value) -> Result<Self> {
        let text = |field: &str| file.get(field).and_then(Value::as_str).unwrap_or_default().to_owned();
        Ok(Self {
            id:    text("id"),
            name:  text("name"),
            title: text("title"),
            key:   b64_decode(&text("key"))?,
        })
    }
}

impl TryFrom<&Record> for Attachment {
    type Error = Error;

    /// A v4 file record names its file in its data and holds the content key itself.
    fn try_from(file: &Record) -> Result<Self> {
        if file.version != 4 {
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
            id:    file.uid.clone(),
            name:  text("name"),
            title: text("title"),
            key:   file.key.clone(),
        })
    }
}

impl Attachment {
    /// The files `record` carries: a legacy record's `extra.files`, the file records its `fileRef`
    /// field points at (ones this account cannot see are skipped), or the file a file record is.
    fn of(vault: &Vault, record: &Record) -> Result<Vec<Self>> {
        match record.version {
            2 => {
                record
                    .extra
                    .as_ref()
                    .and_then(|extra| extra.get("files"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(Self::try_from)
                    .collect()
            }
            3 => {
                Ok(record
                    .typed_fields()
                    .find(|field| field.field_type() == "fileRef")
                    .into_iter()
                    .flat_map(|field| field.values())
                    .filter_map(Value::as_str)
                    .filter_map(|uid| vault.records.get(uid))
                    .filter_map(|file| Self::try_from(file).ok())
                    .collect())
            }
            4 => Ok(vec![Self::try_from(record)?]),
            _ => Ok(Vec::new()),
        }
    }

    /// Whether `wanted` is this attachment's id, or its title or name in any letter case.
    fn is_named(&self, wanted: &str) -> bool {
        let same = |text: &str| text.to_lowercase() == wanted.to_lowercase();
        self.id == wanted || same(&self.title) || same(&self.name)
    }
}

/// How a file's content is encrypted.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Cipher {
    Cbc,
    Gcm,
}

impl From<i32> for Cipher {
    /// From the `file_key_type` of a `vault/files_download` reply; only "by data key (GCM)" means GCM.
    fn from(file_key_type: i32) -> Self {
        if file_key_type == RecordKeyType::EncryptedByDataKeyGcm as i32 {
            Self::Gcm
        } else {
            Self::Cbc
        }
    }
}

impl Cipher {
    /// Decrypts a downloaded body where it lies; the plaintext is a window of `body`.
    fn open<'a>(self, body: &'a mut [u8], key: &[u8]) -> Result<&'a [u8]> {
        match self {
            Self::Cbc => crypto::decrypt_aes_v1_in_place(body, key),
            Self::Gcm => crypto::decrypt_aes_v2_in_place(body, key),
        }
    }
}

/// Where to fetch one attachment's content and how it is encrypted.
struct Ticket {
    url:    String,
    cipher: Cipher,
}

/// Logs in and syncs when needed, then lends out the session and the vault together.
fn connected(app: &mut App) -> Result<(&mut Session, &Vault)> {
    app.vault()?;
    match (app.session.as_mut(), app.vault.as_ref()) {
        (Some(session), Some(vault)) => Ok((session, vault)),
        _ => Err(Error::NotLoggedIn),
    }
}

/// No overall timeout, like Commander: a large attachment can legitimately take minutes.
fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(None::<Duration>)
        .build()?)
}

impl Run for DownloadAttachment {
    fn run(self, app: &mut App) -> Result<()> {
        let cwd = app.cwd.clone();
        let out_dir = match self.out_dir {
            Some(UserPath(dir)) => dir,
            None => std::env::current_dir()?,
        };
        let layout = Layout::from(self.preserve_dir);
        let naming = Naming::from(self.record_title);
        let (session, vault) = connected(app)?;

        let records = select_records(vault, &cwd, &self.records, Depth::from(self.recursive));
        if records.is_empty() {
            return Err(Error::Generic(format!("Record(s) \"{}\" not found", self.records.join(", "))));
        }
        std::fs::create_dir_all(&out_dir)?;
        let http = http_client()?;
        let (mut saved, mut refused) = (0, 0);
        for record in records {
            let mut attachments = Attachment::of(vault, record)?;
            attachments.retain(|a| self.names.is_empty() || self.names.iter().any(|name| a.is_named(name)));
            if attachments.is_empty() {
                continue;
            }
            let dir = destination(vault, &out_dir, layout, record);
            std::fs::create_dir_all(&dir)?;
            // One signed URL per attachment, in order; `None` where the server refused
            let tickets = if record.version == 2 {
                legacy_tickets(session, vault, record, &attachments)?
            } else {
                file_tickets(session, &attachments)?
            };
            for (attachment, ticket) in attachments.iter().zip(tickets) {
                let Some(ticket) = ticket else {
                    eprintln!("Error requesting download URL for file \"{}\"", attachment.id);
                    refused += 1;
                    continue;
                };
                let name = local_name(attachment, record, naming);
                let path = free_path(&dir, &name, &record.uid, &attachment.id);
                eprintln!("Downloading '{}'", std::path::absolute(&path)?.display());
                download(&http, &ticket, &attachment.key, &path)?;
                saved += 1;
            }
        }
        if refused > 0 {
            return Err(Error::Generic(format!("{refused} attachment(s) could not be downloaded")));
        }
        if saved == 0 {
            eprintln!("No attachments found");
        }
        Ok(())
    }
}

/// The records the command line names: a record UID or path, or a folder UID or path standing for
/// every record in it.
fn select_records<'v>(vault: &'v Vault, cwd: &str, specs: &[String], depth: Depth) -> Vec<&'v Record> {
    let mut found: BTreeMap<&str, &Record> = BTreeMap::new();
    for spec in specs {
        if let Some(record) = vault.records.get(spec) {
            found.insert(&record.uid, record);
        } else if let Some(folder) = resolve_folder(vault, cwd, spec) {
            for record in folder_tree(vault, folder, depth)
                .iter()
                .flat_map(|uid| vault.records_in(uid))
            {
                found.insert(&record.uid, record);
            }
        } else if let Some(record) = resolve_record(vault, cwd, spec) {
            found.insert(&record.uid, record);
        }
    }
    found.into_values().collect()
}

/// A folder and, for [`Depth::Subtree`], everything below it.
fn folder_tree(vault: &Vault, root: String, depth: Depth) -> Vec<String> {
    let mut uids = vec![root];
    if depth == Depth::Subtree {
        let mut next = 0;
        while let Some(uid) = uids.get(next) {
            let children = vault.subfolders_of(uid).to_vec();
            uids.extend(children);
            next += 1;
        }
    }
    uids
}

/// The folder a record's files are saved in.
fn destination(vault: &Vault, out_dir: &Path, layout: Layout, record: &Record) -> PathBuf {
    match layout {
        Layout::Flat => out_dir.to_path_buf(),
        Layout::ByFolder => {
            // Which of several folders a record sits in is arbitrary; the lowest UID keeps it stable.
            let folder = vault
                .folder_records
                .iter()
                .filter(|(folder, uids)| !folder.is_empty() && uids.contains(&record.uid))
                .map(|(folder, _)| folder)
                .min();
            // Like Commander, folder names keep only letters and digits
            let path: String = folder
                .map(|folder| vault.folder_path(folder))
                .unwrap_or_default()
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '/')
                .collect();
            path.split('/')
                .filter(|name| !name.is_empty())
                .fold(out_dir.to_path_buf(), |dir, name| dir.join(name))
        }
    }
}

/// The name a file is saved under. Only the last component of the stored name survives, so a
/// hostile attachment name cannot write outside the output folder.
fn local_name(attachment: &Attachment, record: &Record, naming: Naming) -> String {
    let stored = Path::new(&attachment.name)
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(&attachment.id);
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

/// Never replaces an earlier download: a taken name gets the record UID, then the file id,
/// inserted before the extension.
fn free_path(dir: &Path, name: &str, record_uid: &str, file_id: &str) -> PathBuf {
    let path = dir.join(name);
    if !path.is_file() {
        return path;
    }
    let stem = Path::new(name).file_stem().and_then(OsStr::to_str).unwrap_or(name);
    let extension = Path::new(name)
        .extension()
        .and_then(OsStr::to_str)
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let with_record = dir.join(format!("{stem}({record_uid}){extension}"));
    if with_record.is_file() {
        dir.join(format!("{stem}({file_id}){extension}"))
    } else {
        with_record
    }
}

fn file_tickets(session: &mut Session, attachments: &[Attachment]) -> Result<Vec<Option<Ticket>>> {
    let rq = FilesGetRequest {
        record_uids: attachments.iter().map(|a| b64_decode(&a.id)).collect::<Result<_>>()?,
        ..Default::default()
    };
    let rs: FilesGetResponse = session.call_typed("vault/files_download", &rq)?;
    Ok(rq
        .record_uids
        .iter()
        .map(|uid| {
            rs.files
                .iter()
                .find(|file| file.record_uid == *uid && file.status == FileGetResult::FgSuccess as i32)
                .map(|file| {
                    Ticket {
                        url:    file.url.clone(),
                        cipher: file.file_key_type.into(),
                    }
                })
        })
        .collect())
}

fn legacy_tickets(
    session: &mut Session,
    vault: &Vault,
    record: &Record,
    attachments: &[Attachment],
) -> Result<Vec<Option<Ticket>>> {
    let mut rq = json!({
        "command": "request_download",
        "file_ids": attachments.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
    });
    if let Some(folder) = access_folder(vault, record) {
        rq["shared_folder_uid"] = folder.into();
    }
    let rs = session.execute_v2(rq)?;
    let downloads = rs["downloads"].as_array().map_or(&[][..], Vec::as_slice);
    Ok((0..attachments.len())
        .map(|i| {
            let url = downloads.get(i)?.get("url")?.as_str()?;
            Some(Ticket {
                url:    url.to_owned(),
                cipher: Cipher::Cbc,
            })
        })
        .collect())
}

/// Legacy requests name the shared folder that grants access when the account does not own the
/// record.
///
/// ponytail: Commander also sends `team_uid` for folders reached only through a team. The vault
/// does not keep which team grants which shared folder, so those downloads rely on the server
/// accepting the folder alone.
fn access_folder<'v>(vault: &'v Vault, record: &Record) -> Option<&'v str> {
    if record.owner {
        return None;
    }
    vault
        .shared_folders
        .values()
        .find(|folder| folder.record_uids.contains(&record.uid))
        .map(|folder| folder.uid.as_str())
}

/// Fetches a signed URL and writes the decrypted content to `path`. Nothing is written when the
/// transfer is cut short or the content fails to authenticate.
fn download(http: &Client, ticket: &Ticket, key: &[u8], path: &Path) -> Result<()> {
    let mut response = http.get(&ticket.url).send()?;
    if !response.status().is_success() {
        return Err(Error::Generic(format!("HTTP status code {}", response.status().as_u16())));
    }
    let mut body = Vec::new();
    if let Some(len) = response.content_length().and_then(|len| usize::try_from(len).ok()) {
        body.try_reserve_exact(len)
            .map_err(|_| Error::Generic(format!("a {len} byte file does not fit in memory")))?;
    }
    response.read_to_end(&mut body)?;
    let plain = ticket.cipher.open(&mut body, key)?;
    std::fs::write(path, plain).map_err(|e| Error::Generic(format!("{}: {e}", path.display())))
}

/// Upload files to a record
#[derive(Args, Debug)]
pub struct UploadAttachment {
    /// File to upload (repeatable)
    #[arg(long = "file", required = true)]
    files:  Vec<UserPath>,
    /// Record path or UID
    record: String,
}

/// A file picked for upload.
struct LocalFile {
    path: PathBuf,
    name: String,
    size: usize,
    mime: MimeType,
}

impl TryFrom<&UserPath> for LocalFile {
    type Error = Error;

    fn try_from(typed: &UserPath) -> Result<Self> {
        let path = std::path::absolute(typed)?;
        let size = path
            .metadata()
            .ok()
            .filter(|meta| meta.is_file())
            .and_then(|meta| usize::try_from(meta.len()).ok())
            .ok_or_else(|| Error::Generic(format!("File \"{}\" does not exist", typed.0.display())))?;
        Ok(Self {
            name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            mime: MimeType::from(path.as_path()),
            path,
            size,
        })
    }
}

/// Content type guessed from a file's extension, as Python's `mimetypes` does for Commander
/// (common types only); empty when unknown.
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

impl fmt::Display for MimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A file record being created: its UID and the key its metadata and content are encrypted with.
struct NewFile {
    uid: Vec<u8>,
    key: Vec<u8>,
}

impl NewFile {
    fn random() -> Self {
        let mut uid = crypto::random_bytes(16);
        // Like Commander, keep the first byte below 0xf8 so the encoded UID never starts with '-' or '_'
        if uid[0] & 0xf8 == 0xf8 {
            uid[0] &= 0x7f;
        }
        Self {
            uid,
            key: crypto::random_bytes(32),
        }
    }
}

impl Run for UploadAttachment {
    fn run(self, app: &mut App) -> Result<()> {
        let cwd = app.cwd.clone();
        let files = self.files.iter().map(LocalFile::try_from).collect::<Result<Vec<_>>>()?;
        let (session, vault) = connected(app)?;
        let record = resolve_record(vault, &cwd, &self.record)
            .ok_or_else(|| Error::Generic(format!("Record UID not found for record \"{}\"", self.record)))?;
        // ponytail: legacy v2 records go through request_upload and a JSON record_update;
        // only typed records are covered until someone needs to attach to an old record.
        if record.version != 3 {
            return Err(Error::Generic(format!(
                "Cannot attach files to \"{}\": only typed (v3) records are supported",
                record.title()
            )));
        }

        let new: Vec<NewFile> = files.iter().map(|_| NewFile::random()).collect();
        let rs: FilesAddResponse =
            session.call_typed("vault/files_add", &add_request(&files, &new, &session.data_key)?)?;
        let http = http_client()?;
        for (file, new) in files.iter().zip(&new) {
            let target = rs
                .files
                .iter()
                .find(|status| status.record_uid == new.uid && status.status == FileAddResult::FaSuccess as i32)
                .ok_or_else(|| Error::Generic(format!("Uploading file {}: Get upload URL error.", file.name)))?;
            send(&http, target, file, new)?;
        }

        let key_type = if session.summary.forbid_key_type2 {
            RecordKeyType::EncryptedByPublicKeyEcc
        } else {
            RecordKeyType::EncryptedByPublicKey
        };
        let rq = link_request(record, &new, key_type)?;
        let rs: RecordsModifyResponse = session.call_typed("vault/records_update", &rq)?;
        if let Some(status) = rs
            .records
            .iter()
            .find(|status| status.record_uid == rq.records[0].record_uid)
            .filter(|status| status.status != RecordModifyResult::RsSuccess as i32)
        {
            let name = RecordModifyResult::try_from(status.status).map_or("UNKNOWN", |result| result.as_str_name());
            return Err(Error::api(name, status.message.clone()));
        }
        eprintln!("Uploaded {} file(s) to \"{}\"", files.len(), record.title());
        // Commander syncs after every write; the next command here does the same
        app.vault = None;
        Ok(())
    }
}

/// The `vault/files_add` request: per file, its key sealed for this account and its metadata
/// sealed with its own key.
fn add_request(files: &[LocalFile], new: &[NewFile], data_key: &[u8]) -> Result<FilesAddRequest> {
    Ok(FilesAddRequest {
        files:       files
            .iter()
            .zip(new)
            .map(|(file, new)| -> Result<FileEntry> {
                let metadata = json!({
                    "title": file.name,
                    "name": file.name,
                    "type": file.mime.to_string(),
                    "size": file.size,
                });
                Ok(FileEntry {
                    record_uid: new.uid.clone(),
                    record_key: crypto::encrypt_aes_v2(&new.key, data_key)?,
                    data: crypto::encrypt_aes_v2(metadata.to_string().as_bytes(), &new.key)?,
                    // Headroom over the nonce and tag, as Commander reserves
                    file_size: i64::try_from(file.size).unwrap_or(i64::MAX).saturating_add(100),
                    ..Default::default()
                })
            })
            .collect::<Result<_>>()?,
        client_time: now_millis(),
    })
}

/// The file's content as `nonce|ciphertext|tag`, encrypted where it was read so a large file is
/// never copied just to be framed.
fn sealed(file: &LocalFile, key: &[u8]) -> Result<Vec<u8>> {
    let mut frame = vec![0; 12];
    frame
        .try_reserve_exact(file.size + 16)
        .map_err(|_| Error::Generic(format!("{} does not fit in memory", file.name)))?;
    std::fs::File::open(&file.path)?.read_to_end(&mut frame)?;
    frame.extend_from_slice(&[0; 16]);
    crypto::encrypt_aes_v2_in_place(&mut frame, key)?;
    Ok(frame)
}

/// The text before and after the encrypted file in a `multipart/form-data` body. The server's form
/// fields come first and the file last: S3-style POST policies ignore anything after the file.
fn form_framing(parameters: &str, boundary: &str, file_ref: &str) -> Result<(String, String)> {
    let fields: serde_json::Map<String, Value> = serde_json::from_str(parameters)?;
    let mut head: String = fields
        .iter()
        .map(|(name, value)| {
            let value = value.as_str().map_or_else(|| value.to_string(), str::to_owned);
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
        })
        .collect();
    head += &format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_ref}\"\r\nContent-Type: \
         application/octet-stream\r\n\r\n"
    );
    Ok((head, format!("\r\n--{boundary}--\r\n")))
}

/// Posts the encrypted file to its signed upload URL. The header, ciphertext and trailer are
/// chained into the request body rather than concatenated.
fn send(http: &Client, target: &FileAddStatus, file: &LocalFile, new: &NewFile) -> Result<()> {
    let frame = sealed(file, &new.key)?;
    let boundary = data_encoding::HEXLOWER.encode(&crypto::random_bytes(16));
    let (head, tail) = form_framing(&target.parameters, &boundary, &b64_encode(&new.uid))?;
    let len = (head.len() + frame.len() + tail.len()) as u64;
    let body = Body::sized(
        Cursor::new(head.into_bytes())
            .chain(Cursor::new(frame))
            .chain(Cursor::new(tail.into_bytes())),
        len,
    );
    let response = http
        .post(&target.url)
        .header("Content-Type", format!("multipart/form-data; boundary={boundary}"))
        .body(body)
        .send()?;
    let status = response.status().as_u16();
    if i32::from(status) != target.success_status_code {
        return Err(Error::Generic(format!("Uploading file {}: HTTP status code {status}", file.name)));
    }
    Ok(())
}

/// The `vault/records_update` request that lists `new` in the record's `fileRef` field (creating the
/// field when there is none) and links their keys under the record key.
fn link_request(record: &Record, new: &[NewFile], key_type: RecordKeyType) -> Result<RecordsUpdateRequest> {
    let mut data = record.data.clone();
    let fields = data
        .as_object_mut()
        .map(|object| object.entry("fields").or_insert_with(|| json!([])))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Error::Generic(format!("Record {} has malformed data", record.uid)))?;
    let refs = new.iter().map(|file| Value::from(b64_encode(&file.uid)));
    let listed = fields
        .iter_mut()
        .find(|field| field["type"] == "fileRef")
        .and_then(|field| field.get_mut("value"))
        .and_then(Value::as_array_mut);
    match listed {
        Some(listed) => listed.extend(refs),
        None => fields.push(json!({"type": "fileRef", "value": refs.collect::<Vec<_>>()})),
    }

    // Commander pads record data to a multiple of 16 bytes, 384 at least, so the GCM length
    // reveals little about the record
    let mut json = serde_json::to_vec(&data)?;
    json.resize(json.len().max(384).next_multiple_of(16), b' ');
    let now = now_millis();
    Ok(RecordsUpdateRequest {
        records:                vec![RecordUpdate {
            record_uid: b64_decode(&record.uid)?,
            client_modified_time: now,
            revision: record.revision,
            data: crypto::encrypt_aes_v2(&json, &record.key)?,
            record_links_add: new
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use clap::Parser;

    use super::*;
    use crate::cli::{Command, ShellLine};
    use crate::vault::Folder;

    fn record(uid: &str, version: i32, data: Value, key: u8) -> Record {
        Record {
            uid: uid.into(),
            version,
            data,
            key: vec![key; 32],
            ..Record::default()
        }
    }

    fn vault_of(records: impl IntoIterator<Item = Record>) -> Vault {
        Vault {
            records: records.into_iter().map(|r| (r.uid.clone(), r)).collect(),
            ..Vault::default()
        }
    }

    /// A fresh empty folder; tests remove it when they pass.
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keeper-cli-test-{}", b64_encode(&crypto::random_bytes(8))));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn attachment(name: &str) -> Attachment {
        Attachment {
            id:    "FILEID".into(),
            name:  name.into(),
            title: String::new(),
            key:   vec![0; 32],
        }
    }

    /// A parent that lists two real files, a dangling UID and a record that is not a file.
    fn v3_vault() -> Vault {
        let parent = record(
            "PARENT",
            3,
            json!({"title": "Server", "fields": [
                {"type": "login", "value": ["root"]},
                {"type": "fileRef", "value": ["F1", "GONE", "NOTAFILE", "F2"]},
            ]}),
            1,
        );
        vault_of([
            parent,
            record("F1", 4, json!({"name": " a.txt ", "title": "Notes", "size": 5}), 2),
            record("F2", 4, json!({"name": "b.bin"}), 3),
            record("NOTAFILE", 3, json!({"title": "x"}), 4),
        ])
    }

    #[test]
    fn v3_attachments_are_the_file_records_a_file_ref_points_at() {
        let vault = v3_vault();
        let found = Attachment::of(&vault, &vault.records["PARENT"]).unwrap();
        assert_eq!(
            found,
            vec![
                Attachment {
                    id:    "F1".into(),
                    name:  "a.txt".into(),
                    title: "Notes".into(),
                    key:   vec![2; 32],
                },
                Attachment {
                    id:    "F2".into(),
                    name:  "b.bin".into(),
                    title: String::new(),
                    key:   vec![3; 32],
                },
            ]
        );
        let itself = Attachment::of(&vault, &vault.records["F2"]).unwrap();
        assert_eq!(itself.len(), 1);
        assert_eq!(itself[0].id, "F2");
    }

    #[test]
    fn v2_attachments_come_from_extra_files_with_their_own_keys() {
        let key = [9u8; 32];
        let legacy = Record {
            uid: "OLD".into(),
            version: 2,
            data: json!({"title": "Legacy"}),
            extra: Some(json!({"files": [
                {"id": "ATT1", "name": "scan.pdf", "title": "Scan", "key": b64_encode(&key), "size": 12},
            ]})),
            key: vec![1; 32],
            ..Record::default()
        };
        let found = Attachment::of(&Vault::default(), &legacy).unwrap();
        assert_eq!(
            found,
            vec![Attachment {
                id:    "ATT1".into(),
                name:  "scan.pdf".into(),
                title: "Scan".into(),
                key:   key.to_vec(),
            }]
        );

        let bad_key = Record {
            extra: Some(json!({"files": [{"id": "ATT2", "key": "***"}]})),
            ..legacy
        };
        assert!(Attachment::of(&Vault::default(), &bad_key).is_err());
    }

    #[test]
    fn content_decrypts_only_with_the_files_own_key() {
        let vault = v3_vault();
        let file = &Attachment::of(&vault, &vault.records["PARENT"]).unwrap()[0];
        let sealed = crypto::encrypt_aes_v2(b"file body", &file.key).unwrap();

        assert_eq!(Cipher::Gcm.open(&mut sealed.clone(), &file.key).unwrap(), b"file body");
        let parent_key = &vault.records["PARENT"].key;
        assert!(Cipher::Gcm.open(&mut sealed.clone(), parent_key).is_err());

        let legacy_key = [7u8; 32];
        let legacy = Attachment::try_from(&json!({"id": "A", "key": b64_encode(&legacy_key)})).unwrap();
        let mut sealed = crypto::encrypt_aes_v1(b"old body", &legacy_key).unwrap();
        assert_eq!(Cipher::Cbc.open(&mut sealed, &legacy.key).unwrap(), b"old body");
    }

    #[test]
    fn server_reported_key_type_picks_the_cipher() {
        assert_eq!(Cipher::from(RecordKeyType::EncryptedByDataKeyGcm as i32), Cipher::Gcm);
        assert_eq!(Cipher::from(RecordKeyType::EncryptedByDataKey as i32), Cipher::Cbc);
        assert_eq!(Cipher::from(RecordKeyType::NoKey as i32), Cipher::Cbc);
    }

    #[test]
    fn name_selector_matches_id_title_or_name_ignoring_case() {
        let file = Attachment {
            id:    "F1".into(),
            name:  "Report.PDF".into(),
            title: "Q3 Report".into(),
            key:   Vec::new(),
        };
        assert!(file.is_named("F1"));
        assert!(file.is_named("report.pdf"));
        assert!(file.is_named("q3 REPORT"));
        assert!(!file.is_named("f1"), "ids are exact");
        assert!(!file.is_named("report"));
    }

    #[test]
    fn saved_names_cannot_escape_the_output_folder() {
        let titled = record("R", 3, json!({"title": "My: Server/1"}), 1);
        assert_eq!(local_name(&attachment("../../etc/passwd"), &titled, Naming::Stored), "passwd");
        assert_eq!(local_name(&attachment(".."), &titled, Naming::Stored), "FILEID");
        assert_eq!(local_name(&attachment(""), &titled, Naming::Stored), "FILEID");
        assert_eq!(local_name(&attachment("key.pem"), &titled, Naming::WithRecordTitle), "My Server1-key.pem");
        let untitled = record("R", 3, json!({"title": "***"}), 1);
        assert_eq!(local_name(&attachment("key.pem"), &untitled, Naming::WithRecordTitle), "key.pem");
    }

    #[test]
    fn taken_names_get_the_record_uid_then_the_file_id() {
        let dir = temp_dir();
        assert_eq!(free_path(&dir, "a.tar.gz", "REC", "FILE"), dir.join("a.tar.gz"));
        std::fs::write(dir.join("a.tar.gz"), b"x").unwrap();
        assert_eq!(free_path(&dir, "a.tar.gz", "REC", "FILE"), dir.join("a.tar(REC).gz"));
        std::fs::write(dir.join("a.tar(REC).gz"), b"x").unwrap();
        assert_eq!(free_path(&dir, "a.tar.gz", "REC", "FILE"), dir.join("a.tar(FILE).gz"));
        std::fs::write(dir.join("README"), b"x").unwrap();
        assert_eq!(free_path(&dir, "README", "REC", "FILE"), dir.join("README(REC)"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn folder(uid: &str, name: &str, parent: Option<&str>, kids: &[&str]) -> (String, Folder) {
        (
            uid.to_owned(),
            Folder {
                uid: uid.into(),
                name: name.into(),
                parent: parent.map(Into::into),
                subfolders: kids.iter().map(|k| (*k).to_owned()).collect(),
                ..Folder::default()
            },
        )
    }

    /// Work (A) > Infra Team! (B) > Deep (C); A holds R1, B holds R2, C holds R3.
    fn folder_vault() -> Vault {
        let mut vault = vault_of(["R1", "R2", "R3"].map(|uid| record(uid, 3, json!({"title": uid}), 1)));
        vault.folders = [
            folder("A", "Work", None, &["B"]),
            folder("B", "Infra Team!", Some("A"), &["C"]),
            folder("C", "Deep", Some("B"), &[]),
        ]
        .into();
        vault.root_folders = vec!["A".into()];
        for (folder, uid) in [("A", "R1"), ("B", "R2"), ("C", "R3")] {
            vault
                .folder_records
                .insert(folder.into(), BTreeSet::from([uid.to_owned()]));
        }
        vault
    }

    #[test]
    fn arguments_select_records_directly_or_through_folders() {
        let vault = folder_vault();
        let pick = |specs: &[&str], depth| {
            let specs: Vec<String> = specs.iter().map(|s| (*s).to_owned()).collect();
            let found = select_records(&vault, "", &specs, depth);
            found.into_iter().map(|r| r.uid.as_str()).collect::<Vec<_>>()
        };
        assert_eq!(pick(&["R3"], Depth::Folder), ["R3"]);
        assert_eq!(pick(&["/Work/Infra Team!/R2"], Depth::Folder), ["R2"]);
        assert_eq!(pick(&["A"], Depth::Folder), ["R1"]);
        assert_eq!(pick(&["Work"], Depth::Subtree), ["R1", "R2", "R3"]);
        assert_eq!(pick(&["B", "R2", "R1"], Depth::Folder), ["R1", "R2"], "duplicates collapse");
        assert!(pick(&["nowhere"], Depth::Subtree).is_empty());
    }

    #[test]
    fn preserved_folders_keep_only_letters_and_digits() {
        let vault = folder_vault();
        let out = Path::new("out");
        let r3 = &vault.records["R3"];
        assert_eq!(destination(&vault, out, Layout::ByFolder, r3), out.join("Work").join("InfraTeam").join("Deep"));
        assert_eq!(destination(&vault, out, Layout::Flat, r3), out);
        let rootless = record("R9", 3, json!({}), 1);
        assert_eq!(destination(&vault, out, Layout::ByFolder, &rootless), out);
    }

    #[test]
    fn tilde_means_home_only_as_a_whole_leading_component() {
        let home = dirs::home_dir().unwrap();
        let path = |typed: &str| UserPath::from_str(typed).unwrap().0;
        assert_eq!(path("~"), home);
        assert_eq!(path("~/files"), home.join("files"));
        assert_eq!(path("~other/files"), PathBuf::from("~other/files"));
        assert_eq!(path("a/~"), PathBuf::from("a/~"));
    }

    #[test]
    fn download_attachment_parses_commander_flags_and_its_alias() {
        let line = ShellLine::try_parse_from([
            "da",
            "-r",
            "--out-dir",
            "~/x",
            "--name",
            "a.txt",
            "--name",
            "b.txt",
            "--preserve-dir",
            "--record-title",
            "UID",
            "Work/Folder",
        ])
        .unwrap();
        let Command::DownloadAttachment(download) = line.command else {
            panic!("`da` should be download-attachment");
        };
        assert_eq!(download.records, ["UID", "Work/Folder"]);
        assert_eq!(download.names, ["a.txt", "b.txt"]);
        assert!(download.recursive && download.preserve_dir && download.record_title);
        assert!(download.out_dir.is_some());
        assert!(ShellLine::try_parse_from(["download-attachment"]).is_err(), "a record is required");
    }

    #[test]
    fn local_files_must_exist_and_report_name_size_and_type() {
        let dir = temp_dir();
        std::fs::write(dir.join("Notes.TXT"), b"hello world").unwrap();
        let file = LocalFile::try_from(&UserPath(dir.join("Notes.TXT"))).unwrap();
        assert_eq!((file.name.as_str(), file.size, file.mime.to_string().as_str()), ("Notes.TXT", 11, "text/plain"));
        std::fs::write(dir.join("archive.tar.gz"), b"").unwrap();
        let tarball = LocalFile::try_from(&UserPath(dir.join("archive.tar.gz"))).unwrap();
        assert_eq!(tarball.mime.to_string(), "");

        let missing = LocalFile::try_from(&UserPath(dir.join("missing.bin"))).err().unwrap();
        assert!(missing.to_string().contains("does not exist"), "{missing}");
        assert!(LocalFile::try_from(&UserPath(dir.clone())).is_err(), "a folder is not a file");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sealed_content_decrypts_with_the_file_key_only() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        for (name, bytes) in [("big.bin", &content[..]), ("empty.bin", &[][..])] {
            std::fs::write(dir.join(name), bytes).unwrap();
            let file = LocalFile::try_from(&UserPath(dir.join(name))).unwrap();
            let frame = sealed(&file, &[3; 32]).unwrap();
            assert_eq!(frame.len(), bytes.len() + 28);
            assert_eq!(crypto::decrypt_aes_v2(&frame, &[3; 32]).unwrap(), bytes);
            assert!(crypto::decrypt_aes_v2(&frame, &[4; 32]).is_err());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_add_request_seals_the_key_for_the_account_and_metadata_for_the_file() {
        let dir = temp_dir();
        std::fs::write(dir.join("notes.txt"), b"hello world").unwrap();
        let files = [LocalFile::try_from(&UserPath(dir.join("notes.txt"))).unwrap()];
        let new = [NewFile {
            uid: vec![1; 16],
            key: vec![6; 32],
        }];
        let rq = add_request(&files, &new, &[5; 32]).unwrap();

        let entry = &rq.files[0];
        assert_eq!(entry.record_uid, new[0].uid);
        assert_eq!(crypto::decrypt_aes_v2(&entry.record_key, &[5; 32]).unwrap(), new[0].key);
        let metadata: Value =
            serde_json::from_slice(&crypto::decrypt_aes_v2(&entry.data, &new[0].key).unwrap()).unwrap();
        assert_eq!(metadata, json!({"title": "notes.txt", "name": "notes.txt", "type": "text/plain", "size": 11}));
        assert_eq!(entry.file_size, 111, "content plus Commander's 100 bytes of headroom");
        assert!(rq.client_time > 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn new_files() -> [NewFile; 2] {
        [
            NewFile {
                uid: vec![1; 16],
                key: vec![6; 32],
            },
            NewFile {
                uid: vec![2; 16],
                key: vec![7; 32],
            },
        ]
    }

    #[test]
    fn linking_appends_to_the_file_ref_field_and_wraps_file_keys_in_the_record_key() {
        let uid = b64_encode(&[9; 16]);
        let mut parent = record(
            &uid,
            3,
            json!({"title": "Server", "fields": [{"type": "login", "value": ["root"]}, {"type": "fileRef", "value": ["OLD"]}]}),
            1,
        );
        parent.revision = 41;
        let new = new_files();
        let rq = link_request(&parent, &new, RecordKeyType::EncryptedByPublicKeyEcc).unwrap();
        assert_eq!(rq.security_data_key_type, RecordKeyType::EncryptedByPublicKeyEcc as i32);

        let update = &rq.records[0];
        assert_eq!(update.record_uid, [9; 16]);
        assert_eq!(update.revision, 41);
        let plain = crypto::decrypt_aes_v2(&update.data, &parent.key).unwrap();
        assert!(plain.len() >= 384 && plain.len().is_multiple_of(16), "padded to a multiple of 16, 384 at least");
        let data: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(data["fields"][0], parent.data["fields"][0], "other fields are untouched");
        assert_eq!(data["fields"][1]["value"], json!(["OLD", b64_encode(&new[0].uid), b64_encode(&new[1].uid)]));

        assert_eq!(update.record_links_add.len(), 2);
        for (link, file) in update.record_links_add.iter().zip(&new) {
            assert_eq!(link.record_uid, file.uid);
            assert_eq!(crypto::decrypt_aes_v2(&link.record_key, &parent.key).unwrap(), file.key);
        }
    }

    #[test]
    fn linking_creates_the_file_ref_field_when_the_record_has_none() {
        let new = new_files();
        let uid = b64_encode(&[9; 16]);
        let refs = json!([b64_encode(&new[0].uid), b64_encode(&new[1].uid)]);
        let field = json!({"type": "fileRef", "value": refs});
        let sealed_data = |parent: &Record| -> Value {
            let rq = link_request(parent, &new, RecordKeyType::EncryptedByPublicKey).unwrap();
            serde_json::from_slice(&crypto::decrypt_aes_v2(&rq.records[0].data, &parent.key).unwrap()).unwrap()
        };

        let no_file_ref = record(&uid, 3, json!({"title": "A", "fields": [{"type": "login", "value": []}]}), 1);
        assert_eq!(sealed_data(&no_file_ref)["fields"][1], field);
        let no_fields = record(&uid, 3, json!({"title": "A"}), 1);
        assert_eq!(sealed_data(&no_fields)["fields"], json!([field]));
        let hollow_file_ref = record(&uid, 3, json!({"fields": [{"type": "fileRef"}]}), 1);
        assert_eq!(sealed_data(&hollow_file_ref)["fields"][1], field, "a field without a value list is not reused");

        let malformed = record(&uid, 3, json!(["not", "an", "object"]), 1);
        assert!(link_request(&malformed, &new, RecordKeyType::EncryptedByPublicKey).is_err());
    }

    #[test]
    fn multipart_form_lists_server_fields_first_and_the_file_last() {
        let (head, tail) =
            form_framing(r#"{"key": "a/b", "policy": "p", "success_action_status": 201}"#, "BOUND", "FILEREF").unwrap();
        assert_eq!(
            head,
            "--BOUND\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\na/b\r\n\
             --BOUND\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\np\r\n\
             --BOUND\r\nContent-Disposition: form-data; name=\"success_action_status\"\r\n\r\n201\r\n\
             --BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"FILEREF\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
        assert_eq!(tail, "\r\n--BOUND--\r\n");
        assert!(form_framing("not json", "B", "F").is_err());
    }

    #[test]
    fn new_file_uids_never_start_with_a_character_that_looks_like_a_flag() {
        for _ in 0..2000 {
            let file = NewFile::random();
            assert_eq!((file.uid.len(), file.key.len()), (16, 32));
            assert!(!b64_encode(&file.uid).starts_with(['-', '_']));
        }
    }

    #[test]
    fn upload_attachment_parses_commander_flags_and_its_alias() {
        let line = ShellLine::try_parse_from(["ua", "--file", "a.txt", "--file", "~/b.txt", "REC"]).unwrap();
        let Command::UploadAttachment(upload) = line.command else {
            panic!("`ua` should be upload-attachment");
        };
        assert_eq!(upload.files.len(), 2);
        assert_eq!(upload.record, "REC");
        assert!(ShellLine::try_parse_from(["upload-attachment", "REC"]).is_err(), "at least one --file");
    }

    /// Answers the first request on localhost with `status` and `reply`, then hands back the whole
    /// request (head and body) it received.
    fn serve_once(status: &'static str, reply: Vec<u8>) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/blob", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(_) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                    Err(e) => panic!("no client connected: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
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
                    let length: usize = head
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
        (url, server)
    }

    #[test]
    fn download_fetches_decrypts_and_writes_only_authentic_content() {
        let dir = temp_dir();
        let path = dir.join("out.bin");
        let http = Client::builder().no_proxy().build().unwrap();
        let key = [8u8; 32];
        let plain: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();

        for (cipher, sealed) in [
            (Cipher::Gcm, crypto::encrypt_aes_v2(&plain, &key).unwrap()),
            (Cipher::Cbc, crypto::encrypt_aes_v1(&plain, &key).unwrap()),
        ] {
            let (url, server) = serve_once("200 OK", sealed);
            download(&http, &Ticket { url, cipher }, &key, &path).unwrap();
            let request = String::from_utf8(server.join().unwrap()).unwrap();
            assert!(request.starts_with("GET /blob HTTP/1.1\r\n"), "{request}");
            assert_eq!(std::fs::read(&path).unwrap(), plain, "{cipher:?}");
            std::fs::remove_file(&path).unwrap();
        }

        let (url, server) = serve_once("403 Forbidden", b"<Error>denied</Error>".to_vec());
        let denied = download(
            &http,
            &Ticket {
                url,
                cipher: Cipher::Gcm,
            },
            &key,
            &path,
        )
        .unwrap_err();
        assert!(denied.to_string().contains("403"), "{denied}");
        server.join().unwrap();

        let mut forged = crypto::encrypt_aes_v2(&plain, &key).unwrap();
        forged[100] ^= 1;
        let (url, server) = serve_once("200 OK", forged);
        assert!(
            download(
                &http,
                &Ticket {
                    url,
                    cipher: Cipher::Gcm
                },
                &key,
                &path
            )
            .is_err()
        );
        server.join().unwrap();
        assert!(!path.exists(), "nothing is written for a refused or forged download");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn upload_posts_one_multipart_form_whose_file_part_decrypts_with_the_file_key() {
        let dir = temp_dir();
        let content: Vec<u8> = (0..=255u8).cycle().take(50_000).collect();
        std::fs::write(dir.join("report.pdf"), &content).unwrap();
        let file = LocalFile::try_from(&UserPath(dir.join("report.pdf"))).unwrap();
        let new = NewFile {
            uid: vec![5; 16],
            key: vec![9; 32],
        };
        let http = Client::builder().no_proxy().build().unwrap();

        let (url, server) = serve_once("201 Created", Vec::new());
        let target = FileAddStatus {
            url,
            parameters: r#"{"key": "uploads/abc", "policy": "p"}"#.into(),
            success_status_code: 201,
            ..FileAddStatus::default()
        };
        send(&http, &target, &file, &new).unwrap();
        let request = server.join().unwrap();

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
        assert!(head.starts_with("post /blob http/1.1\r\n"), "{head}");
        assert_eq!(header("content-length"), body.len().to_string());

        let file_ref = b64_encode(&new.uid);
        let before_file = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/abc\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"policy\"\r\n\r\np\r\n\
             --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{file_ref}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
        let after_file = format!("\r\n--{boundary}--\r\n");
        assert!(body.starts_with(before_file.as_bytes()));
        assert!(body.ends_with(after_file.as_bytes()));
        let sealed = &body[before_file.len()..body.len() - after_file.len()];
        assert_eq!(crypto::decrypt_aes_v2(sealed, &new.key).unwrap(), content);

        let (url, server) = serve_once("200 OK", Vec::new());
        let target = FileAddStatus {
            url,
            parameters: "{}".into(),
            success_status_code: 201,
            ..FileAddStatus::default()
        };
        let wrong = send(&http, &target, &file, &new).unwrap_err();
        assert!(wrong.to_string().contains("HTTP status code 200"), "{wrong}");
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
