//! `download-attachment`: the files attached to records.
//!
//! A v3 record lists its files in a `fileRef` field. Each entry is the UID of a v4 *file record*
//! whose own key encrypts the content, stored behind a signed URL that `vault/files_download`
//! hands out. A legacy v2 record keeps its files in `extra.files`, each with a key of its own, and
//! gets the URL from the JSON `request_download` command. Content is framed like every other
//! Keeper blob: `iv|ciphertext` for CBC, `nonce|ciphertext|tag` for GCM.
//!
//! ponytail: a file is held in memory whole (once, decrypted in place). Stream it if attachments
//! beyond a few hundred MB matter; GCM can only be authenticated at the end anyway.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use clap::Args;
use reqwest::blocking::Client;
use serde_json::{Value, json};

use crate::auth::Session;
use crate::commands::{App, Run, resolve_folder, resolve_record};
use crate::crypto;
use crate::prelude::*;
use crate::proto::records::{FileGetResult, FilesGetRequest, FilesGetResponse, RecordKeyType};
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
        let dir = std::env::temp_dir().join(format!("keeper-cli-test-{}", b64_encode(&crypto::random_bytes(8))));
        std::fs::create_dir_all(&dir).unwrap();
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
}
