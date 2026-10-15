//! `vault/sync_down`, key unwrapping, and the decrypted in-memory vault.
//!
//! Key hierarchy: the data key (or the account's RSA/EC keys) unwraps record keys, team keys
//! and shared folder keys; team keys unwrap more shared folder keys; shared folder keys unwrap
//! record keys and nested folder keys; a parent record key can unwrap a linked child's key.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use p256::SecretKey;
use rsa::RsaPrivateKey;
use serde_json::Value;

use crate::auth::Session;
use crate::crypto;
use crate::prelude::*;
use crate::proto::records::RecordKeyType;
use crate::proto::vault::{SyncDownRequest, SyncDownResponse};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FolderKind {
    #[default]
    User,
    SharedFolder,
    SharedFolderFolder,
}

#[derive(Debug, Default)]
pub struct Folder {
    pub uid:               String,
    pub kind:              FolderKind,
    pub name:              String,
    /// `None` means the vault root.
    pub parent:            Option<String>,
    pub subfolders:        Vec<String>,
    /// The folder's own key; for a shared folder this is the shared folder key.
    pub key:               Vec<u8>,
    /// The shared folder this folder lives in (itself, for a shared folder root).
    pub shared_folder_uid: Option<String>,
}

#[derive(Debug, Default)]
pub struct Record {
    pub uid:                  String,
    pub version:              i32,
    pub revision:             i64,
    pub shared:               bool,
    pub client_modified_time: i64,
    pub data:                 Value,
    pub extra:                Option<Value>,
    pub key:                  Vec<u8>,
    /// Whether this account owns the record (from record metadata).
    pub owner:                bool,
    /// Unencrypted server-side record data, e.g. the `file_ids` of a v3 record's attachments.
    pub udata:                Option<Value>,
    /// Storage size of a v4 file record's content.
    pub file_size:            i64,
}

#[derive(Debug)]
pub struct SharedFolder {
    pub uid:                    String,
    pub name:                   String,
    pub record_uids:            Vec<String>,
    pub users:                  Vec<String>,
    pub teams:                  Vec<String>,
    pub default_manage_records: bool,
    pub default_manage_users:   bool,
    pub default_can_edit:       bool,
    pub default_can_share:      bool,
    pub key:                    Vec<u8>,
}

#[derive(Debug)]
pub struct Team {
    pub uid:            String,
    pub name:           String,
    pub restrict_edit:  bool,
    pub restrict_share: bool,
    pub restrict_view:  bool,
}

#[derive(Default)]
pub struct Vault {
    pub records:        BTreeMap<String, Record>,
    pub shared_folders: BTreeMap<String, SharedFolder>,
    pub teams:          BTreeMap<String, Team>,
    pub folders:        HashMap<String, Folder>,
    /// Root-level folder UIDs, i.e. the children of `""`.
    pub root_folders:   Vec<String>,
    /// Folder UID (`""` for the root) to the records filed there.
    pub folder_records: HashMap<String, BTreeSet<String>>,
}

impl Vault {
    pub fn records_in(&self, folder_uid: &str) -> impl Iterator<Item = &Record> {
        self.folder_records
            .get(folder_uid)
            .into_iter()
            .flatten()
            .filter_map(|uid| self.records.get(uid))
    }

    pub fn subfolders_of(&self, folder_uid: &str) -> &[String] {
        if folder_uid.is_empty() {
            &self.root_folders
        } else {
            self.folders.get(folder_uid).map_or(&[], |f| &f.subfolders)
        }
    }

    pub fn folder_name(&self, folder_uid: &str) -> &str {
        self.folders.get(folder_uid).map_or("My Vault", |f| &f.name)
    }

    /// `/`-joined path of folder names from the root; `/` for the root itself.
    pub fn folder_path(&self, folder_uid: &str) -> String {
        let mut names = Vec::new();
        let mut cursor = Some(folder_uid.to_owned()).filter(|u| !u.is_empty());
        while let Some(uid) = cursor {
            let Some(folder) = self.folders.get(&uid) else { break };
            names.push(folder.name.replace('/', "//"));
            cursor = folder.parent.clone();
        }
        names.reverse();
        format!("/{}", names.join("/"))
    }
}

/// Keys able to open other keys, as tagged by `records.RecordKeyType`: the account's (data key
/// plus RSA/EC private keys) or a team's.
struct KeyRing<'a> {
    data_key: &'a [u8],
    rsa:      Option<&'a RsaPrivateKey>,
    ecc:      Option<&'a SecretKey>,
}

impl KeyRing<'_> {
    fn decrypt(&self, ciphertext: &[u8], key_type: i32) -> Result<Vec<u8>> {
        match RecordKeyType::try_from(key_type)? {
            RecordKeyType::EncryptedByDataKey => crypto::decrypt_aes_v1(ciphertext, self.data_key),
            RecordKeyType::EncryptedByDataKeyGcm => crypto::decrypt_aes_v2(ciphertext, self.data_key),
            RecordKeyType::EncryptedByPublicKey => {
                crypto::decrypt_rsa(
                    ciphertext,
                    self.rsa
                        .ok_or_else(|| Error::Crypto("no RSA key to open this key".into()))?,
                )
            }
            RecordKeyType::EncryptedByPublicKeyEcc => {
                crypto::decrypt_ec(
                    ciphertext,
                    self.ecc
                        .ok_or_else(|| Error::Crypto("no EC key to open this key".into()))?,
                )
            }
            other => Err(Error::Crypto(format!("unsupported key type {other:?}"))),
        }
    }
}

fn uid(bytes: &[u8]) -> String {
    b64_encode(bytes)
}

/// Keeper uses UIDs padded with ten zero bytes as "no folder" placeholders.
fn is_placeholder_uid(bytes: &[u8]) -> bool {
    bytes.is_empty() || bytes.starts_with(&[0; 10]) || bytes.ends_with(&[0; 10])
}

fn folder_name(data: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(data).ok()?;
    value.get("name")?.as_str().map(str::to_owned)
}

/// Downloads the whole vault and decrypts everything this account can reach.
///
/// ponytail: always a full sync (empty continuation token). Commander keeps the token and
/// applies incremental `removed*` deltas; add that if one process ever re-syncs large vaults
/// often enough for the re-download to matter.
pub fn sync_down(session: &mut Session) -> Result<Vault> {
    let mut pages = Vec::new();
    let mut token = Vec::new();
    loop {
        let rq = SyncDownRequest {
            continuation_token: token,
            ..Default::default()
        };
        let rs: SyncDownResponse = session.call_typed("vault/sync_down", &rq)?;
        token = rs.continuation_token.clone();
        let more = rs.has_more;
        pages.push(rs);
        if !more {
            break;
        }
    }
    let keys = KeyRing {
        data_key: &session.data_key,
        rsa:      session.rsa_key.as_ref(),
        ecc:      session.ecc_key.as_ref(),
    };
    Ok(build(&pages, &keys))
}

fn build(pages: &[SyncDownResponse], keys: &KeyRing) -> Vault {
    let mut record_keys: HashMap<String, Vec<u8>> = HashMap::new();
    let mut team_sf_keys: HashMap<String, Vec<u8>> = HashMap::new();
    let mut vault = Vault::default();

    for team in pages.iter().flat_map(|p| &p.teams) {
        let team_uid = uid(&team.team_uid);
        let Ok(team_key) = keys.decrypt(&team.team_key, team.team_key_type) else {
            continue;
        };
        let team_rsa = (!team.team_private_key.is_empty())
            .then(|| {
                crypto::decrypt_aes_v1(&team.team_private_key, &team_key).and_then(|d| crypto::load_rsa_private_key(&d))
            })
            .and_then(Result::ok);
        let team_ecc = (!team.team_ecc_private_key.is_empty())
            .then(|| {
                crypto::decrypt_aes_v2(&team.team_ecc_private_key, &team_key)
                    .and_then(|d| crypto::load_ec_private_key(&d))
            })
            .and_then(Result::ok);
        let team_keys = KeyRing {
            data_key: &team_key,
            rsa:      team_rsa.as_ref(),
            ecc:      team_ecc.as_ref(),
        };
        for sfk in &team.shared_folder_keys {
            if let Ok(key) = team_keys.decrypt(&sfk.shared_folder_key, sfk.key_type) {
                team_sf_keys.insert(uid(&sfk.shared_folder_uid), key);
            }
        }
        vault.teams.insert(
            team_uid.clone(),
            Team {
                uid:            team_uid,
                name:           team.name.clone(),
                restrict_edit:  team.restrict_edit,
                restrict_share: team.restrict_share,
                restrict_view:  team.restrict_view,
            },
        );
    }

    let mut sf_keys: HashMap<String, Vec<u8>> = HashMap::new();
    for sf in pages.iter().flat_map(|p| &p.shared_folders) {
        let sf_uid = uid(&sf.shared_folder_uid);
        let key = if sf.shared_folder_key.is_empty() {
            team_sf_keys.get(&sf_uid).cloned()
        } else {
            keys.decrypt(&sf.shared_folder_key, sf.key_type)
                .ok()
                .or_else(|| team_sf_keys.get(&sf_uid).cloned())
        };
        let Some(key) = key else { continue };
        let name = if sf.name.is_empty() {
            crypto::decrypt_aes_v1(&sf.data, &key)
                .ok()
                .and_then(|d| folder_name(&d))
        } else {
            crypto::decrypt_aes_v1(&sf.name, &key)
                .ok()
                .and_then(|n| String::from_utf8(n).ok())
        };
        vault.shared_folders.insert(
            sf_uid.clone(),
            SharedFolder {
                name:                   name.unwrap_or_else(|| sf_uid.clone()),
                uid:                    sf_uid.clone(),
                record_uids:            Vec::new(),
                users:                  Vec::new(),
                teams:                  Vec::new(),
                default_manage_records: sf.default_manage_records,
                default_manage_users:   sf.default_manage_users,
                default_can_edit:       sf.default_can_edit,
                default_can_share:      sf.default_can_reshare,
                key:                    key.clone(),
            },
        );
        sf_keys.insert(sf_uid, key);
    }

    let usernames: HashMap<Vec<u8>, &str> = pages
        .iter()
        .flat_map(|p| &p.users)
        .map(|u| (u.account_uid.clone(), u.username.as_str()))
        .collect();
    for sfu in pages.iter().flat_map(|p| &p.shared_folder_users) {
        if let Some(sf) = vault.shared_folders.get_mut(&uid(&sfu.shared_folder_uid)) {
            let name = if sfu.username.is_empty() {
                usernames
                    .get(&sfu.account_uid)
                    .map_or_else(|| uid(&sfu.account_uid), |u| (*u).to_owned())
            } else {
                sfu.username.clone()
            };
            sf.users.push(name);
        }
    }
    for sft in pages.iter().flat_map(|p| &p.shared_folder_teams) {
        if let Some(sf) = vault.shared_folders.get_mut(&uid(&sft.shared_folder_uid)) {
            sf.teams.push(if sft.name.is_empty() {
                uid(&sft.team_uid)
            } else {
                sft.name.clone()
            });
        }
    }

    let mut owned: HashSet<String> = HashSet::new();
    for md in pages.iter().flat_map(|p| &p.record_meta_data) {
        if md.owner {
            owned.insert(uid(&md.record_uid));
        }
        if let Ok(key) = keys.decrypt(&md.record_key, md.record_key_type)
            && key.len() == 32
        {
            record_keys.insert(uid(&md.record_uid), key);
        }
    }
    for sfr in pages.iter().flat_map(|p| &p.shared_folder_records) {
        let sf_uid = uid(&sfr.shared_folder_uid);
        let rec_uid = uid(&sfr.record_uid);
        if let Some(sf) = vault.shared_folders.get_mut(&sf_uid) {
            sf.record_uids.push(rec_uid.clone());
        }
        if record_keys.contains_key(&rec_uid) {
            continue;
        }
        let Some(sf_key) = sf_keys.get(&sf_uid) else { continue };
        // A 60-byte wrapped key is GCM (12 nonce + 32 key + 16 tag); anything else is CBC.
        let key = if sfr.record_key.len() == 60 {
            crypto::decrypt_aes_v2(&sfr.record_key, sf_key)
        } else {
            crypto::decrypt_aes_v1(&sfr.record_key, sf_key)
        };
        if let Ok(key) = key {
            record_keys.insert(rec_uid, key);
        }
    }
    // Linked (child) records can be nested, so resolve until no more keys appear.
    loop {
        let mut progressed = false;
        for link in pages.iter().flat_map(|p| &p.record_links) {
            let child = uid(&link.child_record_uid);
            if record_keys.contains_key(&child) {
                continue;
            }
            let Some(parent_key) = record_keys.get(&uid(&link.parent_record_uid)) else {
                continue;
            };
            if let Ok(key) = crypto::decrypt_aes_v2(&link.record_key, parent_key) {
                record_keys.insert(child, key);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    for r in pages.iter().flat_map(|p| &p.records) {
        let rec_uid = uid(&r.record_uid);
        let Some(key) = record_keys.get(&rec_uid) else { continue };
        let decrypted = if r.version >= 3 {
            crypto::decrypt_aes_v2(&r.data, key)
        } else {
            crypto::decrypt_aes_v1(&r.data, key)
        };
        let Some(data) = decrypted.ok().and_then(|d| serde_json::from_slice::<Value>(&d).ok()) else {
            continue;
        };
        let extra = (r.version < 3 && !r.extra.is_empty())
            .then(|| crypto::decrypt_aes_v1(&r.extra, key).ok())
            .flatten()
            .and_then(|e| serde_json::from_slice(&e).ok());
        vault.records.insert(
            rec_uid.clone(),
            Record {
                uid: rec_uid.clone(),
                version: r.version,
                revision: r.revision,
                shared: r.shared,
                client_modified_time: r.client_modified_time,
                data,
                extra,
                key: key.clone(),
                owner: owned.contains(&rec_uid),
                udata: (!r.udata.is_empty())
                    .then(|| serde_json::from_str(&r.udata).ok())
                    .flatten(),
                file_size: r.file_size,
            },
        );
    }

    for uf in pages.iter().flat_map(|p| &p.user_folders) {
        let folder_uid = uid(&uf.folder_uid);
        let folder_key = keys.decrypt(&uf.user_folder_key, uf.key_type).ok();
        let name = folder_key
            .as_ref()
            .and_then(|k| crypto::decrypt_aes_v1(&uf.data, k).ok())
            .and_then(|d| folder_name(&d));
        vault.folders.insert(
            folder_uid.clone(),
            Folder {
                name:              name.unwrap_or_else(|| folder_uid.clone()),
                uid:               folder_uid,
                kind:              FolderKind::User,
                parent:            (!uf.parent_uid.is_empty()).then(|| uid(&uf.parent_uid)),
                subfolders:        Vec::new(),
                key:               folder_key.unwrap_or_default(),
                shared_folder_uid: None,
            },
        );
    }
    for ufsf in pages.iter().flat_map(|p| &p.user_folder_shared_folders) {
        let sf_uid = uid(&ufsf.shared_folder_uid);
        let Some(sf) = vault.shared_folders.get(&sf_uid) else {
            continue;
        };
        vault.folders.insert(
            sf_uid.clone(),
            Folder {
                name:              sf.name.clone(),
                uid:               sf_uid.clone(),
                kind:              FolderKind::SharedFolder,
                parent:            (!is_placeholder_uid(&ufsf.folder_uid)).then(|| uid(&ufsf.folder_uid)),
                subfolders:        Vec::new(),
                key:               sf.key.clone(),
                shared_folder_uid: Some(sf_uid.clone()),
            },
        );
    }
    for sff in pages.iter().flat_map(|p| &p.shared_folder_folders) {
        let sf_uid = uid(&sff.shared_folder_uid);
        let Some(sf_key) = sf_keys.get(&sf_uid) else { continue };
        let folder_uid = uid(&sff.folder_uid);
        let folder_key = crypto::decrypt_aes_v1(&sff.shared_folder_folder_key, sf_key).ok();
        let name = folder_key
            .as_ref()
            .and_then(|k| crypto::decrypt_aes_v1(&sff.data, k).ok())
            .and_then(|d| folder_name(&d));
        vault.folders.insert(
            folder_uid.clone(),
            Folder {
                name:              name.unwrap_or_else(|| folder_uid.clone()),
                uid:               folder_uid,
                kind:              FolderKind::SharedFolderFolder,
                parent:            Some(if sff.parent_uid.is_empty() {
                    sf_uid.clone()
                } else {
                    uid(&sff.parent_uid)
                }),
                subfolders:        Vec::new(),
                key:               folder_key.unwrap_or_default(),
                shared_folder_uid: Some(sf_uid),
            },
        );
    }

    for ufr in pages.iter().flat_map(|p| &p.user_folder_records) {
        let folder = if ufr.folder_uid.is_empty() {
            String::new()
        } else {
            uid(&ufr.folder_uid)
        };
        vault
            .folder_records
            .entry(folder)
            .or_default()
            .insert(uid(&ufr.record_uid));
    }
    for sffr in pages.iter().flat_map(|p| &p.shared_folder_folder_records) {
        let folder = uid(if sffr.folder_uid.is_empty() {
            &sffr.shared_folder_uid
        } else {
            &sffr.folder_uid
        });
        vault
            .folder_records
            .entry(folder)
            .or_default()
            .insert(uid(&sffr.record_uid));
    }

    link_folders(&mut vault);
    vault
}

/// Fills `subfolders`/`root_folders`, re-homing folders whose parent is not visible to this
/// account (e.g. a shared folder filed inside someone else's private folder) at the root.
fn link_folders(vault: &mut Vault) {
    let uids: HashSet<String> = vault.folders.keys().cloned().collect();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut roots = Vec::new();
    for folder in vault.folders.values_mut() {
        match &folder.parent {
            Some(p) if uids.contains(p) => children.entry(p.clone()).or_default().push(folder.uid.clone()),
            _ => {
                folder.parent = None;
                roots.push(folder.uid.clone());
            }
        }
    }
    let by_name = |vault: &Vault, list: &mut Vec<String>| {
        list.sort_by_cached_key(|u| vault.folders[u].name.to_lowercase());
    };
    by_name(vault, &mut roots);
    for (parent, mut kids) in children {
        by_name(vault, &mut kids);
        if let Some(f) = vault.folders.get_mut(&parent) {
            f.subfolders = kids;
        }
    }
    vault.root_folders = roots;
}

impl Record {
    pub fn title(&self) -> &str {
        self.data
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
    }

    pub fn record_type(&self) -> &str {
        match self.version {
            2 => "legacy",
            4 => "file",
            5 => "app",
            _ => self.data.get("type").and_then(Value::as_str).unwrap_or("login"),
        }
    }

    pub fn notes(&self) -> &str {
        self.data.get("notes").and_then(Value::as_str).unwrap_or_default()
    }

    /// Typed fields (`fields` then `custom`) of a v3+ record.
    pub fn typed_fields(&self) -> impl Iterator<Item = TypedField<'_>> {
        ["fields", "custom"]
            .into_iter()
            .filter_map(|k| self.data.get(k).and_then(Value::as_array))
            .flatten()
            .map(TypedField)
    }

    fn typed_value(&self, field_type: &str) -> Option<&Value> {
        self.typed_fields()
            .find(|f| f.field_type() == field_type)
            .and_then(|f| f.values().first())
    }

    fn typed_str(&self, field_type: &str) -> Option<&str> {
        self.typed_value(field_type)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }

    pub fn login(&self) -> Option<&str> {
        if self.version == 2 {
            return self
                .data
                .get("secret1")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
        }
        self.typed_str("login")
    }

    pub fn password(&self) -> Option<&str> {
        if self.version == 2 {
            return self
                .data
                .get("secret2")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
        }
        self.typed_str("password")
    }

    pub fn url(&self) -> Option<&str> {
        if self.version == 2 {
            return self.data.get("link").and_then(Value::as_str).filter(|s| !s.is_empty());
        }
        self.typed_str("url")
    }

    /// The `otpauth://` URL, from a `oneTimeCode`/`otp` field or a legacy record's extra.
    pub fn totp_url(&self) -> Option<&str> {
        if self.version == 2 {
            return self
                .extra
                .as_ref()?
                .get("fields")?
                .as_array()?
                .iter()
                .find(|f| f.get("field_type").and_then(Value::as_str) == Some("totp"))?
                .get("data")?
                .as_str();
        }
        self.typed_str("oneTimeCode").or_else(|| self.typed_str("otp"))
    }

    /// One-line summary in the style of Commander's `list` "Description" column.
    pub fn description(&self) -> String {
        if self.version == 6 {
            return "PAM Configuration".into();
        }
        if let Some(login) = self.login() {
            let mut parts = vec![login.to_owned()];
            if let Some(url) = self.url() {
                parts.push(url.to_owned());
            } else if let Some(host) = self.typed_value("host").or_else(|| self.typed_value("pamHostname")) {
                let name = host.get("hostName").and_then(Value::as_str).unwrap_or_default();
                match host.get("port").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                    Some(port) if !name.is_empty() => parts.push(format!("{name}:{port}")),
                    _ if !name.is_empty() => parts.push(name.to_owned()),
                    _ => {}
                }
            }
            return parts.join(" @ ");
        }
        if self.version == 2 {
            return self.url().unwrap_or_default().to_owned();
        }
        if self.version == 4 {
            let name = self.data.get("name").and_then(Value::as_str).unwrap_or_default();
            return name.to_owned();
        }
        if let Some(card) = self.typed_value("paymentCard") {
            let number = card.get("cardNumber").and_then(Value::as_str).unwrap_or_default();
            if number.len() > 4 {
                return format!("*{}", &number[number.len() - 4..]);
            }
        }
        if let Some(addr) = self.typed_value("address") {
            let get = |k: &str| addr.get(k).and_then(Value::as_str).unwrap_or_default();
            let parts = [
                format!("{} {}", get("street1"), get("street2")).trim().to_owned(),
                get("city").to_owned(),
                format!("{} {}", get("state"), get("zip")).trim().to_owned(),
                get("country").to_owned(),
            ];
            return parts
                .into_iter()
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(", ");
        }
        String::new()
    }

    /// `(label, value)` pairs for display and search; masked types are flagged.
    pub fn display_fields(&self) -> Vec<DisplayField> {
        let mut out = Vec::new();
        let mut push = |label: String, value: String, secret: bool| {
            if !value.is_empty() {
                out.push(DisplayField { label, value, secret });
            }
        };
        match self.version {
            2 => {
                push("Login".into(), self.login().unwrap_or_default().into(), false);
                push("Password".into(), self.password().unwrap_or_default().into(), true);
                push("URL".into(), self.url().unwrap_or_default().into(), false);
                if let Some(totp) = self.totp_url() {
                    push("TOTP URL".into(), totp.into(), true);
                }
                for c in self.data.get("custom").and_then(Value::as_array).into_iter().flatten() {
                    let name = c.get("name").and_then(Value::as_str).unwrap_or_default();
                    let value = c.get("value").and_then(Value::as_str).unwrap_or_default();
                    push(name.into(), value.into(), false);
                }
            }
            4 => {
                push("Name".into(), self.data.get("name").and_then(Value::as_str).unwrap_or_default().into(), false);
                push(
                    "MIME Type".into(),
                    self.data.get("type").and_then(Value::as_str).unwrap_or_default().into(),
                    false,
                );
                if let Some(size) = self.data.get("size").and_then(Value::as_u64) {
                    push("Size".into(), format!("{size} bytes"), false);
                }
            }
            _ => {
                for f in self.typed_fields() {
                    let value = f
                        .values()
                        .iter()
                        .map(render_value)
                        .filter(|v| !v.is_empty())
                        .collect::<Vec<_>>()
                        .join(", ");
                    push(f.label(), value, f.is_secret());
                }
            }
        }
        out
    }

    /// All-tokens, case-insensitive substring match over UID, title, type and field text,
    /// mirroring Commander's default (non-regex) search.
    pub fn matches(&self, tokens: &[String]) -> bool {
        if tokens.is_empty() {
            return true;
        }
        let mut haystack = format!("{} {} {} {}", self.uid, self.title(), self.record_type(), self.notes());
        for f in self.display_fields() {
            haystack.push(' ');
            haystack.push_str(&f.label);
            haystack.push(' ');
            haystack.push_str(&f.value);
        }
        let haystack = haystack.to_lowercase();
        tokens.iter().all(|t| haystack.contains(&t.to_lowercase()))
    }
}

pub struct DisplayField {
    pub label:  String,
    pub value:  String,
    pub secret: bool,
}

pub struct TypedField<'a>(&'a Value);

impl<'a> TypedField<'a> {
    pub fn field_type(&self) -> &'a str {
        self.0.get("type").and_then(Value::as_str).unwrap_or("text")
    }

    pub fn values(&self) -> &'a [Value] {
        self.0.get("value").and_then(Value::as_array).map_or(&[], Vec::as_slice)
    }

    pub fn label(&self) -> String {
        match self.0.get("label").and_then(Value::as_str).filter(|l| !l.is_empty()) {
            Some(l) => l.to_owned(),
            None => humanize_field_type(self.field_type()),
        }
    }

    fn is_secret(&self) -> bool {
        matches!(
            self.field_type(),
            "password" | "secret" | "pinCode" | "oneTimeCode" | "otp" | "keyPair" | "securityQuestion" | "cardRef"
        ) || self.0.get("privacyScreen").and_then(Value::as_bool).unwrap_or(false)
    }
}

fn humanize_field_type(t: &str) -> String {
    match t {
        "url" => "URL".into(),
        "oneTimeCode" | "otp" => "TOTP URL".into(),
        "pamHostname" => "Hostname".into(),
        _ => {
            let mut out = String::new();
            for (i, c) in t.chars().enumerate() {
                if i == 0 {
                    out.extend(c.to_uppercase());
                } else if c.is_uppercase() {
                    out.push(' ');
                    out.push(c);
                } else {
                    out.push(c);
                }
            }
            out
        }
    }
}

/// Typed-field values are strings, numbers (dates as epoch millis) or small objects
/// (`name`, `phone`, `host`, ...); objects render as `key: value` pairs.
fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Object(map) => {
            map.iter()
                .filter_map(|(k, v)| {
                    let s = render_value(v);
                    (!s.is_empty()).then(|| format!("{k}: {s}"))
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::proto::vault::{
        Record as PbRecord,
        RecordLink,
        RecordMetaData,
        SharedFolder as PbSharedFolder,
        SharedFolderFolder,
        SharedFolderFolderRecord,
        SharedFolderRecord,
        UserFolder,
        UserFolderRecord,
        UserFolderSharedFolder,
    };

    fn v3_record(uid: &[u8], key: &[u8], data: Value) -> PbRecord {
        PbRecord {
            record_uid: uid.to_vec(),
            version: 3,
            data: crypto::encrypt_aes_v2(data.to_string().as_bytes(), key).unwrap(),
            ..Default::default()
        }
    }

    /// One page exercising every unwrap path: data-key records, a shared folder with a
    /// GCM-wrapped record, a linked child record, and a three-level folder tree.
    #[test]
    fn sync_page_decrypts_every_key_path_and_builds_tree() {
        let data_key = crypto::random_bytes(32);
        let keys = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let (k_own, k_sf, k_shared, k_child, k_uf, k_sff) = (
            crypto::random_bytes(32),
            crypto::random_bytes(32),
            crypto::random_bytes(32),
            crypto::random_bytes(32),
            crypto::random_bytes(32),
            crypto::random_bytes(32),
        );
        let (r_own, r_shared, r_child) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let (f_user, f_sf, f_sub) = ([4u8; 16], [5u8; 16], [6u8; 16]);

        let page = SyncDownResponse {
            record_meta_data: vec![RecordMetaData {
                record_uid: r_own.to_vec(),
                record_key: crypto::encrypt_aes_v1(&k_own, &data_key).unwrap(),
                record_key_type: RecordKeyType::EncryptedByDataKey as i32,
                ..Default::default()
            }],
            shared_folders: vec![PbSharedFolder {
                shared_folder_uid: f_sf.to_vec(),
                shared_folder_key: crypto::encrypt_aes_v2(&k_sf, &data_key).unwrap(),
                key_type: RecordKeyType::EncryptedByDataKeyGcm as i32,
                name: crypto::encrypt_aes_v1(b"Team Stuff", &k_sf).unwrap(),
                ..Default::default()
            }],
            shared_folder_records: vec![SharedFolderRecord {
                shared_folder_uid: f_sf.to_vec(),
                record_uid: r_shared.to_vec(),
                record_key: crypto::encrypt_aes_v2(&k_shared, &k_sf).unwrap(),
                ..Default::default()
            }],
            record_links: vec![RecordLink {
                parent_record_uid: r_own.to_vec(),
                child_record_uid: r_child.to_vec(),
                record_key: crypto::encrypt_aes_v2(&k_child, &k_own).unwrap(),
                ..Default::default()
            }],
            records: vec![
                v3_record(
                    &r_own,
                    &k_own,
                    json!({"title": "Mine", "type": "login", "fields": [{"type": "login", "value": ["me"]}]}),
                ),
                v3_record(&r_shared, &k_shared, json!({"title": "Shared", "type": "login"})),
                v3_record(&r_child, &k_child, json!({"title": "Child", "type": "file"})),
                v3_record(&[9u8; 16], &crypto::random_bytes(32), json!({"title": "Unreachable"})),
            ],
            user_folders: vec![UserFolder {
                folder_uid: f_user.to_vec(),
                user_folder_key: crypto::encrypt_aes_v1(&k_uf, &data_key).unwrap(),
                key_type: RecordKeyType::EncryptedByDataKey as i32,
                data: crypto::encrypt_aes_v1(br#"{"name":"Work"}"#, &k_uf).unwrap(),
                ..Default::default()
            }],
            user_folder_shared_folders: vec![UserFolderSharedFolder {
                folder_uid: f_user.to_vec(),
                shared_folder_uid: f_sf.to_vec(),
                ..Default::default()
            }],
            shared_folder_folders: vec![SharedFolderFolder {
                shared_folder_uid: f_sf.to_vec(),
                folder_uid: f_sub.to_vec(),
                shared_folder_folder_key: crypto::encrypt_aes_v1(&k_sff, &k_sf).unwrap(),
                data: crypto::encrypt_aes_v1(br#"{"name":"Deep"}"#, &k_sff).unwrap(),
                ..Default::default()
            }],
            user_folder_records: vec![UserFolderRecord {
                record_uid: r_own.to_vec(),
                ..Default::default()
            }],
            shared_folder_folder_records: vec![SharedFolderFolderRecord {
                shared_folder_uid: f_sf.to_vec(),
                folder_uid: f_sub.to_vec(),
                record_uid: r_shared.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let vault = build(&[page], &keys);
        let titles: Vec<&str> = vault.records.values().map(Record::title).collect();
        assert_eq!(titles.len(), 3, "unreachable record must be dropped: {titles:?}");
        assert!(titles.contains(&"Mine") && titles.contains(&"Shared") && titles.contains(&"Child"));
        assert_eq!(vault.records[&uid(&r_own)].login(), Some("me"));

        assert_eq!(vault.root_folders, vec![uid(&f_user)]);
        assert_eq!(vault.folder_path(&uid(&f_sub)), "/Work/Team Stuff/Deep");
        assert_eq!(vault.records_in(&uid(&f_sub)).map(Record::title).collect::<Vec<_>>(), ["Shared"]);
        assert_eq!(vault.records_in("").map(Record::title).collect::<Vec<_>>(), ["Mine"]);
    }

    #[test]
    fn legacy_record_fields_and_totp_come_from_data_and_extra() {
        let r = Record {
            uid: "u".into(),
            version: 2,
            revision: 0,
            shared: false,
            client_modified_time: 0,
            data: json!({"title": "Old", "secret1": "bob", "secret2": "pw", "link": "https://x", "custom": [{"name": "PIN", "value": "1234"}]}),
            extra: Some(json!({"fields": [{"field_type": "totp", "data": "otpauth://totp/x?secret=AAAA"}]})),
            ..Record::default()
        };
        assert_eq!(r.description(), "bob @ https://x");
        assert_eq!(r.totp_url(), Some("otpauth://totp/x?secret=AAAA"));
        assert!(r.matches(&["BOB".into(), "pin".into()]));
        assert!(!r.matches(&["bob".into(), "nope".into()]));
    }
}
