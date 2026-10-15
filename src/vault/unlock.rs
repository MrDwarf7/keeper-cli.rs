//! Turning a downloaded sync into a [`Vault`]. Keys depend on each other in a fixed order (team
//! keys open shared folder keys, which open record and subfolder keys, and parent records open
//! linked children), so each stage is its own type and only the next stage can follow it.

use std::collections::{BTreeMap, HashMap, HashSet};

use aes::cipher::block_padding::Pkcs7;
use p256::SecretKey;
use prost::Message;
use rsa::RsaPrivateKey;
use serde_json::Value;

use super::{Folder, FolderKind, Location, Record, RecordKind, SharedFolder, Team, Vault};
use crate::auth::Session;
use crate::crypto::{self, AesKey};
use crate::prelude::*;
use crate::proto::records::RecordKeyType;
use crate::proto::vault::{SyncDownRequest, SyncDownResponse};
use crate::uid::Uid;

/// Keys able to open other keys, as tagged by `records.RecordKeyType`: the account's (data key
/// plus RSA/EC private keys) or a team's.
pub struct KeyRing<'a> {
    pub data_key: &'a AesKey,
    pub rsa:      Option<&'a RsaPrivateKey>,
    pub ecc:      Option<&'a SecretKey>,
}

impl<'a> From<&'a Session> for KeyRing<'a> {
    fn from(session: &'a Session) -> Self {
        Self {
            data_key: &session.data_key,
            rsa:      session.rsa_key.as_ref(),
            ecc:      session.ecc_key.as_ref(),
        }
    }
}

#[derive(Clone, Copy)]
enum WrappingKey<'a> {
    DataKeyCbc(&'a AesKey),
    DataKeyGcm(&'a AesKey),
    Rsa(&'a RsaPrivateKey),
    Ecc(&'a SecretKey),
}

impl WrappingKey<'_> {
    fn open(self, ciphertext: &[u8]) -> Result<AesKey> {
        let plain = match self {
            Self::DataKeyCbc(key) => crypto::decrypt_cbc::<Pkcs7>(ciphertext, key)?,
            Self::DataKeyGcm(key) => crypto::decrypt_aes_v2(ciphertext, key)?,
            Self::Rsa(key) => crypto::decrypt_rsa(ciphertext, key)?,
            Self::Ecc(key) => crypto::decrypt_ec(ciphertext, key)?,
        };
        AesKey::try_from(plain)
    }
}

impl KeyRing<'_> {
    fn wrapping_type(key_type: i32) -> Option<RecordKeyType> {
        match key_type {
            value if value == RecordKeyType::EncryptedByDataKey as i32 => Some(RecordKeyType::EncryptedByDataKey),
            value if value == RecordKeyType::EncryptedByDataKeyGcm as i32 => Some(RecordKeyType::EncryptedByDataKeyGcm),
            value if value == RecordKeyType::EncryptedByPublicKey as i32 => Some(RecordKeyType::EncryptedByPublicKey),
            value if value == RecordKeyType::EncryptedByPublicKeyEcc as i32 => {
                Some(RecordKeyType::EncryptedByPublicKeyEcc)
            }
            _ => None,
        }
    }

    fn wrapping_key(&self, key_type: RecordKeyType) -> Option<WrappingKey<'_>> {
        match key_type {
            RecordKeyType::EncryptedByDataKey => Some(WrappingKey::DataKeyCbc(self.data_key)),
            RecordKeyType::EncryptedByDataKeyGcm => Some(WrappingKey::DataKeyGcm(self.data_key)),
            RecordKeyType::EncryptedByPublicKey => self.rsa.map(WrappingKey::Rsa),
            RecordKeyType::EncryptedByPublicKeyEcc => self.ecc.map(WrappingKey::Ecc),
            _ => None,
        }
    }

    fn record_wrapping_key(&self, ciphertext: &[u8], key_type: i32) -> Option<WrappingKey<'_>> {
        if ciphertext.is_empty() {
            return None;
        }
        let key_type = Self::wrapping_type(key_type)?;
        self.wrapping_key(key_type)
    }

    fn folder_wrapping_key(&self, ciphertext: &[u8], key_type: i32) -> Option<WrappingKey<'_>> {
        if ciphertext.is_empty() {
            return None;
        }
        match Self::wrapping_type(key_type) {
            Some(key_type) => self.wrapping_key(key_type),
            None => Some(WrappingKey::DataKeyCbc(self.data_key)),
        }
    }
}

fn context<T, E>(result: Result<T, E>, uid: &Uid, stage: &str) -> Result<T>
where
    E: Into<Error>,
{
    result.map_err(|source| {
        Error::Context {
            context: format!("{stage} for vault object {uid}"),
            source:  Box::new(source.into()),
        }
    })
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
        let request = SyncDownRequest {
            continuation_token: token,
            ..Default::default()
        };
        let response = session
            .rest
            .execute("vault/sync_down", &session.session_token, &request)?;
        let rs = SyncDownResponse::decode(response.as_slice())?;
        token = rs.continuation_token.clone();
        let more = rs.has_more;
        pages.push(rs);
        if !more {
            break;
        }
    }
    let ring = KeyRing::from(&*session);
    Unlock::from(Download(pages))
        .open_teams(&ring)?
        .open_shared_folders(&ring)?
        .key_records(&ring)?
        .into_vault(&ring)
}

/// Every page of one full sync.
pub(super) struct Download(pub(super) Vec<SyncDownResponse>);

pub(super) struct Unlock<Stage> {
    download: Download,
    stage:    Stage,
}

pub(super) struct Downloaded;

pub(super) struct TeamsOpen {
    teams:            BTreeMap<Uid, Team>,
    /// Shared folder keys reachable only through team membership.
    team_folder_keys: HashMap<Uid, AesKey>,
}

pub(super) struct SharedFoldersOpen {
    teams:              BTreeMap<Uid, Team>,
    shared_folders:     BTreeMap<Uid, SharedFolder>,
    shared_folder_data: HashMap<Uid, Value>,
}

pub(super) struct RecordsKeyed {
    teams:              BTreeMap<Uid, Team>,
    shared_folders:     BTreeMap<Uid, SharedFolder>,
    shared_folder_data: HashMap<Uid, Value>,
    record_keys:        HashMap<Uid, AesKey>,
    owned:              HashSet<Uid>,
}

impl From<Download> for Unlock<Downloaded> {
    fn from(download: Download) -> Self {
        Self {
            download,
            stage: Downloaded,
        }
    }
}

impl Unlock<Downloaded> {
    pub(super) fn open_teams(self, ring: &KeyRing) -> Result<Unlock<TeamsOpen>> {
        let mut teams = BTreeMap::new();
        let mut team_folder_keys = HashMap::new();
        for team in self.download.0.iter().flat_map(|page| &page.teams) {
            let uid = Uid::from(team.team_uid.as_slice());
            let Some(wrapping_key) = ring.record_wrapping_key(&team.team_key, team.team_key_type) else {
                continue;
            };
            let team_key = context(wrapping_key.open(&team.team_key), &uid, "opening team key")?;
            let team_rsa = if team.team_private_key.is_empty() {
                None
            } else {
                Some(context(
                    crypto::decrypt_cbc::<Pkcs7>(&team.team_private_key, &team_key)
                        .and_then(|der| crypto::load_rsa_private_key(&der)),
                    &uid,
                    "opening team RSA private key",
                )?)
            };
            let team_ecc = if team.team_ecc_private_key.is_empty() {
                None
            } else {
                Some(context(
                    crypto::decrypt_aes_v2(&team.team_ecc_private_key, &team_key)
                        .and_then(|raw| SecretKey::from_slice(&raw).map_err(Error::from)),
                    &uid,
                    "opening team ECC private key",
                )?)
            };
            let team_ring = KeyRing {
                data_key: &team_key,
                rsa:      team_rsa.as_ref(),
                ecc:      team_ecc.as_ref(),
            };
            for sfk in &team.shared_folder_keys {
                let uid = Uid::from(sfk.shared_folder_uid.as_slice());
                let Some(wrapping_key) = team_ring.record_wrapping_key(&sfk.shared_folder_key, sfk.key_type) else {
                    continue;
                };
                let key = context(wrapping_key.open(&sfk.shared_folder_key), &uid, "opening team shared-folder key")?;
                team_folder_keys.insert(uid, key);
            }
            teams.insert(
                uid.clone(),
                Team {
                    uid,
                    name: team.name.clone(),
                    restrict_edit: team.restrict_edit,
                    restrict_share: team.restrict_share,
                    restrict_view: team.restrict_view,
                },
            );
        }
        Ok(Unlock {
            download: self.download,
            stage:    TeamsOpen {
                teams,
                team_folder_keys,
            },
        })
    }
}

fn folder_data(data: &[u8], key: &AesKey) -> Result<Value> {
    let plain = crypto::decrypt_cbc::<Pkcs7>(data, key)?;
    Ok(serde_json::from_slice(&plain)?)
}

fn folder_name(data: &Value) -> Option<&str> {
    data.get("name").and_then(Value::as_str).filter(|name| !name.is_empty())
}

fn shared_folder_name(ciphertext: &[u8], key: &AesKey) -> Result<String> {
    Ok(String::from_utf8(crypto::decrypt_cbc::<Pkcs7>(ciphertext, key)?)?)
}

impl Unlock<TeamsOpen> {
    pub(super) fn open_shared_folders(self, ring: &KeyRing) -> Result<Unlock<SharedFoldersOpen>> {
        let TeamsOpen {
            teams,
            mut team_folder_keys,
        } = self.stage;
        let mut shared_folders = BTreeMap::new();
        let mut shared_folder_data = HashMap::new();
        for sf in self.download.0.iter().flat_map(|page| &page.shared_folders) {
            let uid = Uid::from(sf.shared_folder_uid.as_slice());
            let own_key = match ring.folder_wrapping_key(&sf.shared_folder_key, sf.key_type) {
                Some(wrapping_key) => {
                    Some(context(wrapping_key.open(&sf.shared_folder_key), &uid, "opening shared-folder key")?)
                }
                None => None,
            };
            let Some(key) = own_key.or_else(|| team_folder_keys.remove(&uid)) else {
                continue;
            };
            let data = if sf.data.is_empty() {
                Value::Null
            } else {
                context(folder_data(&sf.data, &key), &uid, "opening shared-folder metadata")?
            };
            let name = if let Some(name) = folder_name(&data) {
                name.to_owned()
            } else if sf.name.is_empty() {
                uid.to_string()
            } else {
                let name = context(shared_folder_name(&sf.name, &key), &uid, "opening shared-folder name")?;
                if name.is_empty() { uid.to_string() } else { name }
            };
            shared_folder_data.insert(uid.clone(), data);
            shared_folders.insert(
                uid.clone(),
                SharedFolder {
                    uid,
                    name,
                    key,
                    record_uids: Vec::new(),
                    users: Vec::new(),
                    teams: Vec::new(),
                    default_manage_records: sf.default_manage_records,
                    default_manage_users: sf.default_manage_users,
                    default_can_edit: sf.default_can_edit,
                    default_can_share: sf.default_can_reshare,
                },
            );
        }

        let usernames: HashMap<&[u8], &str> = self
            .download
            .0
            .iter()
            .flat_map(|page| &page.users)
            .map(|user| (user.account_uid.as_slice(), user.username.as_str()))
            .collect();
        for sfu in self.download.0.iter().flat_map(|page| &page.shared_folder_users) {
            if let Some(sf) = shared_folders.get_mut(&Uid::from(sfu.shared_folder_uid.as_slice())) {
                sf.users.push(match sfu.username.as_str() {
                    "" => {
                        usernames.get(sfu.account_uid.as_slice()).map_or_else(
                            || Uid::from(sfu.account_uid.as_slice()).to_string(),
                            |user| (*user).to_owned(),
                        )
                    }
                    named => named.to_owned(),
                });
            }
        }
        for sft in self.download.0.iter().flat_map(|page| &page.shared_folder_teams) {
            if let Some(sf) = shared_folders.get_mut(&Uid::from(sft.shared_folder_uid.as_slice())) {
                sf.teams.push(match sft.name.as_str() {
                    "" => Uid::from(sft.team_uid.as_slice()).to_string(),
                    named => named.to_owned(),
                });
            }
        }
        Ok(Unlock {
            download: self.download,
            stage:    SharedFoldersOpen {
                teams,
                shared_folders,
                shared_folder_data,
            },
        })
    }
}

impl Unlock<SharedFoldersOpen> {
    pub(super) fn key_records(self, ring: &KeyRing) -> Result<Unlock<RecordsKeyed>> {
        let SharedFoldersOpen {
            teams,
            mut shared_folders,
            shared_folder_data,
        } = self.stage;
        let mut record_keys = HashMap::new();
        let mut owned = HashSet::new();

        for md in self.download.0.iter().flat_map(|page| &page.record_meta_data) {
            let uid = Uid::from(md.record_uid.as_slice());
            if md.owner {
                owned.insert(uid.clone());
            }
            let Some(wrapping_key) = ring.record_wrapping_key(&md.record_key, md.record_key_type) else {
                continue;
            };
            let key = context(wrapping_key.open(&md.record_key), &uid, "opening record key")?;
            record_keys.insert(uid, key);
        }

        for sfr in self.download.0.iter().flat_map(|page| &page.shared_folder_records) {
            let record_uid = Uid::from(sfr.record_uid.as_slice());
            let Some(sf) = shared_folders.get_mut(&Uid::from(sfr.shared_folder_uid.as_slice())) else {
                continue;
            };
            sf.record_uids.push(record_uid.clone());
            if record_keys.contains_key(&record_uid) || sfr.record_key.is_empty() {
                continue;
            }
            // A 60-byte wrapped key is GCM (12 nonce + 32 key + 16 tag); anything else is CBC.
            let opened = if sfr.record_key.len() == 60 {
                crypto::decrypt_aes_v2(&sfr.record_key, &sf.key)
            } else {
                crypto::decrypt_cbc::<Pkcs7>(&sfr.record_key, &sf.key)
            }
            .and_then(AesKey::try_from);
            let key = context(opened, &record_uid, "opening shared-folder record key")?;
            record_keys.insert(record_uid, key);
        }

        // Linked records can nest, so repeat until a pass opens nothing new.
        loop {
            let mut opened = Vec::new();
            for link in self.download.0.iter().flat_map(|page| &page.record_links) {
                let child_uid = Uid::from(link.child_record_uid.as_slice());
                if record_keys.contains_key(&child_uid) || link.record_key.is_empty() {
                    continue;
                }
                let parent_uid = Uid::from(link.parent_record_uid.as_slice());
                let Some(parent_key) = record_keys.get(&parent_uid) else {
                    continue;
                };
                let key = context(
                    crypto::decrypt_aes_v2(&link.record_key, parent_key).and_then(AesKey::try_from),
                    &child_uid,
                    &format!("opening linked record key from parent {parent_uid}"),
                )?;
                opened.push((child_uid, key));
            }
            if opened.is_empty() {
                break;
            }
            record_keys.extend(opened);
        }

        Ok(Unlock {
            download: self.download,
            stage:    RecordsKeyed {
                teams,
                shared_folders,
                shared_folder_data,
                record_keys,
                owned,
            },
        })
    }
}

impl Unlock<RecordsKeyed> {
    pub(super) fn into_vault(self, ring: &KeyRing) -> Result<Vault> {
        let RecordsKeyed {
            teams,
            shared_folders,
            shared_folder_data,
            mut record_keys,
            owned,
        } = self.stage;
        let records = unlock_records(&self.download, &mut record_keys, &owned)?;
        let folders = unlock_folders(&self.download, &shared_folders, &shared_folder_data, ring)?;
        let mut vault = Vault {
            records,
            shared_folders,
            teams,
            folders,
            ..Vault::default()
        };
        file_records(&self.download, &mut vault);
        vault.link_tree();
        Ok(vault)
    }
}

fn unlock_records(
    download: &Download,
    record_keys: &mut HashMap<Uid, AesKey>,
    owned: &HashSet<Uid>,
) -> Result<BTreeMap<Uid, Record>> {
    let mut records = BTreeMap::new();
    for record in download.0.iter().flat_map(|page| &page.records) {
        let uid = Uid::from(record.record_uid.as_slice());
        let Some(key) = record_keys.remove(&uid) else {
            continue;
        };
        let kind = match record.version {
            2 => {
                let extra = if record.extra.is_empty() {
                    None
                } else {
                    let plain = context(
                        crypto::decrypt_cbc::<Pkcs7>(&record.extra, &key),
                        &uid,
                        "decrypting legacy record extra",
                    )?;
                    Some(context(serde_json::from_slice(&plain), &uid, "parsing legacy record extra")?)
                };
                RecordKind::Legacy { extra }
            }
            3 => RecordKind::Typed,
            4 => RecordKind::File { size: record.file_size },
            5 => RecordKind::Application,
            6 => RecordKind::PamConfiguration,
            _ => continue,
        };
        let plain = match &kind {
            RecordKind::Legacy { .. } => crypto::decrypt_cbc::<Pkcs7>(&record.data, &key),
            _ => crypto::decrypt_aes_v2(&record.data, &key),
        };
        let plain = context(plain, &uid, "decrypting record data")?;
        let data = context(serde_json::from_slice(&plain), &uid, "parsing record data")?;
        let udata = if record.udata.is_empty() {
            None
        } else {
            Some(context(serde_json::from_str(&record.udata), &uid, "parsing record udata")?)
        };
        records.insert(
            uid.clone(),
            Record {
                owner: owned.contains(&uid),
                uid,
                kind,
                data,
                revision: record.revision,
                shared: record.shared,
                client_modified_time: record.client_modified_time,
                key,
                udata,
            },
        );
    }
    Ok(records)
}

fn unlock_folders(
    download: &Download,
    shared_folders: &BTreeMap<Uid, SharedFolder>,
    shared_folder_data: &HashMap<Uid, Value>,
    ring: &KeyRing,
) -> Result<HashMap<Uid, Folder>> {
    let user_folders = download.0.iter().flat_map(|page| &page.user_folders).map(|folder| {
        let uid = Uid::from(folder.folder_uid.as_slice());
        let key = match ring.folder_wrapping_key(&folder.user_folder_key, folder.key_type) {
            Some(wrapping_key) => {
                Some(context(wrapping_key.open(&folder.user_folder_key), &uid, "opening user folder key")?)
            }
            None => None,
        };
        let data = match key.as_ref() {
            Some(key) if !folder.data.is_empty() => {
                context(folder_data(&folder.data, key), &uid, "opening user folder metadata")?
            }
            _ => Value::Null,
        };
        let name = folder_name(&data).unwrap_or_else(|| uid.as_ref()).to_owned();
        Ok((
            uid.clone(),
            Folder {
                uid,
                name,
                data,
                kind: FolderKind::User,
                parent: Location::from(folder.parent_uid.as_slice()),
                subfolders: Vec::new(),
                key,
            },
        ))
    });
    let shared_roots = download
        .0
        .iter()
        .flat_map(|page| &page.user_folder_shared_folders)
        .map(|link| {
            let uid = Uid::from(link.shared_folder_uid.as_slice());
            let shared_folder = shared_folders.get(&uid);
            let data = shared_folder_data.get(&uid).cloned().unwrap_or(Value::Null);
            let name = folder_name(&data)
                .or_else(|| shared_folder.map(|shared_folder| shared_folder.name.as_str()))
                .unwrap_or_else(|| uid.as_ref())
                .to_owned();
            Ok((
                uid.clone(),
                Folder {
                    uid,
                    name,
                    data,
                    kind: FolderKind::SharedFolder,
                    parent: Location::from(link.folder_uid.as_slice()),
                    subfolders: Vec::new(),
                    key: shared_folder.map(|shared_folder| shared_folder.key.clone()),
                },
            ))
        });
    let shared_subfolders = download
        .0
        .iter()
        .flat_map(|page| &page.shared_folder_folders)
        .map(|folder| {
            let shared_folder = Uid::from(folder.shared_folder_uid.as_slice());
            let uid = Uid::from(folder.folder_uid.as_slice());
            let key = match shared_folders.get(&shared_folder) {
                Some(sf) if !folder.shared_folder_folder_key.is_empty() => {
                    Some(context(
                        crypto::decrypt_cbc::<Pkcs7>(&folder.shared_folder_folder_key, &sf.key)
                            .and_then(AesKey::try_from),
                        &uid,
                        "opening shared-folder subfolder key",
                    )?)
                }
                _ => None,
            };
            let data = match key.as_ref() {
                Some(key) if !folder.data.is_empty() => {
                    context(folder_data(&folder.data, key), &uid, "opening shared-folder subfolder metadata")?
                }
                _ => Value::Null,
            };
            let name = folder_name(&data).unwrap_or_else(|| uid.as_ref()).to_owned();
            let parent = if folder.parent_uid.is_empty() {
                Location::Folder(shared_folder.clone())
            } else {
                Location::from(folder.parent_uid.as_slice())
            };
            Ok((
                uid.clone(),
                Folder {
                    uid,
                    name,
                    data,
                    kind: FolderKind::SharedFolderFolder { shared_folder },
                    parent,
                    subfolders: Vec::new(),
                    key,
                },
            ))
        });
    user_folders.chain(shared_roots).chain(shared_subfolders).collect()
}

fn file_records(download: &Download, vault: &mut Vault) {
    for folder in download.0.iter().flat_map(|page| &page.user_folder_records) {
        vault
            .filed
            .entry(Location::from(folder.folder_uid.as_slice()))
            .or_default()
            .insert(Uid::from(folder.record_uid.as_slice()));
    }
    for record in download.0.iter().flat_map(|page| &page.shared_folder_folder_records) {
        let folder_uid = if record.folder_uid.is_empty() {
            &record.shared_folder_uid
        } else {
            &record.folder_uid
        };
        vault
            .filed
            .entry(Location::from(folder_uid.as_slice()))
            .or_default()
            .insert(Uid::from(record.record_uid.as_slice()));
    }
}
