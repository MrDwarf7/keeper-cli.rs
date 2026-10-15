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

impl KeyRing<'_> {
    fn open_folder_key(&self, ciphertext: &[u8], key_type: i32) -> Result<AesKey> {
        let key_type = RecordKeyType::try_from(key_type);
        match key_type {
            Ok(
                kind @ (RecordKeyType::EncryptedByDataKey
                | RecordKeyType::EncryptedByDataKeyGcm
                | RecordKeyType::EncryptedByPublicKey
                | RecordKeyType::EncryptedByPublicKeyEcc),
            ) => self.open(ciphertext, kind),
            _ => AesKey::try_from(crypto::decrypt_cbc::<Pkcs7>(ciphertext, self.data_key)?),
        }
    }

    fn open(&self, ciphertext: &[u8], key_type: RecordKeyType) -> Result<AesKey> {
        let plain = match key_type {
            RecordKeyType::EncryptedByDataKey => crypto::decrypt_cbc::<Pkcs7>(ciphertext, self.data_key)?,
            RecordKeyType::EncryptedByDataKeyGcm => crypto::decrypt_aes_v2(ciphertext, self.data_key)?,
            RecordKeyType::EncryptedByPublicKey => {
                crypto::decrypt_rsa(
                    ciphertext,
                    self.rsa
                        .ok_or_else(|| Error::Crypto("no RSA key to open this key".into()))?,
                )?
            }
            RecordKeyType::EncryptedByPublicKeyEcc => {
                crypto::decrypt_ec(
                    ciphertext,
                    self.ecc
                        .ok_or_else(|| Error::Crypto("no EC key to open this key".into()))?,
                )?
            }
            other => return Err(Error::Crypto(format!("unsupported key type {other:?}"))),
        };
        AesKey::try_from(plain)
    }
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
    Ok(Unlock::from(Download(pages))
        .open_teams(&ring)
        .open_shared_folders(&ring)
        .key_records(&ring)
        .into_vault(&ring))
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
    pub(super) fn open_teams(self, ring: &KeyRing) -> Unlock<TeamsOpen> {
        let mut teams = BTreeMap::new();
        let mut team_folder_keys = HashMap::new();
        for team in self.download.0.iter().flat_map(|page| &page.teams) {
            let Ok(key_type) = RecordKeyType::try_from(team.team_key_type) else {
                continue;
            };
            let Ok(team_key) = ring.open(&team.team_key, key_type) else {
                continue;
            };
            let team_rsa = crypto::decrypt_cbc::<Pkcs7>(&team.team_private_key, &team_key)
                .and_then(|der| crypto::load_rsa_private_key(&der))
                .ok();
            let team_ecc = crypto::decrypt_aes_v2(&team.team_ecc_private_key, &team_key)
                .ok()
                .and_then(|raw| SecretKey::from_slice(&raw).ok());
            let team_ring = KeyRing {
                data_key: &team_key,
                rsa:      team_rsa.as_ref(),
                ecc:      team_ecc.as_ref(),
            };
            for sfk in &team.shared_folder_keys {
                let Ok(key_type) = RecordKeyType::try_from(sfk.key_type) else {
                    continue;
                };
                if let Ok(key) = team_ring.open(&sfk.shared_folder_key, key_type) {
                    team_folder_keys.insert(Uid::from(sfk.shared_folder_uid.as_slice()), key);
                }
            }
            let uid = Uid::from(team.team_uid.as_slice());
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
        Unlock {
            download: self.download,
            stage:    TeamsOpen {
                teams,
                team_folder_keys,
            },
        }
    }
}

fn folder_data(data: &[u8], key: &AesKey) -> Option<Value> {
    serde_json::from_slice(&crypto::decrypt_cbc::<Pkcs7>(data, key).ok()?).ok()
}

fn folder_name(data: &Value) -> Option<&str> {
    data.get("name").and_then(Value::as_str).filter(|name| !name.is_empty())
}

fn shared_folder_name(ciphertext: &[u8], key: &AesKey) -> Option<String> {
    String::from_utf8(crypto::decrypt_cbc::<Pkcs7>(ciphertext, key).ok()?)
        .ok()
        .filter(|name| !name.is_empty())
}

impl Unlock<TeamsOpen> {
    pub(super) fn open_shared_folders(self, ring: &KeyRing) -> Unlock<SharedFoldersOpen> {
        let TeamsOpen {
            teams,
            mut team_folder_keys,
        } = self.stage;
        let mut shared_folders = BTreeMap::new();
        let mut shared_folder_data = HashMap::new();
        for sf in self.download.0.iter().flat_map(|page| &page.shared_folders) {
            let uid = Uid::from(sf.shared_folder_uid.as_slice());
            let own_key = ring.open_folder_key(&sf.shared_folder_key, sf.key_type).ok();
            let Some(key) = own_key.or_else(|| team_folder_keys.remove(&uid)) else {
                continue;
            };
            let data = folder_data(&sf.data, &key).unwrap_or(Value::Null);
            let name = folder_name(&data)
                .map(str::to_owned)
                .or_else(|| shared_folder_name(&sf.name, &key))
                .unwrap_or_else(|| uid.to_string());
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
        Unlock {
            download: self.download,
            stage:    SharedFoldersOpen {
                teams,
                shared_folders,
                shared_folder_data,
            },
        }
    }
}

impl Unlock<SharedFoldersOpen> {
    pub(super) fn key_records(self, ring: &KeyRing) -> Unlock<RecordsKeyed> {
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
            let Ok(key_type) = RecordKeyType::try_from(md.record_key_type) else {
                continue;
            };
            if let Ok(key) = ring.open(&md.record_key, key_type) {
                record_keys.insert(uid, key);
            }
        }

        for sfr in self.download.0.iter().flat_map(|page| &page.shared_folder_records) {
            let record_uid = Uid::from(sfr.record_uid.as_slice());
            let Some(sf) = shared_folders.get_mut(&Uid::from(sfr.shared_folder_uid.as_slice())) else {
                continue;
            };
            sf.record_uids.push(record_uid.clone());
            if record_keys.contains_key(&record_uid) {
                continue;
            }
            // A 60-byte wrapped key is GCM (12 nonce + 32 key + 16 tag); anything else is CBC.
            let plain = if sfr.record_key.len() == 60 {
                crypto::decrypt_aes_v2(&sfr.record_key, &sf.key)
            } else {
                crypto::decrypt_cbc::<Pkcs7>(&sfr.record_key, &sf.key)
            };
            if let Ok(key) = plain.and_then(AesKey::try_from) {
                record_keys.insert(record_uid, key);
            }
        }

        // Linked records can nest, so repeat until a pass opens nothing new.
        loop {
            let opened: Vec<(Uid, AesKey)> = self
                .download
                .0
                .iter()
                .flat_map(|page| &page.record_links)
                .filter(|link| !record_keys.contains_key(&Uid::from(link.child_record_uid.as_slice())))
                .filter_map(|link| {
                    let parent = record_keys.get(&Uid::from(link.parent_record_uid.as_slice()))?;
                    let key = crypto::decrypt_aes_v2(&link.record_key, parent)
                        .and_then(AesKey::try_from)
                        .ok()?;
                    Some((Uid::from(link.child_record_uid.as_slice()), key))
                })
                .collect();
            if opened.is_empty() {
                break;
            }
            record_keys.extend(opened);
        }

        Unlock {
            download: self.download,
            stage:    RecordsKeyed {
                teams,
                shared_folder_data,
                shared_folders,
                record_keys,
                owned,
            },
        }
    }
}

impl Unlock<RecordsKeyed> {
    pub(super) fn into_vault(self, ring: &KeyRing) -> Vault {
        let RecordsKeyed {
            teams,
            shared_folders,
            shared_folder_data,
            mut record_keys,
            owned,
        } = self.stage;
        let records = unlock_records(&self.download, &mut record_keys, &owned);
        let folders = unlock_folders(&self.download, &shared_folders, &shared_folder_data, ring);
        let mut vault = Vault {
            records,
            shared_folders,
            teams,
            folders,
            ..Vault::default()
        };
        file_records(&self.download, &mut vault);
        vault.link_tree();
        vault
    }
}

fn unlock_records(
    download: &Download,
    record_keys: &mut HashMap<Uid, AesKey>,
    owned: &HashSet<Uid>,
) -> BTreeMap<Uid, Record> {
    download
        .0
        .iter()
        .flat_map(|page| &page.records)
        .filter_map(|record| {
            let uid = Uid::from(record.record_uid.as_slice());
            let key = record_keys.remove(&uid)?;
            let kind = match record.version {
                2 => {
                    RecordKind::Legacy {
                        extra: crypto::decrypt_cbc::<Pkcs7>(&record.extra, &key)
                            .ok()
                            .and_then(|extra| serde_json::from_slice(&extra).ok()),
                    }
                }
                3 => RecordKind::Typed,
                4 => RecordKind::File { size: record.file_size },
                5 => RecordKind::Application,
                6 => RecordKind::PamConfiguration,
                _ => return None,
            };
            let plain = match &kind {
                RecordKind::Legacy { .. } => crypto::decrypt_cbc::<Pkcs7>(&record.data, &key),
                _ => crypto::decrypt_aes_v2(&record.data, &key),
            };
            let data = serde_json::from_slice(&plain.ok()?).ok()?;
            Some((
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
                    udata: serde_json::from_str(&record.udata).ok(),
                },
            ))
        })
        .collect()
}

fn unlock_folders(
    download: &Download,
    shared_folders: &BTreeMap<Uid, SharedFolder>,
    shared_folder_data: &HashMap<Uid, Value>,
    ring: &KeyRing,
) -> HashMap<Uid, Folder> {
    let user_folders = download.0.iter().flat_map(|page| &page.user_folders).map(|folder| {
        let uid = Uid::from(folder.folder_uid.as_slice());
        let key = ring.open_folder_key(&folder.user_folder_key, folder.key_type).ok();
        let data = key
            .as_ref()
            .and_then(|key| folder_data(&folder.data, key))
            .unwrap_or(Value::Null);
        let name = folder_name(&data).unwrap_or_else(|| uid.as_ref()).to_owned();
        Folder {
            uid,
            name,
            data,
            kind: FolderKind::User,
            parent: Location::from(folder.parent_uid.as_slice()),
            subfolders: Vec::new(),
            key,
        }
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
            Folder {
                uid,
                name,
                data,
                kind: FolderKind::SharedFolder,
                parent: Location::from(link.folder_uid.as_slice()),
                subfolders: Vec::new(),
                key: shared_folder.map(|shared_folder| shared_folder.key.clone()),
            }
        });
    let shared_subfolders = download
        .0
        .iter()
        .flat_map(|page| &page.shared_folder_folders)
        .map(|folder| {
            let shared_folder = Uid::from(folder.shared_folder_uid.as_slice());
            let key = shared_folders.get(&shared_folder).and_then(|sf| {
                crypto::decrypt_cbc::<Pkcs7>(&folder.shared_folder_folder_key, &sf.key)
                    .and_then(AesKey::try_from)
                    .ok()
            });
            let uid = Uid::from(folder.folder_uid.as_slice());
            let data = key
                .as_ref()
                .and_then(|key| folder_data(&folder.data, key))
                .unwrap_or(Value::Null);
            let name = folder_name(&data).unwrap_or_else(|| uid.as_ref()).to_owned();
            let parent = if folder.parent_uid.is_empty() {
                Location::Folder(shared_folder.clone())
            } else {
                Location::from(folder.parent_uid.as_slice())
            };
            Folder {
                uid,
                name,
                data,
                kind: FolderKind::SharedFolderFolder { shared_folder },
                parent,
                subfolders: Vec::new(),
                key,
            }
        });
    user_folders
        .chain(shared_roots)
        .chain(shared_subfolders)
        .map(|folder| (folder.uid.clone(), folder))
        .collect()
}

fn file_records(download: &Download, vault: &mut Vault) {
    for folder in download.0.iter().flat_map(|page| &page.user_folder_records) {
        vault.file(Location::from(folder.folder_uid.as_slice()), Uid::from(folder.record_uid.as_slice()));
    }
    for record in download.0.iter().flat_map(|page| &page.shared_folder_folder_records) {
        let folder_uid = if record.folder_uid.is_empty() {
            &record.shared_folder_uid
        } else {
            &record.folder_uid
        };
        vault.file(Location::from(folder_uid.as_slice()), Uid::from(record.record_uid.as_slice()));
    }
}
