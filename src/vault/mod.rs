//! The decrypted vault: everything `vault/sync_down` returns that this account can open.

mod folder;
mod path;
mod record;
mod unlock;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub use self::folder::{Folder, FolderKind, Location};
pub use self::path::{PathAnchor, PathResolution, VaultPath};
pub use self::record::{Record, RecordKind, Secrets};
pub use self::unlock::sync_down;
use crate::crypto::AesKey;
use crate::uid::Uid;

#[derive(Debug, Default)]
pub struct Vault {
    pub records:             BTreeMap<Uid, Record>,
    pub shared_folders:      BTreeMap<Uid, SharedFolder>,
    pub teams:               BTreeMap<Uid, Team>,
    pub folders:             HashMap<Uid, Folder>,
    /// Children of [`Location::Root`]; other folders keep theirs in `Folder::subfolders`.
    pub(crate) root_folders: Vec<Uid>,
    pub(crate) filed:        HashMap<Location, BTreeSet<Uid>>,
}

#[derive(Debug)]
pub struct SharedFolder {
    pub uid:                    Uid,
    pub name:                   String,
    pub key:                    AesKey,
    pub record_uids:            Vec<Uid>,
    pub users:                  Vec<String>,
    pub teams:                  Vec<String>,
    pub default_manage_records: bool,
    pub default_manage_users:   bool,
    pub default_can_edit:       bool,
    pub default_can_share:      bool,
}

#[derive(Debug)]
pub struct Team {
    pub uid:            Uid,
    pub name:           String,
    pub restrict_edit:  bool,
    pub restrict_share: bool,
    pub restrict_view:  bool,
}

impl Vault {
    pub fn folder(&self, at: &Location) -> Option<&Folder> {
        match at {
            Location::Root => None,
            Location::Folder(uid) => self.folders.get(uid),
        }
    }

    pub fn records_in(&self, at: &Location) -> impl Iterator<Item = &Record> {
        self.filed
            .get(at)
            .into_iter()
            .flatten()
            .filter_map(|uid| self.records.get(uid))
    }

    pub fn subfolders_of(&self, at: &Location) -> &[Uid] {
        match at {
            Location::Root => &self.root_folders,
            Location::Folder(_) => self.folder(at).map_or(&[], |f| &f.subfolders),
        }
    }

    /// `/`-joined folder names from the root, with `/` inside names escaped as `//`.
    pub fn path_of(&self, at: &Location) -> String {
        let mut components = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = self.folder(at);
        while let Some(folder) = cursor {
            if !seen.insert(folder.uid.clone()) {
                break;
            }
            components.push(folder.name.clone());
            cursor = self.folder(&folder.parent);
        }
        components.reverse();
        VaultPath {
            anchor: PathAnchor::Root,
            components,
            trailing_separator: false,
        }
        .to_string()
    }

    fn resolve_part(&self, at: &Location, part: &str) -> Option<Location> {
        match part {
            "." => Some(at.clone()),
            ".." => {
                Some(match self.folder(at) {
                    Some(folder) => folder.parent.clone(),
                    None => Location::Root,
                })
            }
            name => {
                let children = self.subfolders_of(at);
                let child = children
                    .iter()
                    .find(|uid| self.folders.get(*uid).is_some_and(|folder| folder.name == name))
                    .or_else(|| {
                        children.iter().find(|uid| {
                            self.folders
                                .get(*uid)
                                .is_some_and(|folder| folder.name.eq_ignore_ascii_case(name))
                        })
                    })?;
                Some(Location::Folder((*child).clone()))
            }
        }
    }

    fn resolve_parsed_path(&self, cwd: &Location, mut path: VaultPath) -> PathResolution {
        let mut at = match path.anchor {
            PathAnchor::Root => Location::Root,
            PathAnchor::Current => cwd.clone(),
        };
        for index in 0..path.components.len() {
            let Some(next) = self.resolve_part(&at, &path.components[index]) else {
                path.components.drain(..index);
                path.anchor = PathAnchor::Current;
                path.trailing_separator = false;
                return PathResolution::Partial {
                    parent: at,
                    tail:   path,
                };
            };
            at = next;
        }
        PathResolution::Full(at)
    }

    /// Resolves an absolute or relative Commander path. `//` is a slash in a folder name.
    pub fn resolve_path(&self, cwd: &Location, path: &str) -> PathResolution {
        let uid = path.trim_end_matches('=');
        if let Some((uid, _)) = self.folders.get_key_value(uid) {
            return PathResolution::Full(Location::Folder(uid.clone()));
        }
        self.resolve_parsed_path(cwd, path.into())
    }

    pub fn resolve_record<'a>(&'a self, cwd: &Location, spec: &str) -> Option<&'a Record> {
        if let Some(record) = self.records.get(spec.trim_end_matches('=')) {
            return Some(record);
        }
        let mut path = VaultPath::from(spec);
        let title = path.components.pop()?;
        let folder = match self.resolve_parsed_path(cwd, path) {
            PathResolution::Full(folder) => folder,
            PathResolution::Partial { .. } => return None,
        };
        self.records_in(&folder)
            .find(|record| record.title() == title)
            .or_else(|| {
                self.records_in(&folder)
                    .find(|record| record.title().eq_ignore_ascii_case(&title))
            })
    }

    /// Every location a record is filed under.
    pub fn locations_of<'a>(&'a self, record: &'a Uid) -> impl Iterator<Item = &'a Location> {
        self.filed
            .iter()
            .filter(move |(_, uids)| uids.contains(record))
            .map(|(at, _)| at)
    }
}

impl Vault {
    /// Builds sorted folder links and breaks cycles at their lowest UID.
    fn link_tree(&mut self) {
        let known: HashSet<Uid> = self.folders.keys().cloned().collect();
        for folder in self.folders.values_mut() {
            folder.subfolders.clear();
            if matches!(&folder.parent, Location::Folder(parent) if !known.contains(parent)) {
                folder.parent = Location::Root;
            }
        }

        let mut done = HashSet::new();
        for start in self.folders.keys().cloned().collect::<Vec<_>>() {
            let mut path = Vec::new();
            let mut positions = HashMap::new();
            let mut cursor = start;
            loop {
                if done.contains(&cursor) {
                    break;
                }
                if let Some(&cycle_start) = positions.get(&cursor) {
                    if let Some(root) = path[cycle_start..].iter().min()
                        && let Some(folder) = self.folders.get_mut(root)
                    {
                        folder.parent = Location::Root;
                    }
                    break;
                }
                positions.insert(cursor.clone(), path.len());
                path.push(cursor.clone());
                match self.folders.get(&cursor).map(|folder| folder.parent.clone()) {
                    Some(Location::Folder(parent)) => cursor = parent,
                    _ => break,
                }
            }
            done.extend(path);
        }

        let mut children: HashMap<Uid, Vec<Uid>> = HashMap::new();
        let mut roots = Vec::new();
        for folder in self.folders.values() {
            match &folder.parent {
                Location::Folder(parent) => children.entry(parent.clone()).or_default().push(folder.uid.clone()),
                Location::Root => roots.push(folder.uid.clone()),
            }
        }
        let names: HashMap<Uid, String> = self
            .folders
            .values()
            .map(|folder| (folder.uid.clone(), folder.name.to_lowercase()))
            .collect();
        roots.sort_by(|a, b| names.get(a).cmp(&names.get(b)));
        for (parent, mut kids) in children {
            kids.sort_by(|a, b| names.get(a).cmp(&names.get(b)));
            if let Some(folder) = self.folders.get_mut(&parent) {
                folder.subfolders = kids;
            }
        }
        self.root_folders = roots;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use aes::cipher::block_padding::Pkcs7;
    use serde_json::Value;

    use super::unlock::{Download, KeyRing, Unlock};
    use super::*;
    use crate::crypto;
    use crate::proto::records::RecordKeyType;
    use crate::proto::vault::{
        Record as PbRecord,
        RecordLink,
        RecordMetaData,
        SharedFolder as PbSharedFolder,
        SharedFolderFolder,
        SharedFolderFolderRecord,
        SharedFolderRecord,
        SyncDownResponse,
        UserFolder,
        UserFolderRecord,
        UserFolderSharedFolder,
    };

    /// A hand-built vault for command tests: `/Work/Infra` holding "DB Admin", plus `/Work/a//b`.
    pub(crate) fn sample() -> Vault {
        let uid = |s: &str| s.parse::<Uid>().unwrap();
        let folder = |id: &str, name: &str, parent: Location, kids: &[&str]| {
            (
                uid(id),
                Folder {
                    uid: uid(id),
                    name: name.into(),
                    data: serde_json::json!({"name": name}),
                    kind: FolderKind::User,
                    parent,
                    subfolders: kids.iter().map(|k| uid(k)).collect(),
                    key: Some(AesKey::random()),
                },
            )
        };
        let work = Location::Folder(uid("AAAA"));
        let mut vault = Vault {
            folders: HashMap::from([
                folder("AAAA", "Work", Location::Root, &["BBBB", "CCCC"]),
                folder("BBBB", "Infra", work.clone(), &[]),
                folder("CCCC", "a/b", work, &[]),
            ]),
            root_folders: vec![uid("AAAA")],
            ..Vault::default()
        };
        vault.records.insert(
            uid("RRRR"),
            Record {
                uid:                  uid("RRRR"),
                kind:                 RecordKind::Typed,
                data:                 serde_json::json!({"title": "DB Admin", "type": "login"}),
                revision:             1,
                shared:               false,
                client_modified_time: 0,
                key:                  AesKey::random(),
                owner:                true,
                udata:                None,
            },
        );
        vault
            .filed
            .entry(Location::Folder(uid("BBBB")))
            .or_default()
            .insert(uid("RRRR"));
        vault
    }

    fn v3_record(uid: &[u8], key: &[u8], data: Value) -> PbRecord {
        PbRecord {
            record_uid: uid.to_vec(),
            version: 3,
            data: crypto::encrypt_aes_v2(data.to_string().as_bytes(), key).unwrap(),
            ..Default::default()
        }
    }

    fn open_vault(download: Download, ring: &KeyRing) -> crate::Result<Vault> {
        Unlock::from(download)
            .open_teams(ring)?
            .open_shared_folders(ring)?
            .key_records(ring)?
            .into_vault(ring)
    }

    fn context_cause(error: crate::Error, uid: &[u8], stage: &str) -> crate::Error {
        let crate::Error::Context { context, source } = error else {
            panic!("expected contextual vault error");
        };
        assert!(context.contains(stage), "{context}");
        assert!(context.contains(&Uid::from(uid).to_string()), "{context}");
        *source
    }

    /// One page exercising every key path: data-key records, a shared folder with a GCM-wrapped
    /// record, a linked child record, and a three-level folder tree.
    #[test]
    fn sync_page_decrypts_every_key_path_and_builds_tree() {
        let data_key = AesKey::random();
        let ring = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let [k_own, k_sf, k_shared, k_child, k_uf, k_sff] = std::array::from_fn(|_| AesKey::random());
        let (r_own, r_shared, r_child) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let (f_user, f_sf, f_sub) = ([4u8; 16], [5u8; 16], [6u8; 16]);

        let page = SyncDownResponse {
            record_meta_data: vec![RecordMetaData {
                record_uid: r_own.to_vec(),
                record_key: crypto::encrypt_cbc::<Pkcs7>(&k_own, &data_key).unwrap(),
                record_key_type: RecordKeyType::EncryptedByDataKey as i32,
                owner: true,
                ..Default::default()
            }],
            shared_folders: vec![PbSharedFolder {
                shared_folder_uid: f_sf.to_vec(),
                shared_folder_key: crypto::encrypt_aes_v2(&k_sf, &data_key).unwrap(),
                key_type: RecordKeyType::EncryptedByDataKeyGcm as i32,
                name: crypto::encrypt_cbc::<Pkcs7>(b"Encrypted Name", &k_sf).unwrap(),
                data: crypto::encrypt_cbc::<Pkcs7>(br#"{"name":"Data name","color":"blue"}"#, &k_sf).unwrap(),
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
                    serde_json::json!({"title": "Mine", "type": "login", "fields": [{"type": "login", "value": ["me"]}]}),
                ),
                v3_record(&r_shared, &k_shared, serde_json::json!({"title": "Shared", "type": "login"})),
                v3_record(&r_child, &k_child, serde_json::json!({"title": "Child", "type": "file"})),
                v3_record(&[9u8; 16], &AesKey::random(), serde_json::json!({"title": "Unreachable"})),
            ],
            user_folders: vec![UserFolder {
                folder_uid: f_user.to_vec(),
                user_folder_key: crypto::encrypt_cbc::<Pkcs7>(&k_uf, &data_key).unwrap(),
                key_type: RecordKeyType::EncryptedByDataKey as i32,
                data: crypto::encrypt_cbc::<Pkcs7>(br#"{"name":"Work"}"#, &k_uf).unwrap(),
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
                shared_folder_folder_key: crypto::encrypt_cbc::<Pkcs7>(&k_sff, &k_sf).unwrap(),
                data: crypto::encrypt_cbc::<Pkcs7>(br#"{"name":"Deep"}"#, &k_sff).unwrap(),
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

        let vault = open_vault(Download(vec![page]), &ring).unwrap();
        let titles: Vec<&str> = vault.records.values().map(Record::title).collect();
        assert_eq!(titles.len(), 3, "unreachable record must be dropped: {titles:?}");
        assert!(titles.contains(&"Mine") && titles.contains(&"Shared") && titles.contains(&"Child"));
        let own = &vault.records[&Uid::from(&r_own[..])];
        assert_eq!(own.login(), Some("me"));
        assert!(own.owner);

        let deep = Location::Folder(Uid::from(&f_sub[..]));
        assert_eq!(vault.subfolders_of(&Location::Root), [Uid::from(&f_user[..])]);
        assert_eq!(vault.path_of(&deep), "/Work/Data name/Deep");
        let shared_root = Location::Folder(Uid::from(&f_sf[..]));
        assert_eq!(
            vault
                .folder(&shared_root)
                .map_or("My Vault", |folder| folder.name.as_str()),
            "Data name"
        );
        assert_eq!(
            vault
                .folder(&shared_root)
                .unwrap()
                .data
                .get("color")
                .and_then(Value::as_str),
            Some("blue")
        );
        assert_eq!(vault.folder(&deep).unwrap().shared_folder(), Some(&Uid::from(&f_sf[..])));
        assert_eq!(vault.records_in(&deep).map(Record::title).collect::<Vec<_>>(), ["Shared"]);
        assert_eq!(vault.records_in(&Location::Root).map(Record::title).collect::<Vec<_>>(), ["Mine"]);
    }

    fn fixed_key(byte: u8) -> AesKey {
        AesKey::try_from(vec![byte; 32]).unwrap()
    }

    #[test]
    fn tampered_known_key_gcm_record_fails_with_uid_context() {
        let data_key = fixed_key(1);
        let record_key = fixed_key(2);
        let ring = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let record_uid = [17; 16];
        let mut record = v3_record(&record_uid, &record_key, serde_json::json!({"title": "tampered"}));
        *record.data.last_mut().unwrap() ^= 1;
        let page = SyncDownResponse {
            record_meta_data: vec![RecordMetaData {
                record_uid: record_uid.to_vec(),
                record_key: crypto::encrypt_cbc::<Pkcs7>(&record_key, &data_key).unwrap(),
                record_key_type: RecordKeyType::EncryptedByDataKey as i32,
                ..Default::default()
            }],
            records: vec![record],
            ..Default::default()
        };

        let error = open_vault(Download(vec![page]), &ring).unwrap_err();
        assert!(matches!(context_cause(error, &record_uid, "decrypting record data"), crate::Error::Crypto(_)));
    }

    #[test]
    fn valid_ciphertext_with_malformed_record_json_fails_with_uid_context() {
        let data_key = fixed_key(3);
        let record_key = fixed_key(4);
        let ring = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let record_uid = [18; 16];
        let page = SyncDownResponse {
            record_meta_data: vec![RecordMetaData {
                record_uid: record_uid.to_vec(),
                record_key: crypto::encrypt_cbc::<Pkcs7>(&record_key, &data_key).unwrap(),
                record_key_type: RecordKeyType::EncryptedByDataKey as i32,
                ..Default::default()
            }],
            records: vec![PbRecord {
                record_uid: record_uid.to_vec(),
                version: 3,
                data: crypto::encrypt_aes_v2(b"{", &record_key).unwrap(),
                ..Default::default()
            }],
            ..Default::default()
        };

        let error = open_vault(Download(vec![page]), &ring).unwrap_err();
        assert!(matches!(context_cause(error, &record_uid, "parsing record data"), crate::Error::Json(_)));
    }

    #[test]
    fn corrupt_known_key_folder_metadata_fails_with_uid_context() {
        let data_key = fixed_key(5);
        let folder_key = fixed_key(6);
        let ring = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let folder_uid = [19; 16];
        let mut folder_data = crypto::encrypt_cbc::<Pkcs7>(b"folder metadata", &folder_key).unwrap();
        folder_data.truncate(16);
        let page = SyncDownResponse {
            user_folders: vec![UserFolder {
                folder_uid: folder_uid.to_vec(),
                user_folder_key: crypto::encrypt_cbc::<Pkcs7>(&folder_key, &data_key).unwrap(),
                key_type: RecordKeyType::EncryptedByDataKey as i32,
                data: folder_data,
                ..Default::default()
            }],
            ..Default::default()
        };

        let error = open_vault(Download(vec![page]), &ring).unwrap_err();
        assert!(matches!(context_cause(error, &folder_uid, "opening user folder metadata"), crate::Error::Crypto(_)));
    }
    #[test]
    fn virtual_paths_resolve_escaped_names_and_unresolved_tails() {
        let mut vault = sample();
        let slash_uid = "DDDD".parse::<Uid>().unwrap();
        vault.folders.insert(
            slash_uid.clone(),
            Folder {
                uid:        slash_uid.clone(),
                name:       "/leading".into(),
                data:       serde_json::json!({"name": "/leading"}),
                kind:       FolderKind::User,
                parent:     Location::Root,
                subfolders: Vec::new(),
                key:        Some(AesKey::random()),
            },
        );
        let padded_uid = Uid::from(&[9u8; 16][..]);
        vault.folders.insert(
            padded_uid.clone(),
            Folder {
                uid:        padded_uid.clone(),
                name:       "padded UID".into(),
                data:       serde_json::json!({"name": "padded UID"}),
                kind:       FolderKind::User,
                parent:     Location::Root,
                subfolders: Vec::new(),
                key:        Some(AesKey::random()),
            },
        );
        vault.link_tree();
        let root = Location::Root;
        let escaped = Location::try_from(vault.resolve_path(&root, "/Work/a//b")).unwrap();
        assert_eq!(vault.path_of(&escaped), "/Work/a//b");
        let slash_path = vault.path_of(&Location::Folder(slash_uid.clone()));
        assert_eq!(slash_path, "///leading");
        assert_eq!(Location::try_from(vault.resolve_path(&root, &slash_path)), Ok(Location::Folder(slash_uid)));
        assert_eq!(
            Location::try_from(vault.resolve_path(&root, "BBBB")),
            Ok(Location::Folder("BBBB".parse().unwrap()))
        );
        let padded_path = format!("{padded_uid}==");
        assert_eq!(Location::try_from(vault.resolve_path(&root, &padded_path)), Ok(Location::Folder(padded_uid)));
        assert_eq!(Location::try_from(vault.resolve_path(&root, "/")), Ok(Location::Root));
        assert_eq!(
            Location::try_from(vault.resolve_path(&Location::Folder("AAAA".parse().unwrap()), "")),
            Ok(Location::Folder("AAAA".parse().unwrap()))
        );

        let partial = vault.resolve_path(&root, "/Work/Infra/missing/a//b");
        let PathResolution::Partial { parent, tail } = &partial else {
            panic!("expected a partial path resolution");
        };
        assert_eq!(parent, &Location::Folder("BBBB".parse().unwrap()));
        assert_eq!(tail.to_string(), "missing/a//b");
        assert_eq!(tail.components, ["missing".to_owned(), "a/b".to_owned()]);
        assert_eq!(Location::try_from(partial), Err(VaultPath::from("missing/a//b")));
        assert_eq!(
            Location::try_from(vault.resolve_path(&Location::Folder("AAAA".parse().unwrap()), "../work/infra")),
            Ok(Location::Folder("BBBB".parse().unwrap()))
        );
        assert_eq!(vault.resolve_record(&root, "/Work/Infra/DB Admin").unwrap().title(), "DB Admin");
        assert_eq!(vault.resolve_record(&root, "/Work/Infra/DB Admin/").unwrap().title(), "DB Admin");
    }

    #[test]
    fn parent_cycles_are_broken_and_paths_terminate() {
        let mut vault = sample();
        let work = "AAAA".parse::<Uid>().unwrap();
        let infra = "BBBB".parse::<Uid>().unwrap();
        vault.folders.get_mut(&work).unwrap().parent = Location::Folder(infra.clone());
        vault.folders.get_mut(&infra).unwrap().parent = Location::Folder(work.clone());
        vault.link_tree();
        let expected_root = if work < infra { work } else { infra };
        assert_eq!(vault.root_folders.as_slice(), std::slice::from_ref(&expected_root));
        assert!(vault.path_of(&Location::Folder(expected_root)).starts_with('/'));
    }

    #[test]
    fn unknown_folder_key_types_use_data_key_and_locked_nodes_survive() {
        let data_key = AesKey::random();
        let user_key = AesKey::random();
        let shared_key = AesKey::random();
        let (user_uid, shared_uid, locked_uid, locked_sub_uid, inaccessible_shared_uid, record_uid) =
            ([1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16], [5u8; 16], [6u8; 16]);
        let ring = KeyRing {
            data_key: &data_key,
            rsa:      None,
            ecc:      None,
        };
        let page = SyncDownResponse {
            record_meta_data: vec![RecordMetaData {
                record_uid: record_uid.to_vec(),
                record_key: crypto::encrypt_cbc::<Pkcs7>(&user_key, &data_key).unwrap(),
                record_key_type: 999,
                ..Default::default()
            }],
            records: vec![v3_record(
                &record_uid,
                &user_key,
                serde_json::json!({"title": "locked record"}),
            )],
            shared_folders: vec![PbSharedFolder {
                shared_folder_uid: shared_uid.to_vec(),
                shared_folder_key: crypto::encrypt_cbc::<Pkcs7>(&shared_key, &data_key).unwrap(),
                key_type: 999,
                name: crypto::encrypt_cbc::<Pkcs7>(b"Encrypted name", &shared_key).unwrap(),
                data: crypto::encrypt_cbc::<Pkcs7>(br#"{"name":"Shared data name","color":"purple"}"#, &shared_key)
                    .unwrap(),
                ..Default::default()
            }],
            user_folders: vec![
                UserFolder {
                    folder_uid: user_uid.to_vec(),
                    user_folder_key: crypto::encrypt_cbc::<Pkcs7>(&user_key, &data_key).unwrap(),
                    key_type: 999,
                    data: crypto::encrypt_cbc::<Pkcs7>(br#"{"name":"Fallback user"}"#, &user_key).unwrap(),
                    ..Default::default()
                },
                UserFolder {
                    folder_uid: locked_uid.to_vec(),
                    parent_uid: user_uid.to_vec(),
                    user_folder_key: vec![1, 2, 3],
                    key_type: RecordKeyType::EncryptedByPublicKey as i32,
                    ..Default::default()
                },
            ],
            user_folder_shared_folders: vec![UserFolderSharedFolder {
                folder_uid: user_uid.to_vec(),
                shared_folder_uid: shared_uid.to_vec(),
                ..Default::default()
            }],
            shared_folder_folders: vec![SharedFolderFolder {
                shared_folder_uid: inaccessible_shared_uid.to_vec(),
                folder_uid: locked_sub_uid.to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let vault = open_vault(Download(vec![page]), &ring).unwrap();
        let user = vault.folder(&Location::Folder(Uid::from(&user_uid[..]))).unwrap();
        assert_eq!(user.name, "Fallback user");
        assert!(user.key.is_some());
        let locked = vault.folder(&Location::Folder(Uid::from(&locked_uid[..]))).unwrap();
        assert_eq!(locked.name, Uid::from(&locked_uid[..]).to_string());
        assert!(locked.key.is_none());
        let shared = vault.folder(&Location::Folder(Uid::from(&shared_uid[..]))).unwrap();
        assert_eq!(shared.name, "Shared data name");
        assert_eq!(shared.data.get("color").and_then(Value::as_str), Some("purple"));
        assert!(shared.key.is_some());
        let locked_subfolder = vault.folder(&Location::Folder(Uid::from(&locked_sub_uid[..]))).unwrap();
        assert_eq!(locked_subfolder.name, Uid::from(&locked_sub_uid[..]).to_string());
        assert!(locked_subfolder.key.is_none());
        assert!(vault.records.is_empty(), "unknown record key types must not use folder-key fallback");
    }
}
