//! The decrypted vault: everything `vault/sync_down` returns that this account can open.

mod folder;
mod record;
mod unlock;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub use self::folder::{Folder, FolderKind, Location};
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

    pub fn name_of(&self, at: &Location) -> &str {
        self.folder(at).map_or("My Vault", |f| &f.name)
    }

    pub fn parent_of(&self, at: &Location) -> Location {
        self.folder(at).map(|f| f.parent.clone()).unwrap_or_default()
    }

    /// `/`-joined folder names from the root, with `/` inside names escaped as `//`.
    pub fn path_of(&self, at: &Location) -> String {
        let mut names = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = self.folder(at);
        while let Some(folder) = cursor {
            if !seen.insert(folder.uid.clone()) {
                break;
            }
            names.push(folder.name.replace('/', "//"));
            cursor = self.folder(&folder.parent);
        }
        names.reverse();
        format!("/{}", names.join("/"))
    }

    /// Every location a record is filed under.
    pub fn locations_of<'a>(&'a self, record: &'a Uid) -> impl Iterator<Item = &'a Location> {
        self.filed
            .iter()
            .filter(move |(_, uids)| uids.contains(record))
            .map(|(at, _)| at)
    }

    fn file(&mut self, at: Location, record: Uid) {
        self.filed.entry(at).or_default().insert(record);
    }
}

impl Vault {
    fn resolve_part(&self, at: &Location, part: &str) -> Option<Location> {
        match part {
            "." => Some(at.clone()),
            ".." => Some(self.parent_of(at)),
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

    fn resolve_parts(&self, mut at: Location, parts: &[String]) -> Option<Location> {
        for part in parts {
            at = self.resolve_part(&at, part)?;
        }
        Some(at)
    }

    /// Resolves an absolute or relative Commander path. `//` is a slash in a folder name.
    pub fn resolve_folder(&self, cwd: &Location, path: &str) -> Option<Location> {
        let (folder, tail) = self.resolve_path_tail(cwd, path);
        tail.is_empty().then_some(folder)
    }

    /// Resolves the deepest existing folder and returns the remaining escaped path.
    pub fn resolve_path_tail(&self, cwd: &Location, path: &str) -> (Location, String) {
        if let Ok(uid) = path.parse::<Uid>()
            && self.folders.contains_key(&uid)
        {
            return (Location::Folder(uid), String::new());
        }
        let (absolute, parts) = split_path(path);
        let mut at = if absolute { Location::Root } else { cwd.clone() };
        for (index, part) in parts.iter().enumerate() {
            let Some(next) = self.resolve_part(&at, part) else {
                return (at, encode_path_parts(&parts[index..]));
            };
            at = next;
        }
        (at, String::new())
    }

    pub fn resolve_record<'a>(&'a self, cwd: &Location, spec: &str) -> Option<&'a Record> {
        if let Ok(uid) = spec.parse::<Uid>()
            && let Some(record) = self.records.get(&uid)
        {
            return Some(record);
        }
        let (absolute, mut parts) = split_path(spec);
        let title = parts.pop()?;
        let folder = if parts.is_empty() && !absolute {
            cwd.clone()
        } else {
            self.resolve_parts(if absolute { Location::Root } else { cwd.clone() }, &parts)?
        };
        self.records_in(&folder)
            .find(|record| record.title() == title)
            .or_else(|| {
                self.records_in(&folder)
                    .find(|record| record.title().eq_ignore_ascii_case(&title))
            })
    }

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

/// Split Commander paths, where `//` escapes a literal slash in one component.
fn split_path(path: &str) -> (bool, Vec<String>) {
    let leading_slashes = path.chars().take_while(|ch| *ch == '/').count();
    let absolute = leading_slashes % 2 == 1;
    let path = if absolute { &path[1..] } else { path };
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '/' {
            part.push(ch);
        } else if chars.peek() == Some(&'/') {
            chars.next();
            part.push('/');
        } else if !part.is_empty() {
            parts.push(std::mem::take(&mut part));
        }
    }
    if !part.is_empty() {
        parts.push(part);
    }
    (absolute, parts)
}

fn encode_path_parts(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| part.replace('/', "//"))
        .collect::<Vec<_>>()
        .join("/")
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
        vault.file(Location::Folder(uid("BBBB")), uid("RRRR"));
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

        let vault = Unlock::from(Download(vec![page]))
            .open_teams(&ring)
            .open_shared_folders(&ring)
            .key_records(&ring)
            .into_vault(&ring);
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
        assert_eq!(vault.name_of(&shared_root), "Data name");
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
    #[test]
    fn escaped_paths_and_deepest_tail_resolve() {
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
        vault.link_tree();
        let cwd = Location::Root;
        let escaped = vault.resolve_folder(&cwd, "/Work/a//b").unwrap();
        assert_eq!(vault.path_of(&escaped), "/Work/a//b");
        let slash_path = vault.path_of(&Location::Folder(slash_uid.clone()));
        assert_eq!(slash_path, "///leading");
        assert_eq!(vault.resolve_folder(&cwd, &slash_path), Some(Location::Folder(slash_uid)));
        let (folder, tail) = vault.resolve_path_tail(&cwd, "/Work/Infra/missing/a//b");
        assert_eq!(folder, Location::Folder("BBBB".parse().unwrap()));
        assert_eq!(tail, "missing/a//b");
        assert!(vault.resolve_folder(&cwd, "/Work/Infra/missing/a//b").is_none());
        assert_eq!(vault.resolve_record(&cwd, "/Work/Infra/DB Admin").unwrap().title(), "DB Admin");
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
                    key_type: 999,
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
        let vault = Unlock::from(Download(vec![page]))
            .open_teams(&ring)
            .open_shared_folders(&ring)
            .key_records(&ring)
            .into_vault(&ring);
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
