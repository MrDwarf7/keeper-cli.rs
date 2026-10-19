use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::AesKey;
use crate::uid::Uid;

/// Where something is filed: the vault root or a folder. The root has no UID, so it gets its
/// own variant instead of a sentinel string.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Location {
    #[default]
    Root,
    Folder(Uid),
}

impl From<Uid> for Location {
    fn from(uid: Uid) -> Self {
        Self::Folder(uid)
    }
}

/// Keeper marks "no folder" with an empty UID or one padded with ten zero bytes.
impl From<&[u8]> for Location {
    fn from(bytes: &[u8]) -> Self {
        if bytes.is_empty() || bytes.starts_with(&[0; 10]) || bytes.ends_with(&[0; 10]) {
            Self::Root
        } else {
            Self::Folder(Uid::from(bytes))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FolderKind {
    /// A private folder of this account.
    User,
    /// The root of a shared folder; its UID is the shared folder's UID.
    SharedFolder,
    /// A subfolder somewhere inside a shared folder.
    SharedFolderFolder { shared_folder: Uid },
}

/// Decrypted folder metadata. Unknown Commander properties are retained on serialization.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FolderData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name:  Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl TryFrom<Value> for FolderData {
    type Error = crate::Error;

    fn try_from(value: Value) -> crate::Result<Self> {
        Ok(serde_json::from_value(value)?)
    }
}

#[derive(Debug)]
pub struct Folder {
    pub uid:        Uid,
    pub name:       String,
    /// Decrypted folder metadata such as its name and color.
    pub data:       FolderData,
    pub kind:       FolderKind,
    pub parent:     Location,
    pub subfolders: Vec<Uid>,
    /// Key for the folder; `None` means the folder is locked.
    pub key:        Option<AesKey>,
}

impl Folder {
    /// The shared folder this folder belongs to, if any.
    pub fn shared_folder(&self) -> Option<&Uid> {
        match &self.kind {
            FolderKind::User => None,
            FolderKind::SharedFolder => Some(&self.uid),
            FolderKind::SharedFolderFolder { shared_folder } => Some(shared_folder),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::FolderData;

    #[test]
    fn metadata_preserves_unknown_properties_and_rejects_malformed_name() {
        let data = FolderData::try_from(json!({"name": "Docs", "color": "blue"})).unwrap();
        assert_eq!(serde_json::to_value(data).unwrap(), json!({"name": "Docs", "color": "blue"}));
        assert!(FolderData::try_from(json!({"name": 7})).is_err());
    }
}
