//! Persistent settings, using Commander's file-storage key names (`user`, `server`,
//! `device_token`, `private_key`, `clone_code`) so a Commander config saved with
//! `config_storage: "file"` can be pointed at directly. Each key can be overridden by a
//! `KEEPER_<KEY>` environment variable; an override is saved like any other value when the client
//! next writes the file (e.g. after login). Keys this client doesn't know are kept and written back.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::prelude::*;

pub const DEFAULT_SERVER: &str = "keepersecurity.com";

/// The platform config directory (e.g. `~/.config/keeper-cli/config.json` on Linux). Not
/// Commander's `~/.keeper/config.json`: Commander may keep protected values in the OS keychain,
/// and this client must not overwrite that file with plaintext ones.
pub fn default_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("keeper-cli")
        .join("config.json")
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Settings {
    #[serde(skip)]
    path:             PathBuf,
    /// The file's other keys, read straight from disk so environment variables never leak in.
    #[serde(skip)]
    other:            Map<String, Value>,
    #[serde(default)]
    pub user:         Option<String>,
    #[serde(default)]
    pub server:       Option<String>,
    #[serde(default)]
    pub device_token: Option<String>,
    /// The device's P-256 private key; Commander's name for it on disk.
    #[serde(default)]
    pub private_key:  Option<String>,
    /// Resumes a "Stay Logged In" session without the master password.
    #[serde(default)]
    pub clone_code:   Option<String>,
}

impl Settings {
    /// A missing file is an empty configuration, as on first run.
    pub fn load(path: PathBuf) -> Result<Self> {
        let mut settings: Self = config::Config::builder()
            .add_source(
                config::File::from(path.as_path())
                    .format(config::FileFormat::Json)
                    .required(false),
            )
            .add_source(config::Environment::with_prefix("KEEPER"))
            .build()?
            .try_deserialize()?;
        settings.other = match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)?,
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => Map::new(),
        };
        settings.path = path;
        Ok(settings)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn server(&self) -> &str {
        self.server.as_deref().unwrap_or(DEFAULT_SERVER)
    }

    /// Writes the file's other keys back untouched; known keys that are now `None` are removed.
    pub fn save(&self) -> Result<()> {
        let mut out = self.other.clone();
        if let Value::Object(known) = serde_json::to_value(self)? {
            for (key, value) in known {
                if value.is_null() {
                    out.remove(&key);
                } else {
                    out.insert(key, value);
                }
            }
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        write_private(&self.path, serde_json::to_string_pretty(&out)?.as_bytes())
    }
}

/// The file holds the device private key and clone code; keep it owner-only.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keeps_unknown_commander_keys_and_drops_cleared_ones() {
        let dir = std::env::temp_dir().join(format!("keeper-cli-settings-{}", std::process::id()));
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, r#"{"user":"a@b.c","clone_code":"x","proxy":"http://p:1","debug":true}"#).unwrap();

        let mut s = Settings::load(path.clone()).unwrap();
        assert_eq!(s.user.as_deref(), Some("a@b.c"));
        assert_eq!(s.server(), DEFAULT_SERVER);
        s.clone_code = None;
        s.device_token = Some("tok".into());
        s.save().unwrap();

        let saved: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["proxy"], "http://p:1");
        assert_eq!(saved["debug"], true);
        assert_eq!(saved["device_token"], "tok");
        assert!(saved.get("clone_code").is_none());
        assert!(Settings::load(dir.join("missing.json")).unwrap().user.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
