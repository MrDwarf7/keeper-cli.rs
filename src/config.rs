//! JSON config using Commander's file-storage key names (`user`, `server`, `device_token`,
//! `private_key`, `clone_code`), so a Commander config saved with `config_storage: "file"`
//! can be pointed at directly. Unknown keys are preserved on save.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::prelude::*;

pub const DEFAULT_SERVER: &str = "keepersecurity.com";

pub struct Config {
    path:   PathBuf,
    values: Map<String, Value>,
}

impl Config {
    /// `--config`, then `KEEPER_CONFIG_FILE`, then `~/.keeper/keeper-cli.json`. The default is
    /// deliberately not Commander's `config.json`: Commander may keep protected values in the OS
    /// keychain, and this client must not overwrite that file with plaintext ones.
    pub fn resolve_path(explicit: Option<&Path>) -> PathBuf {
        if let Some(p) = explicit {
            return p.to_path_buf();
        }
        if let Some(p) = std::env::var_os("KEEPER_CONFIG_FILE") {
            return PathBuf::from(p);
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".keeper")
            .join("keeper-cli.json")
    }

    pub fn load(path: PathBuf) -> Result<Self> {
        let values = match std::fs::read_to_string(&path) {
            Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)?,
            Ok(_) => Map::new(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Map::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, values })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
    }

    pub fn set(&mut self, key: &str, value: Option<String>) {
        match value {
            Some(v) => self.values.insert(key.to_owned(), Value::String(v)),
            None => self.values.remove(key),
        };
    }

    pub fn server(&self) -> &str {
        self.get("server").unwrap_or(DEFAULT_SERVER)
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(&self.values)?;
        write_private(&self.path, text.as_bytes())
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
