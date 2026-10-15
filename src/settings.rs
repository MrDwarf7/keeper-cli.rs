//! Persistent Commander-compatible settings with environment overrides.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::prelude::*;

pub const DEFAULT_SERVER: &str = "keepersecurity.com";

pub fn default_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("keeper-cli")
        .join("config.json")
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Settings {
    #[serde(skip)]
    pub path:             PathBuf,
    #[serde(skip)]
    other:                serde_json::Map<String, serde_json::Value>,
    #[serde(skip)]
    pub(crate) file_user: Option<String>,
    #[serde(default)]
    pub user:             Option<String>,
    #[serde(default)]
    pub server:           Option<String>,
    #[serde(default)]
    pub device_token:     Option<String>,
    #[serde(default)]
    pub private_key:      Option<String>,
    #[serde(default)]
    pub clone_code:       Option<String>,
}

impl Settings {
    /// Read only the requested path, then layer `KEEPER_*` values over it.
    pub fn load(path: PathBuf) -> Result<Self> {
        reject_symlink(&path)?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let file_values = if text.trim().is_empty() {
            serde_json::Map::new()
        } else {
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&text)?
        };

        let mut builder = config::Config::builder();
        if !text.trim().is_empty() {
            builder = builder.add_source(config::File::from_str(&text, config::FileFormat::Json));
        }
        let merged = builder
            .add_source(config::Environment::with_prefix("KEEPER").ignore_empty(true))
            .build()?;
        let values: serde_json::Map<String, serde_json::Value> = merged.try_deserialize()?;
        validate_file_storage(&values)?;
        let mut settings: Self = serde_json::from_value(serde_json::Value::Object(values))?;
        settings.user = settings.user.as_deref().and_then(nonempty);
        settings.server = settings.server.as_deref().and_then(nonempty);
        settings.device_token = settings.device_token.as_deref().and_then(nonempty);
        settings.private_key = settings.private_key.as_deref().and_then(nonempty);
        settings.clone_code = settings.clone_code.as_deref().and_then(nonempty);
        settings.file_user = file_values
            .get("user")
            .and_then(serde_json::Value::as_str)
            .and_then(nonempty);
        settings.other = file_values;
        settings.path = path;
        Ok(settings)
    }

    /// Update the file atomically; stored credentials never follow a symlink or persist passwords.
    pub fn save(&self) -> Result<()> {
        reject_symlink(&self.path)?;
        let mut out = self.other.clone();
        if let serde_json::Value::Object(known) = serde_json::to_value(self)? {
            for (key, value) in known {
                if value.is_null() {
                    out.remove(&key);
                } else {
                    out.insert(key, value);
                }
            }
        }
        out.remove("password");
        out.remove("master_password");
        if let Some(dir) = self.path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        write_private(&self.path, serde_json::to_string_pretty(&out)?.as_bytes())
    }
}

fn nonempty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn validate_file_storage(values: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    match values.get("config_storage") {
        None | Some(serde_json::Value::Null) => Ok(()),
        Some(serde_json::Value::String(storage)) if storage.eq_ignore_ascii_case("file") => Ok(()),
        _ => {
            Err(Error::Generic(
                "config_storage must be 'file'; refusing to write device credentials to a protected backend config"
                    .into(),
            ))
        }
    }
}

fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(Error::Generic(format!("refusing to read or replace symlink config path {}", path.display())))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let (temp, mut file) = loop {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".keeper-cli-{}-{id}.tmp", std::process::id()));
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        reject_symlink(path)?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keeps_unknown_keys_but_not_passwords_or_cleared_values() {
        let dir = std::env::temp_dir().join(format!("keeper-cli-settings-{}", std::process::id()));
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            r#"{"user":"a@b.c","clone_code":"x","proxy":"http://p:1","debug":true,"password":"secret"}"#,
        )
        .unwrap();

        let mut settings = Settings::load(path.clone()).unwrap();
        assert_eq!(settings.user.as_deref(), Some("a@b.c"));
        assert!(settings.server.is_none());
        settings.clone_code = None;
        settings.device_token = Some("tok".into());
        settings.save().unwrap();

        let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["proxy"], "http://p:1");
        assert_eq!(saved["debug"], true);
        assert_eq!(saved["device_token"], "tok");
        assert!(saved.get("clone_code").is_none());
        assert!(saved.get("password").is_none());
        assert!(Settings::load(dir.join("missing.json")).unwrap().user.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn blank_and_missing_files_are_empty_without_extension_probing() {
        let dir = std::env::temp_dir().join(format!("keeper-cli-settings-empty-{}", std::process::id()));
        let path = dir.join("config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, " \n\t").unwrap();
        std::fs::write(dir.join("config.json"), r#"{"user":"other@example.com"}"#).unwrap();
        assert!(Settings::load(path).unwrap().user.is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_config_paths_are_not_read_or_replaced() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = std::env::temp_dir().join(format!("keeper-cli-settings-link-{}", std::process::id()));
        let target = dir.join("real.json");
        let link = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&target, r#"{"user":"safe@example.com"}"#).unwrap();
        symlink(&target, &link).unwrap();
        assert!(Settings::load(link.clone()).is_err());
        let mut settings = Settings::load(target.clone()).unwrap();
        settings.path = link;
        assert!(settings.save().is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), r#"{"user":"safe@example.com"}"#);
        settings.path = target.clone();
        settings.save().unwrap();
        assert_eq!(std::fs::metadata(target).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
