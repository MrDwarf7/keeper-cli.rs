use clap::{Args, Subcommand, ValueEnum};
use prost::Message;

use super::{App, Detail, DetailLine, Run};
use crate::auth::Registration;
use crate::prelude::*;
use crate::proto::account_summary::{AccountSummaryElements, AccountSummaryRequest};
use crate::proto::authentication::UserSettingRequest;

#[derive(Args, Debug)]
pub struct Login {
    pub email: Option<String>,
}

impl Run for Login {
    fn run(self, app: &mut App) -> Result<()> {
        let user = match self.email {
            Some(user) => user,
            None => app.default_user()?,
        };
        if user.is_empty() {
            return Err(Error::Cancelled);
        }
        app.login(user)
    }
}

#[derive(Args, Debug)]
pub struct Logout;

impl Run for Logout {
    fn run(self, app: &mut App) -> Result<()> {
        if let Some(mut session) = app.session.take()
            && let Err(error) = session.rest.execute("vault/logout_v3", &session.session_token, &())
        {
            eprintln!("Server logout failed: {error}");
        }
        app.vault = None;
        app.cwd = Default::default();
        app.settings.clone_code = None;
        app.settings.save()?;
        eprintln!("Logged out; persistent login on this device has been cleared.");
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Whoami {
    #[arg(short, long)]
    verbose: bool,
}

impl Run for Whoami {
    fn run(self, app: &mut App) -> Result<()> {
        app.ensure_synced()?;
        let detail = Detail::from(self.verbose);
        let session = app.session.as_ref().ok_or(Error::NotLoggedIn)?;
        let host = session.rest.host.to_string();
        let center = match host.as_str() {
            h if h.contains("govcloud") => "US GOV",
            h if h.ends_with(".eu") => "EU",
            h if h.ends_with(".com.au") => "AU",
            h if h.ends_with(".ca") => "CA",
            h if h.ends_with(".jp") => "JP",
            _ => "US",
        };
        print!(
            "{}{}{}",
            DetailLine("User", &session.user),
            DetailLine("Server", &host),
            DetailLine("Data Center", center)
        );
        if let Some(license) = &session.summary.license {
            let account_type = match license.account_type {
                2 => "Enterprise",
                1 => "Family Plan",
                _ => &license.product_type_name,
            };
            print!(
                "{}{}{}",
                DetailLine("Account Type", account_type),
                DetailLine("Renewal Date", &license.expiration_date),
                DetailLine("BreachWatch", &license.breach_watch_enabled.to_string())
            );
            if license.bytes_total > 0 {
                print!(
                    "{}{}{}",
                    DetailLine("Storage Capacity", &format!("{}GB", license.bytes_total >> 30)),
                    DetailLine("Storage Usage", &format!("{}%", license.bytes_used * 100 / license.bytes_total)),
                    DetailLine("Storage Renewal Date", &license.storage_expiration_date)
                );
            }
        }
        if detail == Detail::Full {
            let vault = app.vault.as_ref().ok_or(Error::NotLoggedIn)?;
            print!(
                "{}{}{}",
                DetailLine("Records", &vault.records.len().to_string()),
                DetailLine("Shared Folders", &vault.shared_folders.len().to_string()),
                DetailLine("Teams", &vault.teams.len().to_string())
            );
        }
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct SyncDown;

impl Run for SyncDown {
    fn run(self, app: &mut App) -> Result<()> {
        if app.session.is_none() {
            let user = app.default_user()?;
            app.login(user)
        } else {
            app.sync()
        }
    }
}

#[derive(Args, Debug)]
pub struct ThisDevice {
    #[command(subcommand)]
    action: Option<DeviceAction>,
}

#[derive(Subcommand, Debug)]
enum DeviceAction {
    /// Store an encrypted copy of the data key for this device.
    Register,
    /// Turn "Stay Logged In" on or off.
    #[command(name = "persistent-login", visible_alias = "pl")]
    PersistentLogin { state: Toggle },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Toggle {
    On,
    Off,
}

impl Run for ThisDevice {
    fn run(self, app: &mut App) -> Result<()> {
        app.ensure_synced()?;
        let device_token = b64_decode(app.settings.device_token.as_deref().ok_or(Error::NotLoggedIn)?)?;
        let device_key =
            p256::SecretKey::from_slice(&b64_decode(app.settings.private_key.as_deref().ok_or(Error::NotLoggedIn)?)?)?;
        let config_path = app.settings.path.display().to_string();
        let session = app.session.as_mut().ok_or(Error::NotLoggedIn)?;
        let request = AccountSummaryRequest {
            summary_version: 3,
            ..Default::default()
        };
        session.summary = AccountSummaryElements::decode(
            session
                .rest
                .execute("login/account_summary", &session.session_token, &request)?
                .as_slice(),
        )?;
        let restricted = session
            .summary
            .enforcements
            .as_ref()
            .and_then(|enforcements| {
                enforcements
                    .booleans
                    .iter()
                    .find(|entry| entry.key == "restrict_persistent_login")
            })
            .is_some_and(|entry| entry.value);
        match self.action {
            None => {
                let device = session
                    .summary
                    .devices
                    .iter()
                    .find(|device| device.encrypted_device_token == device_token);
                let persistent = session
                    .summary
                    .settings
                    .as_ref()
                    .is_some_and(|settings| settings.persistent_login)
                    && !restricted;
                print!(
                    "{}{}{}{}",
                    DetailLine("Device Name", device.map_or("Unknown", |device| device.device_name.as_str())),
                    DetailLine(
                        "Data Key Present",
                        &device
                            .is_some_and(|device| device.encrypted_data_key_present)
                            .to_string()
                    ),
                    DetailLine("Persistent Login", if persistent { "ON" } else { "OFF" }),
                    DetailLine("Config File", &config_path)
                );
            }
            action => {
                if let Some(DeviceAction::PersistentLogin { state }) = action {
                    if restricted {
                        return Err(Error::Generic(
                            "\"Stay Logged In\" is restricted by your Keeper administrator".into(),
                        ));
                    }
                    let request = UserSettingRequest {
                        setting: "persistent_login".into(),
                        value:   match state {
                            Toggle::On => "1",
                            Toggle::Off => "0",
                        }
                        .into(),
                    };
                    session
                        .rest
                        .execute("setting/set_user_setting", &session.session_token, &request)?;
                    eprintln!("Persistent login {}", if state == Toggle::On { "ENABLED" } else { "DISABLED" });
                }
                match session.register_device_data_key(device_token, &device_key)? {
                    Registration::Added => eprintln!("Successfully registered device"),
                    Registration::AlreadyPresent => eprintln!("Device already registered"),
                }
            }
        }
        Ok(())
    }
}
