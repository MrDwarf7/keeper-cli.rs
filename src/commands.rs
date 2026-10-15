//! Command implementations over a logged-in session and synced vault.

use serde_json::{Value, json};

use crate::auth::{self, Session};
use crate::cli::{Command, DetailFormat, DeviceAction, Format, Toggle};
use crate::generator::{self, Rules};
use crate::prelude::*;
use crate::settings::Settings;
use crate::totp::Totp;
use crate::vault::{self, FolderKind, Record, Vault};

const MASK: &str = "********";
const DESCRIPTION_WIDTH: usize = 40;

pub struct App {
    pub config: Settings,
    user:       Option<String>,
    password:   Option<String>,
    session:    Option<Session>,
    vault:      Option<Vault>,
    /// Current folder UID; `""` is the vault root.
    pub cwd:    String,
}

impl App {
    pub fn new(config: Settings, user: Option<String>, password: Option<String>) -> Self {
        Self {
            config,
            user,
            password,
            session: None,
            vault: None,
            cwd: String::new(),
        }
    }

    fn login(&mut self, email: Option<String>) -> Result<()> {
        let session = auth::login(&mut self.config, email.or_else(|| self.user.clone()), self.password.take())?;
        eprintln!("Logged in as {}", session.user);
        self.session = Some(session);
        self.vault = None;
        self.sync()
    }

    fn sync(&mut self) -> Result<()> {
        let session = self.session.as_mut().ok_or(Error::NotLoggedIn)?;
        let vault = vault::sync_down(session)?;
        eprintln!("Decrypted {} records.", vault.records.len());
        if !self.cwd.is_empty() && !vault.folders.contains_key(&self.cwd) {
            self.cwd.clear();
        }
        self.vault = Some(vault);
        Ok(())
    }

    fn vault(&mut self) -> Result<&Vault> {
        if self.vault.is_none() {
            if self.session.is_none() {
                self.login(None)?;
            } else {
                self.sync()?;
            }
        }
        Ok(self.vault.as_ref().expect("synced above"))
    }

    pub fn prompt(&self) -> String {
        let name = match &self.vault {
            Some(v) if !self.cwd.is_empty() => v.folder_name(&self.cwd).to_owned(),
            _ => "My Vault".to_owned(),
        };
        format!("{name}> ")
    }

    pub fn run(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Login { email } => self.login(email),
            Command::Logout => self.logout(),
            Command::Whoami { verbose } => self.whoami(verbose),
            Command::SyncDown => {
                if self.session.is_none() {
                    self.login(None)
                } else {
                    self.sync()
                }
            }
            Command::Ls {
                detail,
                folders_only,
                records_only,
                recursive,
                pattern,
            } => {
                let cwd = self.cwd.clone();
                ls(self.vault()?, &cwd, &pattern, detail, folders_only, records_only, recursive);
                Ok(())
            }
            Command::Cd { folder } => {
                let cwd = self.cwd.clone();
                let vault = self.vault()?;
                let target = resolve_folder(vault, &cwd, &folder)
                    .ok_or_else(|| Error::Generic(format!("Invalid folder path: {folder}")))?;
                println!("{}", vault.folder_path(&target));
                self.cwd = target;
                Ok(())
            }
            Command::Tree {
                records,
                verbose,
                folder,
            } => {
                let cwd = self.cwd.clone();
                let vault = self.vault()?;
                let root = resolve_folder(vault, &cwd, &folder)
                    .ok_or_else(|| Error::Generic(format!("Invalid folder path: {folder}")))?;
                tree(vault, &root, records, verbose);
                Ok(())
            }
            Command::List {
                record_type,
                verbose,
                format,
                pattern,
            } => {
                let tokens = search_terms(&pattern);
                let vault = self.vault()?;
                let records: Vec<&Record> = vault
                    .records
                    .values()
                    .filter(|r| {
                        record_type.is_empty() || record_type.iter().any(|t| t.eq_ignore_ascii_case(r.record_type()))
                    })
                    .filter(|r| r.matches(&tokens))
                    .collect();
                print_records(records, verbose, format);
                Ok(())
            }
            Command::Search {
                verbose,
                format,
                pattern,
            } => {
                let vault = self.vault()?;
                search(vault, &pattern, verbose, format);
                Ok(())
            }
            Command::Get { unmask, format, uid } => {
                let cwd = self.cwd.clone();
                get(self.vault()?, &cwd, &uid, unmask, format)
            }
            Command::ListSf { format, pattern } => {
                let tokens = search_terms(&pattern);
                let vault = self.vault()?;
                let rows: Vec<Vec<String>> = sorted_by_name(vault.shared_folders.values(), |sf| &sf.name)
                    .into_iter()
                    .filter(|sf| {
                        let hay = format!("{} {}", sf.uid, sf.name).to_lowercase();
                        tokens.iter().all(|t| hay.contains(&t.to_lowercase()))
                    })
                    .map(|sf| vec![sf.uid.clone(), sf.name.clone()])
                    .collect();
                output(&["shared_folder_uid", "name"], &rows, format);
                Ok(())
            }
            Command::ListTeam { format } => {
                let vault = self.vault()?;
                let rows: Vec<Vec<String>> = sorted_by_name(vault.teams.values(), |t| &t.name)
                    .into_iter()
                    .map(|t| {
                        let restricts: Vec<&str> = [
                            (t.restrict_edit, "Edit"),
                            (t.restrict_share, "Share"),
                            (t.restrict_view, "View"),
                        ]
                        .into_iter()
                        .filter_map(|(on, name)| on.then_some(name))
                        .collect();
                        vec![t.uid.clone(), t.name.clone(), restricts.join(", ")]
                    })
                    .collect();
                output(&["team_uid", "name", "restricts"], &rows, format);
                Ok(())
            }
            Command::Totp { details, record } => {
                let cwd = self.cwd.clone();
                totp(self.vault()?, &cwd, record.as_deref(), details)
            }
            Command::Generate {
                length,
                number,
                rules,
                symbols,
                digits,
                uppercase,
                lowercase,
                format,
            } => {
                let rules = match rules {
                    Some(r) => Rules::parse(&r, length)?,
                    None => {
                        Rules {
                            length: length.unwrap_or(generator::DEFAULT_LENGTH),
                            symbols,
                            digits,
                            uppercase,
                            lowercase,
                        }
                    }
                };
                let passwords = (0..number.max(1))
                    .map(|_| generator::generate(&rules))
                    .collect::<Result<Vec<_>>>()?;
                match format {
                    Format::Json => println!("{}", serde_json::to_string_pretty(&passwords)?),
                    Format::Table => passwords.iter().for_each(|p| println!("{p}")),
                }
                Ok(())
            }
            Command::ThisDevice { action } => self.this_device(action),
            Command::Shell | Command::Exit => Ok(()),
        }
    }

    fn this_device(&mut self, action: Option<DeviceAction>) -> Result<()> {
        if self.session.is_none() {
            self.login(None)?;
        }
        let device_token = b64_decode(self.config.device_token.as_deref().ok_or(Error::NotLoggedIn)?)?;
        let device_key = crate::crypto::load_ec_private_key(&b64_decode(
            self.config.private_key.as_deref().ok_or(Error::NotLoggedIn)?,
        )?)?;
        let session = self.session.as_mut().ok_or(Error::NotLoggedIn)?;
        match action {
            None => {
                session.refresh_summary()?;
                let summary = &session.summary;
                let device = summary
                    .devices
                    .iter()
                    .find(|d| d.encrypted_device_token == device_token);
                let persistent = summary.settings.as_ref().is_some_and(|s| s.persistent_login)
                    && !persistent_login_restricted(session);
                detail_line("Device Name", device.map_or("Unknown", |d| d.device_name.as_str()));
                detail_line("Data Key Present", &device.is_some_and(|d| d.encrypted_data_key_present).to_string());
                detail_line("Persistent Login", if persistent { "ON" } else { "OFF" });
                detail_line("Config File", &self.config.path().display().to_string());
            }
            Some(DeviceAction::Register) => {
                if session.register_device_data_key(device_token, &device_key)? {
                    eprintln!("Successfully registered device");
                } else {
                    eprintln!("Device already registered");
                }
            }
            Some(DeviceAction::PersistentLogin { state }) => {
                if persistent_login_restricted(session) {
                    return Err(Error::Generic("\"Stay Logged In\" is restricted by your Keeper administrator".into()));
                }
                session.set_user_setting("persistent_login", if state == Toggle::On { "1" } else { "0" })?;
                eprintln!("Persistent login {}", if state == Toggle::On { "ENABLED" } else { "DISABLED" });
                session.register_device_data_key(device_token, &device_key)?;
            }
        }
        Ok(())
    }

    fn logout(&mut self) -> Result<()> {
        if let Some(mut session) = self.session.take()
            && let Err(e) = session.logout()
        {
            eprintln!("Server logout failed: {e}");
        }
        self.vault = None;
        self.cwd.clear();
        self.config.clone_code = None;
        self.config.save()?;
        eprintln!("Logged out; persistent login on this device has been cleared.");
        Ok(())
    }

    fn whoami(&mut self, verbose: bool) -> Result<()> {
        // Like every Commander command, whoami authenticates first; a one-shot run has no session yet.
        self.vault()?;
        let session = self.session.as_ref().ok_or(Error::NotLoggedIn)?;
        let host = session.rest.host();
        let mut rows = vec![
            ("User", session.user.clone()),
            ("Server", host.clone()),
            ("Data Center", data_center(&host).into()),
        ];
        if let Some(license) = &session.summary.license {
            let account_type = match license.account_type {
                2 => "Enterprise".to_owned(),
                1 => "Family Plan".to_owned(),
                _ => license.product_type_name.clone(),
            };
            rows.push(("Account Type", account_type));
            rows.push(("Renewal Date", license.expiration_date.clone()));
            if license.bytes_total > 0 {
                rows.push(("Storage Capacity", format!("{}GB", license.bytes_total >> 30)));
                rows.push(("Storage Usage", format!("{}%", license.bytes_used * 100 / license.bytes_total)));
                rows.push(("Storage Renewal Date", license.storage_expiration_date.clone()));
            }
            rows.push(("BreachWatch", license.breach_watch_enabled.to_string()));
        }
        if verbose && let Some(v) = &self.vault {
            rows.push(("Records", v.records.len().to_string()));
            rows.push(("Shared Folders", v.shared_folders.len().to_string()));
            rows.push(("Teams", v.teams.len().to_string()));
        }
        for (k, v) in rows {
            println!("{k:>21}: {v}");
        }
        Ok(())
    }
}

fn persistent_login_restricted(session: &Session) -> bool {
    session
        .summary
        .enforcements
        .as_ref()
        .and_then(|e| e.booleans.iter().find(|b| b.key == "restrict_persistent_login"))
        .is_some_and(|b| b.value)
}

fn data_center(host: &str) -> &'static str {
    match host {
        h if h.contains("govcloud") => "US GOV",
        h if h.ends_with(".eu") => "EU",
        h if h.ends_with(".com.au") => "AU",
        h if h.ends_with(".ca") => "CA",
        h if h.ends_with(".jp") => "JP",
        _ => "US",
    }
}

fn sorted_by_name<'a, T>(items: impl Iterator<Item = &'a T>, name: impl Fn(&T) -> &str) -> Vec<&'a T> {
    let mut items: Vec<&T> = items.collect();
    items.sort_by_cached_key(|i| name(i).to_lowercase());
    items
}

/// Splits a Commander-style path; `//` is an escaped literal slash inside a name.
fn split_path(path: &str) -> (bool, Vec<String>) {
    let absolute = path.starts_with('/') && !path.starts_with("//");
    let parts = path
        .replace("//", "\0")
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.replace('\0', "/"))
        .collect();
    (absolute, parts)
}

fn child_named<'a>(vault: &'a Vault, parent: &str, name: &str) -> Option<&'a String> {
    let kids = vault.subfolders_of(parent);
    kids.iter().find(|uid| vault.folders[*uid].name == name).or_else(|| {
        kids.iter()
            .find(|uid| vault.folders[*uid].name.eq_ignore_ascii_case(name))
    })
}

pub fn resolve_folder(vault: &Vault, cwd: &str, path: &str) -> Option<String> {
    if vault.folders.contains_key(path) {
        return Some(path.to_owned());
    }
    let (absolute, parts) = split_path(path);
    let mut current = if absolute { String::new() } else { cwd.to_owned() };
    for part in parts {
        current = match part.as_str() {
            "." => current,
            ".." => {
                vault
                    .folders
                    .get(&current)
                    .and_then(|f| f.parent.clone())
                    .unwrap_or_default()
            }
            name => child_named(vault, &current, name)?.clone(),
        };
    }
    Some(current)
}

pub fn resolve_record<'a>(vault: &'a Vault, cwd: &str, spec: &str) -> Option<&'a Record> {
    if let Some(r) = vault.records.get(spec) {
        return Some(r);
    }
    let (absolute, mut parts) = split_path(spec);
    let title = parts.pop()?;
    let folder = if parts.is_empty() && !absolute {
        cwd.to_owned()
    } else {
        let joined = parts.iter().map(|p| p.replace('/', "//")).collect::<Vec<_>>().join("/");
        resolve_folder(vault, cwd, &if absolute { format!("/{joined}") } else { joined })?
    };
    let in_folder = || vault.records_in(&folder);
    in_folder()
        .find(|r| r.title() == title)
        .or_else(|| in_folder().find(|r| r.title().eq_ignore_ascii_case(&title)))
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_owned()
    } else {
        format!("{}...", s.chars().take(width.saturating_sub(3)).collect::<String>())
    }
}

/// `snake_case` headers become "Title Case" in tables and stay as JSON keys.
fn output(headers: &[&str], rows: &[Vec<String>], format: Format) {
    match format {
        Format::Json => {
            let items: Vec<Value> = rows
                .iter()
                .map(|row| {
                    Value::Object(
                        headers
                            .iter()
                            .zip(row)
                            .map(|(h, v)| ((*h).to_owned(), Value::String(v.clone())))
                            .collect(),
                    )
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items).expect("strings serialize"));
        }
        Format::Table => {
            let titles: Vec<String> = headers.iter().map(|h| title_case(h)).collect();
            print_table(&titles, rows, true);
        }
    }
}

fn title_case(h: &str) -> String {
    h.split('_')
        .map(|w| {
            match w {
                "uid" => "UID".to_owned(),
                w => {
                    let mut c = w.chars();
                    c.next()
                        .map(|f| f.to_uppercase().chain(c).collect())
                        .unwrap_or_default()
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_table(headers: &[String], rows: &[Vec<String>], numbered: bool) {
    if rows.is_empty() {
        println!("No results");
        return;
    }
    let mut headers = headers.to_vec();
    let mut rows = rows.to_vec();
    if numbered {
        headers.insert(0, "#".into());
        for (i, row) in rows.iter_mut().enumerate() {
            row.insert(0, (i + 1).to_string());
        }
    }
    let widths: Vec<usize> = (0..headers.len())
        .map(|c| {
            rows.iter()
                .map(|r| r[c].chars().count())
                .chain([headers[c].chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: &[String]| {
        cells
            .iter()
            .zip(&widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    println!("{}", line(&headers));
    println!("{}", widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  "));
    for row in &rows {
        println!("{}", line(row));
    }
}

fn print_records(mut records: Vec<&Record>, verbose: bool, format: Format) {
    records.sort_by_cached_key(|r| r.title().to_lowercase());
    let rows: Vec<Vec<String>> = records
        .iter()
        .map(|r| {
            let description = r.description();
            vec![
                r.uid.clone(),
                r.record_type().to_owned(),
                if verbose {
                    r.title().to_owned()
                } else {
                    truncate(r.title(), DESCRIPTION_WIDTH)
                },
                if verbose {
                    description
                } else {
                    truncate(&description, DESCRIPTION_WIDTH)
                },
                r.shared.to_string(),
            ]
        })
        .collect();
    output(&["record_uid", "type", "title", "description", "shared"], &rows, format);
}

fn ls(vault: &Vault, cwd: &str, pattern: &str, detail: bool, folders_only: bool, records_only: bool, recursive: bool) {
    // Like Commander, the argument is a folder path when it resolves to one, else a name filter.
    // An empty pattern resolves to the current folder and an empty filter keeps everything.
    let (folder, filter) = match resolve_folder(vault, cwd, pattern) {
        Some(f) => (f, String::new()),
        None => (cwd.to_owned(), pattern.to_lowercase()),
    };
    let mut queue = vec![folder];
    let mut first = true;
    while let Some(folder) = queue.pop() {
        if recursive {
            if !first {
                println!();
            }
            println!("{}:", vault.folder_path(&folder));
        }
        first = false;
        let keep = |name: &str| name.to_lowercase().contains(&filter);
        let folders: Vec<&String> = vault
            .subfolders_of(&folder)
            .iter()
            .filter(|u| keep(&vault.folders[*u].name))
            .collect();
        let mut records: Vec<&Record> = vault.records_in(&folder).filter(|r| keep(r.title())).collect();
        records.sort_by_cached_key(|r| r.title().to_lowercase());

        if detail {
            if !records_only && !folders.is_empty() {
                let rows: Vec<Vec<String>> = folders
                    .iter()
                    .map(|u| {
                        let f = &vault.folders[*u];
                        let flags = match f.kind {
                            FolderKind::User => "",
                            FolderKind::SharedFolder => "S",
                            FolderKind::SharedFolderFolder => "s",
                        };
                        vec![f.uid.clone(), f.name.clone(), flags.to_owned()]
                    })
                    .collect();
                print_table(&["Folder UID".into(), "Name".into(), "Flags".into()], &rows, true);
            }
            if !folders_only && !records.is_empty() {
                if !records_only && !folders.is_empty() {
                    println!();
                }
                print_records(records, false, Format::Table);
            }
        } else {
            if !records_only {
                for u in &folders {
                    println!("{}/", vault.folders[*u].name);
                }
            }
            if !folders_only {
                for r in &records {
                    println!("{}", r.title());
                }
            }
        }
        if recursive {
            queue.extend(vault.subfolders_of(&folder).iter().rev().cloned());
        }
    }
}

fn tree(vault: &Vault, root: &str, records: bool, verbose: bool) {
    let label = |name: &str, uid: &str| {
        if verbose {
            format!("{name} ({uid})")
        } else {
            name.to_owned()
        }
    };
    println!("{}", label(vault.folder_name(root), if root.is_empty() { "/" } else { root }));
    fn walk(vault: &Vault, folder: &str, prefix: &str, records: bool, label: &dyn Fn(&str, &str) -> String) {
        let kids = vault.subfolders_of(folder);
        let mut recs: Vec<&Record> = if records {
            vault.records_in(folder).collect()
        } else {
            Vec::new()
        };
        recs.sort_by_cached_key(|r| r.title().to_lowercase());
        let total = kids.len() + recs.len();
        for (i, uid) in kids.iter().enumerate() {
            let last = i + 1 == total;
            let f = &vault.folders[uid];
            let marker = if f.kind == FolderKind::SharedFolder {
                " [Shared]"
            } else {
                ""
            };
            println!("{prefix}{}{}{marker}", if last { "└── " } else { "├── " }, label(&f.name, uid));
            walk(vault, uid, &format!("{prefix}{}", if last { "    " } else { "│   " }), records, label);
        }
        for (i, r) in recs.iter().enumerate() {
            let last = kids.len() + i + 1 == total;
            println!("{prefix}{}{}", if last { "└── " } else { "├── " }, label(r.title(), &r.uid));
        }
    }
    walk(vault, root, "", records, &label);
}

/// Terms may arrive as separate arguments or as one quoted string; either way every word must
/// match, in any order.
fn search_terms(pattern: &[String]) -> Vec<String> {
    pattern
        .iter()
        .flat_map(|p| p.split_whitespace())
        .map(str::to_owned)
        .collect()
}

fn search(vault: &Vault, pattern: &[String], verbose: bool, format: Format) {
    let tokens = search_terms(pattern);
    let records: Vec<&Record> = vault.records.values().filter(|r| r.matches(&tokens)).collect();
    let hit = |text: &str| {
        let text = text.to_lowercase();
        tokens.iter().all(|t| text.contains(&t.to_lowercase()))
    };
    let folders: Vec<Vec<String>> = sorted_by_name(vault.shared_folders.values(), |sf| &sf.name)
        .into_iter()
        .filter(|sf| hit(&format!("{} {}", sf.uid, sf.name)))
        .map(|sf| vec![sf.uid.clone(), sf.name.clone()])
        .collect();
    let teams: Vec<Vec<String>> = sorted_by_name(vault.teams.values(), |t| &t.name)
        .into_iter()
        .filter(|t| hit(&format!("{} {}", t.uid, t.name)))
        .map(|t| vec![t.uid.clone(), t.name.clone()])
        .collect();
    if format == Format::Json {
        let mut records = records;
        records.sort_by_cached_key(|r| r.title().to_lowercase());
        let as_objects = |rows: &[Vec<String>], key: &str| -> Vec<Value> {
            rows.iter().map(|r| json!({key: r[0], "name": r[1]})).collect()
        };
        let body = json!({
            "records": records.iter().map(|r| json!({"record_uid": r.uid, "type": r.record_type(), "title": r.title(), "description": r.description()})).collect::<Vec<_>>(),
            "shared_folders": as_objects(&folders, "shared_folder_uid"),
            "teams": as_objects(&teams, "team_uid"),
        });
        println!("{}", serde_json::to_string_pretty(&body).expect("json values serialize"));
        return;
    }
    if !records.is_empty() {
        println!("Records:");
        print_records(records, verbose, Format::Table);
    }
    if !folders.is_empty() {
        println!("\nShared Folders:");
        print_table(&["Shared Folder UID".into(), "Name".into()], &folders, true);
    }
    if !teams.is_empty() {
        println!("\nTeams:");
        print_table(&["Team UID".into(), "Name".into()], &teams, true);
    }
}

fn detail_line(label: &str, value: &str) {
    let mut lines = value.lines();
    println!("{label:>20}: {}", lines.next().unwrap_or_default());
    for line in lines {
        println!("{:>20}  {line}", "");
    }
}

fn get(vault: &Vault, cwd: &str, spec: &str, unmask: bool, format: DetailFormat) -> Result<()> {
    if let Some(record) = vault.records.get(spec).or_else(|| resolve_record(vault, cwd, spec)) {
        return show_record(vault, record, unmask, format);
    }
    let shared_folder = vault.shared_folders.get(spec);
    if let Some(folder) = vault.folders.get(spec).filter(|_| shared_folder.is_none()) {
        let kind = match folder.kind {
            FolderKind::User => "user_folder",
            FolderKind::SharedFolder => "shared_folder",
            FolderKind::SharedFolderFolder => "shared_folder_folder",
        };
        let parent = folder.parent.clone().unwrap_or_default();
        if format == DetailFormat::Json {
            let body = json!({"folder_uid": folder.uid, "type": kind, "name": folder.name, "parent_uid": parent, "path": vault.folder_path(&folder.uid)});
            println!("{}", serde_json::to_string_pretty(&body)?);
        } else {
            detail_line("Folder UID", &folder.uid);
            detail_line("Folder Type", kind);
            detail_line("Name", &folder.name);
            detail_line("Path", &vault.folder_path(&folder.uid));
            if !parent.is_empty() {
                detail_line("Parent Folder UID", &parent);
            }
        }
        return Ok(());
    }
    if let Some(sf) = shared_folder {
        if format == DetailFormat::Json {
            let body = json!({
                "shared_folder_uid": sf.uid, "name": sf.name,
                "default_manage_records": sf.default_manage_records, "default_manage_users": sf.default_manage_users,
                "default_can_edit": sf.default_can_edit, "default_can_share": sf.default_can_share,
                "users": sf.users, "teams": sf.teams, "record_count": sf.record_uids.len(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        } else {
            detail_line("Shared Folder UID", &sf.uid);
            detail_line("Name", &sf.name);
            detail_line("Default Manage Records", &sf.default_manage_records.to_string());
            detail_line("Default Manage Users", &sf.default_manage_users.to_string());
            detail_line("Default Can Edit", &sf.default_can_edit.to_string());
            detail_line("Default Can Share", &sf.default_can_share.to_string());
            detail_line("Records", &sf.record_uids.len().to_string());
            if !sf.users.is_empty() {
                detail_line("Users", &sf.users.join("\n"));
            }
            if !sf.teams.is_empty() {
                detail_line("Teams", &sf.teams.join("\n"));
            }
        }
        return Ok(());
    }
    if let Some(team) = vault.teams.get(spec) {
        if format == DetailFormat::Json {
            let body = json!({"team_uid": team.uid, "name": team.name, "restrict_edit": team.restrict_edit, "restrict_share": team.restrict_share, "restrict_view": team.restrict_view});
            println!("{}", serde_json::to_string_pretty(&body)?);
        } else {
            detail_line("Team UID", &team.uid);
            detail_line("Name", &team.name);
            detail_line("Restrict Edit", &team.restrict_edit.to_string());
            detail_line("Restrict Share", &team.restrict_share.to_string());
            detail_line("Restrict View", &team.restrict_view.to_string());
        }
        return Ok(());
    }
    Err(Error::Generic(format!("Cannot find any object with UID or path: {spec}")))
}

fn show_record(vault: &Vault, record: &Record, unmask: bool, format: DetailFormat) -> Result<()> {
    let fields = record.display_fields();
    let shown = |f: &vault::DisplayField| {
        if f.secret && !unmask {
            MASK.to_owned()
        } else {
            f.value.clone()
        }
    };
    let folders: Vec<String> = vault
        .folder_records
        .iter()
        .filter(|(_, uids)| uids.contains(&record.uid))
        .map(|(folder, _)| vault.folder_path(folder))
        .collect();
    if format == DetailFormat::Json {
        let body = json!({
            "record_uid": record.uid,
            "type": record.record_type(),
            "title": record.title(),
            "fields": fields.iter().map(|f| json!({"label": f.label, "value": shown(f)})).collect::<Vec<_>>(),
            "notes": record.notes(),
            "shared": record.shared,
            "revision": record.revision,
            "client_modified_time": record.client_modified_time,
            "folders": folders,
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }
    detail_line("UID", &record.uid);
    detail_line("Type", record.record_type());
    detail_line("Title", record.title());
    for f in &fields {
        detail_line(&f.label, &shown(f));
    }
    if !record.notes().is_empty() {
        detail_line("Notes", record.notes());
    }
    if let Some(url) = record.totp_url()
        && let Ok((code, remaining)) = Totp::parse(url).and_then(|t| t.code_now())
    {
        detail_line("Two Factor Code", &format!("{code} valid for {remaining} sec"));
    }
    if !folders.is_empty() {
        detail_line("Folders", &folders.join("\n"));
    }
    Ok(())
}

fn totp(vault: &Vault, cwd: &str, spec: Option<&str>, details: bool) -> Result<()> {
    let Some(spec) = spec else {
        let mut with_totp: Vec<&Record> = vault.records.values().filter(|r| r.totp_url().is_some()).collect();
        with_totp.sort_by_cached_key(|r| r.title().to_lowercase());
        let rows: Vec<Vec<String>> = with_totp
            .iter()
            .map(|r| {
                let (code, remaining) = Totp::parse(r.totp_url().unwrap_or_default())
                    .and_then(|t| t.code_now())
                    .map_or_else(|e| (format!("error: {e}"), String::new()), |(c, s)| (c, format!("{s}s")));
                vec![r.uid.clone(), truncate(r.title(), DESCRIPTION_WIDTH), code, remaining]
            })
            .collect();
        print_table(&["Record UID".into(), "Title".into(), "Code".into(), "Valid For".into()], &rows, true);
        return Ok(());
    };
    let record = resolve_record(vault, cwd, spec).ok_or_else(|| Error::Generic(format!("Record not found: {spec}")))?;
    let url = record
        .totp_url()
        .ok_or_else(|| Error::Generic(format!("Record \"{}\" has no TOTP", record.title())))?;
    let totp = Totp::parse(url)?;
    let (code, remaining) = totp.code_now()?;
    if details {
        detail_line("Record UID", &record.uid);
        detail_line("Title", record.title());
        detail_line("TOTP URL", url);
    }
    println!("{code}");
    eprintln!("valid for {remaining} seconds");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::*;
    use crate::vault::Folder;

    fn folder(uid: &str, name: &str, parent: Option<&str>, kids: &[&str]) -> (String, Folder) {
        (
            uid.to_owned(),
            Folder {
                uid: uid.into(),
                kind: FolderKind::User,
                name: name.into(),
                parent: parent.map(Into::into),
                subfolders: kids.iter().map(|k| (*k).to_owned()).collect(),
                ..Folder::default()
            },
        )
    }

    fn vault() -> Vault {
        let mut v = Vault {
            folders: HashMap::from([
                folder("A", "Work", None, &["B", "S"]),
                folder("B", "Infra", Some("A"), &[]),
                folder("S", "a/b", Some("A"), &[]),
            ]),
            root_folders: vec!["A".into()],
            ..Vault::default()
        };
        v.records.insert(
            "R1".into(),
            Record {
                uid: "R1".into(),
                version: 3,
                revision: 1,
                shared: false,
                client_modified_time: 0,
                data: json!({"title": "DB Admin", "type": "login"}),
                extra: None,
                ..Record::default()
            },
        );
        v.folder_records.insert("B".into(), BTreeSet::from(["R1".to_owned()]));
        v
    }

    #[test]
    fn folder_paths_resolve_relative_absolute_parent_and_escaped_slash() {
        let v = vault();
        assert_eq!(resolve_folder(&v, "", "Work/Infra").as_deref(), Some("B"));
        assert_eq!(resolve_folder(&v, "B", "..").as_deref(), Some("A"));
        assert_eq!(resolve_folder(&v, "B", "../..").as_deref(), Some(""));
        assert_eq!(resolve_folder(&v, "B", "/work").as_deref(), Some("A"));
        assert_eq!(resolve_folder(&v, "A", "a//b").as_deref(), Some("S"));
        assert_eq!(resolve_folder(&v, "", "B").as_deref(), Some("B"));
        assert_eq!(resolve_folder(&v, "", "Nope"), None);
        assert_eq!(v.folder_path("S"), "/Work/a//b");
    }

    #[test]
    fn records_resolve_by_uid_title_or_path() {
        let v = vault();
        assert_eq!(resolve_record(&v, "", "R1").map(|r| r.uid.as_str()), Some("R1"));
        assert_eq!(resolve_record(&v, "B", "db admin").map(|r| r.uid.as_str()), Some("R1"));
        assert_eq!(resolve_record(&v, "", "/Work/Infra/DB Admin").map(|r| r.uid.as_str()), Some("R1"));
        assert!(resolve_record(&v, "", "DB Admin").is_none());
    }
}
