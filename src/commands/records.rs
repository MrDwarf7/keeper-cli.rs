use clap::Args;

use super::{App, Clipped, Detail, DetailLine, Run, Table};
use crate::cli::{DetailFormat, Format};
use crate::totp::Totp as TotpConfig;
use crate::vault::{Folder, Record, Secrets, SharedFolder, Team};

#[derive(Args, Debug)]
pub struct List {
    #[arg(short = 't', long = "type")]
    record_type: Vec<String>,
    #[arg(short, long)]
    verbose:     bool,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format:      Format,
    pattern:     Vec<String>,
}

impl Run for List {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        let terms = terms(&self.pattern);
        let mut records: Vec<_> = view
            .vault
            .records
            .values()
            .filter(|record| {
                self.record_type.is_empty() || self.record_type.iter().any(|kind| matches_kind(record, kind))
            })
            .filter(|record| record.matches(&terms))
            .collect();
        records.sort_by_cached_key(|record| record.title().to_lowercase());
        records_table(records, Detail::from(self.verbose), self.format);
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Search {
    #[arg(short, long)]
    verbose: bool,
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format:  Format,
    pattern: Vec<String>,
}

impl Run for Search {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        let terms = terms(&self.pattern);
        let mut records: Vec<_> = view
            .vault
            .records
            .values()
            .filter(|record| record.matches(&terms))
            .collect();
        records.sort_by_cached_key(|record| record.title().to_lowercase());
        match self.format {
            Format::Table => {
                if !records.is_empty() {
                    println!("Records:");
                    records_table(records, Detail::from(self.verbose), Format::Table);
                }
                let mut folders = Table::new(&["shared_folder_uid", "name"]);
                for folder in view
                    .vault
                    .shared_folders
                    .values()
                    .filter(|folder| matches_terms(&format!("{} {}", folder.uid, folder.name), &terms))
                {
                    folders.push([folder.uid.to_string(), folder.name.clone()]);
                }
                if !folders.rows.is_empty() {
                    println!("\nShared Folders:");
                    folders.print(Format::Table);
                }
                let mut teams = Table::new(&["team_uid", "name"]);
                for team in view
                    .vault
                    .teams
                    .values()
                    .filter(|team| matches_terms(&format!("{} {}", team.uid, team.name), &terms))
                {
                    teams.push([team.uid.to_string(), team.name.clone()]);
                }
                if !teams.rows.is_empty() {
                    println!("\nTeams:");
                    teams.print(Format::Table);
                }
            }
            Format::Json => {
                let body = serde_json::json!({
                    "records": records.iter().map(|record| serde_json::json!({"record_uid": record.uid.to_string(), "type": record.record_type(), "title": record.title(), "description": record.description()})).collect::<Vec<_>>(),
                    "shared_folders": view.vault.shared_folders.values().filter(|folder| matches_terms(&format!("{} {}", folder.uid, folder.name), &terms)).map(|folder| serde_json::json!({"shared_folder_uid": folder.uid.to_string(), "name": folder.name})).collect::<Vec<_>>(),
                    "teams": view.vault.teams.values().filter(|team| matches_terms(&format!("{} {}", team.uid, team.name), &terms)).map(|team| serde_json::json!({"team_uid": team.uid.to_string(), "name": team.name})).collect::<Vec<_>>(),
                });
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Get {
    #[arg(long)]
    unmask: bool,
    #[arg(long, value_enum, default_value_t = DetailFormat::Detail)]
    format: DetailFormat,
    uid:    String,
}

impl Run for Get {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        let mut found = Vec::new();
        if let Some(record) = view.vault.resolve_record(view.cwd, &self.uid) {
            found.push(Object::Record(record));
        } else if let Some(folder) = view.vault.shared_folders.get(self.uid.as_str()) {
            found.push(Object::SharedFolder(folder));
        } else if let Some(folder) = view.vault.folders.get(self.uid.as_str()) {
            found.push(Object::Folder(folder));
        } else if let Some(team) = view.vault.teams.get(self.uid.as_str()) {
            found.push(Object::Team(team));
        } else {
            let query = self.uid.to_lowercase();
            found.extend(
                view.vault
                    .records
                    .values()
                    .filter(|record| record.title().to_lowercase().contains(&query))
                    .map(Object::Record),
            );
            found.extend(
                view.vault
                    .shared_folders
                    .values()
                    .filter(|folder| folder.name.to_lowercase().contains(&query))
                    .map(Object::SharedFolder),
            );
            found.extend(
                view.vault
                    .folders
                    .values()
                    .filter(|folder| {
                        !matches!(folder.kind, crate::vault::FolderKind::SharedFolder)
                            && folder.name.to_lowercase().contains(&query)
                    })
                    .map(Object::Folder),
            );
            found.extend(
                view.vault
                    .teams
                    .values()
                    .filter(|team| team.name.to_lowercase().contains(&query))
                    .map(Object::Team),
            );
        }
        match found.as_slice() {
            [] => Err(crate::Error::Generic(format!("Cannot find vault object: {}", self.uid))),
            [Object::Record(record)] => show_record(view.vault, record, Secrets::from(self.unmask), self.format),
            [object] => {
                let value = serde_json::Value::from(object);
                match self.format {
                    DetailFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                    DetailFormat::Detail => {
                        for (name, value) in value.as_object().expect("vault objects serialize as maps") {
                            let text = value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string());
                            print!("{}", DetailLine(name, &text));
                        }
                    }
                }
                Ok(())
            }
            objects => {
                let mut table = Table::new(&["uid", "type", "name"]);
                for object in objects {
                    table.push(object.table_row());
                }
                table.print(match self.format {
                    DetailFormat::Detail => Format::Table,
                    DetailFormat::Json => Format::Json,
                });
                Ok(())
            }
        }
    }
}

enum Object<'a> {
    Record(&'a Record),
    Folder(&'a Folder),
    SharedFolder(&'a SharedFolder),
    Team(&'a Team),
}

impl Object<'_> {
    fn table_row(&self) -> [String; 3] {
        match self {
            Self::Record(record) => {
                [
                    record.uid.to_string(),
                    record.record_type().to_owned(),
                    record.title().to_owned(),
                ]
            }
            Self::Folder(folder) => [folder.uid.to_string(), "folder".to_owned(), folder.name.clone()],
            Self::SharedFolder(folder) => [folder.uid.to_string(), "shared_folder".to_owned(), folder.name.clone()],
            Self::Team(team) => [team.uid.to_string(), "team".to_owned(), team.name.clone()],
        }
    }
}

impl From<&Object<'_>> for serde_json::Value {
    fn from(object: &Object<'_>) -> Self {
        match object {
            Object::Record(record) => {
                serde_json::json!({"uid": record.uid.to_string(), "type": record.record_type(), "name": record.title()})
            }
            Object::Folder(folder) => {
                serde_json::json!({"uid": folder.uid.to_string(), "type": "folder", "name": folder.name})
            }
            Object::SharedFolder(folder) => {
                serde_json::json!({"uid": folder.uid.to_string(), "type": "shared_folder", "name": folder.name,
                "users": folder.users, "teams": folder.teams, "record_count": folder.record_uids.len(),
                "default_can_edit": folder.default_can_edit, "default_can_share": folder.default_can_share,
                "default_manage_records": folder.default_manage_records, "default_manage_users": folder.default_manage_users})
            }
            Object::Team(team) => {
                serde_json::json!({"uid": team.uid.to_string(), "type": "team", "name": team.name,
                "restrict_edit": team.restrict_edit, "restrict_share": team.restrict_share, "restrict_view": team.restrict_view})
            }
        }
    }
}

#[derive(Args, Debug)]
pub struct ListSf {
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format:  Format,
    pattern: Vec<String>,
}

impl Run for ListSf {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        let terms = terms(&self.pattern);
        let mut table = Table::new(&["shared_folder_uid", "name"]);
        for folder in view
            .vault
            .shared_folders
            .values()
            .filter(|folder| matches_terms(&format!("{} {}", folder.uid, folder.name), &terms))
        {
            table.push([folder.uid.to_string(), folder.name.clone()]);
        }
        table.print(self.format);
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct ListTeam {
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,
}

impl Run for ListTeam {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        let mut table = Table::new(&["team_uid", "name", "restricts"]);
        for team in view.vault.teams.values() {
            let restricts = [
                (team.restrict_edit, "Edit"),
                (team.restrict_share, "Share"),
                (team.restrict_view, "View"),
            ]
            .into_iter()
            .filter_map(|(enabled, label)| enabled.then_some(label))
            .collect::<Vec<_>>()
            .join(", ");
            table.push([team.uid.to_string(), team.name.clone(), restricts]);
        }
        table.print(self.format);
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Totp {
    #[arg(long)]
    details: bool,
    record:  Option<String>,
}

impl Run for Totp {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let view = app.view()?;
        match self.record {
            Some(spec) => show_totp(view.vault, view.cwd, &spec, Detail::from(self.details)),
            None => list_totp(view.vault),
        }
    }
}

fn terms(pattern: &[String]) -> Vec<String> {
    pattern
        .iter()
        .flat_map(|part| part.split_whitespace())
        .map(str::to_owned)
        .collect()
}

fn matches_terms(text: &str, terms: &[String]) -> bool {
    let text = text.to_lowercase();
    terms.iter().all(|term| text.contains(&term.to_lowercase()))
}

fn matches_kind(record: &Record, kind: &str) -> bool {
    kind.eq_ignore_ascii_case(record.record_type())
        || (kind.eq_ignore_ascii_case("legacy") && record.record_type() == "general")
}

fn records_table(records: Vec<&Record>, detail: Detail, format: Format) {
    let mut table = Table::new(&["record_uid", "type", "title", "description", "shared"]);
    for record in records {
        let title = if detail == Detail::Full || format == Format::Json {
            record.title().to_owned()
        } else {
            Clipped(record.title(), 40).to_string()
        };
        let description = record.description();
        let description = if detail == Detail::Full || format == Format::Json {
            description
        } else {
            Clipped(&description, 40).to_string()
        };
        table.push([
            record.uid.to_string(),
            record.record_type().to_owned(),
            title,
            description,
            record.shared.to_string(),
        ]);
    }
    table.print(format);
}

fn show_record(
    vault: &crate::vault::Vault,
    record: &Record,
    secrets: Secrets,
    format: DetailFormat,
) -> crate::Result<()> {
    let fields = record.display_fields(secrets);
    match format {
        DetailFormat::Json => {
            let body = serde_json::json!({
                "record_uid": record.uid.to_string(), "type": record.record_type(), "title": record.title(),
                "fields": fields.iter().map(|field| serde_json::json!({"label": field.label, "value": field.value})).collect::<Vec<_>>(),
                "notes": record.notes(), "shared": record.shared, "revision": record.revision,
                "client_modified_time": record.client_modified_time,
                "udata": record.udata,
                "storage_size": match record.kind { crate::vault::RecordKind::File { size } => Some(size), _ => None },
                "folders": vault.locations_of(&record.uid).map(|at| vault.path_of(at)).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        DetailFormat::Detail => {
            print!("{}", DetailLine("UID", record.uid.as_ref()));
            print!("{}", DetailLine("Type", record.record_type()));
            print!("{}", DetailLine("Title", record.title()));
            for field in fields {
                print!("{}", DetailLine(&field.label, field.value.as_ref()));
            }
            if !record.notes().is_empty() {
                print!("{}", DetailLine("Notes", record.notes()));
            }
            let folders = vault
                .locations_of(&record.uid)
                .map(|at| vault.path_of(at))
                .collect::<Vec<_>>()
                .join("\n");
            if !folders.is_empty() {
                print!("{}", DetailLine("Folders", &folders));
            }
        }
    }
    Ok(())
}

fn list_totp(vault: &crate::vault::Vault) -> crate::Result<()> {
    let mut table = Table::new(&["record_uid", "title", "code", "valid_for"]);
    for record in vault.records.values().filter(|record| record.totp_url().is_some()) {
        let (code, remaining) = record
            .totp_url()
            .and_then(|url| url.parse::<TotpConfig>().ok())
            .and_then(|totp| totp.code_now().ok())
            .map_or_else(
                || ("invalid TOTP".to_owned(), String::new()),
                |code| (code.to_string(), format!("{}s", code.remaining)),
            );
        table.push([
            record.uid.to_string(),
            Clipped(record.title(), 40).to_string(),
            code,
            remaining,
        ]);
    }
    table.print(Format::Table);
    Ok(())
}

fn show_totp(
    vault: &crate::vault::Vault,
    cwd: &crate::vault::Location,
    spec: &str,
    detail: Detail,
) -> crate::Result<()> {
    let record = vault
        .resolve_record(cwd, spec)
        .ok_or_else(|| crate::Error::Generic(format!("Record not found: {spec}")))?;
    let url = record
        .totp_url()
        .ok_or_else(|| crate::Error::Generic(format!("Record \"{}\" has no TOTP", record.title())))?;
    let code = url.parse::<TotpConfig>()?.code_now()?;
    if detail == Detail::Full {
        print!("{}", DetailLine("Record UID", record.uid.as_ref()));
        print!("{}", DetailLine("Title", record.title()));
        print!("{}", DetailLine("TOTP URL", url));
    }
    println!("{code}");
    eprintln!("valid for {} seconds", code.remaining);
    Ok(())
}
