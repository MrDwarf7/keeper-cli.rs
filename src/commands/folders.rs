use clap::Args;

use super::{App, Clipped, Detail, Run, Table};
use crate::folder_edit::{Case, Glob};
use crate::vault::{FolderKind, Location};

#[derive(Args, Debug)]
pub struct Ls {
    #[arg(short = 'l', long = "list")]
    detail:       bool,
    #[arg(short = 'f', long = "folders")]
    folders_only: bool,
    #[arg(short = 'r', long = "records")]
    records_only: bool,
    #[arg(short = 'R', long)]
    recursive:    bool,
    #[arg(default_value_t, hide_default_value = true)]
    pattern:      String,
}

#[derive(Clone, Copy)]
enum Listing {
    All,
    Folders,
    Records,
}

#[derive(Clone, Copy)]
enum Depth {
    Current,
    Recursive,
}

impl Run for Ls {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let listing = match (self.folders_only, self.records_only) {
            (true, false) => Listing::Folders,
            (false, true) => Listing::Records,
            _ => Listing::All,
        };
        let depth = if self.recursive {
            Depth::Recursive
        } else {
            Depth::Current
        };
        let detail = Detail::from(self.detail);
        let view = app.view()?;
        let (root, tail) = view.vault.resolve_path_tail(view.cwd, &self.pattern);
        let pattern = Glob::new(if tail.is_empty() { "*" } else { &tail }, Case::Ignore);
        let mut queue = vec![root];
        let mut hits = 0;
        while let Some(folder) = queue.pop() {
            if matches!(depth, Depth::Recursive) {
                println!("{}:", view.vault.path_of(&folder));
            }
            hits += list_one(view.vault, &folder, &pattern, listing, detail);
            if matches!(depth, Depth::Recursive) {
                queue.extend(
                    view.vault
                        .subfolders_of(&folder)
                        .iter()
                        .rev()
                        .cloned()
                        .map(Location::Folder),
                );
                if !queue.is_empty() {
                    println!();
                }
            }
        }
        if hits == 0 && !tail.is_empty() {
            return Err(crate::Error::Generic(format!("{tail}: No such folder or record")));
        }
        Ok(())
    }
}

fn list_one(vault: &crate::vault::Vault, folder: &Location, pattern: &Glob, listing: Listing, detail: Detail) -> usize {
    let folders: Vec<_> = vault
        .subfolders_of(folder)
        .iter()
        .filter(|uid| pattern.is_match(&vault.folders[*uid].name) || pattern.is_match(uid.as_ref()))
        .collect();
    let mut records: Vec<_> = vault
        .records_in(folder)
        .filter(|record| pattern.is_match(record.title()))
        .collect();
    records.sort_by_cached_key(|record| record.title().to_lowercase());
    let hits = match listing {
        Listing::All => folders.len() + records.len(),
        Listing::Folders => folders.len(),
        Listing::Records => records.len(),
    };
    match detail {
        Detail::Compact => {
            if !matches!(listing, Listing::Records) {
                for uid in &folders {
                    println!("{}/", vault.folders[*uid].name);
                }
            }
            if !matches!(listing, Listing::Folders) {
                for record in records {
                    println!("{}", record.title());
                }
            }
        }
        Detail::Full => {
            if !matches!(listing, Listing::Records) {
                let mut table = Table::new(&["folder_uid", "name", "flags"]);
                for uid in folders {
                    let folder = &vault.folders[uid];
                    let flags = match folder.kind {
                        FolderKind::User => "",
                        FolderKind::SharedFolder => "S",
                        FolderKind::SharedFolderFolder { .. } => "s",
                    };
                    table.push(vec![uid.to_string(), folder.name.clone(), flags.into()]);
                }
                table.print(crate::cli::Format::Table);
            }
            if !matches!(listing, Listing::Folders) {
                let mut table = Table::new(&["record_uid", "type", "title", "description", "shared"]);
                for record in records {
                    table.push(vec![
                        record.uid.to_string(),
                        record.record_type().into(),
                        Clipped(record.title(), 40).to_string(),
                        Clipped(&record.description(), 40).to_string(),
                        record.shared.to_string(),
                    ]);
                }
                table.print(crate::cli::Format::Table);
            }
        }
    }
    hits
}

#[derive(Args, Debug)]
pub struct Cd {
    #[arg(default_value = "/")]
    folder: String,
}

impl Run for Cd {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let target = {
            let view = app.view()?;
            view.vault
                .resolve_folder(view.cwd, &self.folder)
                .ok_or_else(|| crate::Error::Generic(format!("Invalid folder path: {}", self.folder)))?
        };
        let path = app.view()?.vault.path_of(&target);
        app.account.as_mut().ok_or(crate::Error::NotLoggedIn)?.cwd = target;
        println!("{path}");
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Tree {
    #[arg(short, long)]
    records: bool,
    #[arg(short, long)]
    verbose: bool,
    #[arg(default_value = ".")]
    folder:  String,
}

#[derive(Clone, Copy)]
enum Contents {
    Folders,
    FoldersAndRecords,
}

#[derive(Clone, Copy)]
enum Labels {
    Names,
    NamesAndUids,
}

impl Run for Tree {
    fn run(self, app: &mut App) -> crate::Result<()> {
        let contents = if self.records {
            Contents::FoldersAndRecords
        } else {
            Contents::Folders
        };
        let labels = if self.verbose {
            Labels::NamesAndUids
        } else {
            Labels::Names
        };
        let view = app.view()?;
        let root = view
            .vault
            .resolve_folder(view.cwd, &self.folder)
            .ok_or_else(|| crate::Error::Generic(format!("Invalid folder path: {}", self.folder)))?;
        println!("{}", label(view.vault.name_of(&root), &root, labels));
        render_tree(view.vault, &root, "", contents, labels);
        Ok(())
    }
}

fn label(name: &str, location: &Location, labels: Labels) -> String {
    match (labels, location) {
        (Labels::Names, _) | (_, Location::Root) => name.to_owned(),
        (Labels::NamesAndUids, Location::Folder(uid)) => format!("{name} ({uid})"),
    }
}

fn render_tree(vault: &crate::vault::Vault, folder: &Location, prefix: &str, contents: Contents, labels: Labels) {
    let folders = vault.subfolders_of(folder);
    let mut records: Vec<_> = match contents {
        Contents::Folders => Vec::new(),
        Contents::FoldersAndRecords => vault.records_in(folder).collect(),
    };
    records.sort_by_cached_key(|record| record.title().to_lowercase());
    let total = folders.len() + records.len();
    for (index, uid) in folders.iter().enumerate() {
        let last = index + 1 == total;
        let folder = &vault.folders[uid];
        let shared = if matches!(folder.kind, FolderKind::SharedFolder) {
            " [Shared]"
        } else {
            ""
        };
        println!(
            "{prefix}{}{shared}",
            if last {
                format!("└── {}", label(&folder.name, &Location::Folder(uid.clone()), labels))
            } else {
                format!("├── {}", label(&folder.name, &Location::Folder(uid.clone()), labels))
            }
        );
        render_tree(
            vault,
            &Location::Folder(uid.clone()),
            &format!("{prefix}{}", if last { "    " } else { "│   " }),
            contents,
            labels,
        );
    }
    for (index, record) in records.iter().enumerate() {
        let last = folders.len() + index + 1 == total;
        println!(
            "{prefix}{}",
            if last {
                format!("└── {}", label(record.title(), &Location::Folder(record.uid.clone()), labels))
            } else {
                format!("├── {}", label(record.title(), &Location::Folder(record.uid.clone()), labels))
            }
        );
    }
}
