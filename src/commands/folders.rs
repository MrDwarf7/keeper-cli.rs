use clap::Args;

use super::{App, Clipped, Detail, Run, Table};
use crate::folder_edit::{Case, Glob};
use crate::vault::{FolderKind, Location, PathResolution};

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
        let mut tail = None;
        let root = match view.vault.resolve_path(view.cwd, &self.pattern) {
            PathResolution::Full(root) => root,
            PathResolution::Partial {
                parent,
                tail: unresolved,
            } => {
                tail = Some(unresolved.to_string());
                parent
            }
        };
        let pattern = Glob::new(tail.as_deref().unwrap_or("*"), Case::Ignore);
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
        if hits == 0
            && let Some(tail) = tail
        {
            return Err(crate::Error::Generic(format!("{tail}: No such folder or record")));
        }
        Ok(())
    }
}

fn list_one(vault: &crate::vault::Vault, folder: &Location, pattern: &Glob, listing: Listing, detail: Detail) -> usize {
    let folders: Vec<_> = vault
        .subfolders_of(folder)
        .iter()
        .filter_map(|uid| {
            vault
                .folders
                .get(uid)
                .filter(|folder| pattern.is_match(&folder.name) || pattern.is_match(uid.as_ref()))
                .map(|folder| (uid, folder))
        })
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
                for (_, folder) in &folders {
                    println!("{}/", folder.name);
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
                for (uid, folder) in folders {
                    let flags = match folder.kind {
                        FolderKind::User => "",
                        FolderKind::SharedFolder => "S",
                        FolderKind::SharedFolderFolder { .. } => "s",
                    };
                    table.push([uid.to_string(), folder.name.clone(), flags.into()]);
                }
                table.print(crate::cli::Format::Table);
            }
            if !matches!(listing, Listing::Folders) {
                let mut table = Table::new(&["record_uid", "type", "title", "description", "shared"]);
                for record in records {
                    table.push([
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
            Location::try_from(view.vault.resolve_path(view.cwd, &self.folder))
                .map_err(|_| crate::Error::Generic(format!("Invalid folder path: {}", self.folder)))?
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
        let root = Location::try_from(view.vault.resolve_path(view.cwd, &self.folder))
            .map_err(|_| crate::Error::Generic(format!("Invalid folder path: {}", self.folder)))?;
        let name = view
            .vault
            .folder(&root)
            .map_or("My Vault", |folder| folder.name.as_str());
        println!("{}", label(name, &root, labels));
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
    let folders: Vec<_> = vault
        .subfolders_of(folder)
        .iter()
        .filter_map(|uid| vault.folders.get(uid).map(|folder| (uid, folder)))
        .collect();
    let mut records: Vec<_> = match contents {
        Contents::Folders => Vec::new(),
        Contents::FoldersAndRecords => vault.records_in(folder).collect(),
    };
    records.sort_by_cached_key(|record| record.title().to_lowercase());
    let total = folders.len() + records.len();
    for (index, (uid, folder)) in folders.iter().enumerate() {
        let last = index + 1 == total;
        let shared = if matches!(folder.kind, FolderKind::SharedFolder) {
            " [Shared]"
        } else {
            ""
        };
        println!(
            "{prefix}{}{shared}",
            if last {
                format!("└── {}", label(&folder.name, &Location::Folder((*uid).clone()), labels))
            } else {
                format!("├── {}", label(&folder.name, &Location::Folder((*uid).clone()), labels))
            }
        );
        render_tree(
            vault,
            &Location::Folder((*uid).clone()),
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
