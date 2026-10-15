use std::collections::BTreeSet;

use clap::CommandFactory;
use serde_json::json;

use super::*;
use crate::cli::{Cli, Command};
use crate::vault::{Folder, Record, SharedFolder};

fn id(n: u8) -> String {
    b64_encode(&[n; 16])
}

fn uid(n: u8) -> Uid {
    id(n).parse().unwrap()
}

const WORK: u8 = 1;
const TEAM: u8 = 2;
const DEEP: u8 = 3;
const DB: u8 = 11;
const SHARED: u8 = 12;
const LOOSE: u8 = 13;

fn team_key() -> Vec<u8> {
    vec![9; 32]
}

fn record(n: u8, version: i32, title: &str) -> (String, Record) {
    (
        id(n),
        Record {
            uid: id(n),
            version,
            revision: 7,
            data: json!({"type": "login", "title": title, "fields": [{"type": "login", "value": ["me"]}]}),
            key: vec![n; 32],
            owner: n != SHARED,
            ..Record::default()
        },
    )
}

/// Root: Work (private) holding "DB Admin"; Team (shared) with subfolder Deep holding "Shared Rec";
/// "Loose" sits at the root.
fn vault() -> Vault {
    let mut v = Vault::default();
    let folder = |n: u8, kind, name: &str, parent: Option<u8>, shared: Option<u8>, kids: &[u8]| {
        (
            id(n),
            Folder {
                uid: id(n),
                kind,
                name: name.into(),
                parent: parent.map(id),
                subfolders: kids.iter().copied().map(id).collect(),
                shared_folder_uid: shared.map(id),
                ..Folder::default()
            },
        )
    };
    v.folders.extend([
        folder(WORK, FolderKind::User, "Work", None, None, &[]),
        folder(TEAM, FolderKind::SharedFolder, "Team", None, Some(TEAM), &[DEEP]),
        folder(DEEP, FolderKind::SharedFolderFolder, "Deep", Some(TEAM), Some(TEAM), &[]),
    ]);
    v.root_folders = vec![id(WORK), id(TEAM)];
    v.shared_folders.insert(
        id(TEAM),
        SharedFolder {
            uid:                    id(TEAM),
            name:                   "Team".into(),
            record_uids:            vec![],
            users:                  vec![],
            teams:                  vec![],
            default_manage_records: true,
            default_manage_users:   true,
            default_can_edit:       true,
            default_can_share:      true,
            key:                    team_key(),
        },
    );
    v.records.extend([
        record(DB, 3, "DB Admin"),
        record(SHARED, 3, "Shared Rec"),
        record(LOOSE, 3, "Loose"),
    ]);
    v.folder_records.insert(id(WORK), BTreeSet::from([id(DB)]));
    v.folder_records.insert(id(DEEP), BTreeSet::from([id(SHARED)]));
    v.folder_records.insert(String::new(), BTreeSet::from([id(LOOSE)]));
    v
}

fn new_record() -> New {
    let mut body = Body {
        type_name: "login".into(),
        title: "Bank".into(),
        notes: "n".into(),
        ..Body::default()
    };
    body.fields.push(field::Field {
        ty: "login".into(),
        label: "login".into(),
        value: vec![json!("bob")],
        ..field::Field::default()
    });
    New {
        uid: uid(40),
        key: crypto::random_bytes(32),
        body,
    }
}

// --- add and update requests ---

#[test]
fn add_at_the_root_wraps_the_record_key_with_the_data_key_only() {
    let data_key = crypto::random_bytes(32);
    let new = new_record();
    let add = record_add(&data_key, &new, &Placement::Root, vec![], 1234).unwrap();

    assert_eq!(add.record_uid, vec![40; 16]);
    assert_eq!(crypto::decrypt_aes_v2(&add.record_key, &data_key).unwrap(), new.key);
    assert_eq!(add.client_modified_time, 1234);
    assert_eq!(add.folder_type, pb::RecordFolderType::UserFolder as i32);
    assert!(add.folder_uid.is_empty() && add.folder_key.is_empty() && add.record_links.is_empty());

    // The data is the record JSON under the record key, padded the way Commander pads it.
    let data = crypto::decrypt_aes_v2(&add.data, &new.key).unwrap();
    assert_eq!((data.len() % 16, data.len() >= 384), (0, true));
    assert_eq!(serde_json::from_slice::<Body>(&data).unwrap(), new.body);
    assert!(crypto::decrypt_aes_v2(&add.data, &data_key).is_err());
}

#[test]
fn add_to_a_private_folder_names_the_folder_without_a_folder_key() {
    let data_key = crypto::random_bytes(32);
    let add = record_add(&data_key, &new_record(), &Placement::Private(uid(WORK)), vec![], 1).unwrap();
    assert_eq!(add.folder_type, pb::RecordFolderType::UserFolder as i32);
    assert_eq!(add.folder_uid, vec![WORK; 16]);
    assert!(add.folder_key.is_empty());
}

#[test]
fn add_to_a_shared_folder_also_wraps_the_record_key_with_the_shared_folder_key() {
    let data_key = crypto::random_bytes(32);
    let new = new_record();
    for (kind, wire) in [
        (pb::RecordFolderType::SharedFolder, 1),
        (pb::RecordFolderType::SharedFolderFolder, 2),
    ] {
        let place = Placement::Shared {
            folder: uid(DEEP),
            kind,
            key: team_key(),
        };
        let add = record_add(&data_key, &new, &place, vec![], 1).unwrap();
        assert_eq!(add.folder_type, wire);
        assert_eq!(add.folder_uid, vec![DEEP; 16]);
        assert_eq!(crypto::decrypt_aes_v2(&add.folder_key, &team_key()).unwrap(), new.key);
        // The user's own copy of the key is still there.
        assert_eq!(crypto::decrypt_aes_v2(&add.record_key, &data_key).unwrap(), new.key);
    }
}

#[test]
fn linked_records_are_attached_with_their_key_wrapped_by_the_new_record_key() {
    let v = vault();
    let key = crypto::random_bytes(32);
    let refs = BTreeSet::from([id(DB), id(SHARED), "not-in-this-vault".to_owned()]);
    let links = links(&v, &key, &refs).unwrap();
    assert_eq!(links.len(), 2);
    for link in &links {
        let n = link.record_uid[0];
        assert!([DB, SHARED].contains(&n));
        assert_eq!(crypto::decrypt_aes_v2(&link.record_key, &key).unwrap(), vec![n; 32]);
    }
    let add = record_add(&crypto::random_bytes(32), &new_record(), &Placement::Root, links, 1).unwrap();
    assert_eq!(add.record_links.len(), 2);
}

#[test]
fn update_carries_the_revision_the_vault_holds_and_the_link_changes() {
    let key = crypto::random_bytes(32);
    let mut old = Existing {
        uid:      uid(DB),
        key:      key.clone(),
        revision: 7,
        body:     new_record().body,
    };
    old.body.title = "Renamed".into();
    let added = links(&vault(), &key, &BTreeSet::from([id(SHARED)])).unwrap();
    let ru = record_update(&old, added, vec![vec![5; 16]], 99).unwrap();

    assert_eq!(ru.record_uid, vec![DB; 16]);
    assert_eq!((ru.revision, ru.client_modified_time), (7, 99));
    let data = crypto::decrypt_aes_v2(&ru.data, &key).unwrap();
    assert_eq!(serde_json::from_slice::<Body>(&data).unwrap().title, "Renamed");
    assert_eq!(ru.record_links_add.len(), 1);
    assert_eq!(ru.record_links_add[0].record_uid, vec![SHARED; 16]);
    assert_eq!(ru.record_links_remove, vec![vec![5; 16]]);
    // An update never re-sends or re-keys the record.
    assert!(ru.non_shared_data.is_empty() && ru.audit.is_none());
}

#[test]
fn security_data_is_encrypted_to_the_ecc_key_only_when_rsa_is_forbidden() {
    let mut summary = AccountSummaryElements::default();
    assert_eq!(pb::RecordKeyType::from(&summary), pb::RecordKeyType::EncryptedByPublicKey);
    summary.forbid_key_type2 = true;
    assert_eq!(pb::RecordKeyType::from(&summary), pb::RecordKeyType::EncryptedByPublicKeyEcc);
}

#[test]
fn the_servers_verdict_becomes_an_api_error_with_its_status_name() {
    let status = |code: i32| {
        pb::RecordsModifyResponse {
            records:  vec![pb::RecordModifyStatus {
                record_uid:  vec![DB; 16],
                status:      code,
                message:     "stale revision".into(),
                link_errors: vec![],
            }],
            revision: 8,
        }
    };
    assert!(verdict(&status(0), &uid(DB)).is_ok());
    let e = verdict(&status(1), &uid(DB)).unwrap_err();
    assert!(
        matches!(&e, Error::Api { code, message } if code == "RS_OUT_OF_SYNC" && message == "stale revision"),
        "{e:?}"
    );
    let e = verdict(&status(99), &uid(DB)).unwrap_err();
    assert!(matches!(&e, Error::Api { code, .. } if code == "99"), "{e:?}");
    // Other records' statuses and an empty response aren't this record's failure.
    assert!(verdict(&status(1), &uid(LOOSE)).is_ok());
    assert!(verdict(&pb::RecordsModifyResponse::default(), &uid(DB)).is_ok());
}

// --- vault lookups ---

#[test]
fn folders_resolve_to_the_placement_commander_uses() {
    let v = vault();
    assert_eq!(placement(&v, "", "/").unwrap(), Placement::Root);
    assert_eq!(placement(&v, "", "Work").unwrap(), Placement::Private(uid(WORK)));
    assert_eq!(placement(&v, "", &id(WORK)).unwrap(), Placement::Private(uid(WORK)));
    assert_eq!(
        placement(&v, "", "Team").unwrap(),
        Placement::Shared {
            folder: uid(TEAM),
            kind:   pb::RecordFolderType::SharedFolder,
            key:    team_key(),
        }
    );
    // A subfolder of a shared folder is wrapped with the shared folder's key, not its own.
    assert_eq!(
        placement(&v, "", "/Team/Deep").unwrap(),
        Placement::Shared {
            folder: uid(DEEP),
            kind:   pb::RecordFolderType::SharedFolderFolder,
            key:    team_key(),
        }
    );
    assert_eq!(placement(&v, &id(TEAM), "Deep").unwrap(), placement(&v, "", "Team/Deep").unwrap());
    assert_eq!(placement(&v, "", "Nope").unwrap_err().to_string(), "Folder not found: Nope");
}

#[test]
fn only_typed_records_can_be_edited() {
    let mut v = vault();
    v.records
        .extend([record(20, 2, "Old"), record(21, 4, "File"), record(22, 6, "Pam Config")]);
    let e = |n: u8| existing(&v, "", &id(n)).map(|r| r.uid.to_string());

    let ok = existing(&v, "", "Work/db admin").unwrap();
    assert_eq!((ok.uid, ok.revision, ok.key), (uid(DB), 7, vec![DB; 32]));
    assert_eq!(ok.body.title, "DB Admin");
    assert_eq!(e(22).unwrap(), id(22));
    assert!(
        e(20)
            .unwrap_err()
            .to_string()
            .starts_with("Legacy record type is not supported.")
    );
    assert_eq!(e(21).unwrap_err().to_string(), format!("Record \"{}\" can not be edited.", id(21)));
    assert_eq!(existing(&v, "", "nothing").unwrap_err().to_string(), "Record \"nothing\" not found.");
}

#[test]
fn rm_finds_records_by_uid_path_or_title_and_every_folder_they_are_in() {
    let mut v = vault();
    let filing = |n: u8, origin| Filing { record: id(n), origin };

    // By UID: every folder holding it.
    v.folder_records.insert(id(TEAM), BTreeSet::from([id(DB)]));
    assert_eq!(
        find(&v, "", &id(DB)).unwrap(),
        [
            filing(DB, Origin::Private(id(WORK))),
            filing(DB, Origin::Shared(id(TEAM)))
        ]
    );
    v.folder_records.remove(&id(TEAM));

    assert_eq!(find(&v, "", &id(LOOSE)).unwrap(), [filing(LOOSE, Origin::Root)]);
    assert_eq!(find(&v, "", &id(SHARED)).unwrap(), [filing(SHARED, Origin::Shared(id(DEEP)))]);
    // A record that no folder lists is treated as sitting at the root.
    v.records.extend([record(30, 3, "Orphan")]);
    assert_eq!(find(&v, "", &id(30)).unwrap(), [filing(30, Origin::Root)]);

    // By path (case-insensitive title), relative or absolute, only that folder.
    assert_eq!(find(&v, "", "Work/db admin").unwrap(), [filing(DB, Origin::Private(id(WORK)))]);
    assert_eq!(find(&v, "", "/Team/Deep/Shared Rec").unwrap(), [filing(SHARED, Origin::Shared(id(DEEP)))]);
    assert_eq!(find(&v, &id(WORK), "DB Admin").unwrap(), [filing(DB, Origin::Private(id(WORK)))]);
    assert_eq!(find(&v, "", "/Loose").unwrap(), [filing(LOOSE, Origin::Root)]);
    assert_eq!(find(&v, "", &format!("Work/{}", id(DB))).unwrap(), [filing(DB, Origin::Private(id(WORK)))]);

    // A bare title that isn't in the current folder falls back to the whole vault.
    assert_eq!(find(&v, "", "shared rec").unwrap(), [filing(SHARED, Origin::Shared(id(DEEP)))]);
}

#[test]
fn rm_refuses_names_that_match_nothing_or_several_records() {
    let mut v = vault();
    let e = find(&v, "", "Ghost").unwrap_err().to_string();
    assert_eq!(e, "No record found matching \"Ghost\". Provide a valid record title, path, or UID.");
    assert!(find(&v, "", "Work/Ghost").is_err());

    v.records.extend([record(31, 3, "Twin"), record(32, 3, "Twin")]);
    v.folder_records.insert(id(WORK), BTreeSet::from([id(DB), id(31)]));
    v.folder_records.insert(id(DEEP), BTreeSet::from([id(SHARED), id(32)]));
    let e = find(&v, "", "Twin").unwrap_err().to_string();
    assert_eq!(
        e,
        format!("\"Twin\" matches 2 records. Use a UID to identify the record:\n  {}\n  {}", id(31), id(32))
    );
    // Naming the folder picks one.
    assert_eq!(find(&v, "", "Work/Twin").unwrap().len(), 1);
}

#[test]
fn names_split_at_the_last_unescaped_slash() {
    for (name, want) in [
        ("Title", ("", "Title")),
        ("A/B/Title", ("A/B", "Title")),
        ("/Title", ("/", "Title")),
        ("/A/Title", ("/A", "Title")),
        ("A//B", ("", "A/B")),
        ("A//B/C//D", ("A//B", "C/D")),
    ] {
        let got = Name::from(name);
        assert_eq!((got.folder.as_str(), got.title.as_str()), want, "{name}");
    }
}

#[test]
fn pre_delete_names_the_folder_the_way_commander_does() {
    let doomed = |origin| {
        serde_json::to_value(Doomed::from(&Filing {
            record: "R".into(),
            origin,
        }))
        .unwrap()
    };
    assert_eq!(
        doomed(Origin::Root),
        json!({"delete_resolution": "unlink", "object_uid": "R", "object_type": "record", "from_type": "user_folder"})
    );
    assert_eq!(
        doomed(Origin::Private("F".into())),
        json!({"delete_resolution": "unlink", "object_uid": "R", "object_type": "record", "from_type": "user_folder", "from_uid": "F"})
    );
    // Shared folders and their subfolders are both "shared_folder_folder" on the wire.
    assert_eq!(
        doomed(Origin::Shared("F".into())),
        json!({"delete_resolution": "unlink", "object_uid": "R", "object_type": "record", "from_type": "shared_folder_folder", "from_uid": "F"})
    );
}

// --- ids ---

#[test]
fn uids_are_16_bytes_of_unpadded_url_safe_base64_that_never_start_like_an_option() {
    for _ in 0..4000 {
        let uid = Uid::random();
        let text = uid.to_string();
        assert_eq!(text.len(), 22);
        assert!(!text.starts_with(['-', '_']), "{text}");
        assert_eq!(text.parse::<Uid>().unwrap(), uid);
        assert_eq!(Vec::from(&uid), b64_decode(&text).unwrap());
    }
    assert!("short".parse::<Uid>().is_err());
    assert!("!!!".parse::<Uid>().is_err());
}

// --- command line ---

#[test]
fn commander_names_and_aliases_are_registered() {
    let root = Cli::command();
    for (name, alias) in [("record-add", "ra"), ("record-update", "ru"), ("append-notes", "an")] {
        assert!(root.find_subcommand(name).is_some(), "{name}");
        assert_eq!(root.find_subcommand(alias).map(|c| c.get_name()), Some(name), "{alias}");
    }
    assert!(root.find_subcommand("rm").is_some());
}

fn raw(cli: &[&str]) -> Vec<String> {
    match Cli::try_parse_from(cli).unwrap().command {
        Some(Command::RecordAdd(c)) => c.args,
        Some(Command::RecordUpdate(c)) => c.args,
        other => panic!("{other:?}"),
    }
}

#[test]
fn record_add_options_reach_the_second_parser_untouched() {
    let args = raw(&[
        "keeper-cli",
        "ra",
        "-t",
        "My Title",
        "-rt",
        "login",
        "--folder=Work",
        "-n",
        "- dash",
        "login=bob",
        "url=https://x",
    ]);
    let opts = parse::<AddOpts>(&args).unwrap().unwrap();
    assert_eq!(opts.title.as_deref(), Some("My Title"));
    assert_eq!(opts.record_type.as_deref(), Some("login"));
    assert_eq!(opts.folder.as_deref(), Some("Work"));
    assert_eq!(opts.notes.as_deref(), Some("- dash"));
    assert_eq!(opts.fields, ["login=bob", "url=https://x"]);
}

#[test]
fn rt_works_in_every_spelling_and_position() {
    for args in [
        &["-rt", "pamUser", "-t", "T"][..],
        &["-t", "T", "-rt=pamUser"],
        &["-t", "T", "--record-type", "pamUser"],
        &["-t", "T", "--record-type=pamUser"],
    ] {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let opts = parse::<AddOpts>(&args).unwrap().unwrap();
        assert_eq!(opts.record_type.as_deref(), Some("pamUser"), "{args:?}");
    }
    // A field or title that merely starts with "-rt" is left alone.
    let args = raw(&["keeper-cli", "ra", "-t", "-rtx", "-rt", "login"]);
    assert_eq!(parse::<AddOpts>(&args).unwrap().unwrap().title.as_deref(), Some("-rtx"));

    let args = raw(&["keeper-cli", "ru", "-r", "UID", "-rt", "login", "-f", "-n", "+more"]);
    let opts = parse::<UpdateOpts>(&args).unwrap().unwrap();
    assert_eq!(
        (opts.record.as_deref(), opts.record_type.as_deref(), opts.force),
        (Some("UID"), Some("login"), true)
    );
    assert_eq!(opts.notes.as_deref(), Some("+more"));
}

#[test]
fn help_and_usage_errors_do_not_need_a_login() {
    assert!(parse::<AddOpts>(&["--help".to_owned()]).unwrap().is_none());
    assert!(parse::<UpdateOpts>(&["-h".to_owned()]).unwrap().is_none());
    let e = parse::<AddOpts>(&["--bogus".to_owned()]).unwrap_err().to_string();
    assert!(e.starts_with("unexpected argument '--bogus'"), "{e}");
    let e = parse::<AddOpts>(&["--labels".to_owned(), "maybe".to_owned()])
        .unwrap_err()
        .to_string();
    assert!(e.contains("possible values: on, off"), "{e}");
}

#[test]
fn rm_and_append_notes_take_commanders_flags() {
    let cli = Cli::try_parse_from(["keeper-cli", "rm", "-f", "--purge", "a", "b"]).unwrap();
    let Some(Command::Rm(rm)) = cli.command else { panic!() };
    assert_eq!((rm.force, rm.purge, rm.records.as_slice()), (true, true, &["a".to_owned(), "b".to_owned()][..]));
    assert_eq!((Removal::from(rm.purge), Confirm::from(rm.force)), (Removal::Purge, Confirm::Skip));
    assert_eq!((Removal::from(false), Confirm::from(false)), (Removal::Unlink, Confirm::Ask));

    let cli = Cli::try_parse_from(["keeper-cli", "an", "--notes", "- more", "UID"]).unwrap();
    let Some(Command::AppendNotes(an)) = cli.command else {
        panic!()
    };
    assert_eq!((an.notes.as_deref(), an.record.as_deref()), (Some("- more"), Some("UID")));
}

fn add_opts(args: &[&str]) -> Result<Add> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    Add::try_from(parse::<AddOpts>(&args)?.unwrap())
}

#[test]
fn record_add_validates_before_it_touches_the_network() {
    let add = add_opts(&[
        "-t",
        "T",
        "-rt",
        "login",
        "-n",
        r"a\nb",
        "-f",
        "--folder",
        "Work",
        "login=bob",
        "  ",
        "Pin=1",
    ])
    .unwrap();
    assert_eq!((add.title.as_str(), add.record_type.as_str(), add.notes.as_str()), ("T", "login", "a\nb"));
    assert_eq!(add.specs.len(), 2);
    assert!(matches!(&add.destination, Destination::Folder(f) if f == "Work"));
    assert_eq!((add.warnings, add.labels, add.format), (Warnings::Ignore, Labels::On, OutputFormat::Text));
    assert!(matches!(add_opts(&["-t", "T", "-rt", "login"]).unwrap().destination, Destination::Root));
    // An empty --folder means the root too.
    assert!(matches!(
        add_opts(&["-t", "T", "-rt", "login", "--folder", ""])
            .unwrap()
            .destination,
        Destination::Root
    ));

    for (args, why) in [
        (&["-rt", "login"][..], "Title parameter is required."),
        (&["-t", "", "-rt", "login"], "Title parameter is required."),
        (&["-t", "T"], "Record type parameter is required."),
        (&["-t", "T", "-rt", "legacy"], "Legacy record type is not supported."),
        (&["-t", "T", "-rt", "login", "oops"], "Expected: <field>=<value>, got: oops; Missing `=`"),
        (&["-t", "T", "-rt", "login", "file=@x.txt"], "File attachments (file=@path) are not supported yet"),
    ] {
        assert_eq!(add_opts(args).err().map(|e| e.to_string()).as_deref(), Some(why), "{args:?}");
    }
}

#[test]
fn record_update_needs_a_record_and_reads_notes_and_title_edits() {
    let edit = |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        Edit::try_from(parse::<UpdateOpts>(&args).unwrap().unwrap())
    };
    let e = edit(&["-t", "x"]).err().unwrap().to_string();
    assert_eq!(e, "Record parameter is required.");

    let e = edit(&["-r", "R", "-t", "New", "-n", "+tail", "-rt", "bankCard", "Pin=1"]).unwrap();
    assert_eq!(
        (e.record.as_str(), e.title.as_deref(), e.record_type.as_deref()),
        ("R", Some("New"), Some("bankCard"))
    );
    assert_eq!(e.notes, Some(NotesEdit::Append("tail".into())));
    assert_eq!((e.specs.len(), e.warnings), (1, Warnings::Heed));

    // An empty title or type means "unchanged"; empty notes mean "clear them".
    let e = edit(&["-r", "R", "-t", "", "-rt", "", "-n", ""]).unwrap();
    assert_eq!((e.title, e.record_type, e.notes), (None, None, Some(NotesEdit::Replace(String::new()))));
}

#[test]
fn warnings_stop_the_command_unless_forced_and_errors_always_do() {
    let warned = || {
        Findings {
            warnings: vec!["w".into()],
            errors:   vec![],
        }
    };
    assert!(settle(Findings::default(), Warnings::Heed).is_ok());
    assert!(
        settle(warned(), Warnings::Heed)
            .unwrap_err()
            .to_string()
            .starts_with("Nothing was saved.")
    );
    assert!(settle(warned(), Warnings::Ignore).is_ok());
    let errors = Findings {
        warnings: vec![],
        errors:   vec!["a".into(), "b".into()],
    };
    assert_eq!(settle(errors, Warnings::Ignore).unwrap_err().to_string(), "a\nb");
}

#[test]
fn syntax_help_is_available_without_a_login() {
    let mut app = App::new(
        crate::config::Config::load(std::env::temp_dir().join("keeper-cli-record-edit-test.json")).unwrap(),
        None,
        None,
    );
    let args = vec!["--syntax-help".to_owned()];
    RecordAdd { args: args.clone() }.run(&mut app).unwrap();
    RecordUpdate { args }.run(&mut app).unwrap();
    assert!(app.session.is_none());
    assert!(SYNTAX_HELP.contains("$GEN") && SYNTAX_HELP.contains("$BASE64") && SYNTAX_HELP.contains("$JSON"));
}
