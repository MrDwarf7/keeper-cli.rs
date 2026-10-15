//! `clipboard-copy` and `find-password`: put one value of a record on the clipboard, or print it.
//!
//! No clipboard crate: every platform ships a tool that takes the text on stdin (`pbcopy`,
//! `clip.exe`, `wl-copy`, `xclip`, `xsel`), and the secret never appears in a command line.
//!
//! ponytail: `--username` is a case-insensitive prefix and the fallback search is the plain
//! all-words match of `search`, where Commander compiles both as regular expressions.

use std::fmt;
use std::io::{ErrorKind, Write};
use std::process::{Command as Process, Stdio};

use clap::{Args, ValueEnum};
use serde_json::Value;

use crate::commands::{App, Run, resolve_record};
use crate::prelude::*;
use crate::totp::Totp;
use crate::vault::{Record, Vault};

/// Copy a record's password, login, TOTP code or a field to the clipboard
#[derive(Args, Debug)]
pub struct ClipboardCopy {
    /// Only a record whose login name starts with this (ignoring case)
    #[arg(long)]
    username: Option<String>,
    /// Where the value goes
    #[arg(long, value_enum, default_value_t)]
    output:   Output,
    /// Output the record UID instead of the password
    #[arg(long)]
    copy_uid: bool,
    /// Output the login name
    #[arg(short, long)]
    login:    bool,
    /// Output the current TOTP code
    #[arg(short, long)]
    totp:     bool,
    /// Output a field: `notes`, a label or field type, `type.label`; `name:property` picks one
    /// part of a composite value (`host:port`)
    #[arg(long)]
    field:    Option<String>,
    /// Record UID, path, title or words to search for
    record:   String,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Output {
    #[default]
    Clipboard,
    Stdout,
    /// Red on red, readable only when selected
    #[value(name = "stdouthidden")]
    StdoutHidden,
}

/// What to take from the record. Commander's flags are not exclusive: the first one set wins, in
/// this order.
enum Item<'a> {
    Uid,
    Login,
    Totp,
    Field(&'a str),
    Password,
}

impl<'a> From<&'a ClipboardCopy> for Item<'a> {
    fn from(args: &'a ClipboardCopy) -> Self {
        if args.copy_uid {
            Self::Uid
        } else if args.login {
            Self::Login
        } else if args.totp {
            Self::Totp
        } else if let Some(name) = args.field.as_deref().filter(|name| !name.is_empty()) {
            Self::Field(name)
        } else {
            Self::Password
        }
    }
}

impl fmt::Display for Item<'_> {
    /// The noun in "<item> copied to clipboard".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uid => f.write_str("Record UID"),
            Self::Login => f.write_str("Login"),
            Self::Totp => f.write_str("TOTP Code"),
            Self::Field("notes") => f.write_str("Notes"),
            Self::Field(name) => write!(f, "Field \"{name}\""),
            Self::Password => f.write_str("Password"),
        }
    }
}

impl Item<'_> {
    /// The text to hand over; an absent or empty value is an error rather than a silent no-op.
    fn text(&self, record: &Record) -> Result<String> {
        let text = match self {
            Self::Uid => Some(record.uid.clone()),
            Self::Login => login(record).map(str::to_owned),
            Self::Totp => {
                record
                    .totp_url()
                    .map(|url| Totp::parse(url).and_then(|totp| totp.code_now()).map(|(code, _)| code))
                    .transpose()?
            }
            Self::Field(spec) => field_text(record, spec),
            Self::Password => record.password().map(str::to_owned),
        };
        text.filter(|text| !text.is_empty())
            .ok_or_else(|| Error::Generic(format!("{self} not found in record \"{}\"", record.title())))
    }
}

/// Which logins `--username` admits.
enum Who {
    Anyone,
    LoginStartsWith(String),
}

impl Who {
    fn admits(&self, record: &Record) -> bool {
        match self {
            Self::Anyone => true,
            Self::LoginStartsWith(prefix) => {
                login(record).is_some_and(|login| login.to_lowercase().starts_with(&prefix.to_lowercase()))
            }
        }
    }
}

/// A record's login name; typed records without a `login` field may have an `email` instead.
fn login(record: &Record) -> Option<&str> {
    record.login().or_else(|| {
        record
            .typed_fields()
            .find(|field| field.field_type() == "email")
            .and_then(|field| field.values().first())
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
    })
}

/// `--field`: `notes`; a legacy record's custom field by name; on typed records a field's label or
/// type, `type.label`, and `name:property` for one key of a composite value.
fn field_text(record: &Record, spec: &str) -> Option<String> {
    if spec == "notes" {
        return Some(record.notes().to_owned());
    }
    let (name, property) = spec.rsplit_once(':').unwrap_or((spec, ""));
    if record.version == 2 {
        return record
            .display_fields()
            .into_iter()
            .find(|field| field.label.eq_ignore_ascii_case(name))
            .map(|field| field.value);
    }
    let (kind, label) = name.split_once('.').unwrap_or((name, ""));
    let field = record
        .typed_fields()
        .find(|field| field.field_type() == kind && (label.is_empty() || field.label().eq_ignore_ascii_case(label)))
        .or_else(|| {
            record
                .typed_fields()
                .find(|field| field.label().eq_ignore_ascii_case(name))
        })?;
    let text = |value: &Value| value.as_str().map_or_else(|| value.to_string(), str::to_owned);
    let parts: Option<Vec<String>> = field
        .values()
        .iter()
        .map(|value| {
            match (value, property) {
                (Value::Object(parts), property) if !property.is_empty() => {
                    parts
                        .iter()
                        .find(|(key, _)| key.to_lowercase().starts_with(&property.to_lowercase()))
                        .map(|(_, part)| text(part))
                }
                _ => Some(text(value)),
            }
        })
        .collect();
    parts.map(|parts| parts.join("\n"))
}

/// The record a command line names: a UID, a path or title (which must satisfy `who`), or else the
/// one record the words match.
fn pick<'v>(vault: &'v Vault, cwd: &str, spec: &str, who: &Who) -> Result<&'v Record> {
    if let Some(record) = vault.records.get(spec) {
        return Ok(record);
    }
    if let Some(record) = resolve_record(vault, cwd, spec).filter(|record| who.admits(record)) {
        return Ok(record);
    }
    let words: Vec<String> = spec.split_whitespace().map(str::to_owned).collect();
    // Password, typed and PAM configuration records; not files or apps
    let mut found: Vec<&Record> = vault
        .records
        .values()
        .filter(|record| matches!(record.version, 2 | 3 | 6) && who.admits(record) && record.matches(&words))
        .collect();
    if found.len() > 1 {
        let titled: Vec<&Record> = found
            .iter()
            .copied()
            .filter(|record| record.title().to_lowercase().contains(&spec.to_lowercase()))
            .collect();
        if titled.len() == 1 {
            found = titled;
        }
    }
    match found.as_slice() {
        [record] => Ok(record),
        [] => Err(Error::Generic("Enter name or uid of existing record".into())),
        _ => Err(Error::Generic(format!("More than one record are found for search criteria: {spec}"))),
    }
}

impl Run for ClipboardCopy {
    fn run(self, app: &mut App) -> Result<()> {
        let cwd = app.cwd.clone();
        let vault = app.vault()?;
        let item = Item::from(&self);
        let who = self
            .username
            .as_ref()
            .map_or(Who::Anyone, |prefix| Who::LoginStartsWith(prefix.clone()));
        let record = pick(vault, &cwd, &self.record, &who)?;
        let text = item.text(record)?;
        match self.output {
            Output::Clipboard => {
                send_to_clipboard(&text)?;
                eprintln!("Record Title: {}", record.title());
                eprintln!("{item} copied to clipboard");
            }
            Output::Stdout => println!("{text}"),
            Output::StdoutHidden => println!("\x1b[31m\x1b[41m{text}\x1b[0m"),
        }
        Ok(())
    }
}

/// How a clipboard tool wants its text on stdin.
#[derive(Clone, Copy)]
enum Encoding {
    Utf8,
    /// Windows' `clip` reads the console code page unless the text is UTF-16LE led by a byte
    /// order mark.
    Utf16,
}

impl Encoding {
    fn encode(self, text: &str) -> Vec<u8> {
        match self {
            Self::Utf8 => text.as_bytes().to_vec(),
            Self::Utf16 => {
                std::iter::once(0xFEFF)
                    .chain(text.encode_utf16())
                    .flat_map(u16::to_le_bytes)
                    .collect()
            }
        }
    }
}

/// A program that reads clipboard text from stdin.
struct Tool {
    program: &'static str,
    args:    &'static [&'static str],
    wants:   Encoding,
}

/// In order of preference: a tool that is missing, or fails (`wl-copy` outside Wayland), hands
/// over to the next, so one list serves every platform.
const TOOLS: &[Tool] = &[
    Tool {
        program: "pbcopy",
        args:    &[],
        wants:   Encoding::Utf8,
    },
    Tool {
        program: "clip.exe",
        args:    &[],
        wants:   Encoding::Utf16,
    },
    Tool {
        program: "wl-copy",
        args:    &[],
        wants:   Encoding::Utf8,
    },
    Tool {
        program: "xclip",
        args:    &["-selection", "clipboard"],
        wants:   Encoding::Utf8,
    },
    Tool {
        program: "xsel",
        args:    &["--clipboard", "--input"],
        wants:   Encoding::Utf8,
    },
];

/// Puts `text` on the system clipboard with the first of [`TOOLS`] that works.
fn send_to_clipboard(text: &str) -> Result<()> {
    for tool in TOOLS {
        let spawned = Process::new(tool.program)
            .args(tool.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if let Some(mut stdin) = child.stdin.take() {
            // A tool that quits early (no display) closes the pipe; its exit status says so
            let _ = stdin.write_all(&tool.wants.encode(text));
        }
        if child.wait()?.success() {
            return Ok(());
        }
    }
    let tried: Vec<&str> = TOOLS.iter().map(|tool| tool.program).collect();
    Err(Error::Generic(format!(
        "no clipboard tool worked (tried {}); use --output stdout instead",
        tried.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde_json::json;

    use super::*;
    use crate::cli::{Command, ShellLine};

    const TOTP_URL: &str = "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn typed(uid: &str, title: &str, fields: Value) -> Record {
        Record {
            uid: uid.into(),
            version: 3,
            data: json!({"title": title, "type": "login", "notes": "remember", "fields": fields}),
            ..Record::default()
        }
    }

    fn vault_of(records: impl IntoIterator<Item = Record>) -> Vault {
        Vault {
            records: records.into_iter().map(|r| (r.uid.clone(), r)).collect(),
            ..Vault::default()
        }
    }

    fn server() -> Record {
        typed(
            "SERVER",
            "Prod Server",
            json!([
                {"type": "login", "value": ["root"]},
                {"type": "password", "value": ["hunter2"]},
                {"type": "host", "label": "Database", "value": [{"hostName": "db.example.com", "port": "5432"}]},
                {"type": "text", "label": "API Key", "value": ["k-123", "k-456"]},
                {"type": "oneTimeCode", "value": [TOTP_URL]},
            ]),
        )
    }

    fn legacy() -> Record {
        Record {
            uid: "OLD".into(),
            version: 2,
            data: json!({"title": "Legacy", "secret1": "admin", "secret2": "pw", "notes": "old notes",
                         "custom": [{"name": "PIN", "value": "1234"}]}),
            extra: Some(json!({"fields": [{"field_type": "totp", "data": TOTP_URL}]})),
            ..Record::default()
        }
    }

    #[test]
    fn items_come_from_the_record_and_missing_ones_are_errors() {
        let server = server();
        assert_eq!(Item::Uid.text(&server).unwrap(), "SERVER");
        assert_eq!(Item::Login.text(&server).unwrap(), "root");
        assert_eq!(Item::Password.text(&server).unwrap(), "hunter2");
        let code = Item::Totp.text(&server).unwrap();
        assert!(code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()), "{code}");

        let old = legacy();
        assert_eq!(Item::Login.text(&old).unwrap(), "admin");
        assert_eq!(Item::Password.text(&old).unwrap(), "pw");
        assert_eq!(Item::Totp.text(&old).unwrap().len(), 6);

        let bare = typed("BARE", "Bare", json!([]));
        for item in [Item::Login, Item::Password, Item::Totp, Item::Field("nothing")] {
            let error = item.text(&bare).unwrap_err().to_string();
            assert_eq!(error, format!("{item} not found in record \"Bare\""));
        }
        let emailed = typed("MAIL", "Mail", json!([{"type": "email", "value": ["me@example.com"]}]));
        assert_eq!(Item::Login.text(&emailed).unwrap(), "me@example.com", "email stands in for a missing login");
    }

    #[test]
    fn fields_resolve_by_label_type_composite_part_and_legacy_name() {
        let server = server();
        let field = |spec: &str| field_text(&server, spec);
        assert_eq!(field("notes").as_deref(), Some("remember"));
        assert_eq!(field("api key").as_deref(), Some("k-123\nk-456"), "labels ignore case; values stack");
        assert_eq!(field("host").as_deref(), Some(r#"{"hostName":"db.example.com","port":"5432"}"#));
        assert_eq!(field("host.database").as_deref(), Some(r#"{"hostName":"db.example.com","port":"5432"}"#));
        assert_eq!(field("host:port").as_deref(), Some("5432"));
        assert_eq!(field("Database:HOSTN").as_deref(), Some("db.example.com"), "properties match by prefix");
        assert_eq!(field("login").as_deref(), Some("root"));
        assert_eq!(field("host:colour"), None);
        assert_eq!(field("host.other"), None);

        let old = legacy();
        assert_eq!(field_text(&old, "pin").as_deref(), Some("1234"));
        assert_eq!(field_text(&old, "notes").as_deref(), Some("old notes"));
        assert_eq!(field_text(&old, "missing"), None);
    }

    #[test]
    fn flags_pick_the_item_in_commanders_order() {
        let item = |args: &[&str]| {
            let mut line = vec!["cc"];
            line.extend(args);
            line.push("REC");
            let Command::ClipboardCopy(copy) = ShellLine::try_parse_from(line).unwrap().command else {
                panic!("`cc` should be clipboard-copy");
            };
            Item::from(&copy).to_string()
        };
        assert_eq!(item(&[]), "Password");
        assert_eq!(item(&["--field", "API Key"]), "Field \"API Key\"");
        assert_eq!(item(&["--field", "notes"]), "Notes");
        assert_eq!(item(&["-t", "--field", "x"]), "TOTP Code");
        assert_eq!(item(&["-l", "-t", "--field", "x"]), "Login");
        assert_eq!(item(&["--copy-uid", "-l"]), "Record UID");
    }

    #[test]
    fn find_password_is_clipboard_copy_that_prints() {
        let output = |args: &[&str]| {
            match ShellLine::try_parse_from(args.iter().copied().chain(["REC"]))
                .unwrap()
                .command
            {
                Command::ClipboardCopy(copy) | Command::FindPassword(copy) => copy.output,
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(output(&["clipboard-copy"]), Output::Clipboard);
        assert_eq!(output(&["cc", "--output", "stdouthidden"]), Output::StdoutHidden);
        assert_eq!(output(&["find-password"]), Output::Stdout);
        assert_eq!(output(&["find-password", "--output", "clipboard"]), Output::Clipboard);
        assert!(ShellLine::try_parse_from(["cc"]).is_err(), "a record is required");
    }

    fn login_record(uid: &str, title: &str, login: &str, notes: &str) -> Record {
        let mut record = typed(uid, title, json!([{"type": "login", "value": [login]}]));
        record.data["notes"] = json!(notes);
        record
    }

    fn uid_of(vault: &Vault, spec: &str, who: &Who) -> Result<String> {
        pick(vault, "", spec, who).map(|record| record.uid.clone())
    }

    #[test]
    fn a_uid_or_title_wins_over_search_and_titles_must_satisfy_the_username() {
        let mut vault = vault_of([
            login_record("ALICE", "Prod Server (alice)", "Alice", ""),
            login_record("BOB", "Prod Server", "bob", ""),
            login_record("STAGE", "Staging", "stage", "mirror of prod server"),
        ]);
        vault
            .folder_records
            .insert(String::new(), ["BOB", "STAGE"].map(String::from).into());
        let alice = Who::LoginStartsWith("ALI".into());

        assert_eq!(uid_of(&vault, "STAGE", &Who::Anyone).unwrap(), "STAGE");
        assert_eq!(uid_of(&vault, "BOB", &alice).unwrap(), "BOB", "a UID needs no login match");
        assert_eq!(uid_of(&vault, "staging", &Who::Anyone).unwrap(), "STAGE", "titles ignore case");
        assert_eq!(uid_of(&vault, "Prod Server", &Who::Anyone).unwrap(), "BOB", "the exact title beats other matches");
        assert_eq!(uid_of(&vault, "Prod Server", &alice).unwrap(), "ALICE", "else the search finds who is asked for");
    }

    #[test]
    fn search_words_narrow_to_one_record_by_title_or_report_why_not() {
        let file = Record {
            uid: "FILE".into(),
            version: 4,
            data: json!({"name": "mail.txt", "title": "Work Mail"}),
            ..Record::default()
        };
        let vault = vault_of([
            login_record("ARCHIVE", "Work Mail Archive", "a", ""),
            login_record("OTHER", "Personal", "b", "mail for work"),
            file,
            legacy(),
        ]);
        assert_eq!(uid_of(&vault, "work mail", &Who::Anyone).unwrap(), "ARCHIVE", "title narrows; files never count");
        assert_eq!(uid_of(&vault, "mail", &Who::LoginStartsWith("B".into())).unwrap(), "OTHER");
        assert_eq!(uid_of(&vault, "old notes", &Who::Anyone).unwrap(), "OLD", "search covers field text");

        let twins = vault_of([
            login_record("ONE", "Prod One", "x", ""),
            login_record("TWO", "Prod Two", "y", ""),
        ]);
        let both = uid_of(&twins, "prod", &Who::Anyone).unwrap_err().to_string();
        assert_eq!(both, "More than one record are found for search criteria: prod");
        let none = uid_of(&twins, "prod", &Who::LoginStartsWith("carol".into()))
            .unwrap_err()
            .to_string();
        assert_eq!(none, "Enter name or uid of existing record");
    }

    #[test]
    fn windows_clip_gets_utf16_with_a_byte_order_mark() {
        assert_eq!(Encoding::Utf8.encode("pa€"), "pa€".as_bytes());
        assert_eq!(Encoding::Utf16.encode("a€"), [0xFF, 0xFE, 0x61, 0x00, 0xAC, 0x20]);
        assert_eq!(Encoding::Utf16.encode("😀"), [0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE], "surrogate pair");
        assert_eq!(Encoding::Utf16.encode(""), [0xFF, 0xFE]);
    }
}
