//! Copy a value from a record to the system clipboard, or print it.
//!
//! Clipboard tools receive the text on stdin, so secrets do not appear in process arguments.

use std::fmt;
use std::io::{ErrorKind, Write};
use std::process::{Command as Process, Stdio};

use clap::{Args, ValueEnum};
use serde_json::Value;

use crate::commands::{App, Run};
use crate::prelude::*;
use crate::totp::Totp;
use crate::vault::{Location, Record, RecordKind, Vault};

/// Copy a record's password, login, TOTP code, UID or a field to the clipboard.
#[derive(Args, Debug)]
pub struct ClipboardCopy {
    #[command(flatten)]
    args: CopyArgs,
}

/// Find a record and print its password by default.
#[derive(Args, Debug)]
pub struct FindPassword {
    #[command(flatten)]
    args: CopyArgs,
}

#[derive(Args, Debug)]
struct CopyArgs {
    /// Only admit records whose login starts with this (case-insensitive).
    #[arg(long)]
    username: Option<String>,
    /// Where to send the selected value; each command has its own default.
    #[arg(long, value_enum)]
    output:   Option<Output>,
    /// Output the record UID instead of the password.
    #[arg(long)]
    copy_uid: bool,
    /// Output the login name.
    #[arg(short, long)]
    login:    bool,
    /// Output the current TOTP code.
    #[arg(short, long)]
    totp:     bool,
    /// Output `notes`, a label or type, `type.label`, or `name:property` from a composite value.
    #[arg(long)]
    field:    Option<String>,
    /// Record UID, path, title or words to search for.
    record:   String,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Output {
    #[default]
    Clipboard,
    Stdout,
    /// Red text on a red background, readable only when selected.
    #[value(name = "stdouthidden")]
    StdoutHidden,
}

enum Item<'a> {
    Uid,
    Login,
    Totp,
    Field(&'a str),
    Password,
}

impl<'a> From<&'a CopyArgs> for Item<'a> {
    fn from(args: &'a CopyArgs) -> Self {
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
    fn text(&self, record: &Record) -> Result<String> {
        let text = match self {
            Self::Uid => Some(record.uid.to_string()),
            Self::Login => login(record).map(str::to_owned),
            Self::Totp => {
                record
                    .totp_url()
                    .map(|url| {
                        url.parse::<Totp>()
                            .and_then(|totp| totp.code_now())
                            .map(|code| code.to_string())
                    })
                    .transpose()?
            }
            Self::Field(spec) => field_text(record, spec),
            Self::Password => record.password().map(str::to_owned),
        };
        text.filter(|text| !text.is_empty())
            .ok_or_else(|| Error::Generic(format!("{self} not found in record \"{}\"", record.title())))
    }
}

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

fn login(record: &Record) -> Option<&str> {
    record.login().or_else(|| {
        record
            .typed_fields()
            .find(|field| field.field_type() == "email")
            .and_then(|field| field.values().next())
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
    })
}

fn field_text(record: &Record, spec: &str) -> Option<String> {
    if spec == "notes" {
        return Some(record.notes().to_owned());
    }
    let (name, property) = spec.rsplit_once(':').unwrap_or((spec, ""));
    if matches!(&record.kind, RecordKind::Legacy { .. }) {
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

fn pick<'v>(vault: &'v Vault, cwd: &Location, spec: &str, who: &Who) -> Result<&'v Record> {
    if let Some(record) = vault.records.get(spec) {
        return Ok(record);
    }
    if let Some(record) = vault.resolve_record(cwd, spec).filter(|record| who.admits(record)) {
        return Ok(record);
    }
    let words: Vec<String> = spec.split_whitespace().map(str::to_owned).collect();
    let mut found: Vec<&Record> = vault
        .records
        .values()
        .filter(|record| {
            matches!(&record.kind, RecordKind::Legacy { .. } | RecordKind::Typed | RecordKind::PamConfiguration)
                && who.admits(record)
                && record.matches(&words)
        })
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
        self.args.run(app, Output::Clipboard)
    }
}

impl Run for FindPassword {
    fn run(self, app: &mut App) -> Result<()> {
        self.args.run(app, Output::Stdout)
    }
}

impl CopyArgs {
    fn run(self, app: &mut App, default_output: Output) -> Result<()> {
        let view = app.view()?;
        let item = Item::from(&self);
        let who = self
            .username
            .as_ref()
            .map_or(Who::Anyone, |prefix| Who::LoginStartsWith(prefix.clone()));
        let record = pick(view.vault, view.cwd, &self.record, &who)?;
        let text = item.text(record)?;
        match self.output.unwrap_or(default_output) {
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

#[derive(Clone, Copy)]
enum Encoding {
    Utf8,
    /// `clip.exe` expects UTF-16LE with a byte order mark.
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

struct Tool {
    program: &'static str,
    args:    &'static [&'static str],
    wants:   Encoding,
}

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
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if let Some(mut stdin) = child.stdin.take() {
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
    use serde_json::json;

    use super::*;

    const TOTP_URL: &str = "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn record(uid: &str, kind: RecordKind, data: Value) -> Record {
        Record {
            uid: crate::uid::Uid::from(uid.as_bytes()),
            kind,
            data,
            revision: 0,
            shared: false,
            client_modified_time: 0,
            key: crate::crypto::AesKey::random(),
            owner: true,
            udata: None,
        }
    }

    fn typed(uid: &str, title: &str, fields: Value) -> Record {
        record(
            uid,
            RecordKind::Typed,
            json!({"title": title, "type": "login", "notes": "remember", "fields": fields}),
        )
    }

    fn vault_of(records: impl IntoIterator<Item = Record>) -> Vault {
        Vault {
            records: records.into_iter().map(|record| (record.uid.clone(), record)).collect(),
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
        record(
            "OLD",
            RecordKind::Legacy {
                extra: Some(json!({"fields": [{"field_type": "totp", "data": TOTP_URL}]})),
            },
            json!({"title": "Legacy", "secret1": "admin", "secret2": "pw", "notes": "old notes", "custom": [{"name": "PIN", "value": "1234"}]}),
        )
    }

    #[test]
    fn output_items_read_record_fields_and_missing_values_are_errors() {
        let server = server();
        assert_eq!(Item::Uid.text(&server).unwrap(), server.uid.to_string());
        assert_eq!(Item::Login.text(&server).unwrap(), "root");
        assert_eq!(Item::Password.text(&server).unwrap(), "hunter2");
        let code = Item::Totp.text(&server).unwrap();
        assert!(code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()));
        let old = legacy();
        assert_eq!(Item::Login.text(&old).unwrap(), "admin");
        assert_eq!(Item::Password.text(&old).unwrap(), "pw");
        assert_eq!(Item::Totp.text(&old).unwrap().len(), 6);
        let bare = typed("BARE", "Bare", json!([]));
        for item in [Item::Login, Item::Password, Item::Totp, Item::Field("nothing")] {
            assert_eq!(item.text(&bare).unwrap_err().to_string(), format!("{item} not found in record \"Bare\""));
        }
        let emailed = typed("MAIL", "Mail", json!([{"type": "email", "value": ["me@example.com"]}]));
        assert_eq!(login(&emailed), Some("me@example.com"));
    }

    #[test]
    fn fields_resolve_notes_labels_types_composite_parts_and_legacy_names() {
        let server = server();
        let field = |spec: &str| field_text(&server, spec);
        assert_eq!(field("notes").as_deref(), Some("remember"));
        assert_eq!(field("api key").as_deref(), Some("k-123\nk-456"));
        assert_eq!(field("host").as_deref(), Some(r#"{"hostName":"db.example.com","port":"5432"}"#));
        assert_eq!(field("host.database").as_deref(), Some(r#"{"hostName":"db.example.com","port":"5432"}"#));
        assert_eq!(field("host:port").as_deref(), Some("5432"));
        assert_eq!(field("Database:HOSTN").as_deref(), Some("db.example.com"));
        assert_eq!(field("login").as_deref(), Some("root"));
        assert_eq!(field("host:colour"), None);
        assert_eq!(field("host.other"), None);
        let old = legacy();
        assert_eq!(field_text(&old, "pin").as_deref(), Some("1234"));
        assert_eq!(field_text(&old, "notes").as_deref(), Some("old notes"));
        assert_eq!(field_text(&old, "missing"), None);
    }

    fn login_record(uid: &str, title: &str, login: &str, notes: &str) -> Record {
        let mut record = typed(uid, title, json!([{"type": "login", "value": [login]}]));
        record.data["notes"] = json!(notes);
        record
    }

    #[test]
    fn uid_titles_and_word_search_honor_login_filtering() {
        let alice = login_record("ALICE", "Prod Server (alice)", "Alice", "");
        let bob = login_record("BOB", "Prod Server", "bob", "");
        let stage = login_record("STAGE", "Staging", "stage", "mirror of prod server");
        let (alice_uid, bob_uid, stage_uid) = (alice.uid.to_string(), bob.uid.to_string(), stage.uid.to_string());
        let vault = vault_of([alice, bob, stage]);
        let cwd = Location::Root;
        let alice_filter = Who::LoginStartsWith("ALI".into());

        assert_eq!(pick(&vault, &cwd, &stage_uid, &Who::Anyone).unwrap().uid.to_string(), stage_uid);
        assert_eq!(pick(&vault, &cwd, &bob_uid, &alice_filter).unwrap().uid.to_string(), bob_uid);
        assert_eq!(pick(&vault, &cwd, "staging", &Who::Anyone).unwrap().title(), "Staging");
        assert_eq!(
            pick(&vault, &cwd, "Prod Server (alice)", &Who::Anyone)
                .unwrap()
                .uid
                .to_string(),
            alice_uid
        );
        assert!(
            pick(&vault, &cwd, "Prod Server", &Who::Anyone).is_err(),
            "ambiguous titles must not choose by map order"
        );
        assert_eq!(pick(&vault, &cwd, "prod", &alice_filter).unwrap().uid.to_string(), alice_uid);
        assert!(pick(&vault, &cwd, "prod", &Who::LoginStartsWith("carol".into())).is_err());
    }

    #[test]
    fn files_and_applications_are_not_search_candidates() {
        let file = record("FILE", RecordKind::File { size: 1 }, json!({"name": "mail.txt", "title": "Work Mail"}));
        let app = record("APP", RecordKind::Application, json!({"title": "Work Mail App"}));
        let vault = vault_of([
            login_record("ARCHIVE", "Work Mail Archive", "a", ""),
            login_record("OTHER", "Personal", "b", "mail for work"),
            file,
            app,
            legacy(),
        ]);
        let cwd = Location::Root;
        assert_eq!(pick(&vault, &cwd, "work mail", &Who::Anyone).unwrap().title(), "Work Mail Archive");
        assert_eq!(
            pick(&vault, &cwd, "mail", &Who::LoginStartsWith("B".into()))
                .unwrap()
                .title(),
            "Personal"
        );
        assert_eq!(pick(&vault, &cwd, "old notes", &Who::Anyone).unwrap().title(), "Legacy");
    }

    #[test]
    fn output_formats_keep_command_defaults_distinct_and_windows_encoding_is_unicode_safe() {
        assert_eq!(Output::default(), Output::Clipboard);
        assert_eq!(Encoding::Utf8.encode("pa€"), "pa€".as_bytes());
        assert_eq!(Encoding::Utf16.encode("a€"), [0xFF, 0xFE, 0x61, 0x00, 0xAC, 0x20]);
        assert_eq!(Encoding::Utf16.encode("😀"), [0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE]);
        assert_eq!(Encoding::Utf16.encode(""), [0xFF, 0xFE]);
    }
}
