use serde_json::Value;

use crate::crypto::AesKey;
use crate::uid::Uid;

/// Keeper's record versions. Only legacy records carry a separate `extra` blob, and only file
/// records have a stored content size, so those live on their variants.
#[derive(Debug)]
pub enum RecordKind {
    /// v2: `secret1`/`secret2`/`link` plus TOTP and attachments in `extra`.
    Legacy { extra: Option<Value> },
    /// v3: a typed record with `fields`/`custom`.
    Typed,
    /// v4: an attachment of a typed record.
    File { size: i64 },
    /// v5: a Secrets Manager application.
    Application,
    /// v6: a PAM configuration, typed-record shaped.
    PamConfiguration,
}

impl RecordKind {
    pub fn version(&self) -> i32 {
        match self {
            Self::Legacy { .. } => 2,
            Self::Typed => 3,
            Self::File { .. } => 4,
            Self::Application => 5,
            Self::PamConfiguration => 6,
        }
    }
}

#[derive(Debug)]
pub struct Record {
    pub uid:                  Uid,
    pub kind:                 RecordKind,
    /// The decrypted record JSON.
    pub data:                 Value,
    pub revision:             i64,
    pub shared:               bool,
    pub client_modified_time: i64,
    pub key:                  AesKey,
    /// Whether this account owns the record (from record metadata).
    pub owner:                bool,
    /// Unencrypted server-side record data, e.g. the `file_ids` of a typed record's attachments.
    pub udata:                Option<Value>,
}

/// Whether hidden field values are printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Secrets {
    Masked,
    Revealed,
}

impl From<bool> for Secrets {
    fn from(unmask: bool) -> Self {
        if unmask { Self::Revealed } else { Self::Masked }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sensitivity {
    Plain,
    Secret,
}

pub struct DisplayField {
    pub label:       String,
    pub value:       String,
    pub sensitivity: Sensitivity,
}

impl DisplayField {
    pub fn shown(&self, secrets: Secrets) -> &str {
        match (self.sensitivity, secrets) {
            (Sensitivity::Secret, Secrets::Masked) => "********",
            _ => &self.value,
        }
    }
}

impl Record {
    fn str_field(&self, key: &str) -> Option<&str> {
        self.data.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
    }

    pub fn title(&self) -> &str {
        self.str_field("title").unwrap_or_default().trim()
    }

    pub fn record_type(&self) -> &str {
        match self.kind {
            RecordKind::Legacy { .. } => "general",
            RecordKind::File { .. } => "file",
            RecordKind::Application => "app",
            RecordKind::Typed | RecordKind::PamConfiguration => self.str_field("type").unwrap_or("login"),
        }
    }

    pub fn notes(&self) -> &str {
        self.str_field("notes").unwrap_or_default()
    }

    /// Typed fields (`fields` then `custom`).
    pub fn typed_fields(&self) -> impl Iterator<Item = TypedField<'_>> {
        ["fields", "custom"]
            .into_iter()
            .filter_map(|k| self.data.get(k).and_then(Value::as_array))
            .flatten()
            .map(TypedField)
    }

    /// First non-empty value among fields of the given types, in `fields` then `custom` order.
    fn typed_value(&self, field_types: &[&str]) -> Option<&Value> {
        self.typed_fields()
            .filter(|f| field_types.contains(&f.field_type()))
            .find_map(|f| f.values().find(|v| !v.is_null() && v.as_str() != Some("")))
    }

    fn typed_str(&self, field_types: &[&str]) -> Option<&str> {
        self.typed_value(field_types).and_then(Value::as_str)
    }

    pub fn login(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("secret1"),
            _ => self.typed_str(&["login"]),
        }
    }

    pub fn password(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("secret2"),
            _ => self.typed_str(&["password"]),
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("link"),
            _ => self.typed_str(&["url"]),
        }
    }

    /// The `otpauth://` URL, from a `oneTimeCode`/`otp` field or a legacy record's extra.
    pub fn totp_url(&self) -> Option<&str> {
        match &self.kind {
            RecordKind::Legacy { extra } => {
                extra
                    .as_ref()
                    .and_then(|extra| extra.get("fields"))
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|field| field.get("field_type").and_then(Value::as_str) == Some("totp"))
                    .filter_map(|field| field.get("data").and_then(Value::as_str))
                    .find(|value| !value.is_empty())
                    .or_else(|| self.typed_str(&["oneTimeCode", "otp"]))
            }
            _ => self.typed_str(&["oneTimeCode", "otp"]),
        }
    }

    /// One-line summary in the style of Commander's `list` "Description" column.
    pub fn description(&self) -> String {
        if let RecordKind::PamConfiguration = self.kind {
            return "PAM Configuration".into();
        }
        if let Some(login) = self.login() {
            let mut parts = vec![login.to_owned()];
            if let Some(url) = self.url() {
                parts.push(url.to_owned());
            } else if let Some(host) = self.typed_value(&["host", "pamHostname"]) {
                let name = host.get("hostName").and_then(Value::as_str).unwrap_or_default();
                match host.get("port").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                    Some(port) if !name.is_empty() => parts.push(format!("{name}:{port}")),
                    _ if !name.is_empty() => parts.push(name.to_owned()),
                    _ => {}
                }
            }
            return parts.join(" @ ");
        }
        match self.kind {
            RecordKind::Legacy { .. } => return self.url().unwrap_or_default().to_owned(),
            RecordKind::File { .. } => return self.str_field("name").unwrap_or_default().to_owned(),
            _ => {}
        }
        if let Some(number) = self
            .typed_value(&["paymentCard"])
            .and_then(|card| card.get("cardNumber"))
            .and_then(Value::as_str)
            && let Some(last4) = number.char_indices().rev().nth(3).map(|(i, _)| &number[i..])
        {
            return format!("*{last4}");
        }
        if let Some(addr) = self.typed_value(&["address"]) {
            let get = |k: &str| addr.get(k).and_then(Value::as_str).unwrap_or_default();
            return [
                format!("{} {}", get("street1"), get("street2")).trim().to_owned(),
                get("city").to_owned(),
                format!("{} {}", get("state"), get("zip")).trim().to_owned(),
                get("country").to_owned(),
            ]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        }
        String::new()
    }

    /// Labelled values for display and search.
    pub fn display_fields(&self) -> Vec<DisplayField> {
        let field = |label: &str, value: Option<&str>, sensitivity| {
            DisplayField {
                label: label.to_owned(),
                value: value.unwrap_or_default().to_owned(),
                sensitivity,
            }
        };
        let fields = match &self.kind {
            RecordKind::Legacy { .. } => {
                let custom = self
                    .data
                    .get("custom")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|c| {
                        let get = |k: &str| c.get(k).and_then(Value::as_str);
                        field(get("name").unwrap_or_default(), get("value"), Sensitivity::Secret)
                    });
                [
                    field("Login", self.login(), Sensitivity::Plain),
                    field("Password", self.password(), Sensitivity::Secret),
                    field("URL", self.url(), Sensitivity::Plain),
                    field("TOTP URL", self.totp_url(), Sensitivity::Secret),
                ]
                .into_iter()
                .chain(custom)
                .collect::<Vec<_>>()
            }
            RecordKind::File { .. } => {
                vec![
                    field("Name", self.str_field("name"), Sensitivity::Plain),
                    field("MIME Type", self.str_field("type"), Sensitivity::Plain),
                    field(
                        "Size",
                        self.data
                            .get("size")
                            .and_then(Value::as_u64)
                            .map(|s| format!("{s} bytes"))
                            .as_deref(),
                        Sensitivity::Plain,
                    ),
                ]
            }
            _ => {
                self.typed_fields()
                    .map(|f| {
                        DisplayField {
                            label:       f.label(),
                            value:       f
                                .values()
                                .map(render_value)
                                .filter(|v| !v.is_empty())
                                .collect::<Vec<_>>()
                                .join(", "),
                            sensitivity: f.sensitivity(),
                        }
                    })
                    .collect()
            }
        };
        fields.into_iter().filter(|f| !f.value.is_empty()).collect()
    }

    /// All-tokens, case-insensitive substring match over UID, title, type and field text,
    /// mirroring Commander's default (non-regex) search.
    pub fn matches(&self, tokens: &[String]) -> bool {
        if tokens.is_empty() {
            return true;
        }
        let mut haystack = format!("{} {} {} {}", self.uid, self.title(), self.record_type(), self.notes());
        for f in self.display_fields() {
            haystack.push(' ');
            haystack.push_str(&f.label);
            haystack.push(' ');
            haystack.push_str(&f.value);
        }
        let haystack = haystack.to_lowercase();
        tokens.iter().all(|t| haystack.contains(&t.to_lowercase()))
    }
}

pub struct TypedField<'a>(&'a Value);

impl<'a> TypedField<'a> {
    pub fn field_type(&self) -> &'a str {
        self.0.get("type").and_then(Value::as_str).unwrap_or("text")
    }

    pub fn values(&self) -> impl Iterator<Item = &'a Value> + use<'a> {
        self.0.get("value").into_iter().flat_map(|value| {
            match value {
                Value::Array(values) => values.as_slice(),
                value => std::slice::from_ref(value),
            }
        })
    }

    pub fn label(&self) -> String {
        match self.0.get("label").and_then(Value::as_str).filter(|l| !l.is_empty()) {
            Some(l) => l.to_owned(),
            None => FieldTypeLabel(self.field_type()).to_string(),
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        let secret_type = matches!(
            self.field_type(),
            "password"
                | "secret"
                | "pinCode"
                | "oneTimeCode"
                | "otp"
                | "keyPair"
                | "securityQuestion"
                | "cardRef"
                | "paymentCard"
                | "bankAccount"
                | "note"
                | "json"
        );
        if secret_type || self.0.get("privacyScreen").and_then(Value::as_bool).unwrap_or(false) {
            Sensitivity::Secret
        } else {
            Sensitivity::Plain
        }
    }
}

/// Renders a camelCase field type (`pinCode`) as a label (`Pin Code`).
struct FieldTypeLabel<'a>(&'a str);

impl std::fmt::Display for FieldTypeLabel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            "url" => return f.write_str("URL"),
            "oneTimeCode" | "otp" => return f.write_str("TOTP URL"),
            "pamHostname" => return f.write_str("Hostname"),
            _ => {}
        }
        for (i, c) in self.0.chars().enumerate() {
            if i == 0 {
                write!(f, "{}", c.to_uppercase())?;
            } else if c.is_uppercase() {
                write!(f, " {c}")?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

/// Typed-field values are strings, numbers (dates as epoch millis) or small objects
/// (`name`, `phone`, `host`, ...); objects render as `key: value` pairs.
fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Object(map) => {
            map.iter()
                .filter_map(|(k, v)| {
                    let s = render_value(v);
                    (!s.is_empty()).then(|| format!("{k}: {s}"))
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record(kind: RecordKind, data: Value) -> Record {
        Record {
            uid: Uid::from(&[1u8; 16][..]),
            kind,
            data,
            revision: 0,
            shared: false,
            client_modified_time: 0,
            key: AesKey::random(),
            owner: true,
            udata: None,
        }
    }

    #[test]
    fn legacy_record_fields_and_totp_come_from_data_and_extra() {
        let r = record(
            RecordKind::Legacy {
                extra: Some(json!({"fields": [
                    {"field_type": "totp", "data": ""},
                    {"field_type": "totp", "data": "otpauth://totp/x?secret=AAAA"}
                ]})),
            },
            json!({"title": "Old", "secret1": "bob", "secret2": "pw", "link": "https://x", "custom": [{"name": "PIN", "value": "1234"}]}),
        );
        assert_eq!(r.description(), "bob @ https://x");
        assert_eq!(r.record_type(), "general");
        assert_eq!(r.totp_url(), Some("otpauth://totp/x?secret=AAAA"));
        assert!(r.matches(&["BOB".into(), "pin".into()]));
        assert!(!r.matches(&["bob".into(), "nope".into()]));
        let password = r.display_fields().into_iter().find(|f| f.label == "Password").unwrap();
        assert_eq!(password.shown(Secrets::Masked), "********");
        assert_eq!(password.shown(Secrets::Revealed), "pw");
        let custom = r.display_fields().into_iter().find(|f| f.label == "PIN").unwrap();
        assert_eq!(custom.shown(Secrets::Masked), "********");
    }

    #[test]
    fn typed_totp_skips_empty_fields_and_falls_back_to_custom() {
        let r = record(
            RecordKind::Typed,
            json!({"title": "T", "type": "login",
                   "fields": [{"type": "oneTimeCode", "value": [""]}],
                   "custom": [{"type": "otp", "value": "otpauth://totp/c?secret=BBBB"}]}),
        );
        assert_eq!(r.totp_url(), Some("otpauth://totp/c?secret=BBBB"));
    }

    #[test]
    fn legacy_totp_falls_back_to_nonempty_custom_field() {
        let r = record(
            RecordKind::Legacy { extra: None },
            json!({"custom": [{"type": "otp", "value": "otpauth://totp/c?secret=CCCC"}]}),
        );
        assert_eq!(r.totp_url(), Some("otpauth://totp/c?secret=CCCC"));
    }
    #[test]
    fn card_description_keeps_last_four_on_multibyte_numbers() {
        let r = record(
            RecordKind::Typed,
            json!({"type": "bankCard", "fields": [{"type": "paymentCard", "value": [{"cardNumber": "４１１１1234"}]}]}),
        );
        assert_eq!(r.description(), "*1234");
    }
    #[test]
    fn scalar_typed_fields_render_and_sensitive_types_are_masked() {
        let r = record(
            RecordKind::Typed,
            json!({"type": "note", "fields": [
                {"type": "login", "value": "alice"},
                {"type": "password", "value": "pass"},
                {"type": "paymentCard", "value": {"cardNumber": "4111111111111111"}},
                {"type": "bankAccount", "value": "account"},
                {"type": "note", "value": "private"},
                {"type": "json", "value": "{\"secret\":true}"}
            ]}),
        );
        assert_eq!(r.login(), Some("alice"));
        let fields = r.display_fields();
        for label in ["Password", "Payment Card", "Bank Account", "Note", "Json"] {
            let field = fields.iter().find(|field| field.label == label).unwrap();
            assert_eq!(field.shown(Secrets::Masked), "********");
            assert_eq!(field.shown(Secrets::Revealed), field.value.as_str());
        }
    }
}
