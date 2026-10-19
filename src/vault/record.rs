use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::crypto::AesKey;
use crate::uid::Uid;

/// Keeper's record versions. Only legacy records carry a separate `extra` blob, and only file
/// records have a stored content size, so those live on their variants.
#[derive(Debug)]
pub enum RecordKind {
    Legacy {
        extra: Option<LegacyExtra>,
    },
    /// v3: a typed record with `fields`/`custom`.
    Typed,
    /// v4: an attachment of a typed record.
    File {
        size: i64,
    },
    /// v5: a Secrets Manager application.
    Application,
    /// v6: a PAM configuration, typed-record shaped.
    PamConfiguration,
}

impl From<&RecordKind> for i32 {
    fn from(kind: &RecordKind) -> Self {
        match kind {
            RecordKind::Legacy { .. } => 2,
            RecordKind::Typed => 3,
            RecordKind::File { .. } => 4,
            RecordKind::Application => 5,
            RecordKind::PamConfiguration => 6,
        }
    }
}

/// The decrypted v2 extension envelope; unknown Commander properties remain available.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LegacyExtra {
    #[serde(default)]
    pub files:  Vec<LegacyFile>,
    #[serde(default)]
    pub fields: Vec<LegacyField>,
    #[serde(flatten)]
    pub extra:  Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LegacyFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id:    Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name:  Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key:   Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LegacyField {
    #[serde(rename = "field_type", default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data:       Option<Value>,
    #[serde(flatten)]
    pub extra:      Map<String, Value>,
}

/// Decrypted record JSON with known top-level and field shapes checked at sync.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RecordData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title:     String,
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub type_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes:     String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name:      Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret1:   Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret2:   Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link:      Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size:      Option<u64>,
    #[serde(default)]
    pub fields:    Vec<RecordField>,
    #[serde(default)]
    pub custom:    Vec<RecordField>,
    #[serde(flatten)]
    pub extra:     Map<String, Value>,
}

/// The field envelope is concrete while `value` and extension properties stay open Commander JSON.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RecordField {
    #[serde(rename = "type", default = "default_field_type")]
    pub ty:             String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label:          Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value:          Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name:           Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub required:       bool,
    #[serde(rename = "privacyScreen", default, skip_serializing_if = "Option::is_none")]
    pub privacy_screen: Option<bool>,
    #[serde(flatten)]
    pub extra:          Map<String, Value>,
}
impl RecordField {
    pub fn values(&self) -> impl Iterator<Item = &Value> + Clone {
        self.value.iter().flat_map(|value| {
            match value {
                Value::Array(values) => values.as_slice(),
                value => std::slice::from_ref(value),
            }
        })
    }
}

fn default_field_type() -> String {
    "text".to_owned()
}

#[derive(Debug)]
pub struct Record {
    pub uid:                  Uid,
    pub kind:                 RecordKind,
    pub data:                 RecordData,
    pub revision:             i64,
    pub shared:               bool,
    pub client_modified_time: i64,
    pub key:                  AesKey,
    /// Whether this account owns the record (from record metadata).
    pub owner:                bool,
    /// Unencrypted server-side record data, e.g. the `file_ids` of a typed record's attachments.
    pub udata:                Option<Value>,
}

/// A v3 typed record validated for operations that require that record version.
#[derive(Clone, Copy, Debug)]
pub struct TypedRecord<'a>(&'a Record);

impl<'a> TryFrom<&'a Record> for TypedRecord<'a> {
    type Error = crate::Error;

    fn try_from(record: &'a Record) -> crate::Result<Self> {
        if matches!(&record.kind, RecordKind::Typed) {
            Ok(Self(record))
        } else {
            Err(crate::Error::Generic(format!("Record {} is not a supported v3 typed record", record.uid)))
        }
    }
}

impl AsRef<Record> for TypedRecord<'_> {
    fn as_ref(&self) -> &Record {
        self.0
    }
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

#[derive(Debug)]
pub struct DisplayField<'a> {
    pub label: std::borrow::Cow<'a, str>,
    pub value: std::borrow::Cow<'a, str>,
}

impl Record {
    fn str_field(&self, key: &str) -> Option<&str> {
        let value = match key {
            "title" => Some(self.data.title.as_str()),
            "type" => Some(self.data.type_name.as_str()),
            "notes" => Some(self.data.notes.as_str()),
            "name" => self.data.name.as_deref(),
            "secret1" => self.data.secret1.as_deref(),
            "secret2" => self.data.secret2.as_deref(),
            "link" => self.data.link.as_deref(),
            _ => self.data.extra.get(key).and_then(Value::as_str),
        };
        value.filter(|s| !s.is_empty())
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

    pub fn typed_fields(&self) -> impl Iterator<Item = TypedField<'_>> {
        self.data.fields.iter().chain(&self.data.custom).map(TypedField)
    }

    /// First non-empty value among fields of the given types, in `fields` then `custom` order.
    fn typed_value(&self, field_types: &[&str]) -> Option<&Value> {
        self.typed_fields()
            .filter(|f| field_types.contains(&f.field_type()))
            .find_map(|f| f.values().find(|v| !v.is_null() && v.as_str() != Some("")))
    }

    pub fn login(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("secret1"),
            _ => self.typed_value(&["login"]).and_then(Value::as_str),
        }
    }

    pub fn password(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("secret2"),
            _ => self.typed_value(&["password"]).and_then(Value::as_str),
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self.kind {
            RecordKind::Legacy { .. } => self.str_field("link"),
            _ => self.typed_value(&["url"]).and_then(Value::as_str),
        }
    }

    /// The `otpauth://` URL, from a `oneTimeCode`/`otp` field or a legacy record's extra.
    pub fn totp_url(&self) -> Option<&str> {
        match &self.kind {
            RecordKind::Legacy { extra } => {
                extra
                    .as_ref()
                    .into_iter()
                    .flat_map(|extra| &extra.fields)
                    .filter(|field| field.field_type.as_deref() == Some("totp"))
                    .filter_map(|field| field.data.as_ref()?.as_str())
                    .find(|value| !value.is_empty())
                    .or_else(|| self.typed_value(&["oneTimeCode", "otp"]).and_then(Value::as_str))
            }
            _ => self.typed_value(&["oneTimeCode", "otp"]).and_then(Value::as_str),
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
            && let Some(last4) = number
                .char_indices()
                .rev()
                .nth(3)
                .and_then(|(start, _)| number.get(start..))
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

    pub fn display_fields<'a>(&'a self, secrets: Secrets) -> Vec<DisplayField<'a>> {
        let secret_value = |value: &'a str| -> std::borrow::Cow<'a, str> {
            match secrets {
                Secrets::Masked => std::borrow::Cow::Borrowed("********"),
                Secrets::Revealed => value.into(),
            }
        };
        match &self.kind {
            RecordKind::Legacy { .. } => {
                let custom = self.data.custom.iter().filter_map(|field| {
                    let Some(Value::String(value)) = field.value.as_ref() else {
                        return None;
                    };
                    let value = (!value.is_empty()).then_some(value.as_str())?;
                    Some(DisplayField {
                        label: field.name.as_deref().unwrap_or_default().into(),
                        value: secret_value(value),
                    })
                });
                [
                    ("Login", self.login().map(std::borrow::Cow::from)),
                    ("Password", self.password().map(secret_value)),
                    ("URL", self.url().map(std::borrow::Cow::from)),
                    ("TOTP URL", self.totp_url().map(secret_value)),
                ]
                .into_iter()
                .filter_map(|(label, value)| {
                    value.map(|value| {
                        DisplayField {
                            label: label.into(),
                            value,
                        }
                    })
                })
                .chain(custom)
                .collect()
            }
            RecordKind::File { .. } => {
                [
                    ("Name", self.str_field("name").map(std::borrow::Cow::from)),
                    ("MIME Type", self.str_field("type").map(std::borrow::Cow::from)),
                    ("Size", self.data.size.map(|size| format!("{size} bytes").into())),
                ]
                .into_iter()
                .filter_map(|(label, value)| {
                    value.map(|value| {
                        DisplayField {
                            label: label.into(),
                            value,
                        }
                    })
                })
                .collect()
            }
            _ => {
                self.typed_fields()
                    .filter_map(|field| {
                        let mut values = field.values().filter(|value| !render_value_is_empty(value)).peekable();
                        let first = values.next()?;
                        let value = if field.is_sensitive() && secrets == Secrets::Masked {
                            "********".into()
                        } else if values.peek().is_none() {
                            match first {
                                Value::String(value) => value.as_str().into(),
                                value => RenderValue(value).to_string().into(),
                            }
                        } else {
                            RenderValues(std::iter::once(first).chain(values)).to_string().into()
                        };
                        Some(DisplayField {
                            label: field.label(),
                            value,
                        })
                    })
                    .collect()
            }
        }
    }

    /// All-tokens, case-insensitive substring match over UID, title, type and field text,
    /// mirroring Commander's default (non-regex) search.
    pub fn matches(&self, tokens: &[String]) -> bool {
        if tokens.is_empty() {
            return true;
        }
        let mut haystack = format!("{} {} {} {}", self.uid, self.title(), self.record_type(), self.notes());
        for f in self.display_fields(Secrets::Revealed) {
            haystack.push(' ');
            haystack.push_str(f.label.as_ref());
            haystack.push(' ');
            haystack.push_str(f.value.as_ref());
        }
        let haystack = haystack.to_lowercase();
        tokens.iter().all(|t| haystack.contains(&t.to_lowercase()))
    }
}

pub struct TypedField<'a>(&'a RecordField);

impl<'a> TypedField<'a> {
    pub fn field_type(&self) -> &'a str {
        self.0.ty.as_str()
    }

    pub fn values(&self) -> impl Iterator<Item = &'a Value> + Clone + use<'a> {
        self.0.values()
    }

    pub fn label(&self) -> std::borrow::Cow<'a, str> {
        match self.0.label.as_deref().filter(|label| !label.is_empty()) {
            Some(label) => label.into(),
            None => FieldTypeLabel(self.field_type()).to_string().into(),
        }
    }

    fn is_sensitive(&self) -> bool {
        matches!(
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
        ) || self.0.privacy_screen == Some(true)
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

/// Displays Commander field values directly into the final formatter.
struct RenderValue<'a>(&'a Value);

impl std::fmt::Display for RenderValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Value::String(value) => f.write_str(value),
            Value::Null => Ok(()),
            Value::Object(map) => {
                let mut entries = map.iter().filter(|(_, value)| !render_value_is_empty(value)).peekable();
                while let Some((key, value)) = entries.next() {
                    if entries.peek().is_some() {
                        write!(f, "{key}: {}, ", RenderValue(value))?;
                    } else {
                        write!(f, "{key}: {}", RenderValue(value))?;
                    }
                }
                Ok(())
            }
            other => write!(f, "{other}"),
        }
    }
}
struct RenderValues<'a, I>(I)
where
    I: Iterator<Item = &'a Value> + Clone;

impl<'a, I> std::fmt::Display for RenderValues<'a, I>
where
    I: Iterator<Item = &'a Value> + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, value) in self.0.clone().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", RenderValue(value))?;
        }
        Ok(())
    }
}

fn render_value_is_empty(v: &Value) -> bool {
    match v {
        Value::String(value) => value.is_empty(),
        Value::Null => true,
        Value::Object(map) => map.values().all(render_value_is_empty),
        _ => false,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn record(kind: RecordKind, data: Value) -> Record {
        Record {
            uid: Uid::from([1u8; 16].as_slice()),
            kind,
            data: serde_json::from_value(data).unwrap(),
            revision: 0,
            shared: false,
            client_modified_time: 0,
            key: AesKey::random(),
            owner: true,
            udata: None,
        }
    }

    #[test]
    fn record_payload_validates_known_shapes_and_round_trips_extensions() {
        let raw = serde_json::json!({
            "title": "Example",
            "fields": [{"type": "text", "value": {"open": [1, null]}, "futureField": "kept"}],
            "future": {"kept": true}
        });
        let data: RecordData = serde_json::from_value(raw.clone()).unwrap();
        let encoded = serde_json::to_value(data).unwrap();
        assert_eq!(encoded.get("future"), raw.get("future"));
        let Some(fields) = encoded.get("fields").and_then(Value::as_array) else {
            panic!("record fields must serialize as an array");
        };
        assert_eq!(fields, &[serde_json::json!({"type": "text", "value": {"open": [1, null]}, "futureField": "kept"})]);
        assert!(serde_json::from_value::<RecordData>(serde_json::json!({"fields": {}})).is_err());
        assert!(serde_json::from_value::<RecordData>(serde_json::json!({"fields": [{"type": 7}]})).is_err());
        assert!(serde_json::from_value::<RecordData>(serde_json::json!({"size": "large"})).is_err());
        assert!(
            serde_json::from_value::<RecordData>(serde_json::json!({"fields": [{"privacyScreen": "yes"}]})).is_err()
        );
    }

    #[test]
    fn legacy_custom_fields_keep_string_value_semantics() {
        let record = record(
            RecordKind::Legacy { extra: None },
            serde_json::json!({"custom": [
                {"name": "PIN", "value": "1234"},
                {"name": "List", "value": ["not", "a", "legacy string"]}
            ]}),
        );
        let fields = record.display_fields(Secrets::Revealed);
        assert_eq!(fields.iter().map(|field| field.value.as_ref()).collect::<Vec<_>>(), ["1234"]);
    }

    #[test]
    fn typed_record_conversion_rejects_unsupported_versions() {
        let typed = record(RecordKind::Typed, serde_json::json!({"type": "login"}));
        assert!(TypedRecord::try_from(&typed).is_ok());

        for kind in [
            RecordKind::Legacy { extra: None },
            RecordKind::File { size: 1 },
            RecordKind::Application,
            RecordKind::PamConfiguration,
        ] {
            let unsupported = record(kind, serde_json::json!({}));
            assert!(TypedRecord::try_from(&unsupported).is_err());
        }
    }

    #[test]
    fn object_and_array_values_keep_commander_rendering() {
        let record = record(
            RecordKind::Typed,
            serde_json::json!({"fields": [
                {"type": "name", "value": {"first": "Ada", "middle": null, "last": "Lovelace", "empty": ""}},
                {"type": "text", "value": ["first", null, {"value": "second"}]}
            ]}),
        );
        let fields = record.display_fields(Secrets::Revealed);
        assert_eq!(fields.first().map(|field| field.value.as_ref()), Some("first: Ada, last: Lovelace"));
        assert_eq!(fields.get(1).map(|field| field.value.as_ref()), Some("first, value: second"));
    }

    #[test]
    fn legacy_record_fields_and_totp_come_from_data_and_extra() {
        let r = record(
            RecordKind::Legacy {
                extra: Some(
                    serde_json::from_value(serde_json::json!({"fields": [
                        {"field_type": "totp", "data": ""},
                        {"field_type": "totp", "data": "otpauth://totp/x?secret=AAAA"}
                    ]}))
                    .unwrap(),
                ),
            },
            serde_json::json!({"title": "Old", "secret1": "bob", "secret2": "pw", "link": "https://x", "custom": [{"name": "PIN", "value": "1234"}]}),
        );
        assert_eq!(r.description(), "bob @ https://x");
        assert_eq!(r.record_type(), "general");
        assert_eq!(r.totp_url(), Some("otpauth://totp/x?secret=AAAA"));
        assert!(r.matches(&["BOB".into(), "pin".into()]));
        assert!(!r.matches(&["bob".into(), "nope".into()]));
        assert!(r.matches(&["1234".into()]));
        assert!(r.matches(&["pw".into()]));
        let password = r
            .display_fields(Secrets::Masked)
            .into_iter()
            .find(|f| f.label == "Password")
            .unwrap();
        assert_eq!(format!("{}", password.value), "********");
        assert_eq!(serde_json::to_string(&password.value).unwrap(), "\"********\"");
        let password = r
            .display_fields(Secrets::Revealed)
            .into_iter()
            .find(|f| f.label == "Password")
            .unwrap();
        assert_eq!(format!("{}", password.value), "pw");
        assert_eq!(serde_json::to_string(&password.value).unwrap(), "\"pw\"");
        let custom = r
            .display_fields(Secrets::Masked)
            .into_iter()
            .find(|f| f.label == "PIN")
            .unwrap();
        assert_eq!(custom.value.as_ref(), "********");
    }

    #[test]
    fn typed_totp_skips_empty_fields_and_falls_back_to_custom() {
        let r = record(
            RecordKind::Typed,
            serde_json::json!({"title": "T", "type": "login",
                   "fields": [{"type": "oneTimeCode", "value": [""]}],
                   "custom": [{"type": "otp", "value": "otpauth://totp/c?secret=BBBB"}]}),
        );
        assert_eq!(r.totp_url(), Some("otpauth://totp/c?secret=BBBB"));
    }

    #[test]
    fn legacy_totp_falls_back_to_nonempty_custom_field() {
        let r = record(
            RecordKind::Legacy { extra: None },
            serde_json::json!({"custom": [{"type": "otp", "value": "otpauth://totp/c?secret=CCCC"}]}),
        );
        assert_eq!(r.totp_url(), Some("otpauth://totp/c?secret=CCCC"));
    }
    #[test]
    fn card_description_keeps_last_four_on_multibyte_numbers() {
        let r = record(
            RecordKind::Typed,
            serde_json::json!({"type": "bankCard", "fields": [{"type": "paymentCard", "value": [{"cardNumber": "４１１１1234"}]}]}),
        );
        assert_eq!(r.description(), "*1234");
    }
    #[test]
    fn scalar_typed_fields_render_and_sensitive_types_are_masked() {
        let r = record(
            RecordKind::Typed,
            serde_json::json!({"type": "note", "fields": [
                {"type": "login", "value": "alice"},
                {"type": "password", "value": "pass"},
                {"type": "paymentCard", "value": {"cardNumber": "4111111111111111"}},
                {"type": "bankAccount", "value": "account"},
                {"type": "note", "value": "private"},
                {"type": "json", "value": "{\"secret\":true}"},
                {"type": "text", "privacyScreen": true, "value": "screen secret"}
            ]}),
        );
        let fields = r.display_fields(Secrets::Masked);
        for label in ["Password", "Payment Card", "Bank Account", "Note", "Json", "Text"] {
            let field = fields.iter().find(|field| field.label.as_ref() == label).unwrap();
            assert_eq!(field.value.as_ref(), "********");
        }
        assert!(r.matches(&["4111111111111111".into()]));
        assert_eq!(
            r.display_fields(Secrets::Revealed)
                .iter()
                .find(|field| field.label.as_ref() == "Password")
                .unwrap()
                .value
                .as_ref(),
            "pass"
        );
    }
    #[test]
    fn empty_fields_are_omitted_and_multiple_values_keep_their_order() {
        let r = record(
            RecordKind::Typed,
            serde_json::json!({"fields": [
                {"type": "text", "value": ["", null, {}, {"empty": null}, "first", "second"]},
                {"type": "password", "value": ["", null]}
            ]}),
        );
        for secrets in [Secrets::Masked, Secrets::Revealed] {
            let fields = r.display_fields(secrets);
            assert_eq!(fields.iter().map(|field| field.label.as_ref()).collect::<Vec<_>>(), ["Text"]);
            let [field] = fields.as_slice() else {
                panic!("expected one non-empty display field");
            };
            assert_eq!(field.value.as_ref(), "first, second");
        }
    }
    #[test]
    fn file_details_include_formatted_size() {
        let r = record(
            RecordKind::File { size: 4096 },
            serde_json::json!({"name": "report.pdf", "type": "application/pdf", "size": 4096}),
        );
        let fields = r.display_fields(Secrets::Masked);
        assert_eq!(
            fields
                .into_iter()
                .map(|field| field.value.into_owned())
                .collect::<Vec<_>>(),
            ["report.pdf", "application/pdf", "4096 bytes"]
        );
    }
}
