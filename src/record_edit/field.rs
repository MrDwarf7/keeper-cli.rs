//! Typed-record fields as Commander edits them: the field catalogue, the
//! `[f.|c.][type.][label]=value` command-line syntax, and applying those edits to a record body.
//!
//! Everything here is pure: no vault, no network.

use std::collections::BTreeSet;
use std::str::FromStr;

use clap::ValueEnum;
use data_encoding::BASE64;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::generator::{self, Rules};
use crate::vault::RecordData;
use crate::{Error, Result, crypto};

// --- catalogue ---------------------------------------------------------------------------------

/// The value shapes of Commander's `FieldTypes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    Text,
    Url,
    Multiline,
    Json,
    FileRef,
    Email,
    Secret,
    Otp,
    Login,
    Password,
    Host,
    Phone,
    Name,
    Address,
    SecurityQuestion,
    PaymentCard,
    BankAccount,
    PrivateKey,
    AddressRef,
    CardRef,
    Date,
    Checkbox,
    Dropdown,
    Schedule,
    Passkey,
    Script,
    RecordRef,
    AppFiller,
    PamResources,
    PamSettings,
    PamRemoteBrowserSettings,
    RbiUrl,
}

const TYPE_NAMES: [(&str, FieldType); 32] = [
    ("text", FieldType::Text),
    ("url", FieldType::Url),
    ("multiline", FieldType::Multiline),
    ("json", FieldType::Json),
    ("fileRef", FieldType::FileRef),
    ("email", FieldType::Email),
    ("secret", FieldType::Secret),
    ("otp", FieldType::Otp),
    ("login", FieldType::Login),
    ("password", FieldType::Password),
    ("host", FieldType::Host),
    ("phone", FieldType::Phone),
    ("name", FieldType::Name),
    ("address", FieldType::Address),
    ("securityQuestion", FieldType::SecurityQuestion),
    ("paymentCard", FieldType::PaymentCard),
    ("bankAccount", FieldType::BankAccount),
    ("privateKey", FieldType::PrivateKey),
    ("addressRef", FieldType::AddressRef),
    ("cardRef", FieldType::CardRef),
    ("date", FieldType::Date),
    ("checkbox", FieldType::Checkbox),
    ("dropdown", FieldType::Dropdown),
    ("schedule", FieldType::Schedule),
    ("passkey", FieldType::Passkey),
    ("script", FieldType::Script),
    ("recordRef", FieldType::RecordRef),
    ("appFiller", FieldType::AppFiller),
    ("pamResources", FieldType::PamResources),
    ("pamSettings", FieldType::PamSettings),
    ("pamRemoteBrowserSettings", FieldType::PamRemoteBrowserSettings),
    ("rbiUrl", FieldType::RbiUrl),
];

impl FieldType {
    fn lookup(name: &str) -> Option<Self> {
        TYPE_NAMES.iter().find(|(n, _)| *n == name).map(|(_, ty)| *ty)
    }
}

impl FromStr for FieldType {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        Self::lookup(name).ok_or_else(|| Error::Generic(format!("unknown field type '{name}'")))
    }
}

/// What a value of a field type looks like in a record's JSON, used to complete and check
/// values given as raw JSON.
pub enum Template {
    Text,
    Number,
    Flag,
    /// An object with exactly these keys.
    Object(&'static [&'static str]),
}

impl From<FieldType> for Template {
    fn from(ty: FieldType) -> Self {
        use FieldType as T;
        match ty {
            T::Date => Self::Number,
            T::Checkbox => Self::Flag,
            T::Host => Self::Object(&["hostName", "port"]),
            T::Phone => Self::Object(&["region", "number", "ext", "type"]),
            T::Name => Self::Object(&["first", "middle", "last"]),
            T::Address => Self::Object(&["street1", "street2", "city", "state", "zip", "country"]),
            T::SecurityQuestion => Self::Object(&["question", "answer"]),
            T::PaymentCard => Self::Object(&["cardNumber", "cardExpirationDate", "cardSecurityCode"]),
            T::BankAccount => Self::Object(&["accountType", "routingNumber", "accountNumber", "otherType"]),
            T::PrivateKey => Self::Object(&["publicKey", "privateKey"]),
            T::Schedule => Self::Object(&["type", "time", "month"]),
            T::Passkey => {
                Self::Object(&[
                    "privateKey",
                    "credentialId",
                    "signCount",
                    "userId",
                    "relyingParty",
                    "username",
                    "createdDate",
                ])
            }
            T::Script => Self::Object(&["fileRef", "command", "recordRef"]),
            T::AppFiller => Self::Object(&["macroSequence", "applicationTitle", "contentFilter"]),
            T::PamResources => Self::Object(&["controllerUid", "folderUid", "resourceRef"]),
            T::PamSettings => Self::Object(&["allowSupplyHost", "connection", "portForward"]),
            T::PamRemoteBrowserSettings => Self::Object(&["connection"]),
            _ => Self::Text,
        }
    }
}

/// How many values a named field may hold; fields that can't repeat match by type alone, so
/// their label is ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Multiple {
    Never,
    Optional,
    Always,
}

/// A named record field (`login`, `oneTimeCode`, `pamHostname`, ...) and the value shape behind it.
#[derive(Clone, Copy, Debug)]
pub struct Def {
    pub ty:       FieldType,
    pub multiple: Multiple,
}

impl Def {
    /// Looks up a catalogue name without treating expected unknown custom types as failures.
    fn lookup(name: &str) -> Option<Self> {
        use FieldType as T;
        use Multiple::{Always, Never, Optional};
        let (ty, multiple) = match name {
            "login" => (T::Login, Never),
            "password" => (T::Password, Never),
            "company" | "accountNumber" => (T::Text, Never),
            "licenseNumber" | "note" => (T::Multiline, Never),
            "bankAccount" => (T::BankAccount, Never),
            "oneTimeCode" => (T::Otp, Never),
            "keyPair" => (T::PrivateKey, Never),
            "pinCode" => (T::Secret, Never),
            "expirationDate" | "birthDate" => (T::Date, Never),
            "securityQuestion" => (T::SecurityQuestion, Always),
            "fileRef" => (T::FileRef, Always),
            "pamResources" => (T::PamResources, Never),
            "pamHostname" => (T::Host, Never),
            "databaseType" | "directoryType" => (T::Dropdown, Never),
            "pamSettings" => (T::PamSettings, Never),
            "pamRemoteBrowserSettings" => (T::PamRemoteBrowserSettings, Never),
            "rbiUrl" => (T::RbiUrl, Never),
            other => (FieldType::lookup(other)?, Optional),
        };
        Some(Self { ty, multiple })
    }
}

impl FromStr for Def {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        Self::lookup(name).ok_or_else(|| Error::Generic(format!("unknown field type '{name}'")))
    }
}

// --- record body -------------------------------------------------------------------------------

// Stored records are produced by many clients; like Commander, coerce odd values rather than
// refusing to edit the record.

fn text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    })
}

fn flag<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Bool(b) => b,
        Value::Number(n) => n.as_i64().is_some_and(|n| n != 0),
        _ => false,
    })
}

fn values<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Value>, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        scalar => vec![scalar],
    })
}

fn field_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Field>, D::Error> {
    Ok(Option::<Vec<Field>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Field {
    #[serde(rename = "type", default, deserialize_with = "text")]
    pub ty:       String,
    #[serde(default, deserialize_with = "text", skip_serializing_if = "String::is_empty")]
    pub label:    String,
    #[serde(default, deserialize_with = "values")]
    pub value:    Vec<Value>,
    #[serde(default, deserialize_with = "flag", skip_serializing_if = "std::ops::Not::not")]
    pub required: bool,
    /// Properties Commander has no model for (`privacyScreen`, `complexity`, ...) survive an edit.
    #[serde(flatten)]
    pub extra:    Map<String, Value>,
}

/// The decrypted JSON of a typed (v3/v6) record.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Body {
    #[serde(rename = "type", default, deserialize_with = "text")]
    pub type_name: String,
    #[serde(default, deserialize_with = "text")]
    pub title:     String,
    #[serde(default, deserialize_with = "text")]
    pub notes:     String,
    #[serde(default, deserialize_with = "field_list")]
    pub fields:    Vec<Field>,
    #[serde(default, deserialize_with = "field_list")]
    pub custom:    Vec<Field>,
    #[serde(flatten)]
    pub extra:     Map<String, Value>,
}

impl From<&RecordData> for Body {
    fn from(data: &RecordData) -> Self {
        let field = |source: &crate::vault::RecordField| {
            let mut extra = source.extra.clone();
            if let Some(name) = &source.name {
                extra.insert("name".into(), Value::String(name.clone()));
            }
            if let Some(privacy_screen) = source.privacy_screen {
                extra.insert("privacyScreen".into(), Value::Bool(privacy_screen));
            }
            Field {
                ty: source.ty.clone(),
                label: source.label.clone().unwrap_or_default(),
                value: match source.value.as_ref() {
                    Some(Value::Null) | None => Vec::new(),
                    Some(Value::Array(values)) => values.clone(),
                    Some(value) => vec![value.clone()],
                },
                required: source.required,
                extra,
            }
        };
        let mut extra = data.extra.clone();
        for (key, value) in [
            ("name", data.name.as_ref().map(|value| Value::String(value.clone()))),
            ("secret1", data.secret1.as_ref().map(|value| Value::String(value.clone()))),
            ("secret2", data.secret2.as_ref().map(|value| Value::String(value.clone()))),
            ("link", data.link.as_ref().map(|value| Value::String(value.clone()))),
            ("size", data.size.map(Value::from)),
        ] {
            if let Some(value) = value {
                extra.insert(key.into(), value);
            }
        }
        Self {
            type_name: data.type_name.clone(),
            title: data.title.clone(),
            notes: data.notes.clone(),
            fields: data.fields.iter().map(field).collect(),
            custom: data.custom.iter().map(field).collect(),
            extra,
        }
    }
}

/// Records this one points at (attachments, linked cards and addresses, ...); each needs a
/// `RecordLink` carrying the target's key.
pub fn refs(body: &Body) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for field in body.fields.iter().chain(&body.custom) {
        match field.ty.as_str() {
            "fileRef" | "addressRef" | "cardRef" | "recordRef" => {
                found.extend(field.value.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            "script" => {
                found.extend(
                    field
                        .value
                        .iter()
                        .filter_map(|script| script.get("fileRef")?.as_str())
                        .map(str::to_owned),
                );
            }
            _ => {}
        }
    }
    found
}

// --- record type definitions -------------------------------------------------------------------

/// One entry of a record type's `fields` list.
#[derive(Debug, Default, Deserialize)]
pub struct TypeField {
    #[serde(rename = "$ref", default)]
    pub reference:       String,
    #[serde(default)]
    pub label:           String,
    #[serde(default)]
    pub required:        bool,
    #[serde(rename = "appFillerData")]
    pub app_filler_data: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TypeDef {
    #[serde(rename = "$id", default)]
    pub id:     String,
    #[serde(default)]
    pub fields: Vec<TypeField>,
}

/// `record-add --labels`: whether fields without a label in the type definition are labelled
/// with their type name (Commander's historical behaviour) or left unlabelled.
#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Labels {
    #[default]
    On,
    Off,
}

impl TypeField {
    /// An empty field of this entry, as a new record of the type starts out.
    pub fn blank(&self, labels: Labels) -> Field {
        let label = match (self.label.as_str(), labels) {
            ("", Labels::On) => self.reference.clone(),
            (label, _) => label.to_owned(),
        };
        Field {
            ty: self.reference.clone(),
            label,
            value: self.default_value(),
            required: self.required,
            ..Field::default()
        }
    }

    fn default_value(&self) -> Vec<Value> {
        match (&self.app_filler_data, self.reference.as_str()) {
            (Some(data), "appFiller") => vec![data.clone()],
            _ => Vec::new(),
        }
    }
}

/// `record-update -rt`: re-shapes a record to another type's field list. Filled-in fields the new
/// type lacks become custom fields; empty ones are dropped.
pub fn adjust(body: &mut Body, defs: &[TypeField]) {
    if defs.iter().any(|d| d.reference.is_empty()) {
        return;
    }
    let mut old: Vec<Field> = body
        .fields
        .iter()
        .chain(&body.custom)
        .filter(|f| !f.value.is_empty())
        .cloned()
        .collect();
    let mut fields = Vec::new();
    let mut rebuild = false;
    for def in defs {
        let ignore_label = Def::lookup(&def.reference).is_some_and(|d| d.multiple == Multiple::Never);
        let same_type = |f: &Field| f.ty == def.reference;
        let found = old
            .iter()
            .position(|f| same_type(f) && (ignore_label || f.label == def.label))
            .or_else(|| {
                if def.label.is_empty() {
                    old.iter().position(same_type)
                } else {
                    old.iter().position(|f| same_type(f) && f.label.is_empty())
                }
            });
        match found {
            Some(i) => {
                let mut field = old.remove(i);
                field.required = def.required;
                if field.label != def.label {
                    field.label.clone_from(&def.label);
                    rebuild = true;
                }
                fields.push(field);
            }
            None => {
                fields.push(Field {
                    ty: def.reference.clone(),
                    label: def.label.clone(),
                    value: def.default_value(),
                    required: def.required,
                    ..Field::default()
                });
                rebuild = true;
            }
        }
    }
    if rebuild || !old.is_empty() {
        body.fields = fields;
        body.custom = old;
    }
}

// --- notes -------------------------------------------------------------------------------------

/// Notes as typed on a command line, where a literal `\n` stands for a newline (`\\n` for a
/// backslash and an `n`).
pub struct Notes(pub String);

impl From<&str> for Notes {
    fn from(typed: &str) -> Self {
        Self(typed.replace("\\\\n", "\0").replace("\\n", "\n").replace('\0', "\\n"))
    }
}

/// `-n`: a leading `+` appends to the existing notes instead of replacing them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotesEdit {
    Replace(String),
    Append(String),
}

impl From<&str> for NotesEdit {
    fn from(typed: &str) -> Self {
        let Notes(notes) = Notes::from(typed);
        match notes.strip_prefix('+') {
            Some(rest) => Self::Append(rest.trim().to_owned()),
            None => Self::Replace(notes),
        }
    }
}

impl NotesEdit {
    pub fn apply(self, notes: &mut String) {
        match self {
            Self::Replace(new) => *notes = new,
            Self::Append(more) => {
                if !notes.is_empty() {
                    notes.push('\n');
                }
                notes.push_str(&more);
            }
        }
    }
}

// --- command-line field syntax -----------------------------------------------------------------

/// Where a `field=value` edit looks first: `f.` insists on the record type's own fields; `c.` is
/// accepted for Commander compatibility but, as there, doesn't restrict anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Section {
    #[default]
    Any,
    Fields,
}

/// One parsed `[f.|c.][type.][label]=value` argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub section: Section,
    /// Empty when only a label was given.
    pub ty:      String,
    pub label:   String,
    pub value:   String,
}

impl FromStr for Spec {
    type Err = Error;

    fn from_str(arg: &str) -> Result<Self> {
        let bad = |why: &str| Error::Generic(format!("Expected: <field>=<value>, got: {arg}; {why}"));
        let (name, mut value) = arg.split_once('=').ok_or_else(|| bad("Missing `=`"))?;
        if name.is_empty() {
            return Err(bad("Missing <field>"));
        }
        // `==` inside the name stands for a literal `=`: keep absorbing "=<more name>=".
        let mut name = name.to_owned();
        while let Some((more, rest)) = value.strip_prefix('=').and_then(|v| v.split_once('=')) {
            name.push('=');
            name.push_str(more);
            value = rest;
        }
        let (section, name) = match name.strip_prefix("f.") {
            Some(name) => (Section::Fields, name),
            None => {
                match name.strip_prefix("c.") {
                    Some(name) => (Section::Any, name),
                    None => (Section::Any, name.as_str()),
                }
            }
        };
        if name.is_empty() {
            return Err(bad("Missing field type or label"));
        }
        let (ty, label) = match name.split_once('.') {
            Some(split) => split,
            None if name == "file" || Def::lookup(name).is_some() => (name, ""),
            None => ("", name),
        };
        Ok(Self {
            section,
            ty: ty.to_owned(),
            label: label.to_owned(),
            value: value.trim().to_owned(),
        })
    }
}

/// What the value of a `field=value` argument asks for.
enum Input<'a> {
    /// `$GEN[:params]`
    Generate(&'a str),
    /// `$BASE64:<encoded>`
    Base64(&'a str),
    /// `$JSON...`, expected to continue `:<json>`
    Json(&'a str),
    Plain(&'a str),
}

impl<'a> From<&'a str> for Input<'a> {
    fn from(value: &'a str) -> Self {
        if let Some(rest) = value.strip_prefix("$GEN") {
            Self::Generate(rest)
        } else if let Some(encoded) = value.strip_prefix("$BASE64:") {
            Self::Base64(encoded)
        } else if let Some(rest) = value.strip_prefix("$JSON") {
            Self::Json(rest)
        } else {
            Self::Plain(value)
        }
    }
}

#[derive(Debug)]
pub enum FindingWarning {
    Message(String),
    Cause(Error),
}

/// Problems found while applying edits. Errors always stop the command; warnings only without
/// `--force`.
#[derive(Debug, Default)]
pub struct Findings {
    pub warnings: Vec<FindingWarning>,
    pub errors:   Vec<Error>,
}

/// What one edit does to a field's values.
enum Assign {
    /// Replace all values.
    Replace(Vec<Value>),
    /// Set the first value (objects are merged into an existing object).
    Set(Value),
}

enum Slot<'a> {
    Fields(&'a mut Field),
    Custom(&'a mut Field),
}

const GEN_LABELS: [&str; 4] = ["password", "passphrase", "pwd", "secret"];

/// Applies `field=value` edits the way Commander's `record-add`/`record-update` do: existing
/// fields are matched first, unknown ones become custom fields, and an empty value deletes.
pub fn apply(body: &mut Body, specs: &[Spec], found: &mut Findings) {
    for spec in specs {
        if spec.value.starts_with("$GEN")
            && spec.ty != "password"
            && GEN_LABELS.contains(&spec.label.to_lowercase().as_str())
        {
            found.errors.push(Error::Generic(format!(
                "Use lowercase field type password='{}' instead of {}=... ($GEN only works on password fields).",
                spec.value, spec.label
            )));
            continue;
        }
        let ty = if spec.ty.is_empty() { "text" } else { spec.ty.as_str() };
        if Def::lookup(ty).is_none() && !spec.value.is_empty() && !spec.value.starts_with("$JSON") {
            found.warnings.push(FindingWarning::Message(format!(
                "Field type \"{ty}\" is not supported. Field: {ty}.{}",
                spec.label
            )));
            continue;
        }
        let Some(slot) = locate(body, spec, ty, found) else {
            continue;
        };
        if spec.value.is_empty() {
            match slot {
                Slot::Fields(field) => field.value.clear(),
                Slot::Custom(_) => {
                    let label = spec.label.to_lowercase();
                    let ignore_label = Def::lookup(ty).is_some_and(|d| d.multiple == Multiple::Never);
                    let mut removed = false;
                    body.custom.retain_mut(|field| {
                        if !removed && field_matches(field, spec, &label, ignore_label) {
                            removed = true;
                            false
                        } else {
                            true
                        }
                    });
                }
            }
            continue;
        }
        let field = match slot {
            Slot::Fields(field) | Slot::Custom(field) => field,
        };
        let assign = match Input::from(spec.value.as_str()) {
            Input::Generate(rest) => generated(&field.ty, rest, found),
            Input::Base64(encoded) => decoded(&field.ty, encoded, found),
            Input::Json(rest) => raw_json(&field.ty, rest, found),
            Input::Plain(typed) => {
                match plain(&field.ty, typed) {
                    Ok(assign) => Some(assign),
                    Err(source) => {
                        found.warnings.push(FindingWarning::Cause(Error::Context {
                            context: format!("Field \"{}\"", field.ty),
                            source:  Box::new(source),
                        }));
                        None
                    }
                }
            }
        };
        if let Some(assign) = assign {
            store(field, assign);
        }
    }
}

/// Finds the field an edit is about, creating a custom field for a non-empty value that matches
/// nothing.
fn field_matches(field: &Field, spec: &Spec, label: &str, ignore_label: bool) -> bool {
    (spec.ty.is_empty() || field.ty == spec.ty) && (ignore_label || field.label.to_lowercase() == label)
}

fn locate<'a>(body: &'a mut Body, spec: &Spec, ty: &str, found: &mut Findings) -> Option<Slot<'a>> {
    let label = spec.label.to_lowercase();
    // An unknown type has no rules: labels count and there is no single-field shortcut.
    let def = Def::lookup(ty);
    let ignore_label = def.is_some_and(|d| d.multiple == Multiple::Never);

    if spec.section == Section::Fields {
        let only = {
            let mut of_type = body.fields.iter().filter(|field| field.ty == ty);
            of_type.next().is_some() && of_type.next().is_none()
        };
        let hit = body
            .fields
            .iter_mut()
            .find(|field| field.ty == ty && (only || field.label.to_lowercase() == label));
        if hit.is_none() {
            found.warnings.push(FindingWarning::Message(format!(
                "Field type \"{ty}\" is not found for record type {}",
                body.type_name
            )));
        }
        return hit.map(Slot::Fields);
    }

    if let Some(index) = body
        .fields
        .iter()
        .position(|field| field_matches(field, spec, &label, ignore_label))
    {
        return body.fields.get_mut(index).map(Slot::Fields);
    }
    // "url=..." without a label hits the record's only url field whatever it is labelled.
    if label.is_empty() && def.is_some_and(|d| d.multiple != Multiple::Always) {
        let mut of_type = body.fields.iter().enumerate().filter(|(_, field)| field.ty == ty);
        if let Some((index, _)) = of_type.next()
            && of_type.next().is_none()
        {
            return body.fields.get_mut(index).map(Slot::Fields);
        }
    }
    if let Some(index) = body
        .custom
        .iter()
        .position(|field| field_matches(field, spec, &label, ignore_label))
    {
        return body.custom.get_mut(index).map(Slot::Custom);
    }
    if spec.value.is_empty() {
        return None;
    }
    body.custom.push(Field {
        ty: ty.to_owned(),
        label: spec.label.clone(),
        ..Field::default()
    });
    body.custom.last_mut().map(Slot::Custom)
}

fn store(field: &mut Field, assign: Assign) {
    let template = Def::lookup(&field.ty).map_or(Template::Text, |d| Template::from(d.ty));
    match assign {
        Assign::Replace(mut values) => {
            values.iter_mut().for_each(|v| complete(&template, v));
            field.value = values;
        }
        Assign::Set(value) => {
            match (field.value.first_mut(), value) {
                (Some(Value::Object(old)), Value::Object(mut new)) => {
                    old.append(&mut new);
                    // A null in the new object deletes that key.
                    old.retain(|_, v| !v.is_null());
                }
                (Some(first), value) => *first = value,
                (None, mut value) => {
                    complete(&template, &mut value);
                    field.value.push(value);
                }
            }
        }
    }
}

/// Adds the keys a value of this shape is expected to have.
fn complete(template: &Template, value: &mut Value) {
    if let (Template::Object(keys), Value::Object(map)) = (template, value) {
        for key in *keys {
            map.entry(*key).or_insert_with(|| Value::String(String::new()));
        }
    }
}

// --- values ------------------------------------------------------------------------------------

fn generated(ty: &str, rest: &str, found: &mut Findings) -> Option<Assign> {
    match ty {
        "password" => {
            let password = rest
                .strip_prefix(':')
                .unwrap_or_default()
                .parse::<Recipe>()
                .and_then(Recipe::password);
            match password {
                Ok(password) => Some(Assign::Set(Value::String(password))),
                Err(error) => {
                    found.errors.push(error);
                    None
                }
            }
        }
        "oneTimeCode" | "otp" => {
            let secret = data_encoding::BASE32.encode(&crypto::random_bytes(20));
            Some(Assign::Set(Value::String(format!("otpauth://totp/Commander?secret={secret}&issuer=Keeper"))))
        }
        "keyPair" | "privateKey" => {
            found.warnings.push(FindingWarning::Message(
                "Generating key pairs with $GEN is not supported; paste the key instead.".into(),
            ));
            None
        }
        other => {
            found
                .warnings
                .push(FindingWarning::Message(format!("Cannot generate a value for a \"{other}\" field.")));
            None
        }
    }
}

fn decoded(ty: &str, encoded: &str, found: &mut Findings) -> Option<Assign> {
    if encoded.is_empty() {
        found
            .warnings
            .push(FindingWarning::Message("Base64 value cannot be empty. Format: $BASE64:<base64_string>".into()));
        return None;
    }
    let text = match BASE64.decode(encoded.as_bytes()).map(String::from_utf8) {
        Ok(Ok(text)) if text.is_empty() => {
            found
                .warnings
                .push(FindingWarning::Message("Base64 decoded to empty value".into()));
            return None;
        }
        Ok(Ok(text)) => text,
        Ok(Err(source)) => {
            found.warnings.push(FindingWarning::Cause(Error::Context {
                context: "Invalid base64 value".into(),
                source:  Box::new(source.into()),
            }));
            return None;
        }
        Err(source) => {
            found.warnings.push(FindingWarning::Cause(Error::Context {
                context: "Invalid base64 value".into(),
                source:  Box::new(source.into()),
            }));
            return None;
        }
    };
    match Def::lookup(ty).map(|d| Template::from(d.ty)) {
        Some(Template::Text) | None => Some(Assign::Set(Value::String(text))),
        Some(_) => {
            found
                .warnings
                .push(FindingWarning::Message(format!("$BASE64 only fits text fields, not \"{ty}\".")));
            None
        }
    }
}

fn raw_json(ty: &str, rest: &str, found: &mut Findings) -> Option<Assign> {
    let Some(json) = rest.strip_prefix(':') else {
        found
            .warnings
            .push(FindingWarning::Message("Format: $JSON:<json_object>".into()));
        return None;
    };
    if json.is_empty() {
        found
            .warnings
            .push(FindingWarning::Message("JSON value cannot be empty. Format: $JSON:<json_object>".into()));
        return None;
    }
    match serde_json::from_str::<Value>(json) {
        Ok(value) => checked(ty, value, found),
        Err(source) => {
            found.warnings.push(FindingWarning::Cause(Error::Context {
                context: "Invalid JSON value".into(),
                source:  Box::new(source.into()),
            }));
            None
        }
    }
}

/// Commander's `validate_json_value`: raw JSON must fit the field's shape, and objects are
/// completed with the shape's keys before they overwrite what the field holds.
fn checked(ty: &str, value: Value, found: &mut Findings) -> Option<Assign> {
    let Some(def) = Def::lookup(ty) else {
        return Some(Assign::Set(value));
    };
    match (Template::from(def.ty), value) {
        (Template::Text, value @ Value::String(_))
        | (Template::Number, value @ (Value::Number(_) | Value::Bool(_)))
        | (Template::Flag, value @ Value::Bool(_)) => Some(Assign::Set(value)),
        (Template::Object(keys), value @ (Value::Array(_) | Value::Object(_))) => {
            let items = match value {
                Value::Array(items) => {
                    if def.multiple != Multiple::Always {
                        found
                            .warnings
                            .push(FindingWarning::Message(format!("Field \"{ty}\" does not support multiple values")));
                    }
                    items
                }
                single => vec![single],
            };
            let mut objects = Vec::new();
            for item in items {
                let mut map = match item {
                    Value::Object(map) => map,
                    _ => {
                        found.warnings.push(FindingWarning::Message(format!(
                            "Field \"{ty}\": expected JSON objects in an object array"
                        )));
                        return None;
                    }
                };
                let mut unknown: Vec<&str> = map.keys().map(String::as_str).filter(|k| !keys.contains(k)).collect();
                unknown.sort_unstable();
                if !unknown.is_empty() {
                    found.warnings.push(FindingWarning::Message(format!(
                        "Field \"{ty}\": Properties \"{}\" are not supported.",
                        unknown.join(", ")
                    )));
                }
                for key in keys {
                    map.entry(*key).or_insert_with(|| Value::String(String::new()));
                }
                objects.push(Value::Object(map));
            }
            match objects.len() {
                0 => None,
                1 => objects.pop().map(Assign::Set),
                _ => Some(Assign::Replace(objects)),
            }
        }
        (Template::Text, _) => {
            found
                .warnings
                .push(FindingWarning::Message(format!("Field \"{ty}\": expected a JSON string")));
            None
        }
        (Template::Number, _) => {
            found
                .warnings
                .push(FindingWarning::Message(format!("Field \"{ty}\": expected a JSON number or boolean")));
            None
        }
        (Template::Flag, _) => {
            found
                .warnings
                .push(FindingWarning::Message(format!("Field \"{ty}\": expected a JSON boolean")));
            None
        }
        (Template::Object(_), _) => {
            found
                .warnings
                .push(FindingWarning::Message(format!("Field \"{ty}\": expected a JSON object or array of objects")));
            None
        }
    }
}

/// Parses the compact notation Commander documents for each field type.
fn plain(ty: &str, typed: &str) -> Result<Assign> {
    use FieldType as T;
    let def: Def = ty.parse()?;
    Ok(match def.ty {
        T::Text
        | T::Url
        | T::Json
        | T::FileRef
        | T::Email
        | T::Secret
        | T::Otp
        | T::Login
        | T::Password
        | T::AddressRef
        | T::CardRef
        | T::Dropdown
        | T::RecordRef
        | T::RbiUrl => Assign::Set(Value::String(typed.to_owned())),
        T::Multiline => Assign::Set(Value::String(Notes::from(typed).0)),
        T::Checkbox => Assign::Set(serde_json::to_value(typed.parse::<Checked>()?)?),
        T::Date => Assign::Set(serde_json::to_value(typed.parse::<Millis>()?)?),
        T::Host => Assign::Set(serde_json::to_value(typed.parse::<Host>()?)?),
        T::Phone => Assign::Set(serde_json::to_value(typed.parse::<Phone>()?)?),
        T::Name => Assign::Set(serde_json::to_value(typed.parse::<Person>()?)?),
        T::Address => Assign::Set(serde_json::to_value(typed.parse::<Address>()?)?),
        T::PaymentCard => Assign::Set(serde_json::to_value(typed.parse::<Card>()?)?),
        T::BankAccount => Assign::Set(serde_json::to_value(typed.parse::<Account>()?)?),
        T::PrivateKey => Assign::Set(serde_json::to_value(typed.parse::<SshKey>()?)?),
        T::SecurityQuestion => {
            Assign::Replace(
                typed
                    .split(';')
                    .map(|qa| Ok(serde_json::to_value(qa.trim().parse::<Question>()?)?))
                    .collect::<Result<_>>()?,
            )
        }
        T::Schedule
        | T::Passkey
        | T::Script
        | T::AppFiller
        | T::PamResources
        | T::PamSettings
        | T::PamRemoteBrowserSettings => {
            return Err(Error::Generic(format!("Unsupported field type: {ty}; use $JSON:<json> instead.")));
        }
    })
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    host_name: String,
    port:      String,
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let (host, port) = typed.split_once(':').unwrap_or((typed, ""));
        Ok(Self {
            host_name: host.trim().to_owned(),
            port:      port.trim().to_owned(),
        })
    }
}

/// `[type:] [REGION] number [ext]`, e.g. `Mobile: US (555)555-1234`.
#[derive(Serialize)]
struct Phone {
    #[serde(rename = "type")]
    kind:   String,
    region: String,
    number: String,
    ext:    String,
}

impl FromStr for Phone {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let (mut kind, rest) = match typed.split_once(':') {
            Some((kind, rest)) if !rest.is_empty() => (kind.to_owned(), rest),
            Some((before, _)) => (String::new(), before),
            None => (String::new(), typed),
        };
        let (mut region, mut number, mut ext) = (String::new(), String::new(), String::new());
        for part in rest.trim().split(' ').map(str::trim) {
            if !part.is_empty() && part.chars().all(char::is_alphabetic) {
                if part.chars().count() == 2 {
                    if region.is_empty() {
                        region = part.to_owned();
                    }
                } else if kind.is_empty() {
                    kind = part.to_owned();
                }
            } else if part.chars().count() >= 6 {
                if number.is_empty() {
                    number = part.to_owned();
                }
            } else if ext.is_empty() {
                ext = part.to_owned();
            }
        }
        Ok(Self {
            kind:   kind.trim().to_owned(),
            region: region.trim().to_owned(),
            number: number.trim().to_owned(),
            ext:    ext.trim().to_owned(),
        })
    }
}

/// `Last, First Middle` or `First Middle Last`.
#[derive(Serialize)]
struct Person {
    first:  String,
    middle: String,
    last:   String,
}

impl FromStr for Person {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let (last, rest) = match (typed.split_once(','), typed.rsplit_once(' ')) {
            (Some((last, rest)), _) => (last, rest),
            (None, Some((rest, last))) => (last, rest),
            (None, None) => (typed, ""),
        };
        let (first, middle) = match rest.trim().rsplit_once(' ') {
            Some((first, middle)) => (first, middle),
            None => (rest.trim(), ""),
        };
        Ok(Self {
            first:  first.trim().to_owned(),
            middle: middle.trim().to_owned(),
            last:   last.trim().to_owned(),
        })
    }
}

/// `street, city, STATE zip, country`.
#[derive(Serialize)]
struct Address {
    street1: String,
    street2: String,
    city:    String,
    state:   String,
    zip:     String,
    country: String,
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let part = |i: usize| {
            typed
                .split(',')
                .nth(i)
                .map_or_else(String::new, |s| s.trim().to_owned())
        };
        let region = part(2);
        let (mut state, mut zip) = match region.split_once(' ') {
            Some((state, zip)) => (state.to_owned(), zip.to_owned()),
            None => (region, String::new()),
        };
        // A lone number is a zip code, not a state.
        if zip.is_empty() && !state.is_empty() && state.chars().all(char::is_numeric) {
            zip = std::mem::take(&mut state);
        }
        Ok(Self {
            street1: part(0),
            street2: String::new(),
            city: part(1),
            state,
            zip,
            country: part(3),
        })
    }
}

/// `question? answer`
#[derive(Serialize)]
struct Question {
    question: String,
    answer:   String,
}

impl FromStr for Question {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let (question, answer) = typed.split_once('?').unwrap_or((typed, ""));
        Ok(Self {
            question: format!("{}?", question.trim()),
            answer:   answer.trim().to_owned(),
        })
    }
}

/// `4111111111111111 04/2026 123`
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Card {
    card_number:          String,
    card_expiration_date: String,
    card_security_code:   String,
}

impl FromStr for Card {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let mut card = Self {
            card_number:          String::new(),
            card_expiration_date: String::new(),
            card_security_code:   String::new(),
        };
        for part in typed.split(' ').map(str::trim).filter(|p| !p.is_empty()) {
            if part.chars().count() > 10 {
                card.card_number = part.to_owned();
            } else if part.contains('/') {
                card.card_expiration_date = part.to_owned();
            } else if part.chars().count() <= 6 {
                card.card_security_code = part.to_owned();
            }
        }
        if card.card_number.is_empty() && card.card_expiration_date.is_empty() && card.card_security_code.is_empty() {
            return Err(Error::Generic("Incorrect payment card value: expected \"<number> <MM/YYYY> <code>\"".into()));
        }
        Ok(card)
    }
}

/// `Checking: 123456789 987654321` (routing number, then account number).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    account_type:   String,
    routing_number: String,
    account_number: String,
}

impl FromStr for Account {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let mut account = Self {
            account_type:   String::new(),
            routing_number: String::new(),
            account_number: String::new(),
        };
        for part in typed.split_whitespace() {
            if part.chars().all(char::is_numeric) {
                if account.routing_number.is_empty() {
                    account.routing_number = part.to_owned();
                } else if account.account_number.is_empty() {
                    account.account_number = part.to_owned();
                }
            } else if account.account_type.is_empty() {
                account.account_type = part.to_owned();
            }
        }
        if account.routing_number.is_empty() && account.account_number.is_empty() {
            return Err(Error::Generic(
                "Incorrect bank account value: expected \"<type> <routing number> <account number>\"".into(),
            ));
        }
        Ok(account)
    }
}

/// A private key, with `\n` standing for newlines so it fits one argument.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SshKey {
    private_key: String,
    public_key:  String,
}

impl FromStr for SshKey {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        Ok(Self {
            private_key: typed.replace("\\n", "\n"),
            public_key:  String::new(),
        })
    }
}

#[derive(Serialize)]
#[serde(transparent)]
struct Checked(bool);

impl FromStr for Checked {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        match typed.to_lowercase().as_str() {
            "1" | "y" | "yes" | "t" | "true" => Ok(Self(true)),
            "0" | "n" | "no" | "f" | "false" => Ok(Self(false)),
            _ => Err(Error::Generic("Incorrect boolean value: expected [t]rue or [f]alse".into())),
        }
    }
}

/// Unix time in milliseconds, written as epoch seconds or milliseconds, `YYYY-MM-DD` (noon UTC,
/// so no time zone moves the day) or `YYYY-MM-DDThh:mm:ssZ`.
#[derive(Serialize)]
#[serde(transparent)]
struct Millis(i64);

impl FromStr for Millis {
    type Err = Error;

    fn from_str(typed: &str) -> Result<Self> {
        let bad = || Error::Generic("Incorrect date value: use epoch time, YYYY-MM-DD or YYYY-MM-DDThh:mm:ssZ".into());
        if is_digits(typed) {
            let n = typed.parse::<i64>().map_err(|source| {
                Error::Context {
                    context: "Incorrect date value: invalid epoch time".into(),
                    source:  Box::new(source.into()),
                }
            })?;
            // Commander's docs show epoch seconds, but stored dates are milliseconds; no
            // plausible millisecond value is below 10^11 (1973).
            return Ok(Self(if n < 100_000_000_000 { n.saturating_mul(1000) } else { n }));
        }
        let (date, clock) = match typed.split_once('T') {
            Some((date, clock)) => (date, clock.strip_suffix('Z').ok_or_else(bad)?),
            None => (typed, "12:00:00"),
        };
        let numbers = |s: &str, sep: char| -> Result<[i64; 3]> {
            let mut parts = s.split(sep);
            let [Some(first), Some(second), Some(third)] = [parts.next(), parts.next(), parts.next()] else {
                return Err(bad());
            };
            if parts.next().is_some() {
                return Err(bad());
            }
            let parse = |part: &str| {
                part.parse::<i64>().map_err(|source| {
                    Error::Context {
                        context: "Incorrect date value: invalid numeric component".into(),
                        source:  Box::new(source.into()),
                    }
                })
            };
            Ok([parse(first)?, parse(second)?, parse(third)?])
        };
        let [year, month, day] = numbers(date, '-')?;
        let [hour, minute, second] = numbers(clock, ':')?;
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let month_days = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            _ => return Err(bad()),
        };
        let in_range = (1..=9999).contains(&year)
            && (1..=month_days).contains(&day)
            && (0..24).contains(&hour)
            && (0..60).contains(&minute)
            && (0..60).contains(&second);
        if !in_range {
            return Err(bad());
        }
        // Days since the epoch of a proleptic Gregorian date (Hinnant's days_from_civil).
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let year_of_era = y - era * 400;
        let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        Ok(Self(((days * 24 + hour) * 3600 + minute * 60 + second) * 1000))
    }
}

// --- generated values --------------------------------------------------------------------------

/// `$GEN:<algorithm>,<length>` for a password; both parts are optional.
struct Recipe {
    algorithm: Algorithm,
    length:    Option<usize>,
}

enum Algorithm {
    Rand,
    /// A Commander algorithm that needs a word list this port doesn't carry.
    Wordlist(&'static str),
}

impl FromStr for Recipe {
    type Err = Error;

    fn from_str(params: &str) -> Result<Self> {
        let params: Vec<&str> = if params.is_empty() {
            Vec::new()
        } else {
            params.split(',').map(str::trim).collect()
        };
        let algorithm = match params.first() {
            None => Algorithm::Rand,
            Some(first) => {
                match first.to_lowercase().as_str() {
                    "rand" => Algorithm::Rand,
                    "dice" => Algorithm::Wordlist("dice"),
                    "crypto" => Algorithm::Wordlist("crypto"),
                    "passphrase" => Algorithm::Wordlist("passphrase"),
                    _ if is_digits(first) => Algorithm::Rand,
                    _ => {
                        return Err(Error::Generic(format!(
                            "Unknown $GEN password algorithm \"{first}\". Valid algorithms: rand, dice, crypto, passphrase."
                        )));
                    }
                }
            }
        };
        let length: Option<usize> = params.iter().find(|p| is_digits(p)).map(|p| p.parse()).transpose()?;
        Ok(Self { algorithm, length })
    }
}

impl Recipe {
    fn password(self) -> Result<String> {
        match self.algorithm {
            Algorithm::Rand => {
                // Commander's bounds for a plain random password.
                let length = self.length.unwrap_or(generator::DEFAULT_LENGTH).clamp(4, 200);
                generator::generate(&Rules {
                    length,
                    ..Rules::default()
                })
            }
            Algorithm::Wordlist(name) => {
                Err(Error::Generic(format!("$GEN password algorithm \"{name}\" is not supported; use rand.")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn login_body() -> Body {
        Body {
            type_name: "login".into(),
            fields: vec![
                Field {
                    ty: "login".into(),
                    label: "login".into(),
                    ..Field::default()
                },
                Field {
                    ty: "password".into(),
                    label: "password".into(),
                    ..Field::default()
                },
                Field {
                    ty: "url".into(),
                    label: "url".into(),
                    ..Field::default()
                },
            ],
            ..Body::default()
        }
    }

    fn spec(arg: &str) -> Spec {
        arg.parse().unwrap()
    }

    fn edit(body: &mut Body, args: &[&str]) -> Findings {
        let specs = args.iter().map(|s| spec(s)).collect::<Vec<_>>();
        let mut found = Findings::default();
        apply(body, &specs, &mut found);
        found
    }

    fn only_value(field: &Field) -> &Value {
        let [value] = field.value.as_slice() else {
            panic!("expected one field value");
        };
        value
    }

    fn only_custom_object(body: &Body) -> &Map<String, Value> {
        let [field] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        let [Value::Object(value)] = field.value.as_slice() else {
            panic!("expected one object value");
        };
        value
    }

    #[test]
    fn field_specs_decode_escaped_equals_and_sections() {
        let parsed: Spec = "f.text.a==b==c= =value".parse().unwrap();
        assert_eq!(parsed.section, Section::Fields);
        assert_eq!(parsed.ty, "text");
        assert_eq!(parsed.label, "a=b=c");
        assert_eq!(parsed.value, "=value");
        assert!("=value".parse::<Spec>().is_err());
        assert!("field".parse::<Spec>().is_err());
    }

    #[test]
    fn field_updates_match_typed_fields_and_remove_custom_fields() {
        let mut body = login_body();
        let found = edit(&mut body, &["login=alice", "password=secret", "text.note=extra"]);
        assert!(found.errors.is_empty() && found.warnings.is_empty());
        let [login, password, url] = body.fields.as_slice() else {
            panic!("expected login, password, and url fields");
        };
        assert_eq!(login.ty, "login");
        assert_eq!(password.ty, "password");
        assert_eq!(url.ty, "url");
        assert!(url.value.is_empty());
        assert_eq!(only_value(login), &json!("alice"));
        assert_eq!(only_value(password), &json!("secret"));
        let [note] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        assert_eq!(note.label, "note");
        let found = edit(&mut body, &["text.note="]);
        assert!(found.warnings.is_empty());
        assert!(body.custom.is_empty());
    }

    #[test]
    fn single_typed_field_fallback_precedes_custom_field_match() {
        let mut body = Body {
            fields: vec![Field {
                ty: "text".into(),
                label: "Main".into(),
                ..Field::default()
            }],
            custom: vec![Field {
                ty: "text".into(),
                value: vec![json!("custom")],
                ..Field::default()
            }],
            ..Body::default()
        };
        let found = edit(&mut body, &["text=typed"]);
        assert!(found.errors.is_empty() && found.warnings.is_empty());
        let [field] = body.fields.as_slice() else {
            panic!("expected one typed field");
        };
        let [custom] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        assert_eq!(only_value(field), &json!("typed"));
        assert_eq!(only_value(custom), &json!("custom"));
    }

    #[test]
    fn exact_field_then_repeated_custom_match_precedes_no_single_fallback() {
        let mut body = Body {
            fields: vec![
                Field {
                    ty: "text".into(),
                    label: "First".into(),
                    ..Field::default()
                },
                Field {
                    ty: "text".into(),
                    label: "Second".into(),
                    ..Field::default()
                },
            ],
            custom: vec![Field {
                ty: "text".into(),
                label: "Custom".into(),
                value: vec![json!("custom")],
                ..Field::default()
            }],
            ..Body::default()
        };

        let found = edit(&mut body, &["text.first=exact", "text.Custom=custom-match"]);
        assert!(found.errors.is_empty() && found.warnings.is_empty());
        let [first, second] = body.fields.as_slice() else {
            panic!("expected two typed fields");
        };
        assert_eq!(only_value(first), &json!("exact"));
        assert!(second.value.is_empty());
        let [custom] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        assert_eq!(only_value(custom), &json!("custom-match"));
    }

    #[test]
    fn unknown_type_is_expected_absence_and_accepts_custom_json() {
        assert!(Def::lookup("futureField").is_none());
        assert!("futureField".parse::<Def>().is_err());

        let mut body = Body::default();
        let found = edit(&mut body, &[r#"futureField.data=$JSON:{"ok":true}"#]);
        assert!(found.warnings.is_empty());
        let [custom] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        assert_eq!(only_value(custom), &json!({"ok": true}));
    }

    #[test]
    fn compound_json_fields_are_completed_and_merge_null_deletes_keys() {
        let mut body = login_body();
        let found = edit(&mut body, &[r#"phone.Cell=$JSON:{"number":"555","type":"Mobile"}"#]);
        assert!(found.warnings.is_empty());
        assert_eq!(only_custom_object(&body).get("type"), Some(&json!("Mobile")));

        // Commander completes each JSON object before applying it, so omitted keys reset to "".
        let found = edit(&mut body, &[r#"phone.Cell=$JSON:{"number":"123","region":"US"}"#]);
        assert!(found.warnings.is_empty());
        let phone = only_custom_object(&body);
        assert_eq!(phone.get("number"), Some(&json!("123")));
        assert_eq!(phone.get("type"), Some(&json!("")));
        assert_eq!(phone.get("region"), Some(&json!("US")));
        assert_eq!(phone.get("ext"), Some(&json!("")));

        let found = edit(&mut body, &[r#"phone.Cell=$JSON:{"type":null}"#]);
        assert!(found.warnings.is_empty());
        assert!(only_custom_object(&body).get("type").is_none());
    }

    #[test]
    fn compound_values_and_notes_use_commander_notation() {
        let mut body = login_body();
        let Notes(notes) = Notes::from("first\\nsecond");
        let found = edit(&mut body, &["phone=Mobile: US (555)555-1234"]);
        assert!(found.errors.is_empty() && found.warnings.is_empty());
        assert_eq!(notes, "first\nsecond");
        assert_eq!(only_custom_object(&body).get("number"), Some(&json!("(555)555-1234")));
        let mut notes = "old".to_owned();
        NotesEdit::from("+ next\\nline").apply(&mut notes);
        assert_eq!(notes, "old\nnext\nline");
    }

    #[test]
    fn invalid_values_warn_and_generation_errors_are_distinct() {
        let mut body = login_body();
        let found = edit(&mut body, &["date=2023-02-29", "text.secret=$GEN"]);
        assert!(!found.warnings.is_empty());
        assert!(!found.errors.is_empty());
    }

    #[test]
    fn changing_type_keeps_filled_fields_as_custom() {
        let mut body = login_body();
        let found = edit(&mut body, &["login=alice", "password=secret"]);
        assert!(found.warnings.is_empty());
        let defs = [TypeField {
            reference: "login".into(),
            label: "User".into(),
            ..TypeField::default()
        }];
        adjust(&mut body, &defs);
        assert_eq!(body.fields.len(), 1);
        let [field] = body.fields.as_slice() else {
            panic!("expected one typed field");
        };
        assert_eq!(only_value(field), &json!("alice"));
        let [custom] = body.custom.as_slice() else {
            panic!("expected one custom field");
        };
        assert_eq!(custom.ty, "password");
    }

    #[test]
    fn references_include_direct_and_script_file_links() {
        let body = Body {
            fields: vec![
                Field {
                    ty: "recordRef".into(),
                    value: vec![json!("one")],
                    ..Field::default()
                },
                Field {
                    ty: "script".into(),
                    value: vec![json!({"fileRef":"two"})],
                    ..Field::default()
                },
            ],
            ..Body::default()
        };
        assert_eq!(refs(&body), BTreeSet::from(["one".to_owned(), "two".to_owned()]));
    }

    #[test]
    fn parsed_dates_accept_seconds_milliseconds_and_calendar_dates() {
        assert_eq!("2022-11-16".parse::<Millis>().unwrap().0, 1_668_600_000_000);
        assert_eq!("1668639533".parse::<Millis>().unwrap().0, 1_668_639_533_000);
        assert_eq!("1668639533000".parse::<Millis>().unwrap().0, 1_668_639_533_000);
        assert!("2023-02-29".parse::<Millis>().is_err());
    }

    #[test]
    fn parsed_dates_require_fixed_calendar_and_clock_components() {
        assert!("2022-11-16T12:34:56Z".parse::<Millis>().is_ok());
        for invalid in [
            "2022-11",
            "2022-11-16-17",
            "2022-11-16T12:00Z",
            "2022-11-16T12:00:00:01Z",
            "sentinel-secret-value",
        ] {
            assert!(invalid.parse::<Millis>().is_err());
        }
    }

    #[test]
    fn invalid_privacy_sensitive_field_values_are_not_echoed() {
        fn parse_error<T>(result: Result<T>) -> Error {
            match result {
                Err(error) => error,
                Ok(_) => panic!("expected invalid field value"),
            }
        }

        let secret = "sentinel-secret-value";
        let card_secret = "secretxx";
        let card_error = parse_error(card_secret.parse::<Card>());
        assert!(!card_error.to_string().contains(card_secret));
        for error in [
            parse_error(secret.parse::<Checked>()),
            parse_error(secret.parse::<Millis>()),
            parse_error(secret.parse::<Account>()),
        ] {
            assert!(!error.to_string().contains(secret));
        }

        let overflow = parse_error("999999999999999999999999".parse::<Millis>());
        assert!(matches!(overflow, Error::Context { .. }));
        assert!(std::error::Error::source(&overflow).is_some());
    }
}
