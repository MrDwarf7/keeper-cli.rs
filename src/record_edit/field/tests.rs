use serde_json::json;

use super::*;

/// A body shaped like a fresh `login` record, labelled the way `record-add` labels it.
fn login_body() -> Body {
    Body {
        type_name: "login".into(),
        title: "T".into(),
        fields: ["login", "password", "url", "fileRef", "oneTimeCode"]
            .map(|ty| {
                TypeField {
                    reference: ty.into(),
                    ..TypeField::default()
                }
                .blank(Labels::On)
            })
            .into(),
        ..Body::default()
    }
}

fn spec(arg: &str) -> Spec {
    arg.parse().unwrap()
}

fn edit(body: &mut Body, args: &[&str]) -> Findings {
    let mut found = Findings::default();
    apply(body, &args.iter().map(|a| spec(a)).collect::<Vec<_>>(), &mut found);
    found
}

fn first(body: &Body, ty: &str) -> Value {
    body.fields
        .iter()
        .chain(&body.custom)
        .find(|f| f.ty == ty)
        .and_then(|f| f.value.first().cloned())
        .unwrap_or(Value::Null)
}

#[test]
fn spec_splits_set_type_label_and_value() {
    let s = spec("login=bob");
    assert_eq!((s.section, s.ty.as_str(), s.label.as_str(), s.value.as_str()), (Section::Any, "login", "", "bob"));

    let s = spec("c.url.Web URL= https://x ");
    assert_eq!(
        (s.section, s.ty.as_str(), s.label.as_str(), s.value.as_str()),
        (Section::Any, "url", "Web URL", "https://x")
    );

    let s = spec("f.password=pw");
    assert_eq!((s.section, s.ty.as_str(), s.label.as_str()), (Section::Fields, "password", ""));

    // Not a field type, so it is a text label.
    let s = spec("Password=x");
    assert_eq!((s.ty.as_str(), s.label.as_str()), ("", "Password"));

    // The first dot splits type from label, as in Commander.
    let s = spec("google.com=x");
    assert_eq!((s.ty.as_str(), s.label.as_str()), ("google", "com"));
    let s = spec("text.google.com=x");
    assert_eq!((s.ty.as_str(), s.label.as_str()), ("text", "google.com"));

    let s = spec("file=@notes.txt");
    assert_eq!((s.ty.as_str(), s.value.as_str()), ("file", "@notes.txt"));
}

#[test]
fn spec_doubled_equals_in_a_label_and_leading_equals_in_a_value() {
    let s = spec("text.aaa==bbb= =ccc");
    assert_eq!((s.ty.as_str(), s.label.as_str(), s.value.as_str()), ("text", "aaa=bbb", "=ccc"));
    // Without a second '=' a value may itself start with one.
    let s = spec("text.a==b");
    assert_eq!((s.label.as_str(), s.value.as_str()), ("a", "=b"));
}

#[test]
fn spec_rejects_malformed_arguments() {
    for (arg, why) in [
        ("login", "Missing `=`"),
        ("=x", "Missing <field>"),
        ("c.=x", "Missing field type or label"),
    ] {
        let e = arg.parse::<Spec>().unwrap_err().to_string();
        assert!(e.contains(why), "{arg}: {e}");
    }
}

#[test]
fn standard_fields_match_by_type_and_single_fields_ignore_the_label() {
    let mut body = login_body();
    let found = edit(&mut body, &["login=bob", "password=s3", "url=https://x"]);
    assert!(found.warnings.is_empty() && found.errors.is_empty(), "{found:?}");
    assert_eq!(first(&body, "login"), json!("bob"));
    assert_eq!(first(&body, "password"), json!("s3"));
    // "url" has one field and an omitted label, so it lands in the record's own field.
    assert_eq!(first(&body, "url"), json!("https://x"));
    assert!(body.custom.is_empty());
}

#[test]
fn unmatched_fields_become_custom_fields_and_empty_values_delete_them() {
    let mut body = login_body();
    edit(&mut body, &["c.text.Note=hello", "Plain=x", "url.Backup=https://b"]);
    let custom: Vec<(&str, &str, &Value)> = body
        .custom
        .iter()
        .map(|f| (f.ty.as_str(), f.label.as_str(), &f.value[0]))
        .collect();
    assert_eq!(
        custom,
        [
            ("text", "Note", &json!("hello")),
            ("text", "Plain", &json!("x")),
            ("url", "Backup", &json!("https://b"))
        ]
    );
    // The same label (any case) updates in place instead of adding another.
    edit(&mut body, &["text.note=changed"]);
    assert_eq!(body.custom.len(), 3);
    assert_eq!(body.custom[0].value, [json!("changed")]);
    // An empty value deletes a custom field...
    edit(&mut body, &["text.Note=", "Plain="]);
    assert_eq!(body.custom.len(), 1);
    // ...but only clears a field of the record type.
    edit(&mut body, &["login=bob", "login="]);
    assert!(body.fields[0].value.is_empty() && body.fields[0].ty == "login");
    // Deleting what doesn't exist is a no-op.
    assert!(edit(&mut body, &["text.Missing="]).warnings.is_empty());
}

#[test]
fn field_set_f_only_looks_at_the_record_type_fields() {
    let mut body = login_body();
    body.custom.push(Field {
        ty: "text".into(),
        label: "Key".into(),
        value: vec![json!("old")],
        ..Field::default()
    });
    let found = edit(&mut body, &["f.text.Key=new"]);
    assert_eq!(found.warnings, ["Field type \"text\" is not found for record type login"]);
    assert_eq!(body.custom[0].value, [json!("old")]);

    // "c." doesn't restrict anything: it finds the standard field first, like Commander.
    edit(&mut body, &["c.login=carol"]);
    assert_eq!(first(&body, "login"), json!("carol"));
    assert_eq!(body.custom.len(), 1);
}

#[test]
fn unknown_field_types_warn_unless_the_value_is_empty_or_json() {
    let mut body = login_body();
    let found = edit(&mut body, &["bogus.x=1"]);
    assert_eq!(found.warnings, ["Field type \"bogus\" is not supported. Field: bogus.x"]);
    assert!(body.custom.is_empty());
    assert!(edit(&mut body, &["bogus.x="]).warnings.is_empty());
}

#[test]
fn generated_passwords_follow_the_recipe() {
    let mut body = login_body();
    for (arg, len) in [
        ("password=$GEN", 20),
        ("password=$GEN:rand,16", 16),
        ("password=$GEN:24", 24),
        ("password=$GEN: rand , 30 ", 30),
        ("password=$GEN:1", 4),
        ("password=$GEN:999", 200),
    ] {
        let found = edit(&mut body, &[arg]);
        assert!(found.errors.is_empty() && found.warnings.is_empty(), "{arg}: {found:?}");
        assert_eq!(first(&body, "password").as_str().unwrap().len(), len, "{arg}");
    }
    let found = edit(&mut body, &["password=$GEN:dice,5"]);
    assert!(found.errors[0].contains("\"dice\" is not supported"), "{found:?}");
    let found = edit(&mut body, &["password=$GEN:bogus"]);
    assert!(found.errors[0].starts_with("Unknown $GEN password algorithm \"bogus\""), "{found:?}");
}

#[test]
fn gen_on_a_password_labelled_text_field_is_refused() {
    let mut body = login_body();
    let found = edit(&mut body, &["Password=$GEN"]);
    assert_eq!(found.errors.len(), 1);
    assert!(found.errors[0].contains("Use lowercase field type password='$GEN'"), "{found:?}");
    assert!(body.custom.is_empty());
    // A type other than password gets a warning instead.
    let found = edit(&mut body, &["login=$GEN"]);
    assert_eq!(found.warnings, ["Cannot generate a value for a \"login\" field."]);
}

#[test]
fn generated_totp_is_an_otpauth_url_with_a_160_bit_secret() {
    let mut body = login_body();
    edit(&mut body, &["oneTimeCode=$GEN"]);
    let url = first(&body, "oneTimeCode");
    let url = url.as_str().unwrap();
    let secret = url
        .strip_prefix("otpauth://totp/Commander?secret=")
        .and_then(|rest| rest.strip_suffix("&issuer=Keeper"))
        .unwrap();
    assert_eq!(BASE32.decode(secret.as_bytes()).unwrap().len(), 20);
}

#[test]
fn base64_values_are_decoded_and_bad_ones_warn() {
    let mut body = login_body();
    let found = edit(&mut body, &["password=$BASE64:ZmpzemRmaGtkZg=="]);
    assert!(found.warnings.is_empty());
    assert_eq!(first(&body, "password"), json!("fjszdfhkdf"));
    for arg in [
        "password=$BASE64:",
        "password=$BASE64:not base64!",
        "password=$BASE64:/w==",
    ] {
        let found = edit(&mut body, &[arg]);
        assert_eq!(found.warnings.len(), 1, "{arg}");
    }
    assert_eq!(first(&body, "password"), json!("fjszdfhkdf"));
}

#[test]
fn json_values_are_completed_and_checked_against_the_field_shape() {
    let mut body = login_body();
    let found = edit(&mut body, &[r#"phone.Cell=$JSON:{"number": "(555) 555-1234", "type": "Mobile"}"#]);
    assert!(found.warnings.is_empty(), "{found:?}");
    assert_eq!(
        body.custom[0].value,
        [json!({"number": "(555) 555-1234", "type": "Mobile", "region": "", "ext": ""})]
    );

    let found = edit(&mut body, &[r#"phone.Cell=$JSON:{"number": "1", "bogus": 1, "alsoBogus": 2}"#]);
    assert_eq!(found.warnings, ["Field \"phone\": Properties \"alsoBogus, bogus\" are not supported."]);
    // The object replaces the old one's keys rather than merging stale ones in.
    assert_eq!(body.custom[0].value[0]["type"], json!(""));

    let found = edit(&mut body, &[r#"text.T=$JSON:[1]"#, "text.U=$JSON:{bad", "text.V=$JSON:"]);
    assert_eq!(found.warnings.len(), 3, "{found:?}");
    let found = edit(&mut body, &[r#"phone.Many=$JSON:[{"number":"1"},{"number":"2"}]"#]);
    assert_eq!(found.warnings, ["Field \"phone\" does not support multiple values"]);
    assert_eq!(body.custom.last().unwrap().value.len(), 2);
}

#[test]
fn compound_values_use_commanders_compact_notation() {
    let mut body = Body::default();
    let found = edit(
        &mut body,
        &[
            "host.H=db.example.com:5432",
            "phone.P=Mobile: US (555)555-1234 77",
            "name.N=Doe, John Jr.",
            "name.N2=Jane Q Doe",
            "address.A=123 Main St, SmallTown, CA 12345, USA",
            "address.A2=1 Road, Town, 90210",
            "paymentCard.C=4111111111111111 04/2026 123",
            "bankAccount.B=Checking 123456789 987654321",
            "securityQuestion.Q=What city? Paris; Your pet? Rex",
            "keyPair.K=-----BEGIN-----\\nabc\\n-----END-----",
            "checkbox.X=yes",
            "date.D=2022-11-16",
        ],
    );
    assert!(found.warnings.is_empty(), "{found:?}");
    let by_label = |label: &str| body.custom.iter().find(|f| f.label == label).unwrap().value.clone();
    assert_eq!(by_label("H"), [json!({"hostName": "db.example.com", "port": "5432"})]);
    assert_eq!(by_label("P"), [json!({"type": "Mobile", "region": "US", "number": "(555)555-1234", "ext": "77"})]);
    assert_eq!(by_label("N"), [json!({"first": "John", "middle": "Jr.", "last": "Doe"})]);
    assert_eq!(by_label("N2"), [json!({"first": "Jane", "middle": "Q", "last": "Doe"})]);
    assert_eq!(
        by_label("A"),
        [
            json!({"street1": "123 Main St", "street2": "", "city": "SmallTown", "state": "CA", "zip": "12345", "country": "USA"})
        ]
    );
    assert_eq!(by_label("A2")[0]["zip"], json!("90210"));
    assert_eq!(by_label("A2")[0]["state"], json!(""));
    assert_eq!(
        by_label("C"),
        [json!({"cardNumber": "4111111111111111", "cardExpirationDate": "04/2026", "cardSecurityCode": "123"})]
    );
    // The bank account's fifth key is filled in even though the notation doesn't set it.
    assert_eq!(
        by_label("B"),
        [
            json!({"accountType": "Checking", "routingNumber": "123456789", "accountNumber": "987654321", "otherType": ""})
        ]
    );
    assert_eq!(
        by_label("Q"),
        [
            json!({"question": "What city?", "answer": "Paris"}),
            json!({"question": "Your pet?", "answer": "Rex"})
        ]
    );
    assert_eq!(by_label("K"), [json!({"privateKey": "-----BEGIN-----\nabc\n-----END-----", "publicKey": ""})]);
    assert_eq!(by_label("X"), [json!(true)]);
    assert_eq!(by_label("D"), [json!(1_668_600_000_000_i64)]);
}

#[test]
fn bad_compound_and_scalar_values_warn_instead_of_saving_garbage() {
    let mut body = Body::default();
    let found = edit(
        &mut body,
        &[
            "paymentCard.C=nonsense",
            "bankAccount.B=nothing here",
            "checkbox.X=maybe",
            "date.D=yesterday",
            "pamSettings.S=x",
        ],
    );
    assert_eq!(found.warnings.len(), 5, "{found:?}");
    assert!(found.warnings[4].contains("use $JSON"), "{found:?}");
    assert!(body.custom.is_empty() || body.custom.iter().all(|f| f.value.is_empty()));
}

#[test]
fn objects_merge_into_the_existing_value_and_nulls_remove_keys() {
    let mut body = Body::default();
    body.custom.push(Field {
        ty: "bankAccount".into(),
        label: "B".into(),
        value: vec![json!({"accountType": "x", "routingNumber": "1", "accountNumber": "2", "otherType": "keep me"})],
        ..Field::default()
    });
    edit(&mut body, &["bankAccount.B=Savings 11 22"]);
    assert_eq!(
        body.custom[0].value[0],
        json!({"accountType": "Savings", "routingNumber": "11", "accountNumber": "22", "otherType": "keep me"})
    );
    edit(&mut body, &[r#"bankAccount.B=$JSON:{"otherType": null}"#]);
    assert_eq!(body.custom[0].value[0].get("otherType"), None);
}

#[test]
fn multiline_values_unescape_newlines() {
    let mut body = Body::default();
    edit(&mut body, &[r"multiline.M=a\nb\\nc"]);
    assert_eq!(body.custom[0].value, [json!("a\nb\\nc")]);
}

#[test]
fn dates_accept_epoch_seconds_milliseconds_and_iso_forms() {
    let ms = |s: &str| s.parse::<Millis>().map(|m| m.0);
    assert_eq!(ms("1668556800").unwrap(), 1_668_556_800_000);
    assert_eq!(ms("1668556800000").unwrap(), 1_668_556_800_000);
    assert_eq!(ms("2022-11-16T00:00:00Z").unwrap(), 1_668_556_800_000);
    assert_eq!(ms("2022-11-16T10:58:53Z").unwrap(), 1_668_596_333_000);
    // A bare date is noon UTC.
    assert_eq!(ms("2022-11-16").unwrap(), 1_668_600_000_000);
    assert_eq!(ms("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(ms("2024-02-29").unwrap(), 1_709_208_000_000);
    for bad in [
        "2023-02-29",
        "2022-13-01",
        "2022-00-10",
        "2022-11-31",
        "2022-11-16T25:00:00Z",
        "2022-11-16T10:00:00",
        "soon",
        "2022-11",
    ] {
        assert!(ms(bad).is_err(), "{bad}");
    }
}

#[test]
fn notes_unescape_and_plus_appends() {
    assert_eq!(Notes::from(r"a\nb").0, "a\nb");
    assert_eq!(Notes::from(r"a\\nb").0, r"a\nb");

    let mut notes = String::new();
    NotesEdit::from("+first").apply(&mut notes);
    assert_eq!(notes, "first");
    NotesEdit::from(r"+  second\nthird ").apply(&mut notes);
    assert_eq!(notes, "first\nsecond\nthird");
    NotesEdit::from("replaced").apply(&mut notes);
    assert_eq!(notes, "replaced");
    NotesEdit::from("").apply(&mut notes);
    assert_eq!(notes, "");
}

#[test]
fn definition_fields_start_labelled_with_their_type_unless_told_otherwise() {
    let def: TypeDef = serde_json::from_str(
        r#"{"$id": "login", "fields": [{"$ref": "login", "required": true}, {"$ref": "text", "label": "Pin"}, {"$ref": "appFiller", "appFillerData": {"macroSequence": "x"}}]}"#,
    )
    .unwrap();
    let on: Vec<Field> = def.fields.iter().map(|f| f.blank(Labels::On)).collect();
    assert_eq!((on[0].label.as_str(), on[0].required), ("login", true));
    assert_eq!(on[1].label, "Pin");
    assert_eq!(on[2].value, [json!({"macroSequence": "x"})]);
    let off: Vec<Field> = def.fields.iter().map(|f| f.blank(Labels::Off)).collect();
    assert_eq!(off[0].label, "");
    assert_eq!(off[1].label, "Pin");
}

#[test]
fn changing_the_record_type_keeps_filled_fields_and_demotes_the_rest() {
    let mut body = login_body();
    edit(&mut body, &["login=bob", "password=pw", "url=https://x", "c.text.Extra=e"]);
    let defs: TypeDef = serde_json::from_str(
        r#"{"fields": [{"$ref": "login", "label": "User", "required": true}, {"$ref": "password"}, {"$ref": "host"}]}"#,
    )
    .unwrap();
    adjust(&mut body, &defs.fields);
    let fields: Vec<(&str, &str, bool, usize)> = body
        .fields
        .iter()
        .map(|f| (f.ty.as_str(), f.label.as_str(), f.required, f.value.len()))
        .collect();
    // login is relabelled, password loses its type-name label, host is new and empty.
    assert_eq!(
        fields,
        [
            ("login", "User", true, 1),
            ("password", "", false, 1),
            ("host", "", false, 0)
        ]
    );
    // The filled url and the custom field survive as custom fields; empty fileRef/oneTimeCode are dropped.
    let custom: Vec<&str> = body.custom.iter().map(|f| f.ty.as_str()).collect();
    assert_eq!(custom, ["url", "text"]);
}

#[test]
fn an_unchanged_shape_leaves_the_record_alone() {
    let mut body = login_body();
    edit(&mut body, &["login=bob"]);
    let before = body.clone();
    let defs: Vec<TypeField> = body
        .fields
        .iter()
        .map(|f| {
            TypeField {
                reference: f.ty.clone(),
                label: f.label.clone(),
                ..TypeField::default()
            }
        })
        .collect();
    adjust(&mut body, &defs);
    assert_eq!(body, before);
}

#[test]
fn refs_collects_every_linked_record() {
    let mut body = Body::default();
    body.fields.push(Field {
        ty: "fileRef".into(),
        value: vec![json!("F1"), json!("F2")],
        ..Field::default()
    });
    body.custom.push(Field {
        ty: "addressRef".into(),
        value: vec![json!("A1")],
        ..Field::default()
    });
    body.custom.push(Field {
        ty: "script".into(),
        value: vec![json!({"fileRef": "S1", "command": "x"})],
        ..Field::default()
    });
    body.custom.push(Field {
        ty: "text".into(),
        value: vec![json!("not a ref")],
        ..Field::default()
    });
    assert_eq!(refs(&body).into_iter().collect::<Vec<_>>(), ["A1", "F1", "F2", "S1"]);
}

#[test]
fn stored_bodies_round_trip_with_properties_and_odd_values_intact() {
    let stored = json!({
        "type": "login",
        "title": "T",
        "notes": null,
        "fields": [
            {"type": "password", "value": ["pw"], "privacyScreen": true, "complexity": {"length": 12}},
            {"type": "text", "label": null, "value": "scalar", "required": 1}
        ],
        "custom": null,
        "references": ["kept"]
    });
    let body: Body = serde_json::from_value(stored).unwrap();
    assert_eq!(body.notes, "");
    assert_eq!(body.fields[1].value, [json!("scalar")]);
    assert!(body.fields[1].required && body.fields[1].label.is_empty());
    let out = serde_json::to_value(&body).unwrap();
    assert_eq!(out["fields"][0]["privacyScreen"], json!(true));
    assert_eq!(out["fields"][0]["complexity"], json!({"length": 12}));
    assert_eq!(out["references"], json!(["kept"]));
    assert_eq!(out["custom"], json!([]));
    assert_eq!(out["fields"][1]["required"], json!(true));
}

#[test]
fn def_names_cover_every_field_type_and_the_named_record_fields() {
    for (name, _) in TYPE_NAMES {
        assert!(name.parse::<Def>().is_ok(), "{name}");
    }
    let d = "login".parse::<Def>().unwrap();
    assert_eq!((d.ty, d.multiple), (FieldType::Login, Multiple::Never));
    let d = "pamHostname".parse::<Def>().unwrap();
    assert_eq!((d.ty, d.multiple), (FieldType::Host, Multiple::Never));
    let d = "text".parse::<Def>().unwrap();
    assert_eq!(d.multiple, Multiple::Optional);
    let d = "securityQuestion".parse::<Def>().unwrap();
    assert_eq!(d.multiple, Multiple::Always);
    assert!("nope".parse::<Def>().is_err());
}
