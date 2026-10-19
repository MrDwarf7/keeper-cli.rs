---
description: "Purpose, implemented scope, and verification status."
keywords: [brief, overview, scope, acceptance-criteria]
order: 0
---

## Purpose

keeper-cli is a Rust command-line client based on the core of
[Keeper Commander](https://github.com/Keeper-Security/Commander). It uses
Commander's command names and supports one-shot commands and a plain interactive
shell.

The authenticated account owns its session, cached vault, and current folder as
one unit, so switching accounts cannot reuse another account's local state.

Decrypted record and folder envelopes validate known shapes while retaining
unknown properties. Field values remain arbitrary JSON, and failures keep
context. A borrowed `TypedRecord` validates a v3 upload or link once; the
existing view carries the session, vault, and current folder. Record display
recurses through values without intermediate joined strings.

Missing key material leaves inaccessible entries locked or unavailable. A failed
decrypt or parse after key resolution is a sync error, not missing data. Errors
retain their sources until the CLI renders them: concise output in release
builds, contextual cause chains with `--debug` or in debug builds.

`VaultPath` represents Commander's virtual paths, including `//` for a literal
slash in a folder name. Resolution returns `PathResolution::Full` or `Partial`.
Operating-system path components normalize those separators, so filesystem path
parsing is not interchangeable.

Presented field values use `std::borrow::Cow<str>` and already contain only the
text allowed by the disclosure policy. Masked views retain replacement text, not
the source secret. Formatting and JSON serialization use standard trait support;
search and clipboard lookup explicitly request revealed values.

Each prepared attachment owns its validated local file, generated UID, and AES
key. `From<LocalFile>` binds them once; `TryFrom<&UploadFile>` seals the
contents with that same key. Registration, transfer, and record linking use
those values directly, so file-to-key pairing cannot drift between parallel
collections.

Attachment transfers use four blocking workers and an estimated 64 MiB shared
buffer-admission budget. Unknown or oversized files run alone, but an individual
file is still fully buffered and can exceed the budget. All uploads must succeed
before the record is linked. Downloads reserve filenames without overwriting
existing files and verify GCM authentication before writing output. Legacy CBC
downloads have no message authentication; only PKCS#7 padding is checked.

Table columns and rows share a const-generic width, so ragged rows cannot be
inserted. Fixed byte layouts use destructuring or checked splits; dynamic
lookups handle missing entries explicitly. TOTP truncation accepts only
supported fixed-size digests, so code generation has no missing-digest failure
state.

Protocol behavior is derived from descriptors embedded in Commander's generated
Python modules and from Commander's source.

## Implemented baseline

- Login with a master password, supported 2FA methods, device approval, region
  redirects, and persistent login.
- Full vault sync and local decryption of records, folders, shared folders,
  teams, and record links.
- Browse and search vault contents with `ls`, `cd`, `tree`, `list`, `search`,
  `get`, `list-sf`, and `list-team`.
- Show TOTP codes and generate passwords.
- Add and update typed records, append notes, and remove records or folder
  links.
- Create, remove, rename, and move folders or records.
- Upload and download supported record attachments; copy record fields to the
  clipboard or print a record password.
- Manage this device's persistent login and run commands in a shell that keeps
  the session and current folder.

## Command examples

```bash
keeper-cli login you@example.com
keeper-cli this-device persistent-login on
keeper-cli list --format json
keeper-cli record-add --help
keeper-cli record-update --help
keeper-cli shell
```

Sensitive values should be entered at prompts where available. Avoid placing
passwords or other secrets in command-line arguments, where they can be exposed
through shell history or process listings.

## Unsupported features

- SSO, WebAuthn/FIDO security-key 2FA, passkeys, biometric login, and account
  recovery.
- PAM, enterprise administration, and other admin commands.
- Vault history and point-in-time restore.
- v2 attachment upload; attachment uploads are limited to supported typed
  records.
- BreachWatch and sharing-management commands.
- ML-KEM ("QRC") transport; requests use classic transmission-key encryption.
- Incremental sync; each sync downloads the full vault.

## Verification status

Local tests and HTTP fixtures provide protocol and command-behavior coverage,
including encrypted local sync payloads, unknown-property round-tripping,
masked and revealed field values, and attachment upload success or failure
without linking on failure. Authenticated live Keeper login, 2FA, persistence,
vault writes, folder and attachment operations, clipboard behavior, and TOTP
acceptance remain unverified.

The implementation aims to meet these local and live acceptance criteria:

1. Login completes with and without a 2FA prompt and can handle device approval.
2. Persistent login resumes without a master-password prompt until logout.
3. A full sync decrypts records reached through shared folders and teams.
4. Read, write, folder, attachment, and clipboard commands produce the expected
   results for the same vault and command inputs.
5. `get` masks hidden fields unless `--unmask` is passed.
6. TOTP output matches the Keeper app.
7. Config settings use Commander's file-storage keys, and environment overrides
   take precedence over file values.
8. The pinned nightly toolchain builds without a `protoc` installation.
