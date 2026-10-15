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

`VaultPath` represents Commander's virtual paths, including `//` for a literal
slash in a folder name. Resolution returns `PathResolution::Full` or `Partial`.
Operating-system path components normalize those separators, so filesystem path
parsing is not interchangeable.

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

No authenticated live Keeper account was supplied. Tests and local HTTP fixtures
are available for protocol and command behavior, but production vault operations
have not been verified against a real account.

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
