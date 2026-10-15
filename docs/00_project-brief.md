---
title: "Project Brief"
description: "Purpose, scope, acceptance criteria, and high-level design."
keywords: [brief, overview, design, scope, acceptance-criteria]
order: 0
---

## Why this exists

Keeper Commander is the official CLI for the Keeper password manager, and it is
a large Python application. For reading a vault from a terminal or a script,
that means a Python runtime and its dependency tree. keeper-cli rebuilds the
core of Commander (login plus read-only vault access) as one Rust binary with
Commander's command names, so existing habits and scripts carry over.

Keeper publishes no `.proto` files and no protocol spec. The wire format comes
from the descriptors embedded in Commander's `*_pb2.py` modules, and the
behavior from Commander's source.

## What the tool does

- Logs in with the v3 flow: master password, 2FA (TOTP, SMS, Duo, RSA, Keeper
  DNA, backup codes), device approval, region redirect, and persistent login via
  a clone code.
- Downloads the whole vault (`vault/sync_down`) and decrypts it locally:
  records, folders, shared folders, teams and record links.
- Browses it: `ls`, `cd`, `tree`, `list`, `search`, `get`, `list-sf`,
  `list-team`.
- Shows current TOTP codes (`totp`) and generates passwords (`generate`, which
  needs no login).
- Manages this device's persistent login (`this-device`).
- Runs one-shot, or as an interactive shell with a current folder.

## CLI shape

```bash
keeper-cli [--config FILE] [--user EMAIL] [--password PW] [--server HOST] [COMMAND]
```

With no command it starts the shell. Command names and aliases (`l`, `s`, `g`,
`lsf`, `lt`, `pl`) follow Commander. `list`, `search`, `list-sf`, `list-team`
and `generate` take `--format table|json`; `get` takes `--format detail|json`.

```bash
keeper-cli login you@example.com
keeper-cli this-device persistent-login on
keeper-cli list --format json
keeper-cli get <UID> --unmask
keeper-cli shell
```

## Acceptance criteria

1. `login` completes against a live account with a master password, with and
   without a 2FA prompt, and with device approval on a new device.
2. After `this-device persistent-login on`, commands run without a password
   prompt until `logout`.
3. After a sync, the record count matches the Keeper web vault, including
   records reached through shared folders and teams.
4. `ls`, `cd`, `tree`, `list`, `search`, `get`, `list-sf` and `list-team` show
   what Commander shows for the same vault.
5. `get` masks hidden fields unless `--unmask` is passed.
6. `totp` prints the same code as the Keeper app.
7. The config file uses Commander's key names (`user`, `server`, `device_token`,
   `private_key`, `clone_code`), is written with mode `0600` on Unix, and keeps
   unknown keys.
8. `cargo build` works on the pinned nightly without `protoc`.

## Out of scope

- SSO login, WebAuthn/FIDO 2FA, passkey and biometric login, account recovery.
- The ML-KEM ("QRC") transport.
- Any vault write: `record-add`, `record-edit`, `rm`, `mkdir`, `mv`, sharing.
- Attachments, enterprise and admin commands, PAM, BreachWatch.
- Incremental sync. Every sync fetches the whole vault.

## Design

The crate is a single binary; each module has one job.

- `crypto.rs`: AES-CBC ("v1") and AES-GCM ("v2") record encryption, P-256 ECIES,
  RSA PKCS#1 v1.5, PBKDF2 key hashes, and decoding of the account's encryption
  parameters.
- `rest.rs`: the encrypted REST transport. Each request seals a fresh
  transmission key to one of Keeper's published server public keys (ids 1 to
  18), retries with the server's key id when it rejects ours, and backs off when
  throttled.
- `auth.rs`: the login state machine, device registration, clone-code persistent
  login, data key recovery, and the `Session` that makes authenticated calls.
- `vault.rs`: full `sync_down`, the key hierarchy (data key, then record, team
  and shared-folder keys, then folder and linked-record keys), the `Record` and
  `Folder` model, and search matching.
- `commands.rs`, `cli.rs`, `main.rs`: the clap command definitions, the command
  implementations, and the shell loop. One-shot commands log in and sync on
  demand; the shell keeps the session and vault between lines.
- `totp.rs`, `generator.rs`: TOTP codes and password generation.
- `settings.rs`: the JSON config, `keeper-cli/config.json` in the platform
  config directory, loaded with the `config` crate so `KEEPER_<KEY>` environment
  variables override file values. It is separate from Commander's `config.json`
  so that plaintext values never overwrite a file whose protected values live in
  the OS keychain.
- `proto/keeper.fds.bin`: a `FileDescriptorSet` extracted from Commander's
  `*_pb2.py` by `tools/extract-protos.ts` and compiled by `build.rs` with
  `prost-build`. Re-run the script against a Commander checkout when Keeper
  changes the protocol.
