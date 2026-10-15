<!-- PROJECT LOGO / BANNER -->
<p align="center">
  <img src="assets/README-header.png" alt="keeper-cli" width="100%">
</p>

<p align="center">
  <img src="assets/icon-128.png" alt="keeper-cli icon" width="64">
</p>

<p align="center">
  <strong>keeper-cli</strong>: a Rust command line client for the Keeper password vault
  <br>
  <a href="https://crates.io/crates/keeper-cli"><img src="https://img.shields.io/crates/v/keeper-cli" alt="crates.io"></a>
  <a href="https://github.com/mrdwarf7/keeper-cli.rs/actions/workflows/build.yml"><img src="https://github.com/mrdwarf7/keeper-cli.rs/actions/workflows/build.yml/badge.svg" alt="build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <a href="https://github.com/mrdwarf7/keeper-cli.rs/releases"><img src="https://img.shields.io/github/v/release/mrdwarf7/keeper-cli.rs" alt="release"></a>
</p>

## keeper-cli

keeper-cli is a Rust rebuild of the core of
[Keeper Commander](https://github.com/Keeper-Security/Commander), the Python CLI
for the Keeper password manager. It logs in, downloads and decrypts your vault,
and lets you browse and read it. It does not write anything back to the vault.

Command names, aliases and the config key names follow Commander, so the
commands you know carry over.

```bash
keeper-cli login you@example.com
keeper-cli list github
keeper-cli get "Work/GitHub" --unmask
```

## Installation

Build from source. The repo pins the nightly toolchain in `rust-toolchain.toml`,
so `rustup` picks it up on its own.

```bash
git clone https://github.com/mrdwarf7/keeper-cli.rs
cd keeper-cli.rs
cargo install --path .
```

No `protoc` is needed. `build.rs` compiles the checked-in `proto/keeper.fds.bin`
with `prost-build`.

## Usage

Run a single command, or start the shell. With no command, `keeper-cli` opens
the shell.

```bash
# One-shot: logs in, syncs the vault, runs the command, exits
keeper-cli list --format json
keeper-cli totp "My Bank"

# Interactive shell: log in and sync once, then run many commands
keeper-cli shell
```

Every one-shot run logs in and does a full vault sync first. Nothing is cached
between runs, so for scripts either enable persistent login (below) or pass
`--password` / `KEEPER_PASSWORD`.

Inside the shell, `cd` changes the current folder and the prompt follows it.
`help` lists commands and `exit` (or `quit`, or Ctrl-D) leaves.

```text
My Vault> tree -r
My Vault> cd Work
Work> ls -l
Work> get GitHub
Work> exit
```

### Global options

These work with every command.

| Option                  | Env var              | Description                                       |
| ----------------------- | -------------------- | ------------------------------------------------- |
| `--config <CONFIG>`     | `KEEPER_CONFIG_FILE` | Config file (default: see Configuration)          |
| `--user <USER>`         |                      | Account email                                     |
| `--password <PASSWORD>` | `KEEPER_PASSWORD`    | Master password; prompted for when omitted        |
| `--server <SERVER>`     |                      | Keeper region host, e.g. `keepersecurity.eu`      |

### Commands

| Command                                                                                          | Alias | Description                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `login [EMAIL]`                                                                                  |       | Log in and remember the account in the config                                                                                                                    |
| `logout`                                                                                         |       | End the session and forget this device's persistent login                                                                                                        |
| `whoami [-v]`                                                                                    |       | Show the logged-in account                                                                                                                                       |
| `sync-down`                                                                                      |       | Download and decrypt the vault again                                                                                                                             |
| `ls [PATTERN] [-l] [-f] [-r] [-R]`                                                               |       | List folder contents. `-l` detailed table, `-f` folders only, `-r` records only, `-R` recurse                                                                    |
| `cd [FOLDER]`                                                                                    |       | Change the current folder (shell only)                                                                                                                           |
| `tree [FOLDER] [-r] [-v]`                                                                        |       | Show the folder structure. `-r` includes records, `-v` shows UIDs                                                                                                |
| `list [PATTERN]... [-t TYPE] [-v] [--format table\|json]`                                        | `l`   | List records. Every search term must match; `-t` is repeatable                                                                                                   |
| `search [PATTERN]... [-v] [--format table\|json]`                                                | `s`   | Search records, shared folders and teams                                                                                                                         |
| `get <UID> [--unmask] [--format detail\|json]`                                                   | `g`   | Show a record, folder, shared folder or team by UID, or a record by path or title. Hidden fields are masked unless you pass `--unmask`                           |
| `list-sf [PATTERN]... [--format table\|json]`                                                    | `lsf` | List shared folders                                                                                                                                              |
| `list-team [--format table\|json]`                                                               | `lt`  | List teams                                                                                                                                                       |
| `totp [RECORD] [--details]`                                                                      |       | Show the current TOTP code of a record, or list the records that have one                                                                                        |
| `generate [-c LENGTH] [-n NUMBER] [-r RULES] [-u N] [-l N] [-d N] [-s N] [--format table\|json]` |       | Generate passwords. `-r` takes `"[length,] upper, lower, digits, symbols"` minimum counts; `-u`, `-l`, `-d` and `-s` set one class, and `0` turns that class off |
| `this-device`                                                                                    |       | Show this device's login settings                                                                                                                                |
| `this-device register`                                                                           |       | Store an encrypted copy of the data key for this device                                                                                                          |
| `this-device persistent-login on\|off`                                                           | `pl`  | Turn "Stay Logged In" on or off                                                                                                                                  |
| `shell`                                                                                          |       | Start the interactive shell                                                                                                                                      |

`generate` does not need a login.

### Login prompts

`login` handles the master password, 2FA (TOTP, SMS, Duo, RSA, Keeper DNA or a
backup code), device approval (email link, Keeper push, or a code), and region
redirects. Prompts go to stderr; command output goes to stdout.

### Running without the master password

Commander's "Stay Logged In" works here too. Log in once, then turn it on:

```bash
keeper-cli login you@example.com
keeper-cli this-device persistent-login on
```

Later runs resume from the device's clone code in the config file and skip the
password prompt. `keeper-cli logout` clears the clone code. An administrator
policy can forbid this; the command reports that when it happens.

## Configuration

keeper-cli reads and writes one JSON file, `config.json` in the platform config
directory: `~/.config/keeper-cli/` on Linux, `~/Library/Application
Support/keeper-cli/` on macOS, `%APPDATA%\keeper-cli\` on Windows. Override the
path with `--config` or `KEEPER_CONFIG_FILE`.

| Key            | Meaning                                          |
| -------------- | ------------------------------------------------ |
| `user`         | Account email, set by `login`                    |
| `server`       | Keeper region host, default `keepersecurity.com` |
| `device_token` | This device's registration token                 |
| `private_key`  | This device's EC private key                     |
| `clone_code`   | Persistent-login token; removed by `logout`      |

These are Commander's file-storage key names, but the file is deliberately not
Commander's `config.json`. Commander can keep protected values in the OS
keychain, and keeper-cli must not overwrite that file with plaintext ones. To
reuse a Commander device, point `--config` at a config saved with
`config_storage: "file"`. Unknown keys are kept when the file is saved.

Each key can also come from a `KEEPER_<KEY>` environment variable, which wins
over the file: `KEEPER_USER`, `KEEPER_SERVER`, `KEEPER_DEVICE_TOKEN`,
`KEEPER_PRIVATE_KEY`, `KEEPER_CLONE_CODE`. An override is written to the file
the next time keeper-cli saves it, for example after a login.

The file holds the device private key and clone code, so on Unix it is written
with mode `0600`.

## Not implemented

- SSO login. SSO accounts fall back to their alternate master password, as in
  Commander.
- WebAuthn / FIDO security-key 2FA
- Passkey and biometric login
- Account recovery
- The ML-KEM ("QRC") transport. Requests use the classic transmission-key
  encryption.
- Any vault write: `record-add`, `record-edit`, `rm`, `mkdir`, `mv`, sharing
- Attachments
- Enterprise and admin commands
- PAM
- BreachWatch
- Incremental sync. Every sync downloads the whole vault.

## Regenerating the protobuf descriptors

Keeper publishes no `.proto` files. Commander ships protoc-generated `*_pb2.py`
modules, and each one embeds its serialized descriptor.
`tools/extract-protos.ts` lifts those bytes into `proto/keeper.fds.bin`, which
`build.rs` compiles.

```bash
git clone --depth 1 https://github.com/Keeper-Security/Commander /tmp/commander
bun tools/extract-protos.ts /tmp/commander
```

By default it starts from `APIRequest.proto`, `SyncDown.proto` and
`AccountSummary.proto`. Pass other root `.proto` names after the checkout path
to include more.

## Development

```bash
cargo build
cargo test
cargo run -- --help
```

## License

MIT, see [LICENSE](LICENSE).
