# keeper-cli

keeper-cli is a Rust command-line client for Keeper, based on the core of
[Keeper Commander](https://github.com/Keeper-Security/Commander). It logs in,
syncs and decrypts the vault locally, supports common read and write workflows,
and runs either one command at a time or as an interactive shell.

```bash
keeper-cli login you@example.com
keeper-cli list github
keeper-cli get "Work/GitHub" --unmask
```

## Installation

Build from source with the repository's pinned nightly toolchain:

```bash
cd keeper-cli.rs
cargo install --path .
```

## Usage

Run a command directly or start the interactive shell. With no command,
`keeper-cli` opens the shell. A one-shot command logs in and syncs the whole
vault before running. The shell keeps the session and vault between commands.

```bash
keeper-cli list --format json
keeper-cli record-add --title "Example login" --record-type login login=demo
keeper-cli record-update --record "Example login" login=demo-user
keeper-cli append-notes --notes "Rotated during maintenance" "Example login"
keeper-cli mkdir Work
keeper-cli totp "My Bank"
keeper-cli shell
```

Inside the shell, `cd` changes the current folder. `help` lists commands;
`exit`, `quit` or Ctrl-D leaves the shell.

```text
My Vault> tree -r
My Vault> cd Work
Work> ls -l
Work> get GitHub
Work> exit
```

### Common commands

| Command                                               | Alias             | Description                                                         |
| ----------------------------------------------------- | ----------------- | ------------------------------------------------------------------- |
| `login [EMAIL]`, `logout`, `whoami`, `sync-down`      |                   | Sign in, clear the session, show the account, or sync the vault     |
| `ls`, `cd`, `tree`                                    |                   | Browse folders and records                                          |
| `list`, `search`, `get`                               | `l`, `s`, `g`     | Find and inspect vault items; `get --unmask` reveals hidden fields  |
| `list-sf`, `list-team`, `totp`                        | `lsf`, `lt`       | Show shared folders, teams, or TOTP codes                           |
| `record-add`, `record-update`, `append-notes`, `rm`   | `ra`, `ru`, `an`  | Add or change records, append notes, or remove records/folder links |
| `mkdir`, `rmdir`, `rndir`, `mv`                       |                   | Create, remove, rename, or move folders and records                 |
| `upload-attachment`, `download-attachment`            | `ua`, `da`        | Transfer record attachments                                         |
| `clipboard-copy`, `find-password`                     | `cc`              | Copy a record field or print its password                           |
| `generate`                                            |                   | Generate passwords without logging in                               |
| `this-device`, `this-device persistent-login on\|off` | `pl` (subcommand) | View device settings or manage persistent login                     |
| `shell`                                               |                   | Start the interactive shell                                         |

`list`, `search`, `list-sf`, and `list-team` support `--format table|json`;
`get` supports `--format detail|json`. `generate` also supports table or JSON
output. Write commands that take secret values can prompt for them; avoid
putting passwords or other secrets directly in command arguments, where they may
be saved in shell history or visible to other local processes.

### Login

Login supports master-password authentication, TOTP, SMS, Duo, RSA, Keeper DNA
and backup codes, device approval, region redirects, and persistent login.
Prompts go to stderr and command output goes to stdout. To keep a device signed
in, enable persistent login after signing in:

```bash
keeper-cli login you@example.com
keeper-cli this-device persistent-login on
```

Later invocations use the stored clone code until `logout` clears it. An
administrator policy can disable persistent login.

### Global options

| Option                  | Environment variable | Description                                         |
| ----------------------- | -------------------- | --------------------------------------------------- |
| `--config <PATH>`       | `KEEPER_CONFIG_FILE` | Config file path                                    |
| `--user <EMAIL>`        | `KEEPER_USER`        | Account email                                       |
| `--password <PASSWORD>` | `KEEPER_PASSWORD`    | Master password; prompted for when omitted          |
| `--server <HOST>`       | `KEEPER_SERVER`      | Keeper region host, for example `keepersecurity.eu` |
| `--debug`               |                      | Show error context and complete cause chains        |

Treat command-line and environment values as secrets. Prefer interactive prompts
when possible.

Release builds use concise error output by default. Add `--debug` to show
contextual cause chains, including each failure in a partial attachment
download. Debug builds enable those diagnostics automatically. Project tracing
events go to stderr; `RUST_LOG` overrides the release default, and an invalid
filter is reported. HTTP URL credentials, query strings, fragments, and API
supplemental data are omitted from reports. JSON payload errors retain their
original source internally but report only the error category and location.

## Configuration

The JSON configuration file is stored in the platform config directory. On
macOS, the default is `~/Library/Application Support/keeper-cli/config.json`;
Linux and Windows use their standard application config directories. Set
`--config` or `KEEPER_CONFIG_FILE` to choose another path.

The configuration includes account and device login settings such as `user`,
`server`, `device_token`, `private_key`, and `clone_code`. `KEEPER_<KEY>`
environment variables override file values. The file uses Commander's
file-storage key names, but is separate from Commander's config file. To reuse
a Commander device, select a config saved with `config_storage: "file"`.

## Implemented baseline and limits

Record and folder changes, attachment transfer, and clipboard/password commands
are implemented. The vault sync is a full download each time; it does not use
incremental history.

Downloads reserve filenames without overwriting existing files. GCM
authentication is checked before output is written. Legacy CBC downloads have
no message authentication; they are checked only for valid PKCS#7 padding. A
failed disk write can still leave a partial new file, and the command reports
the failure.

Attachment transfers use four blocking workers and an estimated shared-buffer
admission budget of 64 MiB. Unknown or oversized file sizes run alone. One file
can still exceed that budget because it is fully buffered; this is not a hard
process-memory limit. Upload files are linked to the record only after every
upload succeeds.

These features are not implemented:

- SSO, WebAuthn/FIDO security keys, passkeys, biometrics, and account recovery.
- PAM, enterprise administration, and other admin commands.
- Vault history and point-in-time restore.
- v2 attachment upload. Attachment upload is limited to supported typed records.
- BreachWatch and sharing-management commands.
- The ML-KEM ("QRC") transport. Requests use classic transmission-key
  encryption.
- Incremental sync; each sync downloads the full vault.

## Verification status

Local tests and HTTP fixtures provide protocol and command-behavior coverage.
They have exercised encrypted sync payloads, unknown-property round-tripping,
masked and revealed field values, and attachment upload success and failure
without linking on failure. Authenticated live Keeper login, 2FA, persistence,
vault writes, folder and attachment operations, clipboard behavior, and TOTP
acceptance remain unverified.

## Regenerating protobuf descriptors

This checkout of Commander contains protoc-generated `*_pb2.py` modules rather
than the corresponding `.proto` files. They embed serialized descriptors. The
extraction script builds `proto/keeper.fds.bin`, which `build.rs` compiles.

```bash
git clone --depth 1 https://github.com/Keeper-Security/Commander /tmp/commander
bun tools/extract-protos.ts /tmp/commander
```

By default, the script starts from `APIRequest.proto`, `SyncDown.proto`, and
`AccountSummary.proto`. Pass other root `.proto` names after the checkout path
to include them.

## Development

Install and activate the development tools with [mise](https://mise.jdx.dev/):

```bash
mise trust && mise install && mise reshim
```

Rust is managed by rustup through `rust-toolchain.toml`. Mise wraps `cargo`
with `mbx`; cargo-make tasks use `CARGO_CMD=mbx` because cargo-make removes the
mise Cargo wrapper from `PATH`. `RUSTC_WRAPPER` stays disabled so mbx remains
the Rust compiler wrapper. Set `CARGO_CMD=cargo` to opt out. The project
`.mbx.toml` keeps the system linker as the default on every platform.

Run the existing `cargo make` aliases from the repository root. `f` formats
Rust, TOML, and Markdown; `ci-*` tasks check without formatting source files:

```bash
cargo make f
cargo make ci-format
cargo make ci-markdown
cargo make ci-check
cargo make A
cargo make r -- --help
```

To bypass mbx for one task, use `CARGO_CMD=cargo cargo make <task>`. If mise is
not activated in your shell, prefix commands with `mise exec --`.

Clippy denies panic-prone collection indexing and direct string slicing. Use
fixed-size data, destructuring, iterators, and checked collection APIs instead.

## License

MIT. See [LICENSE](LICENSE) for the project license and
[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) for Keeper Commander's notice.
