<!-- PROJECT LOGO / BANNER -->
<p align="center">
  <img src="assets/README-header.png" alt="keeper-cli" width="100%">
</p>

<p align="center">
  <img src="assets/icon-128.png" alt="keeper-cli icon" width="64">
</p>

<p align="center">
  <strong>keeper-cli</strong> -- A compelling tagline
  <br>
  <a href="https://crates.io/crates/keeper-cli"><img src="https://img.shields.io/crates/v/keeper-cli" alt="crates.io"></a>
  <a href="https://github.com/mrdwarf7/keeper-cli.rs/actions/workflows/build.yml"><img src="https://github.com/mrdwarf7/keeper-cli.rs/actions/workflows/build.yml/badge.svg" alt="build"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <a href="https://github.com/mrdwarf7/keeper-cli.rs/releases"><img src="https://img.shields.io/github/v/release/mrdwarf7/keeper-cli.rs" alt="release"></a>
</p>

<!-- TAGLINE + DESCRIPTION -->
## keeper-cli

A longer 2-3 sentence description of what this project does and who it's for.

```bash
# Quick example
keeper-cli input.txt -o output.txt
```

## Features

- **Feature 1** — Description
- **Feature 2** — Description
- **Feature 3** — Description
- **Cross-platform** — Linux, macOS, Windows
- **Zero dependencies** — Single binary, no runtime

## Screenshots

<!-- Add screenshots/GIFs for TUIs/GUIs -->
<!-- ![Demo](assets/demo.gif) -->

## Installation

### Cargo (Recommended)

```bash
cargo install keeper-cli
```

### One-liner (Linux/macOS)

```bash
curl -fsSL https://github.com/mrdwarf7/keeper-cli.rs/raw/main/build/install.sh | sh
```

Installs to `/usr/local/bin` (or `~/.local/bin` if not writable). Set `KEEPER_CLI_VERSION=vX.Y.Z` to pin a version.

### System Packages

| OS | Command |
|----|---------|
| Arch | `pacman -S keeper-cli` |
| macOS | `brew install keeper-cli` |
| Fedora | `dnf copr enable mrdwarf7/keeper-cli && dnf install keeper-cli` |
| NixOS | `nix-shell -p keeper-cli` |
| Windows | `winget install keeper-cli` |

### Release Archives

Download from [Releases](https://github.com/mrdwarf7/keeper-cli.rs/releases/latest).

Each archive contains:

```
keeper-cli-<target>-<tag>.zip
  keeper-cli[.exe]
  README.md
  LICENSE-MIT
  LICENSE-APACHE
  THIRD_PARTY_NOTICES.md
```

### Supported Targets

| OS | Arch | Triple |
|----|------|--------|
| Linux | x86_64 | `x86_64-unknown-linux-gnu` |
| Linux | arm64 | `aarch64-unknown-linux-gnu` |
| macOS | Intel | `x86_64-apple-darwin` |
| macOS | Apple Silicon | `aarch64-apple-darwin` |
| Windows | x86_64 | `x86_64-pc-windows-msvc` |

## Usage

```bash
keeper-cli [OPTIONS] <INPUT>
```

### Examples

```bash
# Basic usage
keeper-cli input.txt

# With output file
keeper-cli input.txt -o output.txt

# Dry run (show what would happen)
keeper-cli --dry-run input.txt

# Verbose logging
RUST_LOG=debug keeper-cli input.txt
```

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--help` | `-h` | Show help |
| `--version` | `-V` | Print version |
| `--output` | `-o` | Output file path |
| `--dry-run` | | Show actions without executing |
| `--quiet` | `-q` | Suppress non-error output |
| `--verbose` | `-v` | Verbose output (repeat for more) |

Logging: `RUST_LOG=debug keeper-cli ...` (default: `info`)

## Dependencies

| Tool | Minimum Version | Install |
|------|-----------------|---------|
| ffmpeg | 4.0+ | `pacman -S ffmpeg` / `brew install ffmpeg` |
| libpcap | 1.9+ | `pacman -S libpcap` / `apt install libpcap-dev` |

## Configuration

Config file at `~/.config/keeper-cli/config.toml`:

```toml
option = "value"
```

Environment variables:
- `KEEPER_CLI_LOG=debug` — Enable debug logging

## How It Works

1. **Step 1** — Description
2. **Step 2** — Description
3. **Step 3** — Description

## Build

```bash
# Release binary
make build          # or: cargo build --release

# Run tests
make test           # or: cargo test

# Run locally
make run            # or: cargo run -- <args>

# Fetch bundled dependencies (ffmpeg, etc.)
./build/fetch-deps.sh <target> <out-dir>
```

## Comparison

| Feature | keeper-cli | Competitor A | Competitor B |
|---------|-----------------|--------------|--------------|
| Feature 1 | ✅ | ✅ | ❌ |
| Feature 2 | ✅ | ❌ | ✅ |
| Feature 3 | ✅ | ✅ | ✅ |

## Links

- [Documentation](https://docs.example.com)
- [Changelog](CHANGELOG.md)
- [Discord](https://discord.gg/XXX)
- [Issues](https://github.com/mrdwarf7/keeper-cli.rs/issues)

## License

MIT OR Apache-2.0 — see [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).