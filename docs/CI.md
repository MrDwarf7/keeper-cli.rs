---
title: CI
description: Development tools, cargo-make tasks, and non-mutating checks.
keywords: [cargo-make, mise, mbx, formatting, lint, check, tests]
---

## CI

### Local Rust task runner

`mise.toml` supplies `cargo-make`, Taplo, rumdl, and the tools used by the
existing watch, Typst, and release tasks. Versions use a 24-hour minimum
release age. Run `mise trust && mise install && mise reshim` to prepare the
environment.

Mise wraps `cargo` with `mbx`. Cargo-make removes that wrapper from `PATH`, so
the task recipes use `CARGO_CMD=mbx`; set `CARGO_CMD=cargo` to opt out. The
project-shared `.mbx.toml` keeps the system linker as the default on every
platform.

| Work                            | Command                         |
| ------------------------------- | ------------------------------- |
| Format Rust, TOML, and Markdown | `cargo make f`                  |
| Check Rust and TOML formatting  | `cargo make ci-format`          |
| Check Markdown                  | `cargo make ci-markdown`        |
| Check all targets               | `cargo make ci-check`           |
| Clippy with warnings denied     | `cargo make ci-clippy`          |
| Pedantic Clippy                 | `cargo make ci-clippy-pedantic` |
| Run tests                       | `cargo make ci-test`            |
| Build documentation             | `cargo make ci-doc`             |
| Build release binary            | `cargo make ci-build-release`   |

The `ci-*` checks do not format source files. Test recipes continue to use
`cargo test`; no nextest runner is configured, so doctest behavior is unchanged.

> Native preference: version pins live in native files (`rust-toolchain.toml`, `.python-version`),
> not duplicated in shell. `cargo` already exports `CARGO_TARGET_DIR` -- use it directly; do not
> redefine `TARGET_DIR` as a second source of truth.

### Toolchain pinning

| Tool        | Pin file                                                             | Composite input                                      | Bump procedure                                                                 |
| ----------- | -------------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------ |
| Rust        | `rust-toolchain.toml` (`channel` + `components`)                     | `setup-rust` `inputs.toolchain` (default reads file) | Edit `rust-toolchain.toml`, verify `cargo make ci-check` locally               |
| Python      | `.python-version` (e.g. `3.12`)                                      | `setup-python` `inputs.python-version`               | Edit `.python-version` + any `Makefile.toml` env that pins it, verify `uv run` |
| uv          | `setup-python` `inputs.uv-version` (`latest`)                        | `setup-python`                                       | Bump in `setup-python/action.yml` default                                      |
| GCC/Clang   | `setup-gcc` `inputs.gcc-version` / `clang-version`                   | `setup-gcc`                                          | Edit `setup-gcc/action.yml` defaults + this doc                                |
| mold        | `setup-rust` `MOLD_VERSION='2.41.0'` (Linux)                         | `setup-rust` `inputs.use-mold`                       | Bump in `setup-rust/action.yml`                                                |
| cargo tools | `setup-rust` `inputs.tools` (`cargo-binstall,cargo-make,just,taplo`) | `setup-rust`                                         | Edit `setup-rust` `inputs.tools` default                                       |

### Setup actions

- `.github/actions/setup-rust` -- Rust + sccache + mold + cache, reads `rust-toolchain.toml`
- `.github/actions/setup-python` -- uv + Python, reads `.python-version`
- `.github/actions/setup-msvc` -- MSVC `cl.exe` + PATH fix, Windows only
- `.github/actions/setup-gcc` -- pinned GCC/Clang, Ubuntu only, otherwise no-op
- `.github/actions/checkout` -- thin wrapper around `actions/checkout@v7`

All use `inputs` with defaults, not `env:` (disallowed in actions).

### Paths

- `Makefile.toml` defines `ROOT = "${CARGO_MAKE_WORKSPACE_WORKING_DIRECTORY}"` (short alias, comment
  explains 15+ chars), `SCRIPT_DIR = "${ROOT}/scripts"`, `TOOL_DIR = "${ROOT}/tools"`.
- `CARGO_TARGET_DIR` is cargo-native; do not redefine `TARGET_DIR`.
- `build/*.toml` extend files inherit `ROOT/SCRIPT_DIR/TOOL_DIR`; keep file-local `env` only if
  strictly scoped.

### Scripts

- PKGBUILD-style base arrays: single `_common_*_flags`, appended per helper via
  `"${_common_flags[@]}"`.
- Candidate-chain dispatch: `_candidates=("bin:helper" ...)` + loop `command -v` + centralized
  switch -> helper. Extends by adding array entry.
- `_usage` via `export t=$'\t'` + `printf "%s\n" "$(cat <<EOF"` with `Usage: ${_self}` where
  `_self="$(basename "${BASH_SOURCE[0]:-$0}")"` so rename stays in sync.
- `printf` over `echo`, explicit failure on missing required arg, handle `-h|--help|help`.

Example `scripts/`:

```text
scripts/
  _common.sh              # common flags + ROOT/TARGET/BUILD
  _compile_c.sh           # leaf, handles toolchain dispatch
  consumer_compile.sh     # dispatcher: consumer_compile.sh <c|cpp|rust|all>
```

Corresponding `build/*.toml` dispatcher:

```toml
[tasks.ffi-consumer-compile-c]
command = "bash"
args = ["${SCRIPT_DIR}/consumer_compile.sh", "c"]
```
