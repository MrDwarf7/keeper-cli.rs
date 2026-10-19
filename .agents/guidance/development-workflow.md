# Development workflow and metadata

Read the task section relevant to your work. `Makefile.toml` and its imported task files are the
source of truth for development commands.

## Use cargo-make tasks

For routine builds, runs, formatting, checks, linting, and tests, MUST use the top-level
`cargo make` aliases. Do not recreate their command chains manually or bypass their dependencies
with direct Cargo commands.

| Work                                      | Command                            |
| ----------------------------------------- | ---------------------------------- |
| Format Rust, TOML, and Markdown           | `cargo make f`                     |
| Check all targets                         | `cargo make c`                     |
| Run Clippy                                | `cargo make cp`                    |
| Run tests                                 | `cargo make t`                     |
| Run all-package tests                     | `cargo make ta`                    |
| Run tests with output visible             | `cargo make tnc`                   |
| Run all-package tests with output visible | `cargo make tanc`                  |
| Build debug / release                     | `cargo make b` / `cargo make br`   |
| Build workspace debug / release           | `cargo make bw` / `cargo make brw` |
| Run debug / release                       | `cargo make r` / `cargo make rr`   |
| Run the build sweep                       | `cargo make ba`                    |
| Run the build-and-test sweep              | `cargo make a`                     |
| Run the full verification sweep           | `cargo make A`                     |
| Clean build artifacts                     | `cargo make cl`                    |

Mise wraps `cargo` with `mbx`; cargo-make tasks use `CARGO_CMD=mbx` because cargo-make removes
mise's Cargo wrapper from `PATH`. Set `CARGO_CMD=cargo` to opt out.

The `ci-*` tasks are non-mutating:

| Check                    | Command                         |
| ------------------------ | ------------------------------- |
| Rust and TOML formatting | `cargo make ci-format`          |
| Markdown lint            | `cargo make ci-markdown`        |
| Cargo check              | `cargo make ci-check`           |
| Clippy warnings          | `cargo make ci-clippy`          |
| Pedantic Clippy          | `cargo make ci-clippy-pedantic` |
| Tests                    | `cargo make ci-test`            |
| Documentation            | `cargo make ci-doc`             |
| Release build            | `cargo make ci-build-release`   |

`cargo make ci-format` and the check tasks do not modify source files. Local `cargo make f` formats
Rust, TOML, and Markdown; avoid running it while others edit the same files.

`A` and `a` are different tasks. `A` runs formatting, Markdown lint, checks, Clippy, and the
build-and-test sweep. Formatting tasks modify files, including TOML files. Account for that when
other agents are working in the same checkout.

The test tasks forward arguments through `${@}`. Prefer that mechanism for targeted tests too:

```sh
cargo make t vault::tests
cargo make tnc vault::tests
cargo make t \
  clipboard::tests::uid_titles_and_word_search_honor_login_filtering -- --exact
```

Use `cargo make r -- --help` to pass arguments to the application. Inspect the task definition
before assuming that a particular alias forwards arguments; not every task does. Direct Cargo use is
an exception for a targeted test or diagnostic that the existing tasks cannot express. State why the
exception is needed. A failing task is not permission to silently bypass it.

Do not invoke release, version-bump, tagging, or publishing tasks without the user's explicit
authorization for those side effects.

The project's CI-specific commands and tool details are in
[the Local Rust task runner section of docs/CI.md](../../docs/CI.md#local-rust-task-runner); read it
when CI-specific information is needed, not for routine alias use.

## Repository metadata and license

Read this section only when using the project template or changing repository
metadata/license/comment policy.

- When using the project template, run its setup procedure and inspect the result. Remove stale
  template names and placeholders from `Cargo.toml`, `Makefile.toml`, and related metadata; do not
  assume the script caught them.
- `LICENSE` must match the user's license from `MrDwarf7/rust_template` on GitHub. Do not replace
  the project's license with an upstream project's license.
- Comments explain constraints and reasons, not what the next line does. Do not add AI attribution
  to code, documentation, commits, or PRs.
