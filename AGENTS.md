# Repository instructions

These rules apply throughout `keeper-cli.rs`. The package and binary are named
`keeper-cli`. Follow the current `Makefile.toml` and its imported task files;
those files are the source of truth for development commands.

## Use cargo-make tasks

For routine builds, runs, formatting, checks, linting, and tests, MUST use the
top-level `cargo make` aliases. Do not recreate their command chains manually
or bypass their dependencies with direct Cargo commands.

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

Mise wraps `cargo` with `mbx`; cargo-make tasks use `CARGO_CMD=mbx` because
cargo-make removes mise's Cargo wrapper from `PATH`. Set `CARGO_CMD=cargo` to
opt out.

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

`cargo make ci-format` and the check tasks do not modify source files. Local
`cargo make f` formats Rust, TOML, and Markdown; avoid running it while others
edit the same files.

`A` and `a` are different tasks. `A` runs formatting, Markdown lint, checks,
Clippy, and the build-and-test sweep. Formatting tasks modify files, including
TOML files. Account for that when other agents are working in the same checkout.

The test tasks forward arguments through `${@}`. Prefer that mechanism for
targeted tests too:

```sh
cargo make t vault::tests
cargo make tnc vault::tests
cargo make t \
  clipboard::tests::uid_titles_and_word_search_honor_login_filtering -- --exact
```

Use `cargo make r -- --help` to pass arguments to the application. Inspect the
task definition before assuming that a particular alias forwards arguments;
not every task does. Direct Cargo use is an exception for a targeted test or
diagnostic that the existing tasks cannot express. State why the exception is
needed. A failing task is not permission to silently bypass it.

Do not invoke release, version-bump, tagging, or publishing tasks without the
user's explicit authorization for those side effects.

## Rust design

- Port Commander's protocol and observable behavior. Do not copy its Python
  class hierarchies, facades, mutable parameter bags, or inheritance patterns.
- Use Rust's type system to make invalid states unrepresentable. Use validated
  newtypes, enums, type-state, builders, or type-state builders where they
  enforce actual invariants or ordering constraints. Do not replace meaningful
  types with loose strings, integers, empty-key sentinels, or boolean switches.
- Keep decryption and vault assembly in coherent stages. Do not grow another
  several-hundred-line `build` function. A stage must own real work rather than
  just forward to another function.
- Prefer standard traits for their intended jobs: `From`/`TryFrom` for
  conversions, `FromStr` for parsing, `Display` for rendering, `Default` for
  defaults, and `Iterator`/`IntoIterator` for traversal. For example, bytes to a
  UID belong in a conversion implementation, not a `uid(bytes)` helper.
- Avoid manual indexing and range slicing in production code and tests,
  including map and JSON indexing. Encode fixed layouts and cardinality with
  arrays, destructuring, validated frame types, and iterators before reaching
  for a positional lookup.
- For genuinely dynamic access, use the collection's checked API: `get`,
  `get_mut`, checked splitting, or map `entry` with
  `or_insert_with`/`or_default`. Handle absence according to the operation's
  contract and preserve failures as crate errors. Do not replace indexing
  mechanically with `get().unwrap()` or `get().expect()`, add fake defaults, or
  hide it behind an `Index` implementation or unchecked access. Tests should
  assert required fixture shape or entries explicitly. Do not add allocation or
  copying merely to avoid brackets.
- Function inputs should almost never be `Option<T>`. Resolve optional input at
  the caller, or model its meaningful states with an enum. Do not pass missing
  or invalid state down the call chain for a callee to guess about.
- NEVER use boolean behavior parameters. Use an expressive enum or separate
  operations. CLI flags may be parsed as booleans, but convert them to domain
  types at the command boundary. Standard trait implementations such as
  `From<bool>` may perform that conversion.
- CLI attributes should use concrete values, collections, and sensible defaults
  wherever possible. Use `Option` only when absence itself matters, such as an
  explicit override versus a stored setting.
- Commands should normally be local-state argument structs implementing the
  shared `Run` trait. A command holds only its own arguments and operation
  state; shared session and vault state belongs in the application context.
  Keep dispatch separate from command behavior. Exceptions need a concrete
  reason, not another hierarchy.
- Use `Option<T>` only for expected absence or no applicable work, never to
  represent a failed operation.
- NEVER discard an error, under any circumstances. Do not use `.ok()`, ignored
  fallible results, empty `Err` branches, or fallback/default values to hide
  failures. Recovery, retries, and partial-success operations must retain their
  errors for the caller and diagnostic reporting.
- Use `crate::Result<T>` (or the imported crate alias) for fallible in-crate
  operations. Use the existing `crate::Error`, managed with `thiserror`, rather
  than ad hoc error types or independently spelling `Result<T, E>`. An external
  trait or API may require another error type; preserve it when converting into
  the crate error at that boundary.
- Preserve original errors and their source chains. Add typed context with
  `thiserror`'s `#[source]` or `#[from]`; do not flatten an underlying error
  into a string, replace it with a generic message, or otherwise erase
  diagnostic information inside the application.
- Map errors to concise, actionable, non-debug user output only at the outermost
  CLI boundary. Debug builds and explicitly enabled debug diagnostics must keep
  the complete error chain and relevant context visible and traceable. Neither
  output mode may disclose passwords, session tokens, or encryption keys.
- Avoid `Result<Option<T>, E>` in project-owned APIs. Resolve absence before the
  fallible operation where possible. If distinct domain outcomes must survive,
  name those outcomes explicitly rather than nesting generic containers; retain
  failures as crate errors, not absence.
- Do not define domain methods named `unwrap`, such as `Keys::unwrap`, to hide
  decryption behavior or error handling.

## No forwarding scaffolding

- Do not add a function whose only purpose is to call another function with
  prefilled arguments or a selected generic type. Call the actual operation at
  the use site and supply the parameter or type there.
- In particular, do not wrap a generic cipher operation just to select padding
  or another generic parameter. Keep the generic operation and select the type
  at its callers.
- Avoid chains of tiny forwarding functions, needless dynamic dispatch, and
  getters/setters that add no invariant or behavior. A trait implementation is
  useful when it supplies a real contract, not merely a second name.
- Reuse existing types and implementations before adding helpers or
  dependencies. Keep compiled paths free of avoidable allocation, copying, and
  repeated computation.
- Any regular expression MUST be hoisted into a named `const` or `static` and
  referenced at the use site. Compile reusable Rust expressions once, for
  example with `LazyLock`. Prefer ordinary string operations when sufficient.
  This applies to scripts as well as Rust.

## Configuration and terminal UI

- Use the `config` crate for configuration loading and layering, including
  native environment-variable precedence. Use the `KEEPER_` prefix; exact
  compatibility with every Commander environment-variable name is optional.
  Do not build a competing configuration parser or precedence mechanism.
- Use the `dirs` crate for platform configuration and related directories.
- If a full-screen terminal UI is needed, use `ratatui`. A plain command shell
  does not need a TUI framework.

## Work organization and version control

- This is a Jujutsu repository. Use `jj`, never raw Git commands for local VCS
  operations. Make regular local commits as work progresses.
- Split the working copy into logical changes between waves of work, for
  example protocol/crypto, vault, commands, and documentation. Keep the working
  copy manageable rather than accumulating one monolithic change.
- Use subagents for independent work. They may spawn their own subagents.
  Give each slice clear file ownership and shared API contracts.
- Create separate jj workspaces when agents would touch the same files or
  otherwise interfere. The integration owner joins the work when the baseline
  is ready, resolves conflicts, and verifies the combined result.
- Coordinate formatting and verification so one agent does not rewrite another
  agent's files mid-edit. Run the repository-wide tasks after integration.
- Local commit permission does not authorize pushes, PR creation, tags, or
  publication. Those still require explicit user approval.

### Parallel jj handoff

For parallel jj work, load `skill://swarm-jj-handoff` alongside
`skill://agent-swarms`. If the session's catalog is stale, read
`~/.omp/agent/managed-skills/swarm-jj-handoff/SKILL.md` directly.

The integration owner must remove task-owned workspaces and revisions proven
fully integrated or redundant, including both jj workspace records and their
on-disk directories. This requirement supersedes the generic instruction to
retain workspaces after a swarm. Preserve user-owned and unresolved work; never
filter away divergence to claim a clean graph. Before handoff, verify the
default log, status, workspace list, and full visible mutable graph. Leave
coherent, described changes and an empty default working copy.

## Repository metadata and license

- When using the project template, run its setup procedure and inspect the
  result. Remove stale template names and placeholders from `Cargo.toml`,
  `Makefile.toml`, and related metadata; do not assume the script caught them.
- `LICENSE` must match the user's license from
  `MrDwarf7/rust_template` on GitHub. Do not replace the project's license with
  an upstream project's license.
- Comments explain constraints and reasons, not what the next line does. Do not
  add AI attribution to code, documentation, commits, or PRs.
