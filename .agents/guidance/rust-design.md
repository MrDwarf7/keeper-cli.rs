# Rust and script design

Read this reference for Rust or script changes and reviews. `Makefile.toml` and its imported task
files remain the source of truth for commands.

## Rust design

- Port Commander's protocol and observable behavior. Do not copy its Python class hierarchies,
  facades, mutable parameter bags, or inheritance patterns.
- Use Rust's type system to make invalid states unrepresentable. Use validated newtypes, enums,
  type-state, builders, or type-state builders where they enforce actual invariants or ordering
  constraints. Do not replace meaningful types with loose strings, integers, empty-key sentinels, or
  boolean switches.
- Keep decryption and vault assembly in coherent stages. Do not grow another several-hundred-line
  `build` function. A stage must own real work rather than just forward to another function.
- Prefer standard traits for their intended jobs: `From`/`TryFrom` for conversions, `FromStr` for
  parsing, `Display` for rendering, `Default` for defaults, and `Iterator`/`IntoIterator` for
  traversal. For example, bytes to a UID belong in a conversion implementation, not a `uid(bytes)`
  helper.
- Avoid manual indexing and range slicing in production code and tests, including map and JSON
  indexing. Encode fixed layouts and cardinality with arrays, destructuring, validated frame types,
  and iterators before reaching for a positional lookup.
- For genuinely dynamic access, use the collection's checked API: `get`, `get_mut`, checked
  splitting, or map `entry` with `or_insert_with`/`or_default`. Handle absence according to the
  operation's contract and preserve failures as crate errors. Do not replace indexing mechanically
  with `get().unwrap()` or `get().expect()`, add fake defaults, or hide it behind an `Index`
  implementation or unchecked access. Tests should assert required fixture shape or entries
  explicitly. Do not add allocation or copying merely to avoid brackets.
- Function inputs should almost never be `Option<T>`. Resolve optional input at the caller, or model
  its meaningful states with an enum. Do not pass missing or invalid state down the call chain for a
  callee to guess about.
- NEVER use boolean behavior parameters. Use an expressive enum or separate operations. CLI flags
  may be parsed as booleans, but convert them to domain types at the command boundary. Standard
  trait implementations such as `From<bool>` may perform that conversion.
- CLI attributes should use concrete values, collections, and sensible defaults wherever possible.
  Use `Option` only when absence itself matters, such as an explicit override versus a stored
  setting.
- Commands should normally be local-state argument structs implementing the shared `Run` trait. A
  command holds only its own arguments and operation state; shared session and vault state belongs
  in the application context. Keep dispatch separate from command behavior. Exceptions need a
  concrete reason, not another hierarchy.
- Use `Option<T>` only for expected absence or no applicable work, never to represent a failed
  operation.
- NEVER discard an error, under any circumstances. Do not use `.ok()`, ignored fallible results,
  empty `Err` branches, or fallback/default values to hide failures. Recovery, retries, and
  partial-success operations must retain their errors for the caller and diagnostic reporting.
- Use `crate::Result<T>` (or the imported crate alias) for fallible in-crate operations. Use the
  existing `crate::Error`, managed with `thiserror`, rather than ad hoc error types or independently
  spelling `Result<T, E>`. An external trait or API may require another error type; preserve it when
  converting into the crate error at that boundary.
- Preserve original errors and their source chains. Add typed context with `thiserror`'s `#[source]`
  or `#[from]`; do not flatten an underlying error into a string, replace it with a generic message,
  or otherwise erase diagnostic information inside the application.
- Map errors to concise, actionable, non-debug user output only at the outermost CLI boundary. Debug
  builds and explicitly enabled debug diagnostics must keep the complete error chain and relevant
  context visible and traceable. Neither output mode may disclose passwords, session tokens, or
  encryption keys.
- Avoid `Result<Option<T>, E>` in project-owned APIs. Resolve absence before the fallible operation
  where possible. If distinct domain outcomes must survive, name those outcomes explicitly rather
  than nesting generic containers; retain failures as crate errors, not absence.
- Do not define domain methods named `unwrap`, such as `Keys::unwrap`, to hide decryption behavior
  or error handling.

## No forwarding scaffolding

- Do not add a function whose only purpose is to call another function with prefilled arguments or a
  selected generic type. Call the actual operation at the use site and supply the parameter or type
  there.
- In particular, do not wrap a generic cipher operation just to select padding or another generic
  parameter. Keep the generic operation and select the type at its callers.
- Avoid chains of tiny forwarding functions, needless dynamic dispatch, and getters/setters that add
  no invariant or behavior. A trait implementation is useful when it supplies a real contract, not
  merely a second name.
- Reuse existing types and implementations before adding helpers or dependencies. Keep compiled
  paths free of avoidable allocation, copying, and repeated computation.
- Any regular expression MUST be hoisted into a named `const` or `static` and referenced at the use
  site. Compile reusable Rust expressions once, for example with `LazyLock`. Prefer ordinary string
  operations when sufficient. This applies to scripts as well as Rust.

## Configuration and terminal UI

Read this section only when changing configuration, platform directories, or terminal UI.

- Use the `config` crate for configuration loading and layering, including native
  environment-variable precedence. Use the `KEEPER_` prefix; exact compatibility with every
  Commander environment-variable name is optional. Do not build a competing configuration parser or
  precedence mechanism.
- Use the `dirs` crate for platform configuration and related directories.
- If a full-screen terminal UI is needed, use `ratatui`. A plain command shell does not need a TUI
  framework.
