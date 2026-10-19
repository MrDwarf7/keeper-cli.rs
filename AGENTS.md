# Repository instructions

These rules apply throughout `keeper-cli.rs`. The package and binary are named `keeper-cli`.
`Makefile.toml` and its imported task files are the source of truth for development commands.

## Always

- Routine builds, runs, formatting, checks, linting, and tests MUST use top-level `cargo make`
  aliases. Direct Cargo is only for a targeted test or diagnostic the tasks cannot express; state
  why. A failing task is never permission to bypass it.
- Do not invoke release, version-bump, tagging, or publishing tasks without explicit user
  authorization.
- Neither concise nor debug output may disclose passwords, session tokens, or encryption keys.
- Comments explain constraints and reasons, not what the next line does. Do not add AI attribution
  to code, documentation, commits, or PRs.
- This is a Jujutsu repository: use `jj`, never raw Git for local VCS. Make regular local commits as
  work progresses and split work into logical changes. Local commit permission does not authorize
  pushes, PRs, tags, or publication.

## Required task routing

| Work                                                                  | MUST read                                                                                                |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Rust or script changes/reviews                                        | `.agents/guidance/rust-design.md`                                                                        |
| Build/run/format/check/lint/test or template/repository metadata work | `.agents/guidance/development-workflow.md`                                                               |
| Parallel jj work                                                      | `.agents/guidance/parallel-jj.md`, `agent-swarms`, and `swarm-jj-handoff` before dispatch or integration |

Read only the references needed for the task. They are the portable, normative source for
project-specific details. For parallel jj handoff, the project cleanup rule overrides generic
workspace-retention advice; preserve user-owned and unresolved work and never hide divergence to
claim a clean graph.
