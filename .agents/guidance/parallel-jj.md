# Work organization and parallel jj handoff

Read this reference for parallel work involving jj. This is a Jujutsu repository: use `jj`, never
raw Git commands for local VCS operations. Make regular local commits as work progresses.

- Split the working copy into logical changes between waves of work, for example protocol/crypto,
  vault, commands, and documentation. Keep the working copy manageable rather than accumulating one
  monolithic change.
- Use subagents for independent work. They may spawn their own subagents. Give each slice clear file
  ownership and shared API contracts.
- Create separate jj workspaces when agents would touch the same files or otherwise interfere. The
  integration owner joins the work when the baseline is ready, resolves conflicts, and verifies the
  combined result.
- Coordinate formatting and verification so one agent does not rewrite another agent's files
  mid-edit. Run the repository-wide tasks after integration.
- Local commit permission does not authorize pushes, PR creation, tags, or publication. Those still
  require explicit user approval.

For parallel jj work, load `skill://swarm-jj-handoff` alongside `skill://agent-swarms`. If the
session's catalog is stale, read `~/.omp/agent/managed-skills/swarm-jj-handoff/SKILL.md` directly.

The integration owner MUST remove task-owned workspaces and revisions proven fully integrated or
redundant, including both jj workspace records and their on-disk directories. This requirement
supersedes the generic instruction to retain workspaces after a swarm. Preserve user-owned and
unresolved work; NEVER filter away divergence to claim a clean graph. Before handoff, verify the
default log, status, workspace list, and full visible mutable graph. Leave coherent, described
changes and an empty default working copy.
