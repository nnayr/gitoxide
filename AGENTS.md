# gitoxide (ditto overlay)

This is the ditto overlay for a fork of gitoxide. It lives on the orphan `ditto` branch checked out at `.ditto/`; the fork's code branches never contain ditto files.

## Build & Test

`node <package-root>/lib/ditto-root.ts gate [<worktree>]` is the full gate. It runs the gate task in `mise.toml` against the code checkout, so run it instead of `mise run gate`. The gate lines in `mise.toml` mirror the fork's own CI and test commands.

## Working rules

Triage beads with the triage skill before claiming. Work in `.wt/<name>/` worktrees; never commit on the primary checkout. After the gate and commit in the worktree, acquire `bd merge-slot`, rebase onto the integration branch recorded in `project.toml` under `[overlay]`, run the full gate again, then `git merge --ff-only` into the primary checkout. Close the bead, remove the worktree, release the merge slot, then push as authorized.

Commit ditto files (specs, plans, review docs, this file) on the `ditto` branch from inside `.ditto/`. Never stage ditto-owned paths (`.ditto/`, `.beads/`, `.pi/`, `.wt/`, `.superpowers/`, `.ditto-update/`, `.beads.gate.lock`) on a code branch; the commit guard refuses them. Only emergencies may bypass the primary-checkout rule with `DITTO_ALLOW_MAIN_COMMIT=1`, and that never bypasses the leak check. The ditto-skills bootstrap injects the shared rules.

## Current State

Initial overlay; update this section as the project evolves.
