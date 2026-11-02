# gitoxide (ditto overlay)

This is the ditto overlay for a fork of gitoxide. It lives on the orphan `ditto` branch checked out at `.ditto/`; the fork's code branches never contain ditto files.

## Build & Test

`node <package-root>/lib/ditto-root.ts gate [<worktree>]` is the full gate. It runs the gate task in `mise.toml` against the code checkout, so run it instead of `mise run gate`. The gate lines in `mise.toml` mirror the fork's own CI and test commands.

## Gate lines

Each line mirrors a job in upstream's `.github/workflows/ci.yml`:

- `cargo fmt --all -- --check`: `lint` job formatting check.
- `just clippy -D warnings -A unknown-lints --no-deps`: `lint` job; clippy in the default, `small`, `max-pure` and `lean-async` configurations.
- `just doc`: `lint` job; rustdoc with `-D warnings`.
- `cargo machete`: `lint` job; unused dependencies.
- `cargo deny --workspace --all-features check bans licenses sources`: `cargo-deny` job.
- `just check`: `test` job (`ci-test`); feature-combination builds and the checks that must fail to compile.
- `CI=1 GIX_TEST_IGNORE_ARCHIVES=1 just unit-tests`: `test` job (`ci-test`). `GIX_TEST_IGNORE_ARCHIVES` reruns fixture scripts as CI does; `CI=1` keeps `gix-testtools` from rewriting the tracked `generated-archives/*.tar` (which would dirty the checkout and let `_needs_archive` tests read regenerated fixtures) and keeps insta from leaving pending snapshots.
- `just check-mode`: `test` job (`ci-test`); executable bits.
- `CI=1 just doc-tests`: `test-doc` job.
- `CI=1 just ci-journey-tests`: `test-journey` job. `CI=1` skips the `not_on_ci` cases, whose output depends on the terminal, exactly as upstream CI does.

Not mirrored: `msrv` (nightly `-Zminimal-versions` rewrites `Cargo.lock`), `cargo-deny-advisories` (network, fails on new advisories unrelated to a change), `wasm`, `pure-rust-build`, `test-fixtures-windows`, cross builds, `check-size` (cargo-diet) and the CI-meta, CodeQL, fuzz, zizmor and release workflows. The extra tools the gate needs (just, cargo-nextest, cargo-machete, cargo-deny) are pinned in `mise.toml`.

## Working rules

Triage beads with the triage skill before claiming. Work in `.wt/<name>/` worktrees; never commit on the primary checkout. After the gate and commit in the worktree, acquire `bd merge-slot`, rebase onto the integration branch recorded in `project.toml` under `[overlay]`, run the full gate again, then `git merge --ff-only` into the primary checkout. Close the bead, remove the worktree, release the merge slot, then push as authorized.

Commit ditto files (specs, plans, review docs, this file) on the `ditto` branch from inside `.ditto/`. Never stage ditto-owned paths (`.ditto/`, `.beads/`, `.pi/`, `.wt/`, `.superpowers/`, `.ditto-update/`, `.beads.gate.lock`) on a code branch; the commit guard refuses them. Only emergencies may bypass the primary-checkout rule with `DITTO_ALLOW_MAIN_COMMIT=1`, and that never bypasses the leak check. The ditto-skills bootstrap injects the shared rules.

## Current State

Initial overlay; update this section as the project evolves.
