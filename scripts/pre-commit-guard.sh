#!/bin/sh
set -eu

# In a linked worktree, --git-dir points to its private metadata directory.
if [ "${DITTO_ALLOW_MAIN_COMMIT:-}" != "1" ] && [ "$(git rev-parse --git-dir)" = "$(git rev-parse --git-common-dir)" ]; then
  echo "Commit in a .wt/ worktree, not the primary checkout (DITTO_ALLOW_MAIN_COMMIT=1 bypasses)." >&2
  exit 1
fi

# Commits inside the ditto worktree are the only place ditto-owned paths may be staged.
primary="$(git rev-parse --path-format=absolute --git-common-dir)/.."
primary="$(cd "$primary" && pwd -P)"
if [ "$(git rev-parse --show-toplevel)" = "$primary/.ditto" ]; then
  exit 0
fi

# git matches the ditto-owned pathspecs itself, so path quoting cannot hide an offender.
# The bypass above does not skip this check; a git failure refuses the commit.
staged="$(mktemp)"
trap 'rm -f "$staged"' EXIT
# Inherited pathspec switches would change how the pathspecs below match.
unset GIT_LITERAL_PATHSPECS GIT_GLOB_PATHSPECS GIT_NOGLOB_PATHSPECS
if ! git diff --cached --name-only -z -- ':/.ditto/' ':/.beads/' ':/.pi/' ':/.wt/' ':/.superpowers/' ':/.ditto-update/' ':/.beads.gate.lock*' > "$staged"; then
  echo "Could not list staged paths; refusing the commit." >&2
  exit 1
fi
if [ -s "$staged" ]; then
  tr '\0' '\n' < "$staged" | sed 's/^/ditto-owned path staged: /' >&2
  echo "Ditto files belong on the ditto branch; commit them from .ditto/." >&2
  exit 1
fi
