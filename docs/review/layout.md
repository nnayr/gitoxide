# Module map

The placement lens checks new and moved code against this map. Keep one entry per crate, package or top-level directory with purpose, what belongs and what does not; prefix a rule the lens must treat as a blocker with `invariant:`. Where the map is silent, the lens follows the convention most comparable code uses.

## Workspace-wide

- invariant: no `.unwrap()` in production code; use `.expect("why")` only where failure is impossible.
- invariant: plumbing crates (`gix-*` other than `gix`) never depend on `gix` or `gitoxide-core`.
- invariant: a plumbing crate already on `gix-error` keeps using it for new errors; a crate still on `thiserror` stays on `thiserror`.
- Git paths are bytes (`BString`/`BStr`); convert to `Path`/`OsStr` only through `gix-path`.
- Fixtures live in each crate's `tests/fixtures/*.sh`; generated archives under `tests/fixtures/generated-archives/`.

## gix

- Purpose: porcelain library entrypoint; interact with repositories the way git does.
- Belongs: `Repository`-backed platforms and caches, configuration-driven wiring of plumbing crates, high-level convenience APIs.
- Does not belong: format parsing or algorithms that do not need a `Repository` (put those in the matching plumbing crate).

## gitoxide-core

- Purpose: the library implementing all capabilities of the `gix` and `ein` CLIs.
- Belongs: command implementations built on `gix`, output formatting.
- Does not belong: argument parsing (`src/`), reusable library functionality (`gix` or a plumbing crate).

## src

- Purpose: the `gix` (plumbing) and `ein` (porcelain) binaries.
- Belongs: clap argument definitions, dispatch into `gitoxide-core`, `anyhow` error handling.
- Does not belong: command logic (`gitoxide-core`).

## tests

- Purpose: workspace-level journey tests (`tests/journey.sh`, `tests/journey/`), snapshots, shared fixtures and `tests/tools` (`gix-testtools`, `jtt`).
- Belongs: end-to-end CLI tests and shared test tooling.
- Does not belong: unit or integration tests of a single crate (that crate's `tests/`).

## examples

- Purpose: small runnable examples of the `gix` API.

## etc

- Purpose: repository support material: CI and check scripts (`etc/scripts`), docker, corpus and fuzzing helpers, diagrams.
- Does not belong: Rust code compiled into any crate.

## Plumbing crates

### gix-actor

- Purpose: A way to identify git actors.

### gix-archive

- Purpose: archive generation from of a worktree stream.

### gix-attributes

- Purpose: A crate of the gitoxide project dealing .gitattributes files.

### gix-bitmap

- Purpose: A crate of the gitoxide project dedicated implementing the standard git bitmap format.

### gix-blame

- Purpose: A crate of the gitoxide project dedicated to implementing a 'blame' algorithm.

### gix-chunk

- Purpose: Interact with the git chunk file format used in multi-pack index and commit-graph files.

### gix-command

- Purpose: A crate of the gitoxide project handling internal git command execution.

### gix-commitgraph

- Purpose: Read-only access to the git commitgraph file format.

### gix-config

- Purpose: A git-config file parser and editor from the gitoxide project.

### gix-config-value

- Purpose: A crate of the gitoxide project providing git-config value parsing.

### gix-credentials

- Purpose: A crate of the gitoxide project to interact with git credentials helpers.

### gix-date

- Purpose: A crate of the gitoxide project parsing dates the way git does.

### gix-diff

- Purpose: Calculate differences between various git objects.

### gix-dir

- Purpose: A crate of the gitoxide project dealing with directory walks.

### gix-discover

- Purpose: Discover git repositories and check if a directory is a git repository.

### gix-error

- Purpose: A crate of the gitoxide project to provide common errors and error-handling utilities.
- Belongs: shared `Exn`/`Message` error types and helpers.
- invariant: depends on no other `gix-*` crate.

### gix-features

- Purpose: A crate to integrate various capabilities using compile-time feature flags.
- Belongs: compile-time capability toggles (parallelism, progress, zlib, hashing backends).

### gix-fetchhead

- Purpose: A crate of the gitoxide project to read and write .git/FETCH_HEAD.

### gix-filter

- Purpose: A crate of the gitoxide project implementing git filters.

### gix-fs

- Purpose: A crate providing file system specific utilities to `gitoxide`.

### gix-fsck

- Purpose: Verifies the connectivity and validity of objects in the database.

### gix-glob

- Purpose: A crate of the gitoxide project dealing with pattern matching.

### gix-hash

- Purpose: Borrowed and owned git hash digests used to identify git objects.
- invariant: no other `gix-*` dependency beyond foundational ones (`gix-features`); hash kind selection stays feature-driven (`sha1`/`sha256`).

### gix-hashtable

- Purpose: A crate that provides hashtable based data structures optimized to utilize ObjectId keys.

### gix-ignore

- Purpose: A crate of the gitoxide project dealing .gitignore files.

### gix-imara-diff

- Purpose: A high performance library for computing diffs, maintained as a modified copy of upstream imara-diff for gitoxide..
- Belongs: the vendored, modified imara-diff; keep divergence from upstream deliberate and minimal.

### gix-index

- Purpose: A work-in-progress crate of the gitoxide project dedicated implementing the git index file.

### gix-lfs

- Purpose: A crate of the gitoxide project dealing with handling git large file support.

### gix-lock

- Purpose: A git-style lock-file implementation.

### gix-macros

- Purpose: Proc-macro utilities for gix.

### gix-mailmap

- Purpose: A crate of the gitoxide project for parsing mailmap files.

### gix-merge

- Purpose: A crate of the gitoxide project implementing merge algorithms.

### gix-negotiate

- Purpose: A crate of the gitoxide project implementing negotiation algorithms.

### gix-note

- Purpose: A crate of the gitoxide project dealing with git notes.

### gix-object

- Purpose: Immutable and mutable git objects with decoding and encoding support.

### gix-odb

- Purpose: Implements various git object databases.

### gix-pack

- Purpose: Implements git packs and related data structures.

### gix-packetline

- Purpose: A crate of the gitoxide project implementing the pkt-line serialization format.

### gix-path

- Purpose: A crate of the gitoxide project dealing paths and their conversions.
- Belongs: all conversions between git byte paths and OS paths.

### gix-pathspec

- Purpose: A crate of the gitoxide project dealing magical pathspecs.

### gix-prompt

- Purpose: A crate of the gitoxide project for handling prompts in the terminal.

### gix-protocol

- Purpose: A crate of the gitoxide project for implementing git protocols.

### gix-quote

- Purpose: A crate of the gitoxide project dealing with various quotations used by git.

### gix-rebase

- Purpose: A crate of the gitoxide project dealing rebases.

### gix-ref

- Purpose: A crate to handle git references.

### gix-refspec

- Purpose: A crate of the gitoxide project for parsing and representing refspecs.

### gix-revision

- Purpose: A crate of the gitoxide project dealing with finding names for revisions and parsing specifications.

### gix-revwalk

- Purpose: A crate providing utilities for walking the revision graph.

### gix-sec

- Purpose: A crate of the gitoxide project providing a shared trust model.

### gix-sequencer

- Purpose: A crate of the gitoxide project handling sequences of human-aided operations.

### gix-shallow

- Purpose: Handle files specifying the shallow boundary.

### gix-status

- Purpose: A crate of the gitoxide project dealing with 'git status'-like functionality.

### gix-submodule

- Purpose: A crate of the gitoxide project dealing git submodules.

### gix-tempfile

- Purpose: A tempfile implementation with a global registry to assure cleanup.

### gix-tix

- Purpose: A tool like `tig`, but minimal, fast and efficient.
- Belongs: the `tix` binary and its UI; not used by library crates.

### gix-trace

- Purpose: A crate to provide minimal `tracing` support that can be turned off to zero cost.

### gix-transport

- Purpose: A crate of the gitoxide project dedicated to implementing the git transport layer.

### gix-traverse

- Purpose: A crate of the gitoxide project.

### gix-tui

- Purpose: A crate of the gitoxide project dedicated to a terminal user interface to interact with git repositories.
- Belongs: terminal UI components; not used by library crates.

### gix-url

- Purpose: A crate of the gitoxide project implementing parsing and serialization of gix-url.

### gix-utils

- Purpose: A crate with `gitoxide` utilities that don't need feature toggles.
- Belongs: small utilities that need no feature toggles.

### gix-validate

- Purpose: Validation functions for various kinds of names in git.

### gix-worktree

- Purpose: A crate of the gitoxide project for shared worktree related types and utilities..

### gix-worktree-state

- Purpose: A crate of the gitoxide project implementing setting the worktree to a particular state.

### gix-worktree-stream

- Purpose: generate a byte-stream from a git-tree.

### gix-zlib

- Purpose: Zlib-rs streaming compression and decompression utilities used by gitoxide.
