//! `gix-protocol::push` — a send-pack / receive-pack client (issue #306).
//!
//! **M1 (`gp01-u02`) — `push()` v1 blocking, non-atomic, single-ref core.**
//!
//! This module mirrors [`fetch()`](crate::fetch()) exactly (same [`Context`](crate::fetch::Context), `Options`/`Outcome`
//! shapes, the caller-supplied pack closure, the "never ends the interaction" discipline). The
//! `gix-protocol` crate never gains a `gix-pack` dependency: the packfile is built by the
//! **caller's** `write_pack` closure, exactly as `fetch` consumes the server's pack through a
//! closure it never parses (see `docs/design/gix-push-implementation-plan.md` §0.3, §3).
//!
//! # Protocol order (v0/v1 receive-pack — there is no push protocol v2, §1.6)
//!
//! ```text
//! handshake(Service::ReceivePack)  → ref advertisement + capabilities   [crate::handshake]
//! C: update-request (command-list; caps after NUL on the FIRST line) + flush   [push::command]
//! C: PACK…  (raw bytes; omitted for delete-only pushes)                        [caller write_pack]
//! S: report-status (unpack + per-ref ok/ng) + flush                            [push::response]
//! ```
//!
//! # M1 scope
//!
//! Blocking single-ref create/update/delete, a **full** pack (`allow_thin_pack=false`, built by
//! the caller over the §3.6 boundary walk), plain `report-status` v1 parsing, and a clean
//! `HashKindMismatch` refusal of an SHA-256 remote. Thin packs, https/ssh transports,
//! report-status-v2 richness, and the atomic paths span M2/M3.
//!
//! # M3 wire features (default OFF)
//!
//! Two optional plumbing legs, negotiated only when the caller opts in via [`Options`](crate::push::Options) **and** the
//! server advertised the capability (§1.3, §3.5):
//!
//! * **push-options** ([`Options::push_options`](crate::push::Options::push_options)) — option pkt-lines sent as their own flush-framed
//!   block between the command-list flush and the pack (delete-only pushes send the block with no
//!   pack).
//! * **side-band-64k** ([`Options::sideband`](crate::push::Options::sideband)) — the report stream is demultiplexed (band 1 = the
//!   report, band 2 = progress, band 3 = a remote error), mirroring `fetch`'s side-band handling.
//!
//! Left at their defaults (empty / `false`) neither touches the wire, so an M1/M2 push is
//! byte-identical. Both have blocking and async twins.

mod types;
pub use types::*;

#[cfg(any(feature = "blocking-client", feature = "async-client"))]
mod error;
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
pub use error::Error;

// All items in `command/` are `pub(crate)` (the encoder is internal), so the module is private —
// unlike `response`/`validate`, which export public types.
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
mod command;

pub mod response;

pub mod validate;
pub use validate::{Advertised, plan_from_advertisement};

// The orchestrator has explicit blocking/async twins (see `function/`); each I/O build re-exports
// its own `push`. The two client features are mutually exclusive, so only one is ever in scope.
#[cfg(any(feature = "blocking-client", feature = "async-client"))]
mod function;
#[cfg(feature = "blocking-client")]
pub use function::push;
#[cfg(feature = "async-client")]
pub use function::push;
