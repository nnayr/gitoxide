//! `gix-protocol::push` — a send-pack / receive-pack client (issue #306).
//!
//! **M1 (`gp01-u02`) — `push()` v1 blocking, non-atomic, single-ref core.**
//!
//! This module mirrors [`fetch`](crate::fetch) exactly (same [`Context`], `Options`/`Outcome`
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
//! report-status-v2 richness, side-band demux, the atomic paths, and the async twin of the
//! orchestrator are later milestones (M2/M3).

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

#[cfg(feature = "blocking-client")]
mod function;
#[cfg(feature = "blocking-client")]
pub use function::push;
