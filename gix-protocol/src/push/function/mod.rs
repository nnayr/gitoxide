//! The push orchestrator (plan §3.3) — the mirror of `fetch::function`.
//!
//! Unlike `fetch`, the two I/O builds cannot be unified with `#[maybe_async]`: the blocking pack
//! closure is `FnOnce(&mut dyn io::Write, …)` while the async one is
//! `AsyncFnOnce(&mut (dyn futures_io::AsyncWrite + Unpin), …)` (the M0 async spike proves this exact
//! seam). So the orchestrator is structured as **explicit twins** — [`blocking_io::push`] and
//! [`async_io::push`] — that share the pure pre-flight ([`preflight`]: the `NoCommands` check plus
//! [`select_capabilities`](crate::push::command::select_capabilities)) and mirror each other's flow
//! byte-for-byte (F4 single-flush on the pack path vs the delete-only path, R2 drop-before-read).
//!
//! The two client features are mutually exclusive, so exactly one `push` is ever in scope; `push/mod`
//! re-exports whichever one the active feature selects.

use crate::push::{Error, Options, RefUpdate, command, command::SelectedCaps};

#[cfg(feature = "blocking-client")]
mod blocking_io;
#[cfg(feature = "blocking-client")]
pub use blocking_io::push;

#[cfg(feature = "async-client")]
mod async_io;
#[cfg(feature = "async-client")]
pub use async_io::push;

/// The pure pre-flight shared by both orchestrator twins (plan §3.3): reject an empty request, then
/// select the capabilities to echo (which also runs the hash-kind precheck, F3). Any impossible
/// request errors here, before a single wire byte is written (F3, F5).
pub(crate) fn preflight(
    updates: &[RefUpdate],
    capabilities: &crate::transport::client::Capabilities,
    opts: &Options,
    user_agent: crate::command::Feature,
) -> Result<SelectedCaps, Error> {
    // 0. Reject nonsense request shapes up front (the both-zero edit is already unrepresentable).
    if updates.is_empty() {
        return Err(Error::NoCommands);
    }
    // 1. Select capabilities (intersect wanted-with-advertised) and run the hash-kind precheck.
    command::select_capabilities(capabilities, updates, opts, user_agent)
}
