//! The async push orchestrator (plan §3.3, milestone M3) — the async twin of [`blocking_io::push`].
//!
//! This mirrors the blocking flow byte-for-byte; only the I/O seams differ. Because the async pack
//! closure is an `AsyncFnOnce` over `futures_io::AsyncWrite` (not a sync `FnOnce` over
//! `std::io::Write`), `#[maybe_async]` cannot unify the two — hence the explicit twin. The seams
//! (async command write via [`command::write_command_list`], async `into_parts()`, `.await` on the
//! pack closure, drop-before-read, then the async [`response::parse`]) are exactly the ones the M0
//! async spike (`push_seam_async_spike.rs`) type-checked.
//!
//! [`blocking_io::push`]: super::blocking_io::push

use std::sync::atomic::AtomicBool;

use gix_utils::progress::DynNestedProgress;

use crate::futures_lite::AsyncWriteExt;
use crate::push::{Context, Error, Options, Outcome, RefUpdate, command, response};
use crate::transport::client::{self, async_io::Transport};

/// Perform one push (send-pack) over an **async** `transport`, whose `handshake` was performed for
/// [`Service::ReceivePack`](crate::transport::Service::ReceivePack).
///
/// The async twin of [`push`](super::blocking_io::push): same [`Context`]/[`Options`]/[`Outcome`]
/// shapes and the same "never ends the interaction" discipline. `write_pack` is an **async** closure
/// streaming the raw packfile for exactly the objects the server lacks; it is awaited with the
/// transport's raw async write side iff at least one create/update command exists (never for a
/// delete-only push). It must write a complete pack — possibly a 0-object one when the server already
/// has every object. The pack itself is built by the caller (the crate never touches `gix-pack`, §0.3).
///
/// # M3 scope
///
/// Async parity with the blocking M1/M2 core: non-atomic, single-ref, plain `report-status` v1. The
/// negotiated object-format must equal the local ODB hash kind or the push is refused with
/// [`Error::HashKindMismatch`] **before any bytes are sent** (F3).
pub async fn push<P, T, E>(
    updates: &[RefUpdate],
    write_pack: impl AsyncFnOnce(
        &mut (dyn futures_io::AsyncWrite + Unpin),
        &mut dyn DynNestedProgress,
        &AtomicBool,
    ) -> Result<(), E>,
    mut progress: P,
    should_interrupt: &AtomicBool,
    ctx: Context<'_, T>,
    opts: Options,
) -> Result<Outcome, Error>
where
    P: gix_utils::progress::NestedProgress,
    P::SubProgress: 'static,
    T: Transport,
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    let _span = gix_trace::coarse!("gix_protocol::push()");
    let Context {
        handshake,
        transport,
        user_agent,
        trace_packetlines,
    } = ctx;
    let version = handshake.server_protocol_version;

    // 0/1. Shared pre-flight: reject empty requests and select capabilities (with the hash-kind
    //      precheck). Any impossible request errors here, before a single wire byte is written (F3, F5).
    let caps = super::preflight(updates, &handshake.capabilities, &opts, user_agent)?;

    // 2. Open the request in BINARY mode — command pkt-lines are emitted byte-exact with no trailing
    //    LF (§1.3, §3.4), and over async HTTP it maps to an unbounded, streaming request body.
    let mut w = transport.request(
        client::WriteMode::Binary,
        client::MessageKind::Flush, // the terminator into_read() emits on the delete-only path
        trace_packetlines,
    )?;

    // 3. Write the command list (first line carries \0<caps>). Do NOT flush here — the exit paths
    //    terminate differently (F4).
    command::write_command_list(&mut w, updates, &caps).await?;

    let has_pack = updates.iter().any(RefUpdate::sends_pack_objects);
    let has_push_options = !caps.push_options.is_empty();

    if has_pack || has_push_options {
        // EXPLICIT-TERMINATOR PATH (async mirror of the blocking twin): command-list flush, then the
        // optional push-options block + its own flush (§1.3), then the pack (if any). into_parts()
        // emits no terminator, so exactly the flushes written here reach the wire.
        w.write_message(client::MessageKind::Flush).await?;
        if has_push_options {
            command::write_push_options(&mut w, &caps.push_options).await?;
            w.write_message(client::MessageKind::Flush).await?;
        }
        let (mut raw, reader) = w.into_parts();
        if has_pack {
            write_pack(&mut *raw, &mut progress, should_interrupt)
                .await
                .map_err(|e| Error::WritePack(e.into()))?;
        }
        // Flush on EVERY into_parts() path — also the options-only (delete + push-options) one — so
        // a buffering transport cannot swallow a flush error into the Drop below (review L1).
        raw.flush().await?;
        drop(raw); // MUST drop before reading (the into_parts deadlock warning, R2)
        Ok(response::parse(reader, updates, version, caps.sideband, &mut progress, should_interrupt).await?)
    } else {
        // DELETE-ONLY, NO PUSH-OPTIONS: no explicit flush and no pack. into_read() emits the SINGLE
        // terminator (the MessageKind::Flush fixed at request()); writing one here too would
        // double-flush (F4). The byte-for-byte delete path.
        let reader = w.into_read().await?;
        Ok(response::parse(reader, updates, version, caps.sideband, &mut progress, should_interrupt).await?)
    }
}
