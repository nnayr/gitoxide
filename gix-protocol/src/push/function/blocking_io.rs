//! The blocking push orchestrator (plan §3.3) — the blocking mirror of `fetch::function::fetch`.

use std::sync::atomic::AtomicBool;

use gix_features::progress::DynNestedProgress;

use crate::push::{Context, Error, Options, Outcome, RefUpdate, command, response};
use crate::transport::client::{self, blocking_io::Transport};

/// Perform one push (send-pack) over `transport`, whose `handshake` was performed for
/// [`Service::ReceivePack`](crate::transport::Service::ReceivePack).
///
/// Like [`fetch`](crate::fetch()), this does **not** end the interaction; it leaves the transport
/// reusable (wrap it in [`SendFlushOnDrop`](crate::SendFlushOnDrop) to close it).
///
/// `write_pack` streams the raw packfile for exactly the objects the server lacks. It is called with
/// the transport's raw write side iff at least one create/update command exists (never for a
/// delete-only push). It must write a complete pack — possibly a 0-object one when the server
/// already has every object. This is the mirror of fetch's `consume_pack`, direction reversed; the
/// pack itself is built by the caller (the `gix-protocol` crate never touches `gix-pack`, §0.3).
///
/// # M1 scope
///
/// Blocking, non-atomic, single-ref, plain `report-status` v1. The negotiated object-format must
/// equal the local ODB hash kind or the push is refused with [`Error::HashKindMismatch`] **before
/// any bytes are sent** (F3). The [`async`](super::async_io::push) twin mirrors this flow exactly.
pub fn push<P, T, E>(
    updates: &[RefUpdate],
    write_pack: impl FnOnce(&mut dyn std::io::Write, &mut dyn DynNestedProgress, &AtomicBool) -> Result<(), E>,
    mut progress: P,
    should_interrupt: &AtomicBool,
    ctx: Context<'_, T>,
    opts: Options,
) -> Result<Outcome, Error>
where
    P: gix_features::progress::NestedProgress,
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

    // 2. Open the request in BINARY mode — load-bearing for two independent reasons: command
    //    pkt-lines are emitted byte-exact with no trailing LF (§1.3, §3.4), and over HTTP it maps to
    //    an unbounded, streaming request body (a text-mode "cleanup" would reintroduce a wire bug and
    //    buffer the whole multi-MiB pack in memory).
    let mut w = transport.request(
        client::WriteMode::Binary,
        client::MessageKind::Flush, // the terminator into_read() emits on the delete-only path
        trace_packetlines,
    )?;

    // 3. Write the command list (first line carries \0<caps>). Do NOT flush here — the exit paths
    //    terminate differently (F4).
    command::write_command_list(&mut w, updates, &caps)?;

    let has_pack = updates.iter().any(RefUpdate::sends_pack_objects);
    let has_push_options = !caps.push_options.is_empty();

    if has_pack || has_push_options {
        // EXPLICIT-TERMINATOR PATH: terminate the command list with ONE explicit flush. When
        // push-options were negotiated, their own pkt-line block + a second flush follow (§1.3), then
        // the pack (if any). into_parts() emits no terminator, so exactly the flushes written here
        // reach the wire — pinned against `git push [--push-option]` by GIT_TRACE_PACKET.
        w.write_message(client::MessageKind::Flush)?;
        if has_push_options {
            command::write_push_options(&mut w, &caps.push_options)?;
            w.write_message(client::MessageKind::Flush)?;
        }
        let (mut raw, reader) = w.into_parts();
        if has_pack {
            write_pack(&mut raw, &mut progress, should_interrupt).map_err(|e| Error::WritePack(e.into()))?;
        }
        // Flush on EVERY into_parts() path — also the options-only (delete + push-options) one — so
        // a buffering transport cannot swallow a flush error into the Drop below (review L1).
        raw.flush()?;
        drop(raw); // MUST drop before reading (the into_parts deadlock warning)
        Ok(response::parse(
            reader,
            updates,
            version,
            caps.sideband,
            &mut progress,
            should_interrupt,
        )?)
    } else {
        // DELETE-ONLY, NO PUSH-OPTIONS: no explicit flush and no pack. into_read() emits the SINGLE
        // terminator (the MessageKind::Flush fixed at request()); writing one here too would
        // double-flush (F4). This is the byte-for-byte M1 delete path.
        let reader = w.into_read()?;
        Ok(response::parse(
            reader,
            updates,
            version,
            caps.sideband,
            &mut progress,
            should_interrupt,
        )?)
    }
}
