//! M0 async compile spike (`gp01-u01`, F6 + consistency-fuse F2) — **COMPILE-ONLY, never run.**
//!
//! Proves the raw-write shape the plan rests on compiles against `into_parts()`'s *async* side
//! (`futures_io::AsyncWrite`) under the `async-client` feature, so the M3 async twin is not
//! resting on an unverified seam. Both per-build seams are proven here:
//!
//!  1. **`command/` write** (consistency-fuse F2): writing command pkt-lines + a flush against the
//!     async `RequestWriter` — which impls `futures_io::AsyncWrite`, NOT `std::io::Write`, so a
//!     sync `io::Write` bound could not compile here.
//!  2. **`write_pack` seam** (F6, elegance-fuse L7): the RATIFIED per-build signature is an
//!     *async closure* — `impl AsyncFnOnce(&mut (dyn AsyncWrite + Unpin), …) -> Result<(), E>` —
//!     the true `maybe_async` mirror of `fetch::consume_pack`, NOT a sync `FnOnce` over an
//!     `AsyncWrite` (which cannot stream natively). We take the async raw writer from
//!     `into_parts()`, hand it to the async closure, `.await`, then drop before reading.
//!
//! The functions below are `#[allow(dead_code)]` and never invoked — building the test binary
//! type-checks them (including the concrete `AsyncFnOnce` instantiation), which is the whole proof.
//!
//! NOTE on the progress arg: the real M1 signature's middle parameter is
//! `&mut dyn gix_features::progress::DynNestedProgress`. `gix-features` is a normal (non-dev)
//! dependency of `gix-protocol`, so it is not nameable from an integration test, and adding it as
//! a dev-dependency would break the additive-only fork invariant (§4.3). We substitute a nameable
//! stand-in (`&mut dyn std::io::Write`) so the closure keeps L7's exact 3-arg arity; the async
//! WRITE seam — the only thing F6 is about — is proven exactly.

#![cfg(all(feature = "push", feature = "async-client"))]
#![allow(dead_code)]

// RED marker: same `push`-module self-gate reference as the blocking spike.
#[allow(unused_imports)]
use gix_protocol::push;

use std::sync::atomic::AtomicBool;

use gix_protocol::futures_io::AsyncWrite;
use gix_protocol::transport::client::MessageKind;
use gix_protocol::transport::client::async_io::RequestWriter;

/// Seam 1 (F2): the command-list write against the async `RequestWriter`.
async fn prove_command_seam(mut w: RequestWriter<'_>) -> std::io::Result<()> {
    use gix_protocol::futures_lite::AsyncWriteExt;
    // One line so the exact bytes (single space between the two zero-oids, then the ref, NUL, caps)
    // are unambiguous — no backslash-newline whitespace collapse to miscount.
    let line = b"0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 refs/rolfdb/data\0report-status";
    w.write_all(line).await?; // RequestWriter: futures_io::AsyncWrite (binary pkt-line mode) — no io::Write bound
    w.write_message(MessageKind::Flush).await?; // async write_message
    let (_raw, _reader) = w.into_parts();
    Ok(())
}

/// Seam 2 (F6/L7): the per-build async `write_pack` closure over `into_parts()`'s async raw side.
async fn drive_pack<E, F>(w: RequestWriter<'_>, write_pack: F, stop: &AtomicBool) -> std::io::Result<()>
where
    E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    F: AsyncFnOnce(&mut (dyn AsyncWrite + Unpin), &mut dyn std::io::Write, &AtomicBool) -> Result<(), E>,
{
    use gix_protocol::futures_lite::AsyncWriteExt;
    let (mut raw, _reader) = w.into_parts(); // async into_parts → Box<dyn AsyncWrite + Unpin>
    let mut progress: Vec<u8> = Vec::new(); // stand-in for &mut dyn DynNestedProgress (see module note)
    write_pack(&mut *raw, &mut progress, stop)
        .await
        .map_err(|e| std::io::Error::other(e.into()))?;
    raw.flush().await?;
    drop(raw); // drop the writer before reading `_reader` — the R2 deadlock discipline, async side
    Ok(())
}

/// Instantiate `drive_pack` with a concrete async closure so the `AsyncFnOnce` bound is actually
/// checked at compile time. Never called.
async fn prove_pack_seam(w: RequestWriter<'_>) {
    let stop = AtomicBool::new(false);
    let _ = drive_pack(
        w,
        async |raw: &mut (dyn AsyncWrite + Unpin), _p: &mut dyn std::io::Write, _s: &AtomicBool| {
            use gix_protocol::futures_lite::AsyncWriteExt;
            // A minimal empty pack (PACK, v2, 0 objects) — content is irrelevant to the compile proof.
            raw.write_all(b"PACK\x00\x00\x00\x02\x00\x00\x00\x00").await?;
            Ok::<(), std::io::Error>(())
        },
        &stop,
    )
    .await;
}
