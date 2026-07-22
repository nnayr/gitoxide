//! Async twin of the command-list writer (plan §3.4, consistency-fuse F2).
//!
//! Under `async-client` the [`RequestWriter`](crate::transport::client::async_io::request::RequestWriter)
//! write side is a `futures_io::AsyncWrite`, not [`std::io::Write`], so the encoder cannot share the
//! blocking signature. The M1 orchestrator is blocking-only (the async orchestrator is M3); this twin
//! exists so the command seam is type-checked under `async-client` — the same per-build seam the M0
//! async spike proved.

use bstr::BString;
use futures_io::AsyncWrite;
use futures_lite::io::AsyncWriteExt;

use crate::push::{
    Error, RefUpdate,
    command::{SelectedCaps, command_line},
};

/// Async twin of [`write_command_list`](super::blocking_io::write_command_list).
#[allow(dead_code)]
pub(crate) async fn write_command_list<W: AsyncWrite + Unpin>(
    w: &mut W,
    updates: &[RefUpdate],
    caps: &SelectedCaps,
) -> Result<(), Error> {
    let zero = gix_hash::ObjectId::null(caps.object_hash).to_hex().to_string();
    for (i, update) in updates.iter().enumerate() {
        let mut line = command_line(update, &zero);
        if i == 0 {
            line.push(0);
            line.extend_from_slice(caps.to_wire_bytes().as_slice());
        }
        w.write_all(&line).await?;
    }
    Ok(())
}

/// Async twin of [`write_push_options`](super::blocking_io::write_push_options) (plan §1.3, M3).
pub(crate) async fn write_push_options<W: AsyncWrite + Unpin>(w: &mut W, options: &[BString]) -> Result<(), Error> {
    for option in options {
        w.write_all(option).await?;
    }
    Ok(())
}
