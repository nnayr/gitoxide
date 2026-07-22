//! Blocking twin of the report-status reader (plan §3.5).

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};

use bstr::BString;
use gix_features::progress::DynNestedProgress;

use crate::push::{Outcome, RefUpdate, response::parse_report};
use crate::transport::client::blocking_io::{ExtendedBufRead, HandleProgress};

/// Read the report-status pkt-lines off `reader` (until the flush-pkt) and parse them into an
/// [`Outcome`].
///
/// With `sideband` off (the M1/default path) this reads plain pkt-lines exactly as before — one
/// `readline_str` per report line — so a push that never negotiates side-band-64k is byte-identical.
/// With `sideband` on, the report is band-multiplexed: band 1 carries the report pkt-lines, band 2
/// progress, band 3 a remote error; we demux via a progress handler (mirroring
/// `fetch::setup_remote_progress`) and re-split the band-1 stream. Truncated/garbage input surfaces
/// as an `Err`, never a panic.
pub(crate) fn parse<'a>(
    mut reader: Box<dyn ExtendedBufRead<'a> + Unpin + 'a>,
    sent: &[RefUpdate],
    version: crate::transport::Protocol,
    sideband: bool,
    progress: &mut dyn DynNestedProgress,
    should_interrupt: &'a AtomicBool,
) -> Result<Outcome, super::Error> {
    let lines = if sideband {
        read_sideband_report(&mut reader, progress, should_interrupt)?
    } else {
        read_plain_report(&mut reader)?
    };
    let (unpack_status, refs) = parse_report(&lines, sent)?;
    Ok(Outcome {
        unpack_status,
        refs,
        server_protocol_version: version,
    })
}

/// Plain (no side-band) report: each `readline_str` yields exactly one report pkt-line payload.
fn read_plain_report<'a>(reader: &mut Box<dyn ExtendedBufRead<'a> + Unpin + 'a>) -> Result<Vec<BString>, super::Error> {
    let mut lines: Vec<BString> = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.readline_str(&mut line)?;
        if read == 0 {
            break;
        }
        lines.push(line.as_bytes().into());
    }
    Ok(lines)
}

/// Side-band-64k report (M3): set a progress handler (band 2 → progress, band 3 → error, mirroring
/// `fetch::setup_remote_progress`), read the demuxed band-1 stream to the outer flush, then re-split
/// it into report pkt-lines.
fn read_sideband_report<'a>(
    reader: &mut Box<dyn ExtendedBufRead<'a> + Unpin + 'a>,
    progress: &mut dyn DynNestedProgress,
    should_interrupt: &'a AtomicBool,
) -> Result<Vec<BString>, super::Error> {
    let mut remote_progress = progress.add_child_with_id("remote".to_string(), super::REMOTE_PROGRESS_ID);
    reader.set_progress_handler(Some(Box::new(move |is_err: bool, data: &[u8]| {
        crate::RemoteProgress::translate_to_progress(is_err, data, &mut remote_progress);
        if should_interrupt.load(Ordering::Relaxed) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }) as HandleProgress<'a>));

    // With the handler set, each `readline_str` yields one demuxed band-1 chunk (band 2/3 are routed
    // to the handler and never returned); the outer flush-pkt ends the stream with a 0-length read.
    // Accumulate every band-1 byte, then re-split — robust to however the server fragments band 1.
    let mut band1 = Vec::new();
    let mut chunk = String::new();
    loop {
        chunk.clear();
        let read = reader.readline_str(&mut chunk)?;
        if read == 0 {
            break;
        }
        band1.extend_from_slice(chunk.as_bytes());
    }
    super::split_report_pkt_lines(&band1)
}
