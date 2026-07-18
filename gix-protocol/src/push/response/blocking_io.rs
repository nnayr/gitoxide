//! Blocking twin of the report-status reader (plan §3.5).

use bstr::BString;

use crate::push::{Outcome, RefUpdate, response::parse_report};
use crate::transport::client::blocking_io::ExtendedBufRead;

/// Read the report-status pkt-lines off `reader` (until the flush-pkt) and parse them into an
/// [`Outcome`]. M1 reads plain pkt-lines (no side-band demux). Truncated/garbage input surfaces as
/// an `Err` from the reader, never a panic.
pub(crate) fn parse<'a>(
    mut reader: Box<dyn ExtendedBufRead<'a> + Unpin + 'a>,
    sent: &[RefUpdate],
    version: crate::transport::Protocol,
) -> Result<Outcome, super::Error> {
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
    let (unpack_status, refs) = parse_report(&lines, sent)?;
    Ok(Outcome {
        unpack_status,
        refs,
        server_protocol_version: version,
    })
}
