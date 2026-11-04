//! The report-status parser (plan §3.5).
//!
//! The meaty logic is `parse_report`, a pure function over already-split pkt-line payloads — so it
//! is unit-testable on byte slices, independent of any transport. The blocking I/O twin reads the
//! pkt-lines off the wire and delegates to it.
//!
//! The reported ref name is kept as a **verbatim** [`BString`] (M5) and correlated to the sent
//! commands by `as_bstr()` equality. The `ng` reason is preserved verbatim and never parsed for
//! control flow (§2.2); [`classify`] is an advisory heuristic only. Truncated or garbage input is an
//! `Err`, never a panic.

use bstr::{BStr, BString, ByteSlice};
use gix_hash::ObjectId;

use crate::push::{RefRejectReason, RefUpdate, RefUpdateStatus, UnpackStatus};

#[cfg(feature = "blocking-client")]
mod blocking_io;
#[cfg(feature = "blocking-client")]
pub(crate) use blocking_io::parse;

#[cfg(all(feature = "async-client", not(feature = "blocking-client")))]
mod async_io;
#[cfg(all(feature = "async-client", not(feature = "blocking-client")))]
pub(crate) use async_io::parse;

/// The progress id for the `remote` child progress a side-band-64k report demux routes band 2 (and
/// band 3, as an error) into (§3.5, M3) — the push analogue of fetch's `ProgressId::RemoteProgress`.
#[allow(dead_code)] // consumed by the sideband reader twins only
pub(crate) const REMOTE_PROGRESS_ID: gix_utils::progress::Id = *b"PSRP";

/// Extra per-ref detail from report-status-v2 `option` lines — informational, never branched on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefUpdateDetails {
    /// The `option old-oid <oid>` value, if reported.
    pub old_oid: Option<ObjectId>,
    /// The `option new-oid <oid>` value, if reported.
    pub new_oid: Option<ObjectId>,
    /// Whether the server reported `option forced-update`.
    pub forced_update: bool,
}

/// The error returned by the report-status parser.
#[derive(Debug)]
#[expect(missing_docs)]
pub enum Error {
    MissingUnpackStatus,
    Malformed { line: BString },
    MissingRefStatus { name: BString },
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingUnpackStatus => f.write_str("the report-status did not begin with an 'unpack' line"),
            Error::Malformed { line } => write!(f, "could not parse the report-status line {line:?}"),
            Error::MissingRefStatus { name } => write!(
                f,
                "the per-ref status for {name:?} is missing, or a status was reported for a ref that was never sent"
            ),
            Error::Io(err) => {
                f.write_str("an I/O error occurred while reading the report-status")?;
                super::error::write_causes(f, err)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::MissingUnpackStatus | Error::Malformed { .. } | Error::MissingRefStatus { .. } => {
                Some(const { &gix_error::ClassificationMarker::CORRUPTION })
            }
            // The server may already have applied the update by the time the report is lost, so a
            // retry-capable cause must stay out of classification; `Display` still names it.
            Error::Io(_) => Some(const { &gix_error::ClassificationMarker::CONFLICT }),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// Advisory classification of an `ng` reason (§2.2). A best-effort heuristic over server prose that
/// the spec declares unspecified and host/version-dependent — for telemetry only, never for control
/// flow.
pub fn classify(reason: &BStr) -> RefRejectReason {
    let lower = reason.to_ascii_lowercase();
    let s = lower.as_bstr();
    if s.contains_str("stale") {
        RefRejectReason::StaleInfo
    } else if s.contains_str("fetch first") {
        RefRejectReason::FetchFirst
    } else if s.contains_str("non-fast-forward") || s.contains_str("non-fast forward") {
        RefRejectReason::NonFastForward
    } else if s.contains_str("force") {
        RefRejectReason::NeedsForce
    } else if s.contains_str("already exists") || s.contains_str("exists") {
        RefRejectReason::AlreadyExists
    } else {
        RefRejectReason::Other
    }
}

/// Parse a v1 (or the v1-subset of a v2) report-status from already-split pkt-line payloads.
///
/// `lines` are the payloads between the request and the terminating flush-pkt (trailing LFs are
/// tolerated). `sent` is the command list, used to correlate reported names and to detect a missing
/// per-ref status. Returns the unpack status and one [`RefUpdateStatus`] per reported ref.
#[allow(dead_code)] // consumed by both reader twins (blocking_io + async_io); allow covers the push-only (no client feature) build
pub(crate) fn parse_report(
    lines: &[BString],
    sent: &[RefUpdate],
) -> Result<(UnpackStatus, Vec<RefUpdateStatus>), Error> {
    let mut iter = lines.iter();
    let first = iter.next().ok_or(Error::MissingUnpackStatus)?;
    let unpack = {
        let payload = trimmed(first);
        let rest = payload.strip_prefix(b"unpack ").ok_or(Error::MissingUnpackStatus)?;
        if rest == b"ok" {
            UnpackStatus::Ok
        } else {
            UnpackStatus::Failed(rest.into())
        }
    };

    let mut statuses: Vec<RefUpdateStatus> = Vec::new();
    let mut last_ok: Option<usize> = None;
    for line in iter {
        let payload = trimmed(line);
        if let Some(rest) = payload.strip_prefix(b"ok ") {
            statuses.push(RefUpdateStatus::Ok {
                name: rest.into(),
                details: None,
            });
            last_ok = Some(statuses.len() - 1);
        } else if let Some(rest) = payload.strip_prefix(b"ng ") {
            let (name, reason) = split_once_space(rest);
            statuses.push(RefUpdateStatus::Rejected {
                name: name.into(),
                reason: reason.into(),
                class: classify(reason.as_bstr()),
            });
            last_ok = None;
        } else if let Some(rest) = payload.strip_prefix(b"option ") {
            // report-status-v2 telemetry — attach to the most recent `ok`, tolerate otherwise.
            if let Some(idx) = last_ok
                && let RefUpdateStatus::Ok { details, .. } = &mut statuses[idx]
            {
                apply_option(details.get_or_insert_with(RefUpdateDetails::default), rest);
            }
        } else {
            // Unknown/trailing lines are tolerated for forward-compatibility (git's lenient client).
        }
    }

    // Correlate: every sent command must have a reported status, and every reported name must match
    // a sent command. Either mismatch is Error::MissingRefStatus (spec §3.5).
    for update in sent {
        let name = update.name().as_bstr();
        if !statuses.iter().any(|s| status_name(s) == name) {
            return Err(Error::MissingRefStatus { name: name.to_owned() });
        }
    }
    for status in &statuses {
        let name = status_name(status);
        if !sent.iter().any(|u| u.name().as_bstr() == name) {
            return Err(Error::MissingRefStatus { name: name.to_owned() });
        }
    }

    Ok((unpack, statuses))
}

/// Split a raw byte stream into pkt-line payloads, stopping at the first flush-pkt (§3.5, M3).
///
/// When `side-band-64k` is negotiated the server multiplexes the report onto band 1, so the reader
/// hands back the band-1 payload as an opaque byte stream — a sequence of report pkt-lines the reader
/// no longer splits for us (unlike the plain path, where each `readline_str` is one pkt-line). This
/// re-frames that stream: `<4-hex-len><payload>` repeated, a `0000` flush-pkt ends the report, and a
/// non-data length (`0001`/`0002`) is skipped. Payloads keep their trailing LF (the shared
/// `parse_report` trims it, exactly as on the plain path).
#[allow(dead_code)] // consumed by the sideband reader twins (blocking_io + async_io)
pub(crate) fn split_report_pkt_lines(buf: &[u8]) -> Result<Vec<BString>, Error> {
    let mut lines = Vec::new();
    let mut pos = 0usize;
    let mut terminated = false;
    while pos + 4 <= buf.len() {
        let len = parse_hex4(&buf[pos..pos + 4]).ok_or_else(|| Error::Malformed {
            line: buf[pos..pos + 4].into(),
        })?;
        if len == 0 {
            terminated = true;
            break; // flush-pkt terminates the report
        }
        if len < 4 {
            pos += 4; // delimiter / response-end special pkt — not part of the report
            continue;
        }
        if pos + len > buf.len() {
            return Err(Error::Malformed {
                line: buf[pos..].into(),
            });
        }
        lines.push(buf[pos + 4..pos + len].into());
        pos += len;
    }
    // 1-3 trailing bytes with no terminating flush-pkt = a truncated band-1 stream; surface it as
    // Malformed instead of silently shortening the report (review: glm LOW x2).
    if !terminated && pos < buf.len() {
        return Err(Error::Malformed {
            line: buf[pos..].into(),
        });
    }
    Ok(lines)
}

#[allow(dead_code)] // consumed by split_report_pkt_lines (sideband path only)
fn parse_hex4(bytes: &[u8]) -> Option<usize> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
}

#[allow(dead_code)] // consumed by both reader twins (blocking_io + async_io); allow covers the push-only (no client feature) build
fn status_name(status: &RefUpdateStatus) -> &BStr {
    match status {
        RefUpdateStatus::Ok { name, .. } | RefUpdateStatus::Rejected { name, .. } => name.as_bstr(),
    }
}

/// Strip a single trailing `\n` (and `\r`) that report-status lines carry.
#[allow(dead_code)] // consumed by both reader twins (blocking_io + async_io); allow covers the push-only (no client feature) build
fn trimmed(line: &BString) -> &[u8] {
    let mut s = line.as_slice();
    if let Some(stripped) = s.strip_suffix(b"\n") {
        s = stripped;
    }
    if let Some(stripped) = s.strip_suffix(b"\r") {
        s = stripped;
    }
    s
}

#[allow(dead_code)] // consumed by both reader twins (blocking_io + async_io); allow covers the push-only (no client feature) build
fn split_once_space(payload: &[u8]) -> (&[u8], &[u8]) {
    match payload.iter().position(|b| *b == b' ') {
        Some(pos) => (&payload[..pos], &payload[pos + 1..]),
        None => (payload, &[]),
    }
}

// `rest` is already trailing-LF-trimmed by `trimmed()` in the caller, so the oid bytes need no
// further stripping.
#[allow(dead_code)] // consumed by both reader twins (blocking_io + async_io); allow covers the push-only (no client feature) build
fn apply_option(details: &mut RefUpdateDetails, rest: &[u8]) {
    let rest = rest.as_bstr();
    if let Some(oid) = rest.strip_prefix(b"old-oid ") {
        details.old_oid = ObjectId::from_hex(oid).ok();
    } else if let Some(oid) = rest.strip_prefix(b"new-oid ") {
        details.new_oid = ObjectId::from_hex(oid).ok();
    } else if rest.starts_with(b"forced-update") {
        details.forced_update = true;
    }
    // `option refname <ref>` is informational; we keep the verbatim name already parsed above.
}
