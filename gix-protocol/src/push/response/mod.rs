//! The report-status parser (plan §3.5).
//!
//! The meaty logic is [`parse_report`], a pure function over already-split pkt-line payloads — so it
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
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("the report-status did not begin with an 'unpack' line")]
    MissingUnpackStatus,
    #[error("could not parse the report-status line {line:?}")]
    Malformed { line: BString },
    #[error("the per-ref status for {name:?} is missing, or a status was reported for a ref that was never sent")]
    MissingRefStatus { name: BString },
    #[error("an I/O error occurred while reading the report-status")]
    Io(#[from] std::io::Error),
}

impl crate::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        false
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
#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 reader is blocking-only
pub(crate) fn parse_report(
    lines: &[BString],
    sent: &[RefUpdate],
) -> Result<(UnpackStatus, Vec<RefUpdateStatus>), Error> {
    let mut iter = lines.iter();
    let first = iter.next().ok_or(Error::MissingUnpackStatus)?;
    let unpack = {
        let payload = trimmed(first);
        let rest = payload
            .strip_prefix(b"unpack ")
            .ok_or(Error::MissingUnpackStatus)?;
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
            if let Some(idx) = last_ok {
                if let RefUpdateStatus::Ok { details, .. } = &mut statuses[idx] {
                    apply_option(details.get_or_insert_with(RefUpdateDetails::default), rest);
                }
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
            return Err(Error::MissingRefStatus {
                name: name.to_owned(),
            });
        }
    }
    for status in &statuses {
        let name = status_name(status);
        if !sent.iter().any(|u| u.name().as_bstr() == name) {
            return Err(Error::MissingRefStatus {
                name: name.to_owned(),
            });
        }
    }

    Ok((unpack, statuses))
}

#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 reader is blocking-only
fn status_name(status: &RefUpdateStatus) -> &BStr {
    match status {
        RefUpdateStatus::Ok { name, .. } | RefUpdateStatus::Rejected { name, .. } => name.as_bstr(),
    }
}

/// Strip a single trailing `\n` (and `\r`) that report-status lines carry.
#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 reader is blocking-only
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

#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 reader is blocking-only
fn split_once_space(payload: &[u8]) -> (&[u8], &[u8]) {
    match payload.iter().position(|b| *b == b' ') {
        Some(pos) => (&payload[..pos], &payload[pos + 1..]),
        None => (payload, &[]),
    }
}

// `rest` is already trailing-LF-trimmed by `trimmed()` in the caller, so the oid bytes need no
// further stripping.
#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 reader is blocking-only
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
