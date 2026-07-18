//! The command-list encoder and capability selection (plan §3.4).
//!
//! Pure capability selection ([`select_capabilities`], [`SelectedCaps::to_wire_bytes`]) lives here,
//! with no I/O. The I/O `write_command_list` is a `maybe_async`-style twin (F2): under
//! `blocking-client` the [`RequestWriter`](crate::transport::client::blocking_io::request::RequestWriter)
//! write side is [`std::io::Write`], under `async-client` it is `futures_io::AsyncWrite`, so the two
//! cannot share one sync signature. §3.3 calls the twin from the orchestrator.

use std::borrow::Cow;

use bstr::BString;
use gix_hash::Kind;

use crate::push::{Atomicity, Error, Options, RefUpdate};

#[cfg(feature = "blocking-client")]
mod blocking_io;
#[cfg(feature = "blocking-client")]
pub(crate) use blocking_io::write_command_list;

#[cfg(feature = "async-client")]
mod async_io;
#[cfg(feature = "async-client")]
#[allow(unused_imports)]
pub(crate) use async_io::write_command_list;

/// The client's selection from the advertised capabilities, plus the negotiated object hash.
///
/// The capabilities are stored **wire-ordered**; [`to_wire_bytes`](Self::to_wire_bytes) space-joins
/// them for the NUL-suffix of the first command line.
pub(crate) struct SelectedCaps {
    /// The negotiated object hash (§3.4, F3) — fixes the zero-id hex width (SHA-1: 40, SHA-256: 64).
    pub(crate) object_hash: Kind,
    /// The capabilities to echo, in wire order.
    features: Vec<BString>,
}

impl SelectedCaps {
    /// The space-joined capability list for the first command line's NUL-suffix.
    pub(crate) fn to_wire_bytes(&self) -> BString {
        let mut out = BString::default();
        for (i, feature) in self.features.iter().enumerate() {
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(feature);
        }
        out
    }
}

/// Select the capabilities to echo: the intersection of what we want with what the server
/// advertised (plan §3.4). Errors early — before any bytes hit the wire — on an impossible request.
///
/// M1 echo-set: `report-status` (required), `object-format=<algo>` (matching the local kind, when
/// advertised), `ofs-delta` (when advertised), `delete-refs` (iff a delete is present), `quiet`
/// (opt-in), `atomic` (opt-in), and `agent=<ua>`. Never echoes `side-band-64k`, `push-options`, or
/// `push-cert` in M1.
#[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 orchestrator is blocking-only
pub(crate) fn select_capabilities(
    caps: &crate::transport::client::Capabilities,
    updates: &[RefUpdate],
    opts: &Options,
    user_agent: (&'static str, Option<Cow<'static, str>>),
) -> Result<SelectedCaps, Error> {
    // Hash-kind precheck (F3): the negotiated object-format MUST equal the local ODB kind, inferred
    // from the oids the caller passed. Refuse an SHA-256 remote against an SHA-1 ODB cleanly, before
    // any bytes are sent — exactly as git's send-pack die()s on a hash-algorithm mismatch.
    let local = updates
        .first()
        .map_or(Kind::Sha1, |u| u.representative_oid().kind());
    let object_hash = match caps.capability("object-format").and_then(|c| c.value()) {
        None => local,
        Some(advertised) if advertised == local.to_string().as_bytes() => local,
        Some(advertised) => {
            return Err(Error::HashKindMismatch {
                local,
                server: advertised.to_owned(),
            });
        }
    };

    let mut features: Vec<BString> = Vec::new();

    // report-status is required — without it the server sends nothing back and we cannot detect a
    // ref-level rejection (the NotFastForward contract, §2).
    let has_v1 = caps.contains("report-status");
    let has_v2 = caps.contains("report-status-v2");
    if opts.report_status_v2 && has_v2 {
        features.push("report-status-v2".into());
    } else if has_v1 {
        features.push("report-status".into());
    } else if has_v2 {
        features.push("report-status-v2".into());
    } else {
        return Err(Error::MissingServerFeature {
            feature: "report-status",
            description: "the server must advertise report-status or report-status-v2 so push can detect rejections",
        });
    }

    if updates.iter().any(RefUpdate::is_delete) {
        if !caps.contains("delete-refs") {
            return Err(Error::MissingServerFeature {
                feature: "delete-refs",
                description: "a delete command requires the server to advertise delete-refs",
            });
        }
        features.push("delete-refs".into());
    }

    if caps.contains("ofs-delta") {
        features.push("ofs-delta".into());
    }

    if opts.quiet && caps.contains("quiet") {
        features.push("quiet".into());
    }

    match opts.atomic {
        Atomicity::Disabled => {}
        Atomicity::WhenAdvertised => {
            if caps.contains("atomic") {
                features.push("atomic".into());
            }
        }
        Atomicity::Required => {
            if !caps.contains("atomic") {
                return Err(Error::MissingServerFeature {
                    feature: "atomic",
                    description: "Atomicity::Required was requested but the server did not advertise atomic",
                });
            }
            features.push("atomic".into());
        }
    }

    // push-options are an M3 wire feature; M1 refuses a non-empty request rather than silently
    // dropping it (F5). The no-cap case is the primary tested law.
    if !opts.push_options.is_empty() {
        return Err(Error::MissingServerFeature {
            feature: "push-options",
            description: "push-options are not implemented before M3; leave Options::push_options empty",
        });
    }

    // side-band demux of the report is an M3 feature; refuse an opt-in rather than silently ignoring
    // it (parity with push_options above), keeping Options::sideband a §3.2-named field with an
    // honest failure mode.
    if opts.sideband {
        return Err(Error::MissingServerFeature {
            feature: "side-band-64k",
            description: "side-band demux is not implemented before M3; leave Options::sideband false",
        });
    }

    if caps.contains("object-format") {
        features.push(format!("object-format={object_hash}").into());
    }

    if let Some(version) = user_agent.1 {
        features.push(format!("{}={}", user_agent.0, version).into());
    }

    Ok(SelectedCaps {
        object_hash,
        features,
    })
}

/// Format a single command triple (`<old> <new> <name>`) into `line`, ready for a pkt-line.
///
/// Matches the [`RefUpdate`] variant so each arm statically knows which slot is the zero-id — no
/// `Option` → zero mapping, no both-none branch to rule out (§3.4). The name is a [`FullName`] so it
/// cannot corrupt the framing. Shared by both I/O twins.
///
/// [`FullName`]: gix_ref::FullName
pub(crate) fn command_line(update: &RefUpdate, zero: &str) -> Vec<u8> {
    use bstr::ByteSlice;
    // A null oid in a non-fixed slot (e.g. `Create { new: null }`) is a caller error the type does
    // not catch — the 3-way split only removes the structurally ambiguous both-zero shape. Trip it in
    // debug so a null slip surfaces in tests rather than as a silent zero-id on the wire.
    let (old, new) = match update {
        RefUpdate::Create { new, .. } => {
            debug_assert!(!new.is_null(), "null object id in a Create command");
            (zero.to_owned(), new.to_hex().to_string())
        }
        RefUpdate::Update {
            expected_old, new, ..
        } => {
            debug_assert!(!expected_old.is_null(), "null object id in an Update command (expected_old)");
            debug_assert!(!new.is_null(), "null object id in an Update command (new)");
            (expected_old.to_hex().to_string(), new.to_hex().to_string())
        }
        RefUpdate::Delete { expected_old, .. } => {
            debug_assert!(!expected_old.is_null(), "null object id in a Delete command");
            (expected_old.to_hex().to_string(), zero.to_owned())
        }
    };
    let mut line = format!("{old} {new} ").into_bytes();
    line.extend_from_slice(update.name().as_bstr().as_bytes());
    line
}
