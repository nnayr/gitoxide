//! The result vocabulary of the push tracking-ref bookkeeping (`gpx09` / design `P9`): the per-ref
//! [`Mode`], the [`Update`] that pairs a mode with its (optional) tracking-ref [`RefEdit`], and the
//! [`Outcome`](crate::remote::push::refs::update::Outcome) the whole `update` pass returns.
//!
//! The push twin of [`fetch::refs::update`](crate::remote::fetch::refs::update), deliberately **not**
//! reusing fetch's `Mode`/`Update` so the push surface never names a `fetch` result type — the same
//! stance as the twin [`plan::Verdict`](crate::remote::push::Verdict) and the twin push errors. It is a
//! *shrunken* analogue: the only local refs push edits are the remote-tracking refs
//! (`refs/remotes/<remote>/*`), so [`Outcome::edits`](crate::remote::push::refs::update::Outcome::edits) holds tracking-ref edits only (05-outcome §Verdict).

use crate::bstr::BString;

use super::super::plan;

/// The disposition of one plan [`Mapping`](super::super::plan::Mapping) after the push — a left-join
/// of its local pre-verdict with the server's per-ref report (design amendment S1).
///
/// Every mapping in the plan gets exactly one `Mode`: a *local pre-verdict* mapping (never sent) keeps
/// its plan verdict; a *sent* mapping is resolved from the server's `ok`/`ng` line and, for an
/// accepted branch update, whether a remote-tracking ref was moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    // ── local pre-verdicts (decided by gpx05's plan, before any wire byte) ──────────────────────
    /// The advertised value already equalled the new value; nothing was sent
    /// ([`Verdict::UpToDate`](super::super::plan::Verdict::UpToDate)).
    UpToDate,
    /// The mapping was refused locally and never sent — carries the exact plan
    /// [`Verdict`](super::super::plan::Verdict) (`RejectedNonFastForward`/`RejectedAlreadyExists`/
    /// `RejectedFetchFirst`/`RejectedNeedsForce`). The design's illustrative `Mode` split this into
    /// `RejectedNonFastForwardLocal`/`RejectedLeaseStaleLocal`; we carry the verdict verbatim instead,
    /// losslessly (a *stale lease* is a prepare-time abort, so it never reaches bookkeeping as a ride-along).
    RejectedLocal(plan::Verdict),
    /// The mapping was sendable but the push was a dry-run, so no wire byte was sent and no server
    /// verdict exists. No tracking ref was touched.
    DryRun,

    // ── server verdicts (from report-status), left-joined by the M5 verbatim-name rule ──────────
    /// The server applied the update and **no** local tracking-ref edit was made for a reason that is
    /// not a per-ref [`SkipReason`]: either the bookkeeping was globally **suppressed** (an `unpack`
    /// failure, or an atomic rollback where a single `ng` reverts the whole push), or an accepted
    /// *delete* found no tracking ref to remove. The umbrella "applied, nothing further locally".
    Ok,
    /// The server applied the update **and** we moved (or removed, for a delete) the corresponding
    /// `refs/remotes/<remote>/<branch>` tracking ref. The [`Update::edit_index`] points at the edit.
    TrackingRefUpdated,
    /// The server applied the update, but no tracking ref was moved — see [`SkipReason`].
    TrackingRefSkipped(SkipReason),
    /// The server **refused** the update (`ng <ref> <reason>`). `reason` is the verbatim server prose;
    /// `class` is the plumbing's advisory heuristic (never branch on it — 02-plumbing §2.2).
    RejectedByServer {
        /// The server's verbatim rejection prose.
        reason: BString,
        /// Advisory classification of `reason`, for telemetry only.
        class: gix_protocol::push::RefRejectReason,
    },
    /// Defensive (design amendment S1): the mapping WAS sent but the report carried **no** matching
    /// status. The plumbing's `parse_report` guarantees a bijective report, so this should not happen;
    /// we surface it rather than panic (e.g. a truncated report under an atomic rollback).
    CorrelationGap,
}

/// Why an accepted push did **not** move a remote-tracking ref (the `Ok`-but-no-edit reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The pushed destination is not under `refs/heads/*`; v1 only maintains branch tracking refs
    /// (05-outcome Q5). Tags and other refs get no tracking ref.
    NotABranch,
    /// The destination is a branch, but no two-sided fetch spec reverse-maps it to a tracking ref
    /// (e.g. an anonymous `remote_at(url)` with no configured fetch specs — the attached-only /
    /// detached limitation, design amendment S7).
    NoMatchingFetchSpec,
    /// The destination reverse-maps to a tracking ref that already exists **symbolically**; we refuse
    /// to overwrite a symref with a direct object id.
    SymbolicTrackingRef,
}

/// Information about the disposition of a single reference after a push, corresponding to the
/// [`Mapping`](super::super::plan::Mapping) at the same index in [`PlannedUpdates::mappings`](super::super::plan::PlannedUpdates::mappings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// How the reference fared.
    pub mode: Mode,
    /// The index into [`Outcome::edits`] of the tracking-ref edit created for this mapping, or `None`
    /// when no local ref was touched (every mode other than [`Mode::TrackingRefUpdated`]).
    pub edit_index: Option<usize>,
}

impl From<Mode> for Update {
    fn from(mode: Mode) -> Self {
        Update { mode, edit_index: None }
    }
}

/// The outcome of the push tracking-ref bookkeeping — the tracking-ref edits that were applied (empty
/// on dry-run / delete-only / a non-branch push) plus one [`Update`] per plan mapping, in plan order.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// All edits performed against the local `refs/remotes/<remote>/*` tracking refs.
    pub edits: Vec<gix_ref::transaction::RefEdit>,
    /// One entry per [`Mapping`](super::super::plan::Mapping), in plan order; `updates[i]` describes
    /// `mappings[i]`.
    pub updates: Vec<Update>,
}

mod error {
    /// The error returned when writing local tracking refs after a push.
    #[derive(Debug, thiserror::Error)]
    #[allow(missing_docs)]
    pub enum Error {
        #[error("Failed to update the local tracking references to match the pushed refs")]
        EditReferences(#[from] crate::reference::edit::Error),
        #[error("Failed to read a local tracking reference while bookkeeping the push")]
        FindReference(#[from] crate::reference::find::Error),
        #[error("A tracking ref reverse-mapped from a pushed destination had an invalid name")]
        InvalidRefName(#[from] gix_validate::reference::name::Error),
    }
}
pub use error::Error;
