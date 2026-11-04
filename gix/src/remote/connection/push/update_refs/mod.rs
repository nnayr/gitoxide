//! Local tracking-ref bookkeeping after a push (`gpx09` / design `P9`) — the send-direction twin of
//! [`fetch::refs`](crate::remote::fetch::refs), wired with `#[path]` and re-exported as
//! [`remote::push::refs`](crate::remote::push::refs) exactly like fetch.
//!
//! After a successful [`send`](crate::remote::push::Prepare::send), `update` correlates the server's
//! per-ref report back to the plan and — for every accepted branch update — moves (or, on a delete,
//! removes) the corresponding `refs/remotes/<remote>/<branch>` tracking ref through one `gix_ref`
//! transaction, writing an `"update by push"` reflog line via the reused fetch
//! [`RefLogMessage`](crate::remote::fetch::RefLogMessage).
//!
//! # Where push is SIMPLER than fetch (05-outcome §"simpler than fetch")
//! The only local refs push edits are the tracking refs, so there is no fast-forward ancestry walk
//! (the ff-check already happened locally in gpx05's plan), no worktree-checkout guard, no symref
//! creation, no unborn/tag special-casing, and no `WritePackedRefs` beyond the default `DeletionsOnly`.
//!
//! # Correlation is PLAN-driven with a left-join (design amendment S1)
//! `update` iterates **every** plan [`Mapping`](crate::remote::push::Mapping) — including the locally
//! rejected ones that were never sent — and left-joins the server [`RefUpdateStatus`](gix_protocol::push::RefUpdateStatus) by the M5
//! verbatim-name rule. A mapping with a local pre-verdict keeps its verdict as its [`Mode`](crate::remote::push::refs::Mode); a sent
//! mapping resolves from its `ok`/`ng` line; a sent mapping with *no* status is a defensive
//! [`Mode::CorrelationGap`](crate::remote::push::refs::Mode::CorrelationGap) rather than a panic.

#![allow(clippy::result_large_err)]

use gix_protocol::push::{Outcome as Report, RefUpdateStatus};
use gix_ref::{
    FullName, FullNameRef, Target,
    transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog},
};

use crate::Repository;
use crate::bstr::{BStr, ByteSlice};
use crate::remote::fetch::RefLogMessage;

use super::plan::{Mapping, PlannedUpdates, Verdict};

///
pub mod update;
pub use update::{Mode, SkipReason, Update};

// The suite drives the blocking-only `send()` (integration) and the (blocking-consumed) `update`;
// gate it like send_pack's own tests so the async-only check stays warning-clean.
#[cfg(all(test, feature = "blocking-network-client"))]
mod tests;

/// Correlate the server's push `report` back to `plan` (plan-driven left-join, design amendment S1)
/// and, for every accepted branch update, move the corresponding `refs/remotes/<remote>/*` tracking
/// ref — producing an [`Outcome`](update::Outcome) with one [`Update`] per plan mapping in plan order.
///
/// * `message` composes the reflog line (default action `"push"`, context `"update by push"`).
/// * `report` is the plumbing push report, or `None` for a wire-silent send (dry-run / nothing-to-push);
///   in that case sendable mappings report [`Mode::DryRun`] and no ref is touched.
/// * `fetch_specs` are the remote's **fetch** refspecs — the reverse-map that turns a pushed
///   destination into its tracking ref (Q5, first-match).
/// * `atomic_active` is `true` iff the `atomic` capability was actually negotiated (design amendment
///   B15); with it, a single `ng` rolls back the whole push, so **all** tracking edits are suppressed.
/// * `dry_run` suppresses the transaction entirely (no ref is written).
///
/// Reference `ng`s are **data**, never an error (05-outcome §Verdict); this returns `Err` only when the
/// local ref transaction itself fails. It deliberately ignores `should_interrupt` — once the server has
/// mutated, we never strand a tracking ref (05-outcome §Gates).
#[cfg_attr(not(feature = "blocking-network-client"), allow(dead_code))]
pub(crate) fn update(
    repo: &Repository,
    message: RefLogMessage,
    plan: &PlannedUpdates,
    report: Option<&Report>,
    fetch_specs: &[gix_refspec::RefSpec],
    atomic_active: bool,
    dry_run: bool,
) -> Result<update::Outcome, update::Error> {
    let _span = gix_trace::detail!("push::update_refs()", mappings = plan.mappings.len());
    let object_hash = repo.object_hash();

    // Global suppression gate (05-outcome §Gates + amendment B15): if the server applied *nothing* —
    // an `unpack` failure, or an atomic rollback where any single `ng` reverts the whole push — we must
    // not move any tracking ref, or a local mirror would diverge from a server that did not change.
    let suppressed = report.is_some_and(|r| {
        let unpack_failed = matches!(r.unpack_status, gix_protocol::push::UnpackStatus::Failed(_));
        let any_ng = r.refs.iter().any(|s| matches!(s, RefUpdateStatus::Rejected { .. }));
        unpack_failed || (atomic_active && any_ng)
    });

    let mut edits: Vec<RefEdit> = Vec::new();
    let mut updates: Vec<Update> = Vec::with_capacity(plan.mappings.len());

    for mapping in &plan.mappings {
        let (mode, edit): (Mode, Option<RefEdit>) = if !mapping.verdict.is_sendable() {
            // Local pre-verdict — never sent, so no server status is expected (S1 left arm).
            let mode = match mapping.verdict {
                Verdict::UpToDate => Mode::UpToDate,
                rejected => Mode::RejectedLocal(rejected),
            };
            (mode, None)
        } else if dry_run || report.is_none() {
            // Sendable, but the push was wire-silent (dry-run): no server verdict, no ref touched.
            (Mode::DryRun, None)
        } else {
            let report = report.expect("report present on the non-dry-run send path");
            match find_status(report, mapping.remote.as_ref()) {
                // Sent but unreported — should not happen given the plumbing's bijection; be defensive.
                None => (Mode::CorrelationGap, None),
                Some(RefUpdateStatus::Rejected { reason, class, .. }) => (
                    Mode::RejectedByServer {
                        reason: reason.clone(),
                        class: class.clone(),
                    },
                    None,
                ),
                // Applied, but bookkeeping globally suppressed: report Ok, touch no ref.
                Some(RefUpdateStatus::Ok { .. }) if suppressed => (Mode::Ok, None),
                Some(RefUpdateStatus::Ok { .. }) => {
                    tracking_ref_disposition(repo, mapping, fetch_specs, object_hash, &message)?
                }
            }
        };

        let edit_index = edit.as_ref().map(|_| edits.len());
        if let Some(edit) = edit {
            edits.push(edit);
        }
        updates.push(Update { mode, edit_index });
    }

    // Apply the tracking-ref edits in one transaction (default `PackedRefs::DeletionsOnly`, reflog on).
    // Dry-run writes nothing. `edit_references` fills each edit's previous value from storage and
    // returns them in input order, so the recorded `edit_index`es stay valid.
    let edits = if dry_run || edits.is_empty() {
        edits
    } else {
        repo.edit_references(edits)?
    };

    Ok(update::Outcome { edits, updates })
}

/// The verbatim name of a server per-ref status (M5), matched against the plan destination.
fn status_name(status: &RefUpdateStatus) -> &BStr {
    match status {
        RefUpdateStatus::Ok { name, .. } | RefUpdateStatus::Rejected { name, .. } => name.as_bstr(),
    }
}

/// Left-join lookup: the server status for `dst`, by the M5 verbatim-name rule (`sent.name() == name`).
fn find_status<'a>(report: &'a Report, dst: &FullNameRef) -> Option<&'a RefUpdateStatus> {
    report.refs.iter().find(|s| status_name(s) == dst.as_bstr())
}

/// Decide the tracking-ref disposition for an accepted (`ok`) push of `mapping`, returning its
/// [`Mode`] and the tracking-ref [`RefEdit`] to apply (if any). v1 maintains tracking refs for
/// `refs/heads/*` destinations only (Q5); the reverse-map is first-match over the remote's two-sided
/// fetch specs.
#[cfg_attr(not(feature = "blocking-network-client"), allow(dead_code))]
fn tracking_ref_disposition(
    repo: &Repository,
    mapping: &Mapping,
    fetch_specs: &[gix_refspec::RefSpec],
    object_hash: gix_hash::Kind,
    message: &RefLogMessage,
) -> Result<(Mode, Option<RefEdit>), update::Error> {
    let dst = mapping.remote.as_ref();
    // v1 scope (Q5): only branches acquire tracking refs.
    if !dst.as_bstr().starts_with(b"refs/heads/") {
        return Ok((Mode::TrackingRefSkipped(SkipReason::NotABranch), None));
    }
    let Some(tracking) = tracking_ref_name(fetch_specs, dst, object_hash) else {
        return Ok((Mode::TrackingRefSkipped(SkipReason::NoMatchingFetchSpec), None));
    };

    // Read the current tracking-ref state (store-level, mirroring the gpx07 plan adapter).
    let existing = repo
        .refs
        .try_find(tracking.as_ref())
        .map_err(|err| update::Error::FindReference(err.into()))?;
    if let Some(existing) = &existing {
        if matches!(existing.target, Target::Symbolic(_)) {
            // Refuse to overwrite a symbolic tracking ref with a direct object id.
            return Ok((Mode::TrackingRefSkipped(SkipReason::SymbolicTrackingRef), None));
        }
    }

    if mapping.local.is_none() {
        // A delete: remove the tracking ref iff it exists; otherwise there is nothing local to do.
        return Ok(match existing {
            Some(existing) => {
                let edit = RefEdit {
                    change: Change::Delete {
                        expected: PreviousValue::MustExistAndMatch(existing.target),
                        log: RefLog::AndReference,
                    },
                    name: tracking,
                    deref: false,
                };
                (Mode::TrackingRefUpdated, Some(edit))
            }
            None => (Mode::Ok, None),
        });
    }

    // A create/update: point the tracking ref at the newly-pushed value.
    let new = mapping.new.expect("an accepted non-delete push carries a new oid");
    let expected = match &existing {
        Some(existing) => PreviousValue::MustExistAndMatch(existing.target.clone()),
        None => PreviousValue::MustNotExist,
    };
    let edit = RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: message.compose("update by push"),
            },
            expected,
            new: Target::Object(new),
        },
        name: tracking,
        deref: false,
    };
    Ok((Mode::TrackingRefUpdated, Some(edit)))
}

/// Reverse-map a pushed destination `dst` (under `refs/heads/*`) through the remote's two-sided **fetch**
/// specs to its local tracking-ref name, first-match — byte-identical to `config::branch::matching_remote`
/// / `branch_remote_tracking_ref_name` (05-outcome amendment B12), re-stated here (a pure function over
/// the fetch specs) so the bookkeeping is self-contained and needs no `revision` feature (unlike the
/// gpx07 plan adapter's private twin). `None` when no two-sided fetch spec maps `dst`.
#[cfg_attr(not(feature = "blocking-network-client"), allow(dead_code))]
fn tracking_ref_name(
    fetch_specs: &[gix_refspec::RefSpec],
    dst: &FullNameRef,
    object_hash: gix_hash::Kind,
) -> Option<FullName> {
    let search = gix_refspec::MatchGroup {
        specs: fetch_specs
            .iter()
            .map(gix_refspec::RefSpec::to_ref)
            .filter(|spec| spec.source().is_some() && spec.destination().is_some())
            .collect(),
    };
    let null = object_hash.null();
    let out = search.match_lhs(std::iter::once(gix_refspec::match_group::Item {
        full_ref_name: dst.as_bstr(),
        target: &null,
        object: None,
    }));
    out.mappings
        .into_iter()
        .next()
        .and_then(|m| m.rhs)
        .and_then(|rhs| FullName::try_from(rhs.as_bstr().to_owned()).ok())
}
