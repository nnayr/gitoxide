//! The public types of the push module (plan §3.2).
//!
//! [`RefUpdate`] is a three-variant enum whose lease lives in the variant: the 3-way split removes
//! the structurally ambiguous both-zero *variant* git rejects (there is no "create-or-delete" shape
//! to represent), and the wire name is a validated [`gix_ref::FullName`] that cannot smuggle a NUL
//! or space into the `command NUL caps` framing (§3.4). A null [`gix_hash::ObjectId`] in a slot
//! (e.g. `Create { new: null }`) is a *caller* error the type does not catch — the encoder trips a
//! debug assert on it (command/mod.rs). The `unpack` line is modelled as [`UnpackStatus`] **data**,
//! not a `Result` channel that invites `?`/`is_err` — the caller decides what is an error (§2).

use bstr::BString;
use gix_hash::ObjectId;
use gix_ref::FullName;

/// Reuse [`fetch::Context`](crate::fetch::Context) — it already carries exactly the fields push
/// needs (the mutable [`Handshake`](crate::Handshake) from `handshake(_, Service::ReceivePack, _)`,
/// the transport, the user agent and the packetline trace flag). Do **not** twin it (F9).
pub use crate::fetch::Context;

/// One ref update command. The force-with-lease lease (§2) lives inside the variant.
///
/// This reuses the [`PreviousValue`](gix_ref::transaction::PreviousValue) lease vocabulary of
/// `gix_ref::transaction` (`MustNotExist` for create, `MustExistAndMatch` for update/delete — which
/// the caller's file:// CAS already uses), but it does **not** mirror
/// [`gix_ref::transaction::Change`]'s shape: `Change` folds create into `Update { expected:
/// MustNotExist }` and has no `Create` variant. Push splits create into its own variant so each
/// encoder arm statically knows which slot is the zero-id (§3.4).
///
/// The three legal wire edits are the three variants; the structurally ambiguous both-zero *variant*
/// is unrepresentable (a null oid in a slot is a caller error, caught by a debug assert in the
/// encoder, not by the type). The name is a [`FullName`], so it cannot contain a NUL or a space that
/// would corrupt the `command NUL capability-list` framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefUpdate {
    /// The ref does not exist yet; create it at `new` (a zero-id old-oid on the wire).
    Create {
        /// The fully-qualified name to create, e.g. `refs/rolfdb/data`.
        name: FullName,
        /// The object id the new ref should point at.
        new: ObjectId,
    },
    /// Move `name` from `expected_old` (the lease, §2) to `new`.
    Update {
        /// The fully-qualified name to update.
        name: FullName,
        /// The value the server must currently advertise for this ref (the lease).
        expected_old: ObjectId,
        /// The object id to move the ref to.
        new: ObjectId,
    },
    /// Delete `name`, leasing its current value `expected_old` (a zero-id new-oid on the wire).
    Delete {
        /// The fully-qualified name to delete.
        name: FullName,
        /// The value the server must currently advertise for this ref (the lease).
        expected_old: ObjectId,
    },
}

impl RefUpdate {
    /// The fully-qualified name this command targets.
    pub fn name(&self) -> &FullName {
        match self {
            RefUpdate::Create { name, .. } | RefUpdate::Update { name, .. } | RefUpdate::Delete { name, .. } => name,
        }
    }

    /// `true` for a delete command — the one shape that sends **no** pack (§1.4).
    pub fn is_delete(&self) -> bool {
        matches!(self, RefUpdate::Delete { .. })
    }

    /// Positive form of `!is_delete()`: a create/update contributes objects to the pack (§3.3, §3.6).
    pub fn sends_pack_objects(&self) -> bool {
        !self.is_delete()
    }

    /// A non-null object id present in this command, used to infer the local ODB hash kind (§3.4, F3).
    #[allow(dead_code)] // consumed by the M3 async orchestrator; the M1 orchestrator is blocking-only
    pub(crate) fn representative_oid(&self) -> &ObjectId {
        match self {
            RefUpdate::Create { new, .. } | RefUpdate::Update { new, .. } => new,
            RefUpdate::Delete { expected_old, .. } => expected_old,
        }
    }
}

/// The `atomic` capability policy (§2.3). Named `Atomicity` (not `Atomic`) so it does not read as a
/// bare flag. rolfdb's default is `Disabled` (a single-ref update is already atomic); the module
/// still implements `WhenAdvertised`/`Required` for upstream generality.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Atomicity {
    /// Never request `atomic`.
    #[default]
    Disabled,
    /// Request `atomic` only when the server advertised it.
    WhenAdvertised,
    /// Require `atomic`; refuse with [`Error::MissingServerFeature`](crate::push::Error) if unadvertised.
    Required,
}

/// Options controlling one [`push()`](crate::push::push) invocation.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The `atomic` capability policy (§2.3). rolfdb: `Disabled`.
    pub atomic: Atomicity,
    /// Prefer `report-status-v2` when the server advertises it. M1 parses the v1 subset either way.
    pub report_status_v2: bool,
    /// Push-options to send after the command-list flush (§1.3, M3). Each becomes one pkt-line,
    /// terminated by the block's own flush before the pack. Requires the server to advertise
    /// `push-options`: a non-empty value against an unadvertised cap is refused with
    /// [`Error::MissingServerFeature`](crate::push::Error), never silently dropped (F5). Empty (the
    /// default) sends no block and echoes no cap, so the push is byte-identical to one without it.
    pub push_options: Vec<BString>,
    /// Echo `quiet` when the server advertises it.
    pub quiet: bool,
    /// Request `side-band-64k` for the report (§3.5, M3). When set **and** advertised, the report is
    /// band-multiplexed (band 1 = report, band 2 = progress, band 3 = remote error) and demuxed by
    /// the response reader. Opting in against an unadvertised cap is refused with
    /// [`Error::MissingServerFeature`](crate::push::Error). `false` (the default) keeps the report as
    /// plain pkt-lines, byte-identical to a push that never negotiates it.
    pub sideband: bool,
}

/// The return **value** of [`push()`](crate::push::push); the caller decides what is an error (§2).
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The server's `unpack ok|<err>` line, as data — not an error channel (F10).
    pub unpack_status: UnpackStatus,
    /// One status per command sent, in the order the server reported them.
    pub refs: Vec<RefUpdateStatus>,
    /// Vestigial for push: receive-pack is always V1 (§1.6), so this is a constant echoed from
    /// [`Handshake::server_protocol_version`](crate::Handshake). Kept for trace; never branched on.
    pub server_protocol_version: gix_transport::Protocol,
}

/// The `unpack` line of report-status, modelled as data (F10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnpackStatus {
    /// `unpack ok` — the server accepted the pack.
    Ok,
    /// `unpack <err>` — the server could not apply the pack (e.g. `index-pack failed`).
    Failed(BString),
}

/// The per-ref outcome of a single command. The reported name is kept as a **verbatim** [`BString`],
/// matching gitoxide's own [`handshake::Ref`](crate::handshake::Ref) which stores server-sent names
/// as `BString` (parse-don't-validate applies to the *outbound* [`RefUpdate::name`], not to inbound
/// server bytes). Correlate to the sent command by `sent.name().as_bstr() == name` (M5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefUpdateStatus {
    /// The server applied the update (`ok <ref>`). `details` carries any report-status-v2 telemetry.
    Ok {
        /// The verbatim server-echoed ref name.
        name: BString,
        /// Report-status-v2 `option` telemetry, if any; `None` means "no extra detail reported".
        details: Option<crate::push::response::RefUpdateDetails>,
    },
    /// The server refused the update (`ng <ref> <reason>`). `reason` is the verbatim prose (never
    /// parsed for control flow, §2.2); `class` is an advisory heuristic classification.
    Rejected {
        /// The verbatim server-echoed ref name.
        name: BString,
        /// The server's verbatim rejection prose.
        reason: BString,
        /// Advisory classification of `reason` — for telemetry only, never branch on it (§2.2).
        class: RefRejectReason,
    },
}

/// Advisory telemetry classification of an `ng` reason (§2.2). Never branch on it for control flow:
/// [`response::classify`](crate::push::response::classify) is a best-effort heuristic over server
/// prose that the spec declares unspecified and host/version-dependent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefRejectReason {
    /// "stale info" — the lease did not match the server's current value.
    StaleInfo,
    /// "fetch first" — the ref moved; fetch before pushing.
    FetchFirst,
    /// "non-fast-forward" — a non-fast-forward update was refused.
    NonFastForward,
    /// The update needs `--force`.
    NeedsForce,
    /// The ref already exists (a create against an existing ref).
    AlreadyExists,
    /// Anything else — prose that did not match a known heuristic.
    Other,
}
