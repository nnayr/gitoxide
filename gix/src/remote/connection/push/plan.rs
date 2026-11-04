//! The push plan (P5, bead `rolfdb-gpx05`) — refspec → command list + lease.
//!
//! This is the deepest porcelain unit and the send-direction analogue of fetch's
//! "resolve specs against the advertisement" step ([`ref_map.rs`](super::super::ref_map)). It turns
//! the configured push refspecs plus the receive-pack advertisement into a `Vec` of
//! [`gix_protocol::push::RefUpdate`] wire commands and the pack-walk **tips**, deciding a local
//! pre-verdict for every ref (mirroring C-git's `set_ref_status_for_push`).
//!
//! # Pure core + oracle seam
//! Everything lives in `plan_inner`, a **pure** function with **zero I/O**: all repository access
//! is injected as four `&mut dyn FnMut` oracles (`has_object`, `ancestry`, `resolve_rev`,
//! `tracking_ref_value`). That is what lets the whole edge-case catalog (E1–E36, below) run as
//! deterministic, fixture-free unit tests over `HashMap` oracles — the plan-side analogue of the Q7
//! "free-function core" for the pack driver, and the same discipline as
//! `fetch/update_refs/tests.rs`.
//!
//! The `plan()` **repo adapter** (wiring the oracles to a real [`Repository`](crate::Repository)) is
//! implemented here by **gpx07** (see [`plan`], the `mod adapter` block) and consumed by
//! `prepare_push` (gpx08). Its `resolve_rev`/`ancestry` oracles need `repo.rev_parse_single` /
//! `repo.merge_base`, both `#[cfg(feature = "revision")]` — a feature the
//! `blocking-network-client`/`async-network-client` gates this module rides do **not** enable — so
//! `plan()` is itself `#[cfg(feature = "revision")]` and the porcelain gate adds `revision`
//! explicitly. A network-client build without `revision` compiles the pure core but omits `plan()`.
//!
//! # The `match_lhs`-for-push gap (settled in the porcelain)
//! We reuse [`MatchGroup::match_lhs`](gix_refspec::MatchGroup::match_lhs) as the matching *engine*
//! (globs, partial names, object ids, negatives, dedup all work as-is once the items are **local**
//! refs) and layer a four-delta push post-pass on top (`§5` of `02-push-plan.md`): bare-`src` rhs,
//! rev-spec sources, delete/matching passes against the advertisement, and push-flavored destination
//! qualification replacing fetch's `validated()`. No `gix-refspec` fork.
//!
//! # Lease / force (Q2)
//! Three disentangled layers: (a) the wire **always** CAS-es `expected_old` = the advertised oid;
//! (b) a `+`-spec skips **only** the local fast-forward check (never the CAS); (c)
//! [`LeasePolicy::ForceWithLease`](crate::remote::push::LeasePolicy::ForceWithLease) with
//! [`Lease::TrackingRef`](crate::remote::push::Lease::TrackingRef)/[`Lease::Exact`](crate::remote::push::Lease::Exact)
//! is applied at plan time — a held lease upgrades an otherwise-rejected update to
//! [`Verdict::Forced`](crate::remote::push::Verdict::Forced), a violation is a prepare-time
//! [`Error::StaleLease`](crate::remote::push::plan::Error::StaleLease). `expected_old` is therefore
//! lease-independent (always the advertised oid), which is why the plan stays immutable under gpx07's
//! late lease builders.

#![allow(clippy::result_large_err)]
// SKELETON: the pure core (`plan_inner`), its input snapshots (`LocalRef`/`HeadState`/`Ancestry`) and
// the private helpers are consumed by the gpx07 `plan()` repo adapter (`mod adapter`) and exercised by
// the in-module `tests`; the public vocabulary is re-exported (and thus live) via the `remote::push`
// facade. The allow stays because the core is still (a) fully unreferenced in a network-client build
// *without* `revision` (where `plan()` is `#[cfg]`-ed out) and (b) reached only through `plan()`, which
// is itself scaffolding until gpx08's `pub prepare_push` roots the chain in a non-test `cargo check`.
// It lifts with gpx08.
#![allow(dead_code)]

use gix_hash::ObjectId;
use gix_protocol::handshake;
use gix_protocol::push::RefUpdate;
use gix_ref::FullName;

use crate::bstr::{BStr, BString, ByteSlice, ByteVec};

/// Which of the two refspec lists a mapping's spec came from. The push-local twin of
/// `gix_protocol::fetch::refmap::SpecIndex` (deliberately not reused so the push surface never names
/// a `fetch` type — the same stance as the twin `Mode` enums).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SpecIndex {
    /// Index into the *explicit* push refspecs (`remote.<name>.push` or the replaced set).
    ExplicitInRemote(usize),
    /// Index into [`PrepareOptions::extra_refspecs`](super::PrepareOptions::extra_refspecs).
    Implicit(usize),
}

impl SpecIndex {
    /// Recover the spec from the two lists this index refers to (mirror of the fetch twin).
    pub fn get<'a>(
        self,
        refspecs: &'a [gix_refspec::RefSpec],
        extra_refspecs: &'a [gix_refspec::RefSpec],
    ) -> Option<&'a gix_refspec::RefSpec> {
        match self {
            SpecIndex::ExplicitInRemote(i) => refspecs.get(i),
            SpecIndex::Implicit(i) => extra_refspecs.get(i),
        }
    }
}

/// The local source of one planned update — what the left-hand side of the push spec resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A local reference matched by name. `id` is the ref's direct target (for an annotated tag the
    /// tag object itself, never peeled — the wire pushes the ref value verbatim).
    Ref {
        /// The fully-qualified local name, e.g. `refs/heads/main` (never `HEAD`; a `HEAD` source is
        /// resolved to its referent during planning, or is [`Source::Detached`]).
        name: FullName,
        /// The object the local ref points to (what the remote ref will be set to).
        id: ObjectId,
    },
    /// The spec's left-hand side was an object id or a rev-spec (`<hex>:dst`, `HEAD~2:dst`); no local
    /// ref name is associated. Verified present in the local ODB.
    ObjectId(ObjectId),
    /// A detached `HEAD` used with an explicit destination (`HEAD:refs/heads/x`).
    Detached {
        /// The commit `HEAD` points at.
        id: ObjectId,
    },
}

impl Source {
    /// The object id this source contributes as the new remote value.
    pub fn id(&self) -> &gix_hash::oid {
        match self {
            Source::Ref { id, .. } | Source::ObjectId(id) | Source::Detached { id } => id,
        }
    }
}

/// The local pre-verdict for one mapping — decided entirely from local data plus the advertisement,
/// before any bytes are sent. Mirrors C-git's `set_ref_status_for_push` (`remote.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Remote ref absent (or advertised unborn): emits [`RefUpdate::Create`].
    ///
    /// Note (F11 hidden refs): a ref that exists server-side but is absent from the advertisement
    /// (e.g. under `transfer.hideRefs`) plans as `Create` with a zero old-oid; receive-pack's own
    /// old-oid check then rejects it as a per-ref `ng`, never a blind overwrite.
    Create,
    /// Advertised old is an ancestor of the new value: a plain [`RefUpdate::Update`].
    FastForward,
    /// Update allowed only because of `+`-force or a satisfied lease; the wire still CAS-es against
    /// the advertised value (Q2: stronger than C-git's default `--force`).
    Forced,
    /// `:dst` (or a matched delete-glob): emits [`RefUpdate::Delete`] leasing the advertised value.
    Delete,
    /// Advertised value already equals the new value; nothing to do (no command).
    UpToDate,
    /// Destination is an existing `refs/tags/*` ref and no force applies (C-git `REJECT_ALREADY_EXISTS`).
    RejectedAlreadyExists,
    /// The advertised old value is not present in the local ODB — ancestry cannot be proven; the user
    /// must fetch first (C-git `REJECT_FETCH_FIRST`).
    RejectedFetchFirst,
    /// Old or new is not a commit (e.g. moving a ref between tag objects) and no force applies
    /// (C-git `REJECT_NEEDS_FORCE`).
    RejectedNeedsForce,
    /// The update is a non-fast-forward and no force applies (C-git `REJECT_NON_FF`).
    RejectedNonFastForward,
}

impl Verdict {
    /// `true` if this verdict emits a wire command.
    pub fn is_sendable(&self) -> bool {
        matches!(
            self,
            Verdict::Create | Verdict::FastForward | Verdict::Forced | Verdict::Delete
        )
    }

    /// `true` for the `Rejected*` group (useful for "did anything get refused locally").
    pub fn is_rejected(&self) -> bool {
        matches!(
            self,
            Verdict::RejectedAlreadyExists
                | Verdict::RejectedFetchFirst
                | Verdict::RejectedNeedsForce
                | Verdict::RejectedNonFastForward
        )
    }
}

/// How (if at all) a non-fast-forward for a mapping was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Force {
    /// No force: only fast-forwards / creates / deletes-with-matching-lease pass.
    No,
    /// The refspec carried a leading `+`.
    SpecForce,
    /// [`with_force_with_lease`](super::PrepareOptions::with_force_with_lease) was set and the lease
    /// held for this mapping.
    LeaseHeld,
}

impl Force {
    /// The stronger of two force levels — used when collapsing exact-duplicate mappings so a
    /// forceful spec is never silently discarded (`No < SpecForce`; `LeaseHeld` is sticky).
    pub(crate) fn or(self, other: Force) -> Force {
        match (self, other) {
            (Force::LeaseHeld, _) | (_, Force::LeaseHeld) => Force::LeaseHeld,
            (Force::SpecForce, _) | (_, Force::SpecForce) => Force::SpecForce,
            (Force::No, Force::No) => Force::No,
        }
    }
}

/// The Q2 lease vocabulary, set via
/// [`PrepareOptions::with_force_with_lease`](super::PrepareOptions::with_force_with_lease).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LeasePolicy {
    /// Default: the wire CAS against the advertisement is the only lease; a `+`-spec alone governs
    /// whether non-fast-forwards pass the local check.
    #[default]
    AdvertisedOnly,
    /// `--force-with-lease` semantics: additionally pin the expected remote value. A satisfied lease
    /// grants force, a violated one aborts the plan with [`Error::StaleLease`].
    ForceWithLease(Lease),
}

/// What value a lease pins the remote to (Q2).
///
/// Note on `Exact`: `02-push-plan.md` amendment B3 reserved `Exact` for a later version; this task
/// (`rolfdb-gpx05`) implements it per the bead's explicit acceptance — `Exact` is a *prepare-time*
/// check (advertised == pinned oid, else [`Error::StaleLease`]); the wire `expected_old` still equals
/// the advertised oid, so it never violates the always-CAS-against-advertisement wire model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lease {
    /// Expect the advertisement to equal the local remote-tracking ref of each destination (the dst
    /// reverse-mapped through the remote's *fetch* specs — the Q5 recipe). A destination with no
    /// tracking ref is [`Error::LeaseTrackingRefMissing`].
    TrackingRef,
    /// Expect exactly this value. Only meaningful when exactly one non-create mapping exists; more is
    /// [`Error::LeaseRequiresSingleUpdate`].
    Exact(ObjectId),
}

/// The fully resolved push plan — the push analogue of fetch's `RefMap`, plus the wire commands and
/// the pack-walk tips.
#[derive(Debug, Clone)]
pub struct PlannedUpdates {
    /// One entry per resolved (source → destination) edge, including non-sendable ones (`UpToDate`,
    /// `Rejected*`). Order: `match_lhs` order, then the delete pass, then the matching-spec pass.
    pub mappings: Vec<Mapping>,
    /// The wire commands, in `mappings` order (the sendable subset). `expected_old` is always the
    /// advertised value (Q2). Empty means "nothing to push" (reported as such by gpx08).
    pub updates: Vec<RefUpdate>,
    /// Pack-walk tips: the `new` oids of all `Create`/`Update` commands, deduplicated, in command
    /// order. (Annotated-tag tips are tag oids; the pack walk peels.) Per amendment **B1** the plan
    /// emits **tips only** — the pack-walk *boundary* set is computed by the pack driver (gpx06) from
    /// the full advertisement, not here.
    pub tips: Vec<ObjectId>,
    /// The explicit refspecs used (echo for [`SpecIndex::ExplicitInRemote`]).
    pub refspecs: Vec<gix_refspec::RefSpec>,
    /// The implicit extra refspecs used (echo for [`SpecIndex::Implicit`]).
    pub extra_refspecs: Vec<gix_refspec::RefSpec>,
    /// All refs the remote advertised (echo of the handshake refs, mirror of `RefMap::remote_refs`).
    pub remote_refs: Vec<handshake::Ref>,
}

impl PlannedUpdates {
    /// `true` if at least one wire command exists.
    pub fn has_updates(&self) -> bool {
        !self.updates.is_empty()
    }

    /// The mapping that produced `updates[update_index]` (gpx09 correlation convenience).
    pub fn mapping_of(&self, update_index: usize) -> Option<&Mapping> {
        self.mappings.iter().find(|m| m.update_index == Some(update_index))
    }
}

/// One resolved (source → destination) edge with its advertisement state and pre-verdict — the push
/// analogue of `gix_protocol::fetch::refmap::Mapping`.
#[derive(Debug, Clone)]
pub struct Mapping {
    /// The local side; `None` for deletions (`:dst`).
    pub local: Option<Source>,
    /// The fully-qualified destination on the remote.
    pub remote: FullName,
    /// The value the server currently advertises for `remote` — `None` when absent or unborn. For an
    /// annotated tag this is the **tag** oid (the ref's stored value), never the peeled object.
    pub advertised: Option<ObjectId>,
    /// The value the remote ref shall have after the push; `None` for deletions.
    pub new: Option<ObjectId>,
    /// Whether (and how) non-fast-forward was authorized.
    pub force: Force,
    /// The spec that produced this mapping.
    pub spec_index: SpecIndex,
    /// The local pre-verdict.
    pub verdict: Verdict,
    /// Index into [`PlannedUpdates::updates`] when `verdict.is_sendable()`.
    pub update_index: Option<usize>,
}

/// The error returned by the push plan. Every variant is a prepare-time abort (C-git parity: these
/// abort the whole push before a byte is sent). [`IsSpuriousError`](gix_protocol::transport::IsSpuriousError)
/// is `false` for every variant.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("src refspec {spec:?} does not match any local ref")]
    SourceMatchesNothing { spec: BString },
    #[error("unable to delete {destination:?}: remote ref does not exist")]
    DeleteAbsentRef { destination: BString },
    #[error(
        "destination {destination:?} is not a full ref name and its type could not be inferred from source {source_spec:?}"
    )]
    UnqualifiedDestination {
        destination: BString,
        // NB: not named `source` — thiserror treats a `source` field as the error `#[source]`.
        source_spec: BString,
    },
    #[error("HEAD is detached; pushing it requires an explicit destination, like HEAD:refs/heads/main")]
    DetachedHeadNeedsDestination,
    #[error("destination {destination} would be written by more than one source: {sources:?}")]
    Conflict {
        destination: FullName,
        /// Display strings of the conflicting sources (object ids or ref names).
        sources: Vec<BString>,
    },
    #[error("source object {id} for {spec:?} does not exist locally")]
    SourceObjectMissing { id: ObjectId, spec: BString },
    #[error("stale lease for {destination}: expected the remote to be at {expected:?}, but it advertised {actual:?}")]
    StaleLease {
        destination: FullName,
        expected: Option<ObjectId>,
        actual: Option<ObjectId>,
    },
    #[error("an exact lease can only be used when exactly one ref is updated, but {candidates} would be")]
    LeaseRequiresSingleUpdate { candidates: usize },
    #[error("no remote-tracking ref is known for {destination} to lease against")]
    LeaseTrackingRefMissing { destination: FullName },
    #[error(transparent)]
    InvalidRefName(#[from] gix_validate::reference::name::Error),
    /// A failure while snapshotting the local repository state (references, `HEAD`, object lookups)
    /// that the `plan()` repo adapter feeds into the pure `plan_inner` core. Boxed so a single
    /// prepare-time variant absorbs the several distinct gix error types the snapshot can raise; like
    /// the rest of [`Error`] it is a whole-push abort and non-spurious.
    #[error("failed to snapshot the local repository for the push plan")]
    Snapshot(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl gix_protocol::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        false
    }
}

/// Snapshot of one local ref, the item vocabulary of the pure core.
#[derive(Debug, Clone)]
pub(crate) struct LocalRef {
    /// The fully-qualified name, e.g. `refs/heads/main`.
    pub name: FullName,
    /// The direct target (the tag object for annotated tags).
    pub target: ObjectId,
    /// The peeled target iff `target` is an annotated tag, else `None`.
    pub peeled: Option<ObjectId>,
}

/// Snapshot of `HEAD`, if born. An unborn `HEAD` is the `None` of the `Option<HeadState>`.
#[derive(Debug, Clone)]
pub(crate) enum HeadState {
    /// A detached `HEAD` pointing directly at a commit.
    Detached { id: ObjectId },
    /// A `HEAD` symbolically pointing at `referent`, which resolves to `id`.
    Symbolic { referent: FullName, id: ObjectId },
}

impl HeadState {
    fn id(&self) -> ObjectId {
        match self {
            HeadState::Detached { id } | HeadState::Symbolic { id, .. } => *id,
        }
    }
}

/// The result of the ancestry oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ancestry {
    /// `old` is an ancestor of `new` — a fast-forward.
    Ancestor,
    /// Both are commits, but `old` is not an ancestor of `new`.
    NotAncestor,
    /// `old` or `new` is not a commit; ancestry is undefined (⇒ `RejectedNeedsForce`).
    NotComparable,
}

// The base list of `gix_refspec::spec::expand_partial_name` (which is `pub(crate)` there, so it is
// re-stated here). Precedence order matters for dwim de-ambiguation (E21) and partial-dst matching.
const PARTIAL_BASES: [&str; 5] = ["", "refs/", "refs/tags/", "refs/heads/", "refs/remotes/"];

/// The stored advertised value of `name` (the value the ref points AT), or `None` when the ref is
/// absent or unborn. Implemented via [`handshake::Ref::unpack`] so future `Ref` variants stay
/// coherent: for `Peeled`/`Symbolic { tag: Some }` (annotated tags, incl. symref→annotated-tag) this
/// is the **tag** oid, never the peeled object (FOLLOWUPS §5; `Ref::unpack().1` == `tag.unwrap_or(object)`).
fn advertised_value_of(remote_refs: &[handshake::Ref], name: &BStr) -> Option<ObjectId> {
    remote_refs.iter().find_map(|r| {
        let (full, target, _peeled) = r.unpack();
        (full == name).then(|| target.map(ToOwned::to_owned))
    })?
}

/// Expand a partial name against a set of full names, returning the first (in precedence order) that
/// exists among `candidates`.
fn expand_partial_against(name: &BStr, candidates: impl Fn(&BStr) -> bool) -> Option<BString> {
    for base in PARTIAL_BASES {
        let mut cand = BString::from(base);
        cand.push_str(name);
        if candidates(cand.as_bstr()) {
            return Some(cand);
        }
    }
    let mut cand = BString::from("refs/remotes/");
    cand.push_str(name);
    cand.push_str("/HEAD");
    candidates(cand.as_bstr()).then_some(cand)
}

/// The precedence rank at which `full` appears in the partial-name expansion of `src`, or `None` if
/// `full` is not one of the expansions (used by the dwim filter, step 3).
fn partial_rank(src: &BStr, full: &BStr) -> Option<usize> {
    for (i, base) in PARTIAL_BASES.iter().enumerate() {
        let mut cand = BString::from(*base);
        cand.push_str(src);
        if cand.as_bstr() == full {
            return Some(i);
        }
    }
    let mut cand = BString::from("refs/remotes/");
    cand.push_str(src);
    cand.push_str("/HEAD");
    (cand.as_bstr() == full).then_some(PARTIAL_BASES.len())
}

/// Match a single-`*` glob against one name (the `Needle::Glob` algorithm re-stated, since it is
/// `pub(crate)` in `gix-refspec`). Returns the substring the `*` captured on success.
fn glob_match_single_star<'a>(pattern: &BStr, name: &'a BStr) -> Option<&'a BStr> {
    let star = pattern.find_byte(b'*')?;
    let prefix = &pattern[..star];
    let suffix = &pattern[star + 1..];
    if name.len() < prefix.len() + suffix.len() {
        return None;
    }
    if !name.starts_with(prefix) || !name.ends_with(suffix) {
        return None;
    }
    Some(name[prefix.len()..name.len() - suffix.len()].as_bstr())
}

// A candidate mapping, before destination qualification / verdict.
struct PreCand {
    spec_index: usize,
    local: Option<Source>,
    new: Option<ObjectId>,
    dest: RawDest,
    force_spec: bool,
}

enum RawDest {
    // Already a full, validated name (deletes, matching-spec, bare-src item names, glob rhs).
    Full(FullName),
    // Needs qualification (explicit partial dst); carries the source category for git's `guess_ref`.
    Qualify {
        text: BString,
        is_branch_src: bool,
        is_tag_src: bool,
    },
}

/// The pure planning core (`02-push-plan.md` §4) — zero I/O; all repository access is injected via
/// the four oracles. `refspecs`/`extra_refspecs` must be **push** specs; `local_refs` and
/// `remote_refs` are the local-ref and advertisement snapshots. See the module docs for the layers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_inner(
    refspecs: &[gix_refspec::RefSpec],
    extra_refspecs: &[gix_refspec::RefSpec],
    local_refs: &[LocalRef],
    head: Option<HeadState>,
    remote_refs: &[handshake::Ref],
    lease: LeasePolicy,
    has_object: &mut dyn FnMut(&gix_hash::oid) -> bool,
    ancestry: &mut dyn FnMut(&gix_hash::oid, &gix_hash::oid) -> Ancestry,
    resolve_rev: &mut dyn FnMut(&BStr) -> Option<ObjectId>,
    tracking_ref_value: &mut dyn FnMut(&FullName) -> Option<ObjectId>,
) -> Result<PlannedUpdates, Error> {
    // Step 0 — aggregate. Explicit specs first so `SpecIndex` offset math is `refspecs.len()`.
    let all_specs: Vec<gix_refspec::RefSpec> = refspecs.iter().chain(extra_refspecs).cloned().collect();
    let spec_index_of = |i: usize| -> SpecIndex {
        if i < refspecs.len() {
            SpecIndex::ExplicitInRemote(i)
        } else {
            SpecIndex::Implicit(i - refspecs.len())
        }
    };

    // Step 1 — build the LOCAL item list; the synthetic `HEAD` item goes first so a `HEAD` needle
    // hits it via the `""` base before any pathological `refs/heads/HEAD`.
    struct ItemOwned {
        name: BString,
        target: ObjectId,
        object: Option<ObjectId>,
        is_head: bool,
        local_name: Option<FullName>,
    }
    let mut item_data: Vec<ItemOwned> = Vec::with_capacity(local_refs.len() + 1);
    if let Some(h) = head.as_ref() {
        item_data.push(ItemOwned {
            name: "HEAD".into(),
            target: h.id(),
            object: None,
            is_head: true,
            local_name: None,
        });
    }
    for r in local_refs {
        item_data.push(ItemOwned {
            name: r.name.as_bstr().to_owned(),
            target: r.target,
            object: r.peeled,
            is_head: false,
            local_name: Some(r.name.clone()),
        });
    }
    let items: Vec<gix_refspec::match_group::Item<'_>> = item_data
        .iter()
        .map(|it| gix_refspec::match_group::Item {
            full_ref_name: it.name.as_bstr(),
            target: it.target.as_ref(),
            object: it.object.as_deref(),
        })
        .collect();

    // Step 2 — group matching via the reused engine (globs / object-ids / negatives / dedup).
    let group = gix_refspec::MatchGroup::from_push_specs(all_specs.iter().map(gix_refspec::RefSpec::to_ref));
    let outcome = group.match_lhs(items.iter().copied());

    // A spec is "glob-shaped" iff its source carries a `*`.
    let src_is_glob = |i: usize| -> bool { all_specs[i].to_ref().source().is_some_and(|s| s.contains(&b'*')) };

    // Which spec sources matched at least one local item (drives step 4's must-match errors).
    let mut spec_matched = vec![false; all_specs.len()];
    let mut pre: Vec<PreCand> = Vec::new();

    // Steps 2→3 assembly: turn raw mappings into PreCands, recording per-spec match counts for dwim.
    struct Raw {
        spec_index: usize,
        item_index: Option<usize>,
        object_lhs: Option<ObjectId>,
        rhs: Option<BString>,
        full_name: Option<BString>,
    }
    let raws: Vec<Raw> = outcome
        .mappings
        .iter()
        .map(|m| {
            let (object_lhs, full_name) = match &m.lhs {
                gix_refspec::match_group::SourceRef::ObjectId(id) => (Some(*id), None),
                gix_refspec::match_group::SourceRef::FullName(name) => (None, Some(name.as_ref().to_owned())),
            };
            Raw {
                spec_index: m.spec_index,
                item_index: m.item_index,
                object_lhs,
                rhs: m.rhs.as_ref().map(|c| c.as_ref().to_owned()),
                full_name,
            }
        })
        .collect();
    // `spec_matched` is computed from the SOURCE-vs-item match directly, NOT from the deduped `raws`:
    // `match_lhs` dedups `(lhs, rhs)` across specs, so an exact-duplicate spec whose mapping was
    // collapsed would otherwise look "unmatched" and trip step 4's must-match error (E28).
    for (si, spec) in all_specs.iter().enumerate() {
        if let Some(src) = spec.to_ref().source() {
            if source_matches_item(src, item_data.iter().map(|it| it.name.as_bstr())) {
                spec_matched[si] = true;
            }
        }
    }

    // Step 3 — dwim de-ambiguation: for a positive, non-glob, PartialName-src spec that produced more
    // than one mapping, keep only the mapping whose full name comes first in expansion precedence.
    let mut drop_raw = vec![false; raws.len()];
    for (si, spec) in all_specs.iter().enumerate() {
        let sr = spec.to_ref();
        let Some(src) = sr.source() else { continue };
        if is_negative_spec(&sr) || src_is_glob(si) {
            continue;
        }
        // Only partial names dwim (not full `refs/...`, not object ids).
        let is_partial = !src.starts_with(b"refs/") && ObjectId::from_hex(src).is_err();
        if !is_partial {
            continue;
        }
        let mut group_idx: Vec<usize> = raws
            .iter()
            .enumerate()
            .filter(|(_, r)| r.spec_index == si && r.full_name.is_some())
            .map(|(i, _)| i)
            .collect();
        if group_idx.len() <= 1 {
            continue;
        }
        // Keep the min-rank member; drop the rest.
        group_idx
            .sort_by_key(|&i| partial_rank(src, raws[i].full_name.as_ref().unwrap().as_bstr()).unwrap_or(usize::MAX));
        for &i in &group_idx[1..] {
            drop_raw[i] = true;
        }
    }

    // Assemble PreCands from surviving raws (steps 2–4 sources + destinations).
    for (ri, r) in raws.iter().enumerate() {
        if drop_raw[ri] {
            continue;
        }
        let sr = all_specs[r.spec_index].to_ref();
        let force_spec = all_specs[r.spec_index].allow_non_fast_forward();
        let is_glob = src_is_glob(r.spec_index);

        // Resolve the local source + new-oid.
        let (local, new_id): (Source, ObjectId) = if let Some(id) = r.object_lhs {
            (Source::ObjectId(id), id)
        } else {
            let item_idx = r.item_index.expect("FullName mapping carries an item index");
            let it = &item_data[item_idx];
            if it.is_head {
                let h = head.as_ref().expect("HEAD item implies a born HEAD");
                match h {
                    HeadState::Symbolic { referent, id } => (
                        Source::Ref {
                            name: referent.clone(),
                            id: *id,
                        },
                        *id,
                    ),
                    HeadState::Detached { id } => (Source::Detached { id: *id }, *id),
                }
            } else {
                let name = it.local_name.clone().expect("local item carries a name");
                (Source::Ref { name, id: it.target }, it.target)
            }
        };

        // Resolve the destination.
        let dest = if is_glob {
            match r.rhs.clone() {
                // Two-sided glob: the engine instantiated the rhs. If it does not start with
                // `refs/`, we DELIBERATELY refuse client-side (Error::UnqualifiedDestination)
                // where C-git would send the literal name and let the SERVER reject it as a
                // "funny refname" (verified empirically: `git push r 'refs/heads/*:qa/*'` →
                // `remote rejected ... (funny refname)`). Same outcome, but typed, fail-fast,
                // and without uploading a pack first.
                Some(text) => RawDest::Qualify {
                    text,
                    is_branch_src: false,
                    is_tag_src: false,
                },
                // One-sided glob (`refs/heads/*` with no dst): the engine returns rhs-less
                // mappings; Push::Matching semantics say dst = the matched ref's own name
                // (review fix — previously fell through as an empty-string qualify and aborted
                // the whole push with a confusing UnqualifiedDestination("")).
                None => match &local {
                    Source::Ref { name, .. } => RawDest::Full(name.clone()),
                    Source::Detached { .. } => return Err(Error::DetachedHeadNeedsDestination),
                    Source::ObjectId(_) => {
                        return Err(Error::UnqualifiedDestination {
                            destination: BString::default(),
                            source_spec: sr.source().map(ToOwned::to_owned).unwrap_or_default(),
                        });
                    }
                },
            }
        } else if let Some(dst_text) = sr.destination() {
            // Explicit dst: qualify against the SOURCE's category (git `guess_ref`), never the
            // engine's `refs/heads/`-cooked rhs (`§5.4`).
            let (is_branch_src, is_tag_src) = source_category(&local);
            RawDest::Qualify {
                text: dst_text.to_owned(),
                is_branch_src,
                is_tag_src,
            }
        } else {
            // Bare src: dst = the matched item's own full name; for HEAD, its referent.
            match &local {
                Source::Ref { name, .. } => RawDest::Full(name.clone()),
                Source::Detached { .. } => return Err(Error::DetachedHeadNeedsDestination),
                Source::ObjectId(_) => {
                    // A bare object-id src has no natural destination.
                    return Err(Error::UnqualifiedDestination {
                        destination: BString::default(),
                        source_spec: sr.source().map(ToOwned::to_owned).unwrap_or_default(),
                    });
                }
            }
        };

        pre.push(PreCand {
            spec_index: r.spec_index,
            local: Some(local),
            new: Some(new_id),
            dest,
            force_spec,
        });
    }

    // Step 4 — rev-spec / must-match for positive Matching specs that produced ZERO mappings.
    for (si, spec) in all_specs.iter().enumerate() {
        let sr = spec.to_ref();
        if is_negative_spec(&sr) || spec_matched[si] {
            continue;
        }
        // Only Matching specs (src present) can "match nothing" in a way that errors; Delete /
        // AllMatchingBranches carry no src and are handled by steps 5/6.
        let instruction = sr.instruction();
        let src = match instruction {
            gix_refspec::Instruction::Push(gix_refspec::instruction::Push::Matching { src, .. }) => src,
            _ => continue,
        };
        if src_is_glob(si) {
            continue; // glob matching nothing is fine (like fetch).
        }
        // A rev-spec source is only admissible with an explicit destination (parser guarantee).
        if let Some(dst_text) = sr.destination() {
            if let Some(id) = resolve_rev(src) {
                let (is_branch_src, is_tag_src) = (false, false);
                pre.push(PreCand {
                    spec_index: si,
                    local: Some(Source::ObjectId(id)),
                    new: Some(id),
                    dest: RawDest::Qualify {
                        text: dst_text.to_owned(),
                        is_branch_src,
                        is_tag_src,
                    },
                    force_spec: spec.allow_non_fast_forward(),
                });
                continue;
            }
        }
        return Err(Error::SourceMatchesNothing { spec: src.to_owned() });
    }

    // ODB-verify every object-id / rev-spec source (the hex-needle path never touched the ODB).
    for c in &pre {
        if let Some(Source::ObjectId(id)) = &c.local {
            if !has_object(id.as_ref()) {
                return Err(Error::SourceObjectMissing {
                    id: *id,
                    spec: c.local.as_ref().map(display_source).unwrap_or_default(),
                });
            }
        }
    }

    // Advertised names that are present (non-absent, non-unborn) — for delete/matching passes.
    let advertised_present = |name: &BStr| advertised_value_of(remote_refs, name).is_some();

    // Step 5 — delete pass (`:dst` / `+:dst`), matched against the ADVERTISEMENT.
    for (si, spec) in all_specs.iter().enumerate() {
        let sr = spec.to_ref();
        let pattern = match sr.instruction() {
            gix_refspec::Instruction::Push(gix_refspec::instruction::Push::Delete { ref_or_pattern }) => ref_or_pattern,
            _ => continue,
        };
        if pattern.contains(&b'*') {
            // Defensive/future-proof: gix-refspec currently rejects the `:glob` delete form as
            // `PatternUnbalanced` (the empty src has no `*` to balance the dst), so this branch is not
            // reachable via today's parser — deletes are always literal in v1. Kept (with its
            // `glob_match_single_star` helper, unit-tested directly) so a parser that later admits glob
            // deletes needs no plan change. single `*`: match every advertised present name.
            for r in remote_refs {
                let (full, target, _) = r.unpack();
                if target.is_none() {
                    continue; // unborn counts absent
                }
                if glob_match_single_star(pattern, full).is_some() {
                    pre.push(PreCand {
                        spec_index: si,
                        local: None,
                        new: None,
                        dest: RawDest::Full(FullName::try_from(full.to_owned())?),
                        force_spec: spec.allow_non_fast_forward(),
                    });
                }
            }
        } else {
            // literal: exact advertised match, else a single partial expansion.
            let qualified = if advertised_present(pattern) {
                Some(pattern.to_owned())
            } else {
                expand_partial_against(pattern, advertised_present)
            };
            match qualified {
                Some(full) => pre.push(PreCand {
                    spec_index: si,
                    local: None,
                    new: None,
                    dest: RawDest::Full(FullName::try_from(full)?),
                    force_spec: spec.allow_non_fast_forward(),
                }),
                None => {
                    return Err(Error::DeleteAbsentRef {
                        destination: pattern.to_owned(),
                    });
                }
            }
        }
    }

    // Step 6 — matching-spec pass (`:` / `+:`): update-only for local `refs/heads/*` also advertised.
    for (si, spec) in all_specs.iter().enumerate() {
        let sr = spec.to_ref();
        if !matches!(
            sr.instruction(),
            gix_refspec::Instruction::Push(gix_refspec::instruction::Push::AllMatchingBranches { .. })
        ) {
            continue;
        }
        for lr in local_refs {
            if lr.name.as_bstr().starts_with(b"refs/heads/") && advertised_present(lr.name.as_bstr()) {
                pre.push(PreCand {
                    spec_index: si,
                    local: Some(Source::Ref {
                        name: lr.name.clone(),
                        id: lr.target,
                    }),
                    new: Some(lr.target),
                    dest: RawDest::Full(lr.name.clone()),
                    force_spec: spec.allow_non_fast_forward(),
                });
            }
        }
    }

    // Step 7 — destination qualification + conflict validation.
    struct Cand {
        spec_index: usize,
        local: Option<Source>,
        new: Option<ObjectId>,
        remote: FullName,
        advertised: Option<ObjectId>,
        force: Force,
        verdict: Verdict,
    }
    let mut cands: Vec<Cand> = Vec::with_capacity(pre.len());
    for c in pre {
        let remote: FullName = match c.dest {
            RawDest::Full(name) => name,
            RawDest::Qualify {
                text,
                is_branch_src,
                is_tag_src,
            } => qualify_destination(
                text.as_bstr(),
                is_branch_src,
                is_tag_src,
                advertised_present,
                c.local.as_ref(),
            )?,
        };
        let advertised = advertised_value_of(remote_refs, remote.as_bstr());
        cands.push(Cand {
            spec_index: c.spec_index,
            local: c.local,
            new: c.new,
            remote,
            advertised,
            force: if c.force_spec { Force::SpecForce } else { Force::No },
            verdict: Verdict::UpToDate, // placeholder, set in step 8
        });
    }

    // Conflict check across all cands: two entries, same remote, different (local, new) ⇒ Conflict;
    // identical duplicates are dropped.
    let mut kept: Vec<Cand> = Vec::with_capacity(cands.len());
    'outer: for c in cands {
        for k in &mut kept {
            if k.remote == c.remote {
                if k.local == c.local && k.new == c.new {
                    // Exact dup — but OR the force bits so `refs/heads/main` + `+:` cannot
                    // silently drop the user's force (review fix): keep the stronger of the two.
                    k.force = k.force.or(c.force);
                    continue 'outer;
                }
                let mut sources: Vec<BString> = vec![
                    k.local.as_ref().map_or_else(|| "(delete)".into(), display_source),
                    c.local.as_ref().map_or_else(|| "(delete)".into(), display_source),
                ];
                sources.sort();
                return Err(Error::Conflict {
                    destination: c.remote,
                    sources,
                });
            }
        }
        kept.push(c);
    }
    let mut cands = kept;

    // Step 7b — sibling-spec force upgrade. The match engine DEDUPS textually-identical mappings
    // before we ever see them, keeping the FIRST spec's index — so `refs/heads/main` +
    // `+refs/heads/main:refs/heads/main` yields one cand whose `+` silently vanished (review
    // finding). C-git refuses this shape outright ("dst ref receives from more than one src",
    // verified empirically) — a DOCUMENTED lenient divergence: instead of erroring on an
    // identical duplicate we keep the mapping and take the STRONGER force of any sibling spec
    // with the same source/destination text.
    for c in &mut cands {
        if matches!(c.force, Force::No) {
            let winning = all_specs[c.spec_index].to_ref();
            for (idx, other) in all_specs.iter().enumerate() {
                let other = other.to_ref();
                if idx != c.spec_index
                    && all_specs[idx].allow_non_fast_forward()
                    && other.source() == winning.source()
                    && (other.destination() == winning.destination() || other.destination().is_none())
                {
                    c.force = c.force.or(Force::SpecForce);
                    break;
                }
            }
        }
    }

    // Step 8 — verdict per mapping (C-git `set_ref_status_for_push` row order).
    for c in &mut cands {
        let is_delete = c.local.is_none();
        if is_delete {
            c.verdict = Verdict::Delete;
            continue;
        }
        let new = c.new.expect("non-delete carries a new oid");
        let advertised = c.advertised;
        c.verdict = match advertised {
            None => Verdict::Create,
            Some(old) if old == new => Verdict::UpToDate,
            Some(old) => {
                if matches!(c.force, Force::SpecForce) {
                    // Force skips the ancestry walk ENTIRELY (must not pay it over many refs).
                    Verdict::Forced
                } else if c.remote.as_bstr().starts_with(b"refs/tags/") {
                    Verdict::RejectedAlreadyExists
                } else if !has_object(old.as_ref()) {
                    Verdict::RejectedFetchFirst
                } else {
                    match ancestry(old.as_ref(), new.as_ref()) {
                        Ancestry::Ancestor => Verdict::FastForward,
                        Ancestry::NotAncestor => Verdict::RejectedNonFastForward,
                        Ancestry::NotComparable => Verdict::RejectedNeedsForce,
                    }
                }
            }
        };
    }

    // Step 9 — lease application (Q2).
    if let LeasePolicy::ForceWithLease(l) = lease {
        // Candidates: every non-Create mapping (creates have nothing to lease).
        let candidate_idx: Vec<usize> = cands
            .iter()
            .enumerate()
            .filter(|(_, c)| c.verdict != Verdict::Create)
            .map(|(i, _)| i)
            .collect();
        match l {
            Lease::Exact(oid) => {
                if candidate_idx.len() > 1 {
                    return Err(Error::LeaseRequiresSingleUpdate {
                        candidates: candidate_idx.len(),
                    });
                }
                if let Some(&i) = candidate_idx.first() {
                    if cands[i].advertised != Some(oid) {
                        return Err(Error::StaleLease {
                            destination: cands[i].remote.clone(),
                            expected: Some(oid),
                            actual: cands[i].advertised,
                        });
                    }
                    let c = &mut cands[i];
                    upgrade_leased(&mut c.verdict, &mut c.force);
                }
            }
            Lease::TrackingRef => {
                for &i in &candidate_idx {
                    let expected = tracking_ref_value(&cands[i].remote);
                    match expected {
                        None => {
                            return Err(Error::LeaseTrackingRefMissing {
                                destination: cands[i].remote.clone(),
                            });
                        }
                        Some(exp) => {
                            if cands[i].advertised != Some(exp) {
                                return Err(Error::StaleLease {
                                    destination: cands[i].remote.clone(),
                                    expected: Some(exp),
                                    actual: cands[i].advertised,
                                });
                            }
                            let c = &mut cands[i];
                            upgrade_leased(&mut c.verdict, &mut c.force);
                        }
                    }
                }
            }
        }
    }

    // Step 10 — emission: build wire commands + tips, then the public mappings.
    let mut updates: Vec<RefUpdate> = Vec::new();
    let mut tips: Vec<ObjectId> = Vec::new();
    let mut mappings: Vec<Mapping> = Vec::with_capacity(cands.len());
    for c in cands {
        let update_index = if c.verdict.is_sendable() {
            let cmd = match c.verdict {
                Verdict::Create => {
                    let new = c.new.expect("create carries a new oid");
                    push_tip(&mut tips, new);
                    RefUpdate::Create {
                        name: c.remote.clone(),
                        new,
                    }
                }
                Verdict::FastForward | Verdict::Forced => {
                    let new = c.new.expect("update carries a new oid");
                    push_tip(&mut tips, new);
                    RefUpdate::Update {
                        name: c.remote.clone(),
                        expected_old: c.advertised.expect("update leases the advertised value"),
                        new,
                    }
                }
                Verdict::Delete => RefUpdate::Delete {
                    name: c.remote.clone(),
                    expected_old: c.advertised.expect("delete leases the advertised value"),
                },
                _ => unreachable!("is_sendable() covers exactly the four arms above"),
            };
            updates.push(cmd);
            Some(updates.len() - 1)
        } else {
            None
        };
        mappings.push(Mapping {
            local: c.local,
            remote: c.remote,
            advertised: c.advertised,
            new: c.new,
            force: c.force,
            spec_index: spec_index_of(c.spec_index),
            verdict: c.verdict,
            update_index,
        });
    }

    Ok(PlannedUpdates {
        mappings,
        updates,
        tips,
        refspecs: refspecs.to_vec(),
        extra_refspecs: extra_refspecs.to_vec(),
        remote_refs: remote_refs.to_vec(),
    })
}

/// A satisfied lease grants force: any `Rejected*` verdict becomes `Forced` with `force = LeaseHeld`.
/// `UpToDate`/`FastForward`/`Delete` keep their verdicts.
fn upgrade_leased(verdict: &mut Verdict, force: &mut Force) {
    if verdict.is_rejected() {
        *verdict = Verdict::Forced;
    }
    *force = Force::LeaseHeld;
}

/// Category of a push source for git's `guess_ref` (branch vs tag). A born-HEAD symbolic source is
/// resolved to its `refs/heads/*` referent, so it reads as a branch here.
fn source_category(local: &Source) -> (bool, bool) {
    match local {
        Source::Ref { name, .. } => {
            let n = name.as_bstr();
            (n.starts_with(b"refs/heads/"), n.starts_with(b"refs/tags/"))
        }
        Source::Detached { .. } | Source::ObjectId(_) => (false, false),
    }
}

/// Qualify a partial destination to a `FullName` (git `guess_ref` parity).
fn qualify_destination(
    text: &BStr,
    is_branch_src: bool,
    is_tag_src: bool,
    advertised_present: impl Fn(&BStr) -> bool + Copy,
    local: Option<&Source>,
) -> Result<FullName, Error> {
    if text.starts_with(b"refs/") {
        return Ok(FullName::try_from(text)?);
    }
    if let Some(full) = expand_partial_against(text, advertised_present) {
        return Ok(FullName::try_from(full)?);
    }
    if is_branch_src {
        let mut full = BString::from("refs/heads/");
        full.push_str(text);
        return Ok(FullName::try_from(full)?);
    }
    if is_tag_src {
        let mut full = BString::from("refs/tags/");
        full.push_str(text);
        return Ok(FullName::try_from(full)?);
    }
    Err(Error::UnqualifiedDestination {
        destination: text.to_owned(),
        source_spec: local.map(display_source).unwrap_or_default(),
    })
}

/// Display a source as bytes for error messages.
fn display_source(s: &Source) -> BString {
    match s {
        Source::Ref { name, .. } => name.as_bstr().to_owned(),
        Source::ObjectId(id) | Source::Detached { id } => id.to_string().into(),
    }
}

/// Append `id` to `tips` unless already present (order-preserving dedup).
fn push_tip(tips: &mut Vec<ObjectId>, id: ObjectId) {
    if !tips.contains(&id) {
        tips.push(id);
    }
}

/// Whether a spec's source matches at least one local item — dedup-independent (so the deduped
/// `match_lhs` output cannot mis-flag a duplicate spec as unmatched, E28). Globs and object-id
/// sources never "match nothing" here (globs are lenient; object needles always emit a mapping).
fn source_matches_item<'a>(src: &BStr, mut item_names: impl Iterator<Item = &'a BStr>) -> bool {
    if src.contains(&b'*') || ObjectId::from_hex(src).is_ok() {
        return true;
    }
    if src.starts_with(b"refs/") {
        return item_names.any(|n| n == src);
    }
    item_names.any(|n| partial_rank(src, n).is_some())
}

/// `true` for a negative (`^src`) push spec. Detected via the public [`gix_refspec::Instruction`]
/// (the `RefSpecRef::mode` field and `types::Mode` are `pub(crate)` in `gix-refspec`).
fn is_negative_spec(sr: &gix_refspec::RefSpecRef<'_>) -> bool {
    matches!(
        sr.instruction(),
        gix_refspec::Instruction::Push(gix_refspec::instruction::Push::Exclude { .. })
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The `plan()` REPO ADAPTER (gpx07, the gpx05 carve-out).
//
// This is the sole in-crate consumer of the pure [`plan_inner`] core: it wires the four oracles to a
// real [`Repository`](crate::Repository) + the connection's [`RemoteDetached`](crate::types::RemoteDetached)
// and its ReceivePack advertisement, and is itself consumed by `prepare_push` (gpx08). It lives behind
// `#[cfg(feature = "revision")]` because the `resolve_rev` oracle needs
// [`rev_parse_single`](crate::Repository::rev_parse_single) (and the `ancestry` oracle
// [`merge_base`](crate::Repository::merge_base)), both `#[cfg(feature = "revision")]` — a feature the
// `*-network-client` gates this module rides do NOT pull in, so the porcelain gate adds `revision`
// explicitly (see `scripts/gix-push-sync.sh`). A network-client build without `revision` simply omits
// `plan()`; the pure core and its catalog tests remain available either way.
#[cfg(feature = "revision")]
mod adapter {
    use gix_hash::{ObjectId, oid};
    use gix_object::Exists;
    use gix_ref::{FullName, FullNameRef};

    use super::{Ancestry, Error, HeadState, LeasePolicy, LocalRef, PlannedUpdates, plan_inner};
    use crate::bstr::{BStr, ByteSlice};

    /// Wire the pure planning core to a live repository.
    ///
    /// `remote` is the detached remote of the push connection; its **push** refspecs (the gpx01
    /// accessor [`push_refspecs`](crate::types::RemoteDetached::push_refspecs)) drive the plan and its
    /// **fetch** refspecs power the `--force-with-lease=<tracking-ref>` reverse-map. `remote_refs` is
    /// the ReceivePack advertisement from the handshake (gpx04). `extra_refspecs` are the
    /// higher-priority [`PrepareOptions::extra_refspecs`](super::super::PrepareOptions::extra_refspecs).
    #[allow(dead_code)] // consumer is gpx08's `prepare_push`; mirrors `plan_inner`'s own scaffolding allow.
    #[allow(clippy::result_large_err)]
    pub(crate) fn plan(
        repo: &crate::Repository,
        remote: &crate::types::RemoteDetached,
        extra_refspecs: &[gix_refspec::RefSpec],
        remote_refs: &[gix_protocol::handshake::Ref],
        lease: LeasePolicy,
    ) -> Result<PlannedUpdates, Error> {
        let refspecs = remote.push_refspecs().to_vec();
        let local_refs = snapshot_local_refs(repo)?;
        let head = snapshot_head(repo)?;
        let object_hash = repo.object_hash();
        let fetch_specs = remote.fetch_specs.clone();

        let mut has_object = |id: &oid| repo.objects.exists(id);
        let mut ancestry = |old: &oid, new: &oid| ancestry_of(repo, old, new);
        let mut resolve_rev = |spec: &BStr| repo.rev_parse_single(spec).ok().map(crate::Id::detach);
        let mut tracking_ref_value = |dst: &FullName| tracking_ref_value(repo, &fetch_specs, dst.as_ref(), object_hash);

        plan_inner(
            &refspecs,
            extra_refspecs,
            &local_refs,
            head,
            remote_refs,
            lease,
            &mut has_object,
            &mut ancestry,
            &mut resolve_rev,
            &mut tracking_ref_value,
        )
    }

    /// Snapshot every local reference as a [`LocalRef`]. Symbolic refs (e.g. a symref under
    /// `refs/heads/`) are skipped — a symbolic source is only pushable via `HEAD`, handled by
    /// [`snapshot_head`]. Annotated tags record their peeled commit in `peeled` (via a full peel);
    /// a peel that fails (broken/partial object graph) degrades to `peeled = None` rather than
    /// aborting the whole snapshot.
    #[allow(clippy::result_large_err)]
    fn snapshot_local_refs(repo: &crate::Repository) -> Result<Vec<LocalRef>, Error> {
        let platform = repo.references().map_err(boxed)?;
        let mut out = Vec::new();
        for reference in platform.all().map_err(boxed)? {
            let reference = reference.map_err(Error::Snapshot)?;
            let name = reference.name().to_owned();
            let target = match reference.target() {
                gix_ref::TargetRef::Object(id) => id.to_owned(),
                gix_ref::TargetRef::Symbolic(_) => continue,
            };
            let peeled = reference
                .into_fully_peeled_id()
                .ok()
                .map(crate::Id::detach)
                .filter(|peeled| *peeled != target);
            out.push(LocalRef { name, target, peeled });
        }
        Ok(out)
    }

    /// Snapshot `HEAD` into the pure core's [`HeadState`]. An unborn `HEAD` (fresh repo, or a symbolic
    /// `HEAD` whose branch does not yet exist) and an unreadable `HEAD` both map to `None`.
    #[allow(clippy::result_large_err)]
    fn snapshot_head(repo: &crate::Repository) -> Result<Option<HeadState>, Error> {
        let head = match repo.head() {
            Ok(head) => head,
            Err(_) => return Ok(None),
        };
        if head.is_detached() {
            return Ok(head.id().map(|id| HeadState::Detached { id: id.detach() }));
        }
        Ok(match (head.referent_name(), head.id()) {
            (Some(referent), Some(id)) => Some(HeadState::Symbolic {
                referent: referent.to_owned(),
                id: id.detach(),
            }),
            _ => None, // unborn symbolic HEAD
        })
    }

    /// The `ancestry` oracle: is `old` an ancestor of `new`? Both must be commits, else the update is
    /// [`Ancestry::NotComparable`] (⇒ `RejectedNeedsForce`, mirroring C-git's non-commit ff refusal).
    /// A best merge-base equal to `old` is exactly "`old` is an ancestor of `new`"; a missing merge
    /// base (disjoint histories) is [`Ancestry::NotAncestor`].
    /// NB (fused review): the oracle seam is infallible, so every `merge_base` failure must fold
    /// into an `Ancestry` value. Disjoint histories (`NoMergeBase`) are genuinely `NotAncestor`;
    /// any OTHER error — a broken ODB/commit-graph, or a SHALLOW local history whose ancestor lies
    /// beyond the graft boundary — folds to `NotComparable` (surfacing as `RejectedNeedsForce`,
    /// never a silent non-FF) and is logged, so an infrastructure fault cannot masquerade as an
    /// ordinary rejection. Safe-degrading: rejects, never corrupts.
    fn ancestry_of(repo: &crate::Repository, old: &oid, new: &oid) -> Ancestry {
        if !object_is_commit(repo, old) || !object_is_commit(repo, new) {
            return Ancestry::NotComparable;
        }
        match repo.merge_base(old.to_owned(), new.to_owned()) {
            Ok(base) => {
                if base.detach().as_ref() == old {
                    Ancestry::Ancestor
                } else {
                    Ancestry::NotAncestor
                }
            }
            Err(crate::repository::merge_base::Error::NotFound { .. }) => Ancestry::NotAncestor,
            Err(_) => {
                gix_trace::coarse!("push::plan::ancestry_oracle_fault");
                Ancestry::NotComparable
            }
        }
    }

    fn object_is_commit(repo: &crate::Repository, id: &oid) -> bool {
        repo.find_object(id)
            .is_ok_and(|obj| obj.kind == gix_object::Kind::Commit)
    }

    /// The `tracking_ref_value` oracle for `--force-with-lease=<tracking-ref>` (Q5 reverse-map): map
    /// the pushed destination `dst` back through the remote's **fetch** refspecs to the local
    /// tracking ref, then read that ref's current object id. `None` if `dst` reverse-maps to nothing
    /// or the tracking ref is absent/symbolic — the pure core turns that into
    /// [`Error::LeaseTrackingRefMissing`]. The reverse-map re-states the private
    /// `config::branch::matching_remote` helper (two-sided fetch specs, first-match) inline, keeping
    /// this self-contained to the push module rather than promoting an upstream `pub(crate)`.
    fn tracking_ref_value(
        repo: &crate::Repository,
        fetch_specs: &[gix_refspec::RefSpec],
        dst: &FullNameRef,
        object_hash: gix_hash::Kind,
    ) -> Option<ObjectId> {
        let name = tracking_ref_name(fetch_specs, dst, object_hash)?;
        repo.refs
            .try_find(name.as_ref())
            .ok()
            .flatten()
            .and_then(|reference| reference.target.try_id().map(ToOwned::to_owned))
    }

    /// Reverse-map `dst` (a `refs/heads/*` destination we pushed to) through the two-sided fetch specs
    /// to the local tracking ref name, first-match — byte-identical to `config::branch::matching_remote`.
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

    fn boxed<E: std::error::Error + Send + Sync + 'static>(err: E) -> Error {
        Error::Snapshot(Box::new(err))
    }

    #[cfg(test)]
    mod tests {
        use super::tracking_ref_name;
        use crate::bstr::BStr;
        use gix_ref::FullName;

        fn spec(s: &str) -> gix_refspec::RefSpec {
            gix_refspec::parse(BStr::new(s), gix_refspec::parse::Operation::Fetch)
                .expect("valid fetch refspec")
                .to_owned()
        }
        fn fname(s: &str) -> FullName {
            FullName::try_from(s).expect("valid full ref name")
        }

        /// The `--force-with-lease=<tracking-ref>` reverse-map is byte-identical to
        /// `config::branch::matching_remote`: a two-sided fetch spec whose lhs matches the pushed dst
        /// yields the rhs tracking ref.
        #[test]
        fn tracking_ref_name_maps_dst_through_the_default_fetch_spec() {
            let specs = vec![spec("+refs/heads/*:refs/remotes/origin/*")];
            let got = tracking_ref_name(&specs, fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
            assert_eq!(got, Some(fname("refs/remotes/origin/main")));
        }

        /// A dst matched by no two-sided fetch spec reverse-maps to nothing (⇒ the pure core raises
        /// `LeaseTrackingRefMissing`).
        #[test]
        fn tracking_ref_name_is_none_without_a_matching_fetch_spec() {
            let specs = vec![spec("+refs/heads/*:refs/remotes/origin/*")];
            let got = tracking_ref_name(&specs, fname("refs/tags/v1").as_ref(), gix_hash::Kind::Sha1);
            assert_eq!(got, None);
        }

        /// First-match on ambiguity, mirroring the helper's documented behavior.
        #[test]
        fn tracking_ref_name_first_match_wins_on_ambiguity() {
            let specs = vec![
                spec("+refs/heads/*:refs/remotes/origin/*"),
                spec("+refs/heads/*:refs/remotes/backup/*"),
            ];
            let got = tracking_ref_name(&specs, fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
            assert_eq!(got, Some(fname("refs/remotes/origin/main")));
        }
    }
}

/// The gpx07 repo adapter's public entry point, consumed by `prepare_push` (gpx08). Unused in a
/// non-test build until gpx08 roots it — the same scaffolding state as the rest of this module.
#[cfg(feature = "revision")]
#[allow(unused_imports)]
pub(crate) use adapter::plan;

#[cfg(test)]
mod tests {
    use super::*;
    use gix_hash::ObjectId;
    use gix_protocol::handshake;
    use gix_ref::FullName;
    use std::collections::{HashMap, HashSet};

    use crate::bstr::BStr;

    fn oid(n: u8) -> ObjectId {
        ObjectId::from_hex(format!("{n:040x}").as_bytes()).expect("valid hex id")
    }
    fn fname(s: &str) -> FullName {
        FullName::try_from(s).expect("valid full ref name")
    }
    fn spec(s: &str) -> gix_refspec::RefSpec {
        gix_refspec::parse(BStr::new(s), gix_refspec::parse::Operation::Push)
            .expect("valid push refspec")
            .to_owned()
    }
    fn direct(name: &str, object: ObjectId) -> handshake::Ref {
        handshake::Ref::Direct {
            full_ref_name: name.into(),
            object,
        }
    }
    fn peeled(name: &str, tag: ObjectId, object: ObjectId) -> handshake::Ref {
        handshake::Ref::Peeled {
            full_ref_name: name.into(),
            tag,
            object,
        }
    }
    fn symbolic(name: &str, target: &str, tag: Option<ObjectId>, object: ObjectId) -> handshake::Ref {
        handshake::Ref::Symbolic {
            full_ref_name: name.into(),
            target: target.into(),
            tag,
            object,
        }
    }
    fn unborn(name: &str) -> handshake::Ref {
        handshake::Ref::Unborn {
            full_ref_name: name.into(),
            target: "refs/heads/main".into(),
        }
    }

    #[derive(Default)]
    struct Fix {
        specs: Vec<&'static str>,
        extra: Vec<&'static str>,
        locals: Vec<(&'static str, ObjectId, Option<ObjectId>)>,
        head: Option<HeadState>,
        advertised: Vec<handshake::Ref>,
        odb: HashSet<ObjectId>,
        ancestry: HashMap<(ObjectId, ObjectId), Ancestry>,
        revs: HashMap<&'static str, ObjectId>,
        tracking: HashMap<&'static str, ObjectId>,
        lease: LeasePolicy,
    }

    impl Fix {
        fn plan(self) -> Result<PlannedUpdates, Error> {
            let refspecs: Vec<_> = self.specs.iter().map(|s| spec(s)).collect();
            let extra: Vec<_> = self.extra.iter().map(|s| spec(s)).collect();
            let locals: Vec<LocalRef> = self
                .locals
                .iter()
                .map(|(n, t, p)| LocalRef {
                    name: fname(n),
                    target: *t,
                    peeled: *p,
                })
                .collect();
            let odb = self.odb;
            let ancestry = self.ancestry;
            let revs = self.revs;
            let tracking = self.tracking;
            let mut has_object = |id: &gix_hash::oid| odb.contains(&id.to_owned());
            let mut anc = |o: &gix_hash::oid, n: &gix_hash::oid| {
                *ancestry
                    .get(&(o.to_owned(), n.to_owned()))
                    .unwrap_or_else(|| panic!("ancestry({o}, {n}) not provided by the fixture"))
            };
            let mut rr = |s: &BStr| revs.get(std::str::from_utf8(s).expect("utf8 rev")).copied();
            let mut tr = |name: &FullName| {
                tracking
                    .get(std::str::from_utf8(name.as_bstr()).expect("utf8 name"))
                    .copied()
            };
            plan_inner(
                &refspecs,
                &extra,
                &locals,
                self.head,
                &self.advertised,
                self.lease,
                &mut has_object,
                &mut anc,
                &mut rr,
                &mut tr,
            )
        }
    }

    // ── helper-level unit tests ─────────────────────────────────────────────────────────────

    #[test]
    fn advertised_value_reads_stored_value_per_unpack_law() {
        let refs = vec![
            direct("refs/heads/d", oid(1)),
            symbolic("refs/sym/none", "refs/heads/d", None, oid(2)),
            symbolic("refs/sym/tag", "refs/tags/v", Some(oid(3)), oid(4)),
            peeled("refs/tags/ann", oid(5), oid(6)),
            unborn("HEAD"),
        ];
        assert_eq!(advertised_value_of(&refs, b"refs/heads/d".as_bstr()), Some(oid(1)));
        // Symbolic tag:None ⇒ the peeled object.
        assert_eq!(advertised_value_of(&refs, b"refs/sym/none".as_bstr()), Some(oid(2)));
        // Symbolic tag:Some (symref→annotated tag) ⇒ the TAG oid, not the peeled object (FOLLOWUPS §5).
        assert_eq!(advertised_value_of(&refs, b"refs/sym/tag".as_bstr()), Some(oid(3)));
        // Peeled (annotated tag) ⇒ the TAG oid, not the peeled commit.
        assert_eq!(advertised_value_of(&refs, b"refs/tags/ann".as_bstr()), Some(oid(5)));
        // Unborn ⇒ None; absent ⇒ None.
        assert_eq!(advertised_value_of(&refs, b"HEAD".as_bstr()), None);
        assert_eq!(advertised_value_of(&refs, b"refs/heads/absent".as_bstr()), None);
    }

    #[test]
    fn glob_match_single_star_cases() {
        assert_eq!(
            glob_match_single_star(b"refs/heads/*".as_bstr(), b"refs/heads/main".as_bstr()),
            Some(b"main".as_bstr())
        );
        assert_eq!(
            glob_match_single_star(b"refs/*/x".as_bstr(), b"refs/a/x".as_bstr()),
            Some(b"a".as_bstr())
        );
        assert_eq!(
            glob_match_single_star(b"refs/heads/*".as_bstr(), b"refs/tags/main".as_bstr()),
            None
        );
        // prefix present, suffix absent.
        assert_eq!(
            glob_match_single_star(b"refs/*/end".as_bstr(), b"refs/a/other".as_bstr()),
            None
        );
    }

    #[test]
    fn partial_rank_precedence() {
        assert_eq!(partial_rank(b"x".as_bstr(), b"x".as_bstr()), Some(0));
        assert_eq!(partial_rank(b"x".as_bstr(), b"refs/tags/x".as_bstr()), Some(2));
        assert_eq!(partial_rank(b"x".as_bstr(), b"refs/heads/x".as_bstr()), Some(3));
        assert_eq!(partial_rank(b"x".as_bstr(), b"refs/nope/x".as_bstr()), None);
    }

    #[test]
    fn spec_index_get() {
        let refspecs = vec![spec("refs/heads/a:refs/heads/a")];
        let extra = vec![spec("refs/heads/b:refs/heads/b")];
        assert_eq!(
            SpecIndex::ExplicitInRemote(0).get(&refspecs, &extra),
            Some(&refspecs[0])
        );
        assert_eq!(SpecIndex::Implicit(0).get(&refspecs, &extra), Some(&extra[0]));
        assert_eq!(SpecIndex::ExplicitInRemote(9).get(&refspecs, &extra), None);
    }

    // ── review-fix regressions (fused gpx05 review) ─────────────────────────────────────────

    /// Review fix 1: a ONE-SIDED glob spec (`refs/heads/*`, no dst) maps each matched branch to
    /// its own name (Push::Matching semantics) — previously it fell through as an empty-string
    /// qualify and aborted the whole push with `UnqualifiedDestination("")`.
    #[test]
    fn one_sided_glob_pushes_each_branch_to_its_own_name() {
        let p = Fix {
            specs: vec!["refs/heads/*"],
            locals: vec![("refs/heads/a", oid(1), None), ("refs/heads/b", oid(2), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        let mut names: Vec<_> = p
            .updates
            .iter()
            .map(|u| match u {
                RefUpdate::Create { name, .. } => name.as_bstr().to_owned(),
                other => panic!("expected creates, got {other:?}"),
            })
            .collect();
        names.sort();
        assert_eq!(names, vec!["refs/heads/a", "refs/heads/b"]);
    }

    /// Review fix 2: collapsing an exact-duplicate mapping keeps the STRONGER force — an explicit
    /// non-force spec plus `+refs/heads/main` must not silently drop the `+` (previously spec
    /// order decided and the force could vanish).
    #[test]
    fn exact_duplicate_keeps_the_stronger_force() {
        let p = Fix {
            specs: vec!["refs/heads/main:refs/heads/main", "+refs/heads/main:refs/heads/main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(3))],
            odb: HashSet::from([oid(3)]),
            ancestry: HashMap::from([((oid(3), oid(2)), Ancestry::NotAncestor)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1, "exact dup collapsed");
        assert_eq!(
            p.mappings[0].verdict,
            Verdict::Forced,
            "the + from the duplicate spec survives the collapse"
        );
    }

    // ── the E-catalog table (E1–E36 + symref-tag + E38/E39/E40) ─────────────────────────────

    #[test]
    fn e_create_new_branch() {
        let p = Fix {
            specs: vec!["refs/heads/f:refs/heads/f"],
            locals: vec![("refs/heads/f", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Create {
                name: fname("refs/heads/f"),
                new: oid(1)
            }]
        );
        assert_eq!(p.tips, vec![oid(1)]);
    }

    #[test]
    fn e_ff_update() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::FastForward);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Update {
                name: fname("refs/heads/main"),
                expected_old: oid(1),
                new: oid(2)
            }]
        );
        assert_eq!(p.tips, vec![oid(2)]);
    }

    #[test]
    fn e12_up_to_date() {
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(1), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::UpToDate);
        assert!(p.updates.is_empty());
        assert!(!p.has_updates());
    }

    #[test]
    fn e7_non_ff_reject() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(3)), Ancestry::NotAncestor);
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(3), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(3)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::RejectedNonFastForward);
        assert!(p.updates.is_empty());
    }

    #[test]
    fn e8_non_ff_forced_skips_ancestry() {
        // ancestry map is EMPTY: a query would panic, proving force skips the walk.
        let p = Fix {
            specs: vec!["+refs/heads/main"],
            locals: vec![("refs/heads/main", oid(3), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(3)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Forced);
        assert_eq!(p.mappings[0].force, Force::SpecForce);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Update {
                name: fname("refs/heads/main"),
                expected_old: oid(1),
                new: oid(3)
            }]
        );
    }

    #[test]
    fn e9_fetch_first() {
        // advertised old (1) is NOT in the local ODB.
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(3), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(3)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::RejectedFetchFirst);
    }

    #[test]
    fn e11_needs_force_non_commit() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(7)), Ancestry::NotComparable);
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(7), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(7)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::RejectedNeedsForce);
    }

    #[test]
    fn e10_tag_already_exists_before_ancestry() {
        // ancestry map EMPTY: the tag row must return before any ancestry/fetch-first query.
        let p = Fix {
            specs: vec!["refs/heads/main:refs/tags/v1"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/tags/v1", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::RejectedAlreadyExists);
    }

    #[test]
    fn delete_present() {
        let p = Fix {
            specs: vec![":refs/heads/gone"],
            advertised: vec![direct("refs/heads/gone", oid(1))],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Delete);
        assert!(p.mappings[0].local.is_none());
        assert_eq!(
            p.updates,
            vec![RefUpdate::Delete {
                name: fname("refs/heads/gone"),
                expected_old: oid(1)
            }]
        );
        assert!(p.tips.is_empty());
    }

    #[test]
    fn e4_delete_absent() {
        let err = Fix {
            specs: vec![":refs/heads/nope"],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::DeleteAbsentRef { .. }));
    }

    #[test]
    fn e5_glob_delete_is_unparseable_in_v1() {
        // gix-refspec rejects the `:glob` delete form as PatternUnbalanced (the empty src has no `*`
        // to balance the dst), so glob deletes are not expressible in v1 — deletes are always
        // literal. The plan's glob-delete branch stays as defensive/future-proof code, and the
        // `glob_match_single_star` matcher it uses is covered by its own unit test above.
        assert!(gix_refspec::parse(BStr::new(":refs/tmp/*"), gix_refspec::parse::Operation::Push).is_err());
    }

    #[test]
    fn e2_delete_unborn_counts_as_absent() {
        // An unborn advertised ref (points at nothing) counts as absent for a delete ⇒ DeleteAbsentRef.
        let err = Fix {
            specs: vec![":refs/heads/main"],
            advertised: vec![unborn("refs/heads/main")],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::DeleteAbsentRef { .. }));
    }

    #[test]
    fn e3_hidden_ref_plans_as_create_not_overwrite() {
        // F11: a ref absent from the advertisement (e.g. hidden by transfer.hideRefs) plans as a
        // Create with a zero old-oid — never a blind overwrite. Receive-pack's own old-oid check
        // then rejects it per-ref (the ng surfaces at gpx08's integration layer).
        let p = Fix {
            specs: vec!["refs/heads/secret:refs/heads/secret"],
            locals: vec![("refs/heads/secret", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1))], // non-empty, but `secret` is hidden
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
        assert_eq!(p.mappings[0].advertised, None);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Create {
                name: fname("refs/heads/secret"),
                new: oid(2)
            }]
        );
    }

    #[test]
    fn e36_annotated_tag_create_uses_tag_oid_as_tip() {
        // Creating an annotated tag: new = the ref's stored TAG oid (5), not the peeled commit (6);
        // the pack-walk tip is the tag oid (the walk peels it later).
        let p = Fix {
            specs: vec!["refs/tags/v1:refs/tags/v1"],
            locals: vec![("refs/tags/v1", oid(5), Some(oid(6)))],
            odb: HashSet::from([oid(5), oid(6)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Create {
                name: fname("refs/tags/v1"),
                new: oid(5)
            }]
        );
        assert_eq!(p.tips, vec![oid(5)]);
    }

    #[test]
    fn e6_delete_annotated_tag_leases_tag_oid() {
        let p = Fix {
            specs: vec![":refs/tags/v1"],
            advertised: vec![peeled("refs/tags/v1", oid(5), oid(6))],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(
            p.updates,
            vec![RefUpdate::Delete {
                name: fname("refs/tags/v1"),
                expected_old: oid(5) // the tag oid, NOT the peeled object oid(6)
            }]
        );
    }

    #[test]
    fn bare_src_partial_expands_destination() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let p = Fix {
            specs: vec!["main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].remote, fname("refs/heads/main"));
    }

    #[test]
    fn e21_dwim_precedence() {
        // `x` matches both refs/heads/x and refs/tags/x; dwim keeps refs/tags/x (first in precedence).
        let p = Fix {
            specs: vec!["x"],
            locals: vec![("refs/heads/x", oid(1), None), ("refs/tags/x", oid(2), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
        assert_eq!(
            p.mappings[0].local,
            Some(Source::Ref {
                name: fname("refs/tags/x"),
                id: oid(2)
            })
        );
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
    }

    #[test]
    fn e17_head_attached() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(4)), Ancestry::Ancestor);
        let p = Fix {
            specs: vec!["HEAD"],
            locals: vec![("refs/heads/dev", oid(4), None)],
            head: Some(HeadState::Symbolic {
                referent: fname("refs/heads/dev"),
                id: oid(4),
            }),
            advertised: vec![direct("refs/heads/dev", oid(1))],
            odb: HashSet::from([oid(1), oid(4)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
        assert_eq!(p.mappings[0].remote, fname("refs/heads/dev"));
        assert_eq!(p.mappings[0].verdict, Verdict::FastForward);
    }

    #[test]
    fn e18_head_detached_bare() {
        let err = Fix {
            specs: vec!["HEAD"],
            head: Some(HeadState::Detached { id: oid(4) }),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::DetachedHeadNeedsDestination));
    }

    #[test]
    fn e19_head_detached_with_destination() {
        let p = Fix {
            specs: vec!["HEAD:refs/heads/x"],
            head: Some(HeadState::Detached { id: oid(4) }),
            odb: HashSet::from([oid(4)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].local, Some(Source::Detached { id: oid(4) }));
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
    }

    #[test]
    fn e20_head_unborn() {
        let err = Fix {
            specs: vec!["HEAD"],
            head: None,
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::SourceMatchesNothing { .. }));
    }

    #[test]
    fn e15_object_id_lhs() {
        let a = oid(1);
        let hex = a.to_string();
        let s: &'static str = Box::leak(format!("{hex}:refs/heads/x").into_boxed_str());
        let p = Fix {
            specs: vec![s],
            odb: HashSet::from([a]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].local, Some(Source::ObjectId(a)));
        assert_eq!(p.mappings[0].verdict, Verdict::Create);

        // Same spec, object missing from the ODB ⇒ SourceObjectMissing.
        let err = Fix {
            specs: vec![s],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::SourceObjectMissing { .. }));
    }

    #[test]
    fn e16_revspec_lhs() {
        let mut revs = HashMap::new();
        revs.insert("HEAD~2", oid(1));
        let p = Fix {
            specs: vec!["HEAD~2:refs/heads/x"],
            odb: HashSet::from([oid(1)]),
            revs,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].local, Some(Source::ObjectId(oid(1))));
        assert_eq!(p.mappings[0].verdict, Verdict::Create);

        // Unresolvable rev-spec ⇒ SourceMatchesNothing.
        let err = Fix {
            specs: vec!["HEAD~2:refs/heads/x"],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::SourceMatchesNothing { .. }));
    }

    #[test]
    fn e13_src_matches_nothing() {
        let err = Fix {
            specs: vec!["refs/heads/nope:refs/heads/x"],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::SourceMatchesNothing { .. }));
    }

    #[test]
    fn e14_glob_matches_nothing() {
        let p = Fix {
            specs: vec!["refs/feat/*:refs/feat/*"],
            locals: vec![("refs/heads/main", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert!(p.mappings.is_empty());
    }

    #[test]
    fn e26_glob_pair() {
        let p = Fix {
            specs: vec!["refs/heads/*:refs/qa/*"],
            locals: vec![("refs/heads/a", oid(1), None), ("refs/heads/b", oid(2), None)],
            advertised: vec![direct("refs/qa/a", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        let qa_a = p.mappings.iter().find(|m| m.remote == fname("refs/qa/a")).unwrap();
        let qa_b = p.mappings.iter().find(|m| m.remote == fname("refs/qa/b")).unwrap();
        assert_eq!(qa_a.verdict, Verdict::UpToDate);
        assert_eq!(qa_b.verdict, Verdict::Create);
    }

    #[test]
    fn e29_negation_prunes_source() {
        let p = Fix {
            specs: vec!["refs/heads/*:refs/heads/*", "^refs/heads/wip"],
            locals: vec![("refs/heads/a", oid(1), None), ("refs/heads/wip", oid(2), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
        assert_eq!(p.mappings[0].remote, fname("refs/heads/a"));
    }

    #[test]
    fn e22_dst_qualify_branch() {
        let p = Fix {
            specs: vec!["refs/heads/a:b"],
            locals: vec![("refs/heads/a", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].remote, fname("refs/heads/b"));
    }

    #[test]
    fn e23_dst_qualify_tag() {
        let p = Fix {
            specs: vec!["refs/tags/v1:v1"],
            locals: vec![("refs/tags/v1", oid(5), Some(oid(6)))],
            odb: HashSet::from([oid(5)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].remote, fname("refs/tags/v1"));
    }

    #[test]
    fn e24_dst_qualify_advertised_beats_guess() {
        // dst `v1` with a branch source would guess refs/heads/v1, but the advertised refs/tags/v1
        // wins (advertised match, precedence tags-before-heads — git dwim_ref parity).
        let p = Fix {
            specs: vec!["refs/heads/a:v1"],
            locals: vec![("refs/heads/a", oid(1), None)],
            advertised: vec![direct("refs/tags/v1", oid(2))],
            odb: HashSet::from([oid(1), oid(2)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].remote, fname("refs/tags/v1"));
    }

    #[test]
    fn e25_dst_unqualified_object_source() {
        let a = oid(1);
        let s: &'static str = Box::leak(format!("{a}:x").into_boxed_str());
        let err = Fix {
            specs: vec![s],
            odb: HashSet::from([a]),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::UnqualifiedDestination { .. }));
    }

    #[test]
    fn e27_conflict() {
        let err = Fix {
            specs: vec!["refs/heads/a:refs/heads/dst", "refs/heads/b:refs/heads/dst"],
            locals: vec![("refs/heads/a", oid(1), None), ("refs/heads/b", oid(2), None)],
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        match err {
            Error::Conflict { sources, .. } => assert_eq!(sources.len(), 2),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn e28_duplicate_deduped() {
        let p = Fix {
            specs: vec!["refs/heads/a:refs/heads/a", "refs/heads/a:refs/heads/a"],
            locals: vec![("refs/heads/a", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
    }

    #[test]
    fn e30_matching_spec() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let p = Fix {
            specs: vec![":"],
            locals: vec![("refs/heads/a", oid(2), None), ("refs/heads/b", oid(3), None)],
            advertised: vec![direct("refs/heads/a", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings.len(), 1);
        assert_eq!(p.mappings[0].remote, fname("refs/heads/a"));
        assert_eq!(p.mappings[0].verdict, Verdict::FastForward);
    }

    #[test]
    fn e31_lease_exact_multi() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let err = Fix {
            specs: vec!["refs/heads/main", "refs/heads/topic"],
            locals: vec![("refs/heads/main", oid(2), None), ("refs/heads/topic", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1)), direct("refs/heads/topic", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            lease: LeasePolicy::ForceWithLease(Lease::Exact(oid(1))),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::LeaseRequiresSingleUpdate { candidates: 2 }));
    }

    #[test]
    fn e32_lease_exact_stale() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let err = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            lease: LeasePolicy::ForceWithLease(Lease::Exact(oid(9))),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        match err {
            Error::StaleLease { expected, actual, .. } => {
                assert_eq!(expected, Some(oid(9)));
                assert_eq!(actual, Some(oid(1)));
            }
            other => panic!("expected StaleLease, got {other:?}"),
        }
    }

    #[test]
    fn e33_lease_tracking_stale_even_when_up_to_date() {
        let mut tracking = HashMap::new();
        tracking.insert("refs/heads/main", oid(9));
        let err = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(1), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1)]),
            tracking,
            lease: LeasePolicy::ForceWithLease(Lease::TrackingRef),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::StaleLease { .. }));
    }

    #[test]
    fn e34_lease_tracking_missing() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let err = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            lease: LeasePolicy::ForceWithLease(Lease::TrackingRef),
            ..Default::default()
        }
        .plan()
        .unwrap_err();
        assert!(matches!(err, Error::LeaseTrackingRefMissing { .. }));
    }

    #[test]
    fn e35_lease_grants_force() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(3)), Ancestry::NotAncestor);
        let mut tracking = HashMap::new();
        tracking.insert("refs/heads/main", oid(1));
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(3), None)],
            advertised: vec![direct("refs/heads/main", oid(1))],
            odb: HashSet::from([oid(1), oid(3)]),
            ancestry,
            tracking,
            lease: LeasePolicy::ForceWithLease(Lease::TrackingRef),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Forced);
        assert_eq!(p.mappings[0].force, Force::LeaseHeld);
        assert_eq!(
            p.updates,
            vec![RefUpdate::Update {
                name: fname("refs/heads/main"),
                expected_old: oid(1),
                new: oid(3)
            }]
        );
    }

    #[test]
    fn e1_unborn_advertised_ref_is_create() {
        let p = Fix {
            specs: vec!["refs/heads/main:refs/heads/main"],
            locals: vec![("refs/heads/main", oid(1), None)],
            advertised: vec![unborn("refs/heads/main")],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].verdict, Verdict::Create);
    }

    #[test]
    fn e40_symbolic_advertised_value() {
        let mut ancestry = HashMap::new();
        ancestry.insert((oid(1), oid(2)), Ancestry::Ancestor);
        let p = Fix {
            specs: vec!["refs/heads/main"],
            locals: vec![("refs/heads/main", oid(2), None)],
            advertised: vec![symbolic("refs/heads/main", "refs/heads/other", None, oid(1))],
            odb: HashSet::from([oid(1), oid(2)]),
            ancestry,
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].advertised, Some(oid(1)));
        assert_eq!(
            p.updates,
            vec![RefUpdate::Update {
                name: fname("refs/heads/main"),
                expected_old: oid(1),
                new: oid(2)
            }]
        );
    }

    #[test]
    fn symref_to_annotated_tag_leases_tag_oid() {
        // A dst advertised as Symbolic { tag: Some } (symref→annotated tag): expected_old is the TAG
        // oid (5), never the peeled object (6) — FOLLOWUPS §5, applied to P5's own scan.
        let p = Fix {
            specs: vec!["+refs/heads/main"],
            locals: vec![("refs/heads/main", oid(7), None)],
            advertised: vec![symbolic("refs/heads/main", "refs/tags/v", Some(oid(5)), oid(6))],
            odb: HashSet::from([oid(5), oid(7)]),
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].advertised, Some(oid(5)));
        assert_eq!(
            p.updates,
            vec![RefUpdate::Update {
                name: fname("refs/heads/main"),
                expected_old: oid(5),
                new: oid(7)
            }]
        );
    }

    #[test]
    fn e38_implicit_spec_index() {
        let p = Fix {
            specs: vec![],
            extra: vec!["refs/heads/a:refs/heads/a"],
            locals: vec![("refs/heads/a", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.mappings[0].spec_index, SpecIndex::Implicit(0));
    }

    #[test]
    fn e39_force_delete() {
        let p = Fix {
            specs: vec!["+:refs/heads/x"],
            advertised: vec![direct("refs/heads/x", oid(1))],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(
            p.updates,
            vec![RefUpdate::Delete {
                name: fname("refs/heads/x"),
                expected_old: oid(1)
            }]
        );
    }

    #[test]
    fn tips_are_deduplicated_in_command_order() {
        let p = Fix {
            specs: vec!["refs/heads/a:refs/heads/x", "refs/heads/b:refs/heads/y"],
            locals: vec![("refs/heads/a", oid(1), None), ("refs/heads/b", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert_eq!(p.updates.len(), 2);
        assert_eq!(p.tips, vec![oid(1)]);
    }

    #[test]
    fn mapping_of_correlates_update_index() {
        let p = Fix {
            specs: vec!["refs/heads/f:refs/heads/f"],
            locals: vec![("refs/heads/f", oid(1), None)],
            ..Default::default()
        }
        .plan()
        .unwrap();
        assert!(p.mapping_of(0).is_some());
        assert_eq!(p.mapping_of(0).unwrap().remote, fname("refs/heads/f"));
    }
}

/// `plan()` repo-adapter integration (gpx07): drive the adapter against a real repository built by a
/// real `git`, pinning that the local-ref/HEAD snapshot + oracles feed the pure core correctly. Gated
/// on `revision` (the adapter's own gate); the module already only compiles under a network-client
/// feature, and `gix-testtools` is a dev-dependency.
#[cfg(all(test, feature = "revision"))]
mod adapter_integration {
    use std::path::Path;

    use gix_protocol::handshake;
    use gix_ref::FullName;

    use super::{LeasePolicy, Verdict, plan};
    use crate::bstr::BStr;

    fn git(args: &[&str], cwd: &Path) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .status()
            .expect("the `git` binary is available for the plan() adapter test");
        assert!(status.success(), "git {args:?} failed");
    }

    fn push_spec(s: &str) -> gix_refspec::RefSpec {
        gix_refspec::parse(BStr::new(s), gix_refspec::parse::Operation::Push)
            .expect("valid push refspec")
            .to_owned()
    }
    fn fetch_spec(s: &str) -> gix_refspec::RefSpec {
        gix_refspec::parse(BStr::new(s), gix_refspec::parse::Operation::Fetch)
            .expect("valid fetch refspec")
            .to_owned()
    }
    fn fname(s: &str) -> FullName {
        FullName::try_from(s).expect("valid full ref name")
    }

    /// A repo with a single commit on `refs/heads/main`, opened isolated; returns `(tempdir, repo,
    /// main-oid)`.
    fn repo_with_main() -> (gix_testtools::tempfile::TempDir, crate::Repository, gix_hash::ObjectId) {
        let tmp = gix_testtools::tempfile::TempDir::new().expect("tempdir");
        let root = tmp.path();
        git(&["init", "--quiet", "-b", "main"], root);
        std::fs::write(root.join("f.txt"), b"hi").expect("write file");
        git(&["add", "f.txt"], root);
        git(&["commit", "--quiet", "-m", "c1"], root);
        let repo = crate::open_opts(root, crate::open::Options::isolated()).expect("open repo");
        let main = repo
            .find_reference("refs/heads/main")
            .expect("main exists")
            .into_fully_peeled_id()
            .expect("peel main")
            .detach();
        (tmp, repo, main)
    }

    fn detached_remote(push: &[&str], fetch: &[&str]) -> crate::types::RemoteDetached {
        crate::types::RemoteDetached {
            name: None,
            urls: Vec::new(),
            url_aliases: Vec::new(),
            url_push_aliases: Vec::new(),
            fetch_specs: fetch.iter().map(|s| fetch_spec(s)).collect(),
            push_urls: Vec::new(),
            push_url_aliases: Vec::new(),
            push_specs: push.iter().map(|s| push_spec(s)).collect(),
            fetch_tags: Default::default(),
        }
    }

    /// An advertisement that lacks the pushed dst ⇒ the adapter plans a `Create` whose new-oid is the
    /// snapshotted local `refs/heads/main` value.
    #[test]
    fn create_when_remote_lacks_the_branch() {
        let (_tmp, repo, main) = repo_with_main();
        let remote = detached_remote(
            &["refs/heads/main:refs/heads/main"],
            &["+refs/heads/*:refs/remotes/origin/*"],
        );
        let plan = plan(&repo, &remote, &[], &[], LeasePolicy::AdvertisedOnly).expect("plan succeeds");
        assert_eq!(plan.mappings.len(), 1);
        assert_eq!(plan.mappings[0].verdict, Verdict::Create);
        assert_eq!(plan.mappings[0].remote, fname("refs/heads/main"));
        assert_eq!(plan.mappings[0].new, Some(main));
        assert_eq!(plan.updates.len(), 1);
    }

    /// An advertisement already at the local value ⇒ `UpToDate`, no wire command (the adapter reads
    /// the real advertised oid through `advertised_value_of`).
    #[test]
    fn up_to_date_when_remote_matches_local() {
        let (_tmp, repo, main) = repo_with_main();
        let remote = detached_remote(
            &["refs/heads/main:refs/heads/main"],
            &["+refs/heads/*:refs/remotes/origin/*"],
        );
        let advertised = vec![handshake::Ref::Direct {
            full_ref_name: "refs/heads/main".into(),
            object: main,
        }];
        let plan = plan(&repo, &remote, &[], &advertised, LeasePolicy::AdvertisedOnly).expect("plan succeeds");
        assert_eq!(plan.mappings.len(), 1);
        assert_eq!(plan.mappings[0].verdict, Verdict::UpToDate);
        assert!(plan.updates.is_empty(), "up-to-date sends no command");
    }

    /// Fused-review requirement: exercise the REAL merge_base oracle's "ancestor" branch — the
    /// remote sits at C1, local advanced to C2 (child of C1) ⇒ `FastForward` update.
    #[test]
    fn fast_forward_when_remote_is_an_ancestor() {
        let (tmp, _repo, c1) = repo_with_main();
        let root = tmp.path();
        std::fs::write(root.join("f.txt"), b"hi2").expect("write file");
        git(&["add", "f.txt"], root);
        git(&["commit", "--quiet", "-m", "c2"], root);
        let repo = crate::open_opts(root, crate::open::Options::isolated()).expect("reopen repo");
        let c2 = repo
            .find_reference("refs/heads/main")
            .expect("main exists")
            .into_fully_peeled_id()
            .expect("peel main")
            .detach();
        assert_ne!(c1, c2);
        let remote = detached_remote(
            &["refs/heads/main:refs/heads/main"],
            &["+refs/heads/*:refs/remotes/origin/*"],
        );
        let advertised = vec![handshake::Ref::Direct {
            full_ref_name: "refs/heads/main".into(),
            object: c1,
        }];
        let plan = plan(&repo, &remote, &[], &advertised, LeasePolicy::AdvertisedOnly).expect("plan succeeds");
        assert_eq!(plan.mappings[0].verdict, Verdict::FastForward, "C1 is C2's ancestor");
        assert_eq!(plan.updates.len(), 1, "a fast-forward emits the update command");
    }

    /// Fused-review requirement: the "not an ancestor" branch — the remote holds a DIVERGENT commit
    /// (sibling of local main, both children of the root) ⇒ `RejectedNonFastForward`, reject-as-data.
    #[test]
    fn non_fast_forward_when_histories_diverge() {
        let (tmp, _repo, c1) = repo_with_main();
        let root = tmp.path();
        // Advance main to C2, then create a divergent sibling D (child of C1) on a side branch —
        // the remote advertises D while we push C2: D is not an ancestor of C2.
        std::fs::write(root.join("f.txt"), b"hi2").expect("write file");
        git(&["add", "f.txt"], root);
        git(&["commit", "--quiet", "-m", "c2"], root);
        git(&["checkout", "--quiet", "-b", "side", &c1.to_string()], root);
        std::fs::write(root.join("g.txt"), b"divergent").expect("write file");
        git(&["add", "g.txt"], root);
        git(&["commit", "--quiet", "-m", "d"], root);
        let repo = crate::open_opts(root, crate::open::Options::isolated()).expect("reopen repo");
        let d = repo
            .find_reference("refs/heads/side")
            .expect("side exists")
            .into_fully_peeled_id()
            .expect("peel side")
            .detach();
        let remote = detached_remote(
            &["refs/heads/main:refs/heads/main"],
            &["+refs/heads/*:refs/remotes/origin/*"],
        );
        let advertised = vec![handshake::Ref::Direct {
            full_ref_name: "refs/heads/main".into(),
            object: d,
        }];
        let plan = plan(&repo, &remote, &[], &advertised, LeasePolicy::AdvertisedOnly).expect("plan succeeds");
        assert_eq!(
            plan.mappings[0].verdict,
            Verdict::RejectedNonFastForward,
            "divergent remote tip is a reject-as-data, not an error"
        );
        assert!(plan.updates.is_empty(), "a rejected mapping emits no wire command");
    }
}
