//! The push **pack driver** (`gpx06` / design `P6`): turn a set of local ref tips plus the
//! server's advertised boundaries into the pack bytes `git-receive-pack` expects, using the
//! `gix_pack::data::output` pipeline (enabled in `gix` by the `gix-pack/generate` feature, E2).
//!
//! The sibling of fetch's [`receive_pack`](super::super::fetch) closure: fetch **receives** a pack
//! and indexes it; push **builds** one and streams it. This module owns only the *construction* —
//! the [`gix_protocol::push`] wiring that hands the closure to the wire is `gpx08`'s job.
//!
//! # Pipeline (verified against `gitoxide-core::pack::create`)
//! `Simple::new(commit_tips, find).hide(boundaries)?` (multi-tip / multi-boundary revwalk) →
//! NB: at MERGE tips the tree-diff expansion may over-include blobs reachable from another
//! boundary line (harmless — the server dedups; see the multi-boundary test). Strict rev-list
//! equality holds for linear history.
//! [`count::objects_unthreaded`] with [`TreeAdditionsComparedToAncestor`] (single-threaded for
//! deterministic output) → the **boundary scrub** (below) → append blob/tag standalone tips →
//! [`iter_from_counts`] with [`PackCopyAndBaseObjects`] and `allow_thin_pack = false` (§7-R1: no
//! fresh delta search) → [`FromEntriesIter`] streaming V2 pack bytes to the writer. A 0-object pack
//! is valid and still written (header + trailer); *delete-only* pushes never call this at all
//! (`gpx08` short-circuits, so this module sees no such case).
//!
//! # Boundary scrub (design Discovery A / amendment B4)
//! `TreeAdditionsComparedToAncestor` diffs each visible commit's tree against its parents'. At the
//! frontier — a visible commit whose parent is *hidden* (reachable from a boundary, i.e. the server
//! already has it) — the counting pass emits that parent **commit** and its **root tree** into the
//! counts, even though the server has them. The scrub removes exactly those leaked objects so the
//! emitted set equals `git rev-list --objects <tips> --not <boundaries>` (an *equality*, not a
//! superset).
//!
//! We compute the leaked set from the **visible frontier** rather than from the boundary tips:
//! `hidden_parents = (⋃ visible.parent_ids) − visible`, plus each hidden parent's root tree. This is
//! a deliberate strengthening of B4's boundary-tip closure, which only catches leaks one hop from a
//! boundary tip and would miss a *deep* shared base (the `hide()` frontier can sit many commits
//! below the advertised tip). The frontier formulation catches the leak at whatever depth it occurs
//! and is what makes the shared-base parity test (B1) an equality — see the module tests.

// The whole pack driver is exercised by this module's own tests but has no in-crate caller until
// `gpx08` (the `send()` terminal) hands `make_write_pack`'s closure to `gix_protocol::push`; allow
// dead_code until then, mirroring the `gpx01` accessors' `#[allow(dead_code)]` scaffolding.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use gix_hash::ObjectId;
use gix_pack::data::output::{Count as OutputCount, bytes::FromEntriesIter, count, entry};
use gix_protocol::handshake::Ref;
use gix_utils::progress::{Count, DynNestedProgress, Progress};

use super::ProgressId;

/// The error produced while building a pack for a push.
///
/// Later units append their own variants as the driver grows; the enum is intentionally not
/// `#[non_exhaustive]`, matching gitoxide's evolution mode for error types. The wrapped
/// [`gix::Error`](crate::Error)s are the erased failures of the respective `gix-traverse`, `gix-pack`
/// and `gix-object` step.
#[derive(Debug)]
pub enum Error {
    Interrupted,
    // NB: a mid-count interrupt arrives as a cancelled `Count` error; write_pack remaps it to the
    // uniform Interrupted above (review F3).
    Traverse(gix_error::Error),
    Count(gix_error::Error),
    IterEntries(gix_error::Error),
    PackWrite(gix_error::Error),
    Find(gix_error::Error),
    Decode(gix_error::Error),
    MergeRepairDiff(Box<dyn std::error::Error + Send + Sync + 'static>),
    MissingObject {
        /// The object that could not be found.
        id: ObjectId,
    },
    UnsupportedTipType {
        /// The tree object that was offered as a tip.
        id: ObjectId,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Interrupted => f.write_str("Interrupted while building the pack"),
            Error::Traverse(err)
            | Error::Count(err)
            | Error::IterEntries(err)
            | Error::PackWrite(err)
            | Error::Find(err)
            | Error::Decode(err) => std::fmt::Display::fmt(err, f),
            Error::MergeRepairDiff(_) => {
                f.write_str("Failed to diff a merge parent's tree during the merge-undercount repair")
            }
            Error::MissingObject { id } => {
                write!(
                    f,
                    "The object {id} to be pushed is missing from the local object database"
                )
            }
            Error::UnsupportedTipType { id } => write!(
                f,
                "Refusing to push the tree object {id} as a ref tip — only commits, annotated tags, and \
                 blobs may be a ref's value; a bare tree has no receive-pack meaning"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Interrupted => Some(const { &gix_error::ClassificationMarker::CANCELLED }),
            Error::Traverse(err)
            | Error::Count(err)
            | Error::IterEntries(err)
            | Error::PackWrite(err)
            | Error::Find(err)
            | Error::Decode(err) => Some(err),
            Error::MergeRepairDiff(err) => Some(&**err),
            Error::MissingObject { .. } => Some(const { &gix_error::ClassificationMarker::NOT_FOUND }),
            Error::UnsupportedTipType { .. } => Some(const { &gix_error::ClassificationMarker::UNSUPPORTED }),
        }
    }
}

/// Statistics gathered while building the pack, surfaced to the caller so `gpx08` can expose them as
/// `push::Status::Pushed { write_pack: Option<Outcome> }`.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The number of objects written into the pack (its header count).
    pub object_count: u32,
    /// The pack's trailing checksum, present once the pack has been fully written.
    pub pack_hash: Option<ObjectId>,
    /// Statistics from the counting phase.
    pub counts: count::objects::Outcome,
    /// Statistics from the entry-generation phase.
    pub entries: entry::iter_from_counts::Outcome,
}

/// Compute the pack **boundaries** from the server's whole handshake `advertised` ref list: every
/// advertised ref value that is also present in the local object database (`db.contains`).
///
/// This owns the `∩ local ODB` filter (design seam ruling B1: P6, not P5, owns it) and is exact
/// C-git `send-pack` parity — the boundary set is *all* advertised refs, not just the ones being
/// pushed to, so pushing `feature` to a remote that also has `main` at a shared base hides that base
/// (via `main`) and the pack excludes its history. Dropping a boundary we lack locally is silent in
/// v1 (a correct-but-larger pack; a dry-run warning arrives with `gpx09`/`P9`).
///
/// For an annotated tag ref (`Ref::Peeled`) both the `tag` value (amendment B2, the ref's real
/// identity) and the peeled `object` are included: the tag oid keeps the tag object out of the pack,
/// while the peeled commit is what actually feeds the commit-history `hide()`. `Ref::Unborn` has no
/// value and contributes nothing.
pub fn boundaries_from_advertised(advertised: &[Ref], db: &impl gix_pack::Find) -> Vec<ObjectId> {
    let mut out = Vec::new();
    let mut seen = gix_hashtable::HashSet::default();
    let mut add = |oid: ObjectId| {
        if db.contains(&oid) && seen.insert(oid) {
            out.push(oid);
        }
    };
    for r in advertised {
        match r {
            Ref::Direct { object, .. } => add(*object),
            Ref::Peeled { tag, object, .. } => {
                add(*tag);
                add(*object);
            }
            Ref::Symbolic { tag, object, .. } => {
                if let Some(tag) = tag {
                    add(*tag);
                }
                add(*object);
            }
            Ref::Unborn { .. } => {}
        }
    }
    out
}

/// Build a pack containing everything reachable from `tips` but not from `boundaries`, streaming its
/// bytes into `out`.
///
/// This is the free-function core the design (Q7) settles on: it takes **no `Repository`**, only a
/// pack-capable object store `objects`. NOTE (B11 correction, verified against the base):
/// `repo.objects` is a `gix_odb::memory::Proxy` and `.clone().into_arc()` KEEPS the proxy wrapper,
/// which implements `gix_object::Find` but NOT `gix_pack::Find` — it does not satisfy this
/// function's bound. The caller (gpx08) must build a dedicated pack-capable handle instead, e.g.
/// `gix_odb::at(repo.git_dir().join("objects"))?.into_arc()?` and call `prevent_pack_unload()` on
/// it first (exactly as the test `Fixture::odb()` below does).
///
/// `tips` are classified by object kind: commits seed the revwalk; blobs and annotated tags are
/// emitted verbatim as standalone entries (a tag also peels its target into the commit walk so a
/// target the server already has is still excluded); a bare tree tip is refused with
/// [`Error::UnsupportedTipType`]. `object_hash` selects the pack checksum algorithm.
///
/// Emits [`ProgressId::CountObjects`] and [`ProgressId::WritePack`] as child progress.
///
/// # Handle configuration (precondition)
/// `objects` **must** have had `prevent_pack_unload()` called on it before this (the pack pipeline
/// resolves pack locations via `location_by_oid`, which panics otherwise). This mirrors
/// `gitoxide-core::pack::create`, which configures the handle up front; the setting is preserved
/// across the `Clone`s this function makes. `gpx08` configures the handle when it builds it.
pub fn write_pack<F>(
    objects: F,
    tips: impl IntoIterator<Item = ObjectId>,
    boundaries: Vec<ObjectId>,
    object_hash: gix_hash::Kind,
    out: &mut dyn std::io::Write,
    progress: &mut dyn DynNestedProgress,
    should_interrupt: &AtomicBool,
) -> Result<Outcome, Error>
where
    F: gix_pack::Find + gix_object::Find + gix_object::FindHeader + Clone + Send + 'static,
{
    if should_interrupt.load(Ordering::Relaxed) {
        return Err(Error::Interrupted);
    }

    // 1. Classify tips into the commit walk vs. the standalone (blob/tag) entries.
    let mut commit_tips: Vec<ObjectId> = Vec::new();
    let mut standalone: Vec<ObjectId> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    for tip in tips {
        classify_tip(&objects, tip, &mut commit_tips, &mut standalone, &mut buf)?;
    }

    // 2. Revwalk the visible commits (tips minus boundaries), recording the visible set and the
    //    union of parents so the boundary scrub can find the hidden frontier.
    let mut counting = progress.add_child_with_id("counting objects".into(), ProgressId::CountObjects.into());
    counting.init(None, gix_utils::progress::count("objects"));

    let mut visible = gix_hashtable::HashSet::default();
    let mut visible_ids: Vec<ObjectId> = Vec::new();
    let mut parent_union: Vec<ObjectId> = Vec::new();
    {
        let walk = gix_traverse::commit::Simple::new(commit_tips.iter().copied(), objects.clone())
            .hide(boundaries.clone())
            .map_err(Error::Traverse)?;
        for info in walk {
            let info = info.map_err(Error::Traverse)?;
            if visible.insert(info.id) {
                visible_ids.push(info.id);
            }
            parent_union.extend(info.parent_ids.iter().copied());
        }
    }

    // 3. Count objects with tree-diff expansion (single-threaded → deterministic order).
    let (mut counts, count_stats) = {
        let mut input = visible_ids.iter().map(|id| Ok::<ObjectId, gix_error::Error>(*id));
        count::objects_unthreaded(
            &objects,
            &mut input,
            &counting,
            should_interrupt,
            count::objects::ObjectExpansion::TreeAdditionsComparedToAncestor,
        )
        .map_err(|e| {
            if e.is_cancelled() {
                Error::Interrupted
            } else {
                Error::Count(e)
            }
        })?
    };

    // 4. Boundary scrub: drop the hidden frontier parents + their root trees that the tree-diff
    //    expansion leaked into the counts (see the module docs). Computed from the visible frontier
    //    so it holds at any shared-base depth.
    let scrub = hidden_frontier_scrub(&objects, &visible, &parent_union, &mut buf);
    if !scrub.is_empty() {
        counts.retain(|c| !scrub.contains(&c.id));
    }

    // 4b. Merge-undercount repair — an UPSTREAM gix-pack defect (v0.63.0,
    //    `output/count/objects/tree.rs` `AllNew`): its `all_seen` set is shared across the
    //    per-parent diff loop while `clear()` only clears `objects`, so for a MERGE commit the
    //    additions recorded against the first parent(s) — whose diff result is then DISCARDED —
    //    poison the seen-set and vanish from the kept last-parent diff. Net effect: genuinely-new
    //    objects are silently missing from the count and the pack is INCOMPLETE for any merge tip
    //    (proven by `multi_boundary_merge_excludes_both_histories`). Repair: recompute the UNION
    //    of tree-diff additions across ALL parents for every visible merge commit and append what
    //    the count missed. Over-inclusion is safe (the server dedups); omission is a broken pack.
    //    Upstream-report candidate; remove this block when the base fixes `AllNew`.
    {
        let counted: gix_hashtable::HashSet = counts.iter().map(|c| c.id).collect();
        let mut missing: Vec<ObjectId> = Vec::new();
        let mut state = gix_diff::tree::State::default();
        let mut buf_parent: Vec<u8> = Vec::new();
        let mut buf_tree: Vec<u8> = Vec::new();
        for id in &visible_ids {
            if should_interrupt.load(Ordering::Relaxed) {
                return Err(Error::Interrupted);
            }
            let commit = gix_object::Find::try_find(&objects, id, &mut buf)
                .map_err(Error::Find)?
                .ok_or_else(|| Error::MissingObject { id: *id })?;
            let mut iter = gix_object::CommitRefIter::from_bytes(commit.data, object_hash);
            let tree_id = iter.tree_id().expect("every commit names a tree");
            let parents: Vec<ObjectId> = iter.parent_ids().collect();
            if parents.len() < 2 {
                continue;
            }
            let mut union = MergeAdditions::default();
            for parent in &parents {
                let parent_commit = gix_object::Find::try_find(&objects, parent, &mut buf_parent)
                    .map_err(Error::Find)?
                    .ok_or_else(|| Error::MissingObject { id: *parent })?;
                let parent_tree_id = gix_object::CommitRefIter::from_bytes(parent_commit.data, object_hash)
                    .tree_id()
                    .expect("every commit names a tree");
                let parent_tree = gix_object::Find::try_find(&objects, &parent_tree_id, &mut buf_parent)
                    .map_err(Error::Find)?
                    .ok_or_else(|| Error::MissingObject { id: parent_tree_id })?;
                let current_tree = gix_object::Find::try_find(&objects, &tree_id, &mut buf_tree)
                    .map_err(Error::Find)?
                    .ok_or_else(|| Error::MissingObject { id: tree_id })?;
                gix_diff::tree(
                    gix_object::TreeRefIter::from_bytes(parent_tree.data, object_hash),
                    gix_object::TreeRefIter::from_bytes(current_tree.data, object_hash),
                    &mut state,
                    &objects,
                    &mut union,
                )
                .map_err(|e| Error::MergeRepairDiff(Box::new(e)))?;
            }
            for oid in union.objects {
                if !counted.contains(&oid) {
                    missing.push(oid);
                }
            }
        }
        if !missing.is_empty() {
            let mut pack_buf = Vec::new();
            for oid in missing {
                let location = gix_pack::Find::location_by_oid(&objects, &oid, &mut pack_buf).map_err(Error::Find)?;
                counts.push(OutputCount::from_data(oid, location));
            }
        }
    }

    // 5. Append the standalone (blob/tag) tips as base entries, de-duplicated against the walk.
    let mut seen: gix_hashtable::HashSet = counts.iter().map(|c| c.id).collect();
    for id in standalone {
        if seen.insert(id) {
            counts.push(OutputCount {
                id,
                entry_pack_location: count::PackLocation::NotLookedUp,
            });
        }
    }

    // 6. Generate entries and stream the pack bytes.
    let object_count = counts.len() as u32;
    let entries_progress = progress.add_child_with_id("creating entries".into(), gix_utils::progress::UNKNOWN);
    let in_order = gix_parallel::InOrderIter::from(
        entry::iter_from_counts(
            counts,
            objects.clone(),
            Box::new(entries_progress),
            entry::iter_from_counts::Options {
                version: gix_pack::data::Version::V2,
                mode: entry::iter_from_counts::Mode::PackCopyAndBaseObjects,
                allow_thin_pack: false,
                // Single-threaded generation so the streamed byte order is deterministic.
                thread_limit: Some(1),
                chunk_size: 1000,
                // Deflate level for objects not copied from an existing pack; DEFAULT matches git's
                // pack.compression default and the field's own default (upstream added it in the
                // gix-zlib split, so the initializer is no longer inferable from `..Default::default()`).
                compression: gix_zlib::Compression::DEFAULT,
            },
        )
        .map_err(Error::IterEntries)?,
    );

    let mut writing = progress.add_child_with_id("writing pack".into(), ProgressId::WritePack.into());
    writing.init(None, gix_utils::progress::bytes());

    let mut from_entries = FromEntriesIter::new(in_order, out, object_count, gix_pack::data::Version::V2, object_hash);
    for written in from_entries.by_ref() {
        if should_interrupt.load(Ordering::Relaxed) {
            return Err(Error::Interrupted);
        }
        let written = written.map_err(Error::PackWrite)?;
        writing.inc_by(written as usize);
    }
    let pack_hash = from_entries.digest();

    use gix_parallel::Finalize;
    // Reaches through FromEntriesIter's public `input`/`inner` fields (vendored gix-pack v0.63.0
    // layout) to recover the entries-written stat; a base bump that reshapes FromEntriesIter will
    // surface here as a compile error, which is the desired breakage mode (review note).
    let entries = from_entries.input.inner.finalize().map_err(Error::IterEntries)?;

    Ok(Outcome {
        object_count,
        pack_hash,
        // NB: captured PRE-scrub, so `counts.total_objects` over-reports by the scrubbed leak
        // count; `object_count` (the pack header figure) is the authoritative number (review F4).
        counts: count_stats,
        entries,
    })
}

/// The synchronous pack-writing closure `gix_protocol::push()` demands (F6): a
/// `FnOnce(&mut dyn io::Write, &mut dyn DynNestedProgress, &AtomicBool) -> Result<(), Error>`.
///
/// Returns the closure together with a shared [`Outcome`] slot; the slot is filled once the closure
/// has run so the caller (`gpx08`) can read the pack statistics into `push::Status::Pushed`. The
/// slot uses the fetch-side `Rc<RefCell<Option<_>>>` capture idiom; it is `!Send`, which is fine for
/// the blocking `gix_protocol::push` whose closure is a bare `FnOnce`.
#[allow(clippy::type_complexity)]
pub fn make_write_pack<F>(
    objects: F,
    tips: Vec<ObjectId>,
    boundaries: Vec<ObjectId>,
    object_hash: gix_hash::Kind,
) -> (
    impl FnOnce(&mut dyn std::io::Write, &mut dyn DynNestedProgress, &AtomicBool) -> Result<(), Error>,
    std::rc::Rc<std::cell::RefCell<Option<Outcome>>>,
)
where
    F: gix_pack::Find + gix_object::Find + gix_object::FindHeader + Clone + Send + 'static,
{
    let stats = std::rc::Rc::new(std::cell::RefCell::new(None));
    let stats_out = std::rc::Rc::clone(&stats);
    let closure = move |out: &mut dyn std::io::Write,
                        progress: &mut dyn DynNestedProgress,
                        should_interrupt: &AtomicBool|
          -> Result<(), Error> {
        let outcome = write_pack(objects, tips, boundaries, object_hash, out, progress, should_interrupt)?;
        *stats_out.borrow_mut() = Some(outcome);
        Ok(())
    };
    (closure, stats)
}

/// Classify a single tip by object kind, following annotated-tag chains.
fn classify_tip<F>(
    objects: &F,
    tip: ObjectId,
    commit_tips: &mut Vec<ObjectId>,
    standalone: &mut Vec<ObjectId>,
    buf: &mut Vec<u8>,
) -> Result<(), Error>
where
    F: gix_object::Find,
{
    enum Step {
        Commit,
        Blob,
        Tree,
        Tag(ObjectId),
    }
    let mut cur = tip;
    loop {
        let step = {
            let data = objects
                .try_find(&cur, buf)
                .map_err(Error::Find)?
                .ok_or(Error::MissingObject { id: cur })?;
            match data.kind {
                gix_object::Kind::Commit => Step::Commit,
                gix_object::Kind::Blob => Step::Blob,
                gix_object::Kind::Tree => Step::Tree,
                gix_object::Kind::Tag => Step::Tag(
                    gix_object::TagRefIter::from_bytes(data.data, cur.kind())
                        .target_id()
                        .map_err(Error::Decode)?,
                ),
            }
        };
        match step {
            Step::Commit => {
                commit_tips.push(cur);
                return Ok(());
            }
            Step::Blob => {
                standalone.push(cur);
                return Ok(());
            }
            Step::Tree => return Err(Error::UnsupportedTipType { id: cur }),
            Step::Tag(target) => {
                // Emit the tag object itself; peel to its target so the target's history is packed
                // by the normal walk-minus-boundaries (a target the server has is thus excluded).
                standalone.push(cur);
                cur = target;
            }
        }
    }
}

/// Compute the scrub set: hidden frontier parent commits (parents of visible commits that are not
/// themselves visible) plus each such commit's root tree.
/// The union-of-additions delegate for the merge-undercount repair (4b): records every added or
/// modified tree/blob oid across successive per-parent diffs WITHOUT a cross-parent seen-poisoning
/// clear bug — the whole point of the repair. Submodule (commit-mode) entries are skipped, exactly
/// as upstream `AllNew` does.
#[derive(Default)]
struct MergeAdditions {
    objects: Vec<ObjectId>,
    seen: gix_hashtable::HashSet,
}

impl gix_diff::tree::Visit for MergeAdditions {
    fn pop_front_tracked_path_and_set_current(&mut self) {}
    fn push_back_tracked_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn push_path_component(&mut self, _component: &gix_object::bstr::BStr) {}
    fn pop_path_component(&mut self) {}
    fn visit(&mut self, change: gix_diff::tree::visit::Change) -> gix_diff::tree::visit::Action {
        use gix_diff::tree::visit::Change;
        match change {
            Change::Addition { oid, entry_mode, .. } | Change::Modification { oid, entry_mode, .. } => {
                if !entry_mode.is_commit() && self.seen.insert(oid) {
                    self.objects.push(oid);
                }
            }
            Change::Deletion { .. } => {}
        }
        std::ops::ControlFlow::Continue(())
    }
}

fn hidden_frontier_scrub<F>(
    objects: &F,
    visible: &gix_hashtable::HashSet,
    parent_union: &[ObjectId],
    buf: &mut Vec<u8>,
) -> gix_hashtable::HashSet
where
    F: gix_object::Find,
{
    let mut scrub = gix_hashtable::HashSet::default();
    for parent in parent_union {
        if visible.contains(parent) || !scrub.insert(*parent) {
            continue;
        }
        // The parent commit leaked as a count; its root tree leaked alongside it. Both are reachable
        // from a boundary (the server has them), so drop both. If we cannot read the parent we also
        // cannot have counted its tree, so there is nothing more to scrub.
        if let Ok(Some(data)) = objects.try_find(parent, buf)
            && data.kind == gix_object::Kind::Commit
            && let Ok(tree) = gix_object::CommitRefIter::from_bytes(data.data, parent.kind()).tree_id()
        {
            scrub.insert(tree);
        }
    }
    scrub
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    use gix_hash::{Kind, ObjectId};

    use super::*;

    // --- object-database fixture helpers -------------------------------------------------------

    // A plain `HandleArc` (`Cache<Handle<Arc<Store>>>`), which — unlike the `memory::Proxy` that
    // `repo.objects` is — implements `gix_pack::Find`. Opened fresh on the repo's `objects` dir so it
    // sees the loose objects written below. (The production `gpx08` wiring must likewise hand a plain
    // pack-capable handle, not the `Proxy` from `repo.objects`; the design's B11 `into_arc()` note is
    // inaccurate for this base, where `into_arc()` on `repo.objects` keeps the `Proxy` wrapper.)
    type Odb = gix_odb::HandleArc;

    /// A repository plus its `Arc`-backed object handle; the tempdir lives as long as the tuple.
    struct Fixture {
        repo: crate::Repository,
        _tmp: gix_testtools::tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
            let repo = crate::init(tmp.path()).expect("init repo");
            Fixture { repo, _tmp: tmp }
        }

        fn odb(&self) -> Odb {
            let mut handle = gix_odb::at(self.repo.git_dir().join("objects"), self.repo.object_hash())
                .expect("open odb")
                .into_arc()
                .expect("arc handle");
            // Required by the pack pipeline's `location_by_oid` (see `write_pack` docs).
            handle.prevent_pack_unload();
            handle
        }

        fn blob(&self, content: &[u8]) -> ObjectId {
            self.repo.write_blob(content).expect("write blob").detach()
        }

        /// Write a flat tree from `(name, mode, oid)` entries (sorted here so the tree is canonical).
        fn tree(&self, mut entries: Vec<(&str, gix_object::tree::EntryKind, ObjectId)>) -> ObjectId {
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let tree = gix_object::Tree {
                entries: entries
                    .into_iter()
                    .map(|(name, kind, oid)| gix_object::tree::Entry {
                        mode: kind.into(),
                        filename: name.into(),
                        oid,
                    })
                    .collect(),
            };
            self.repo.write_object(&tree).expect("write tree").detach()
        }

        fn commit(&self, tree: ObjectId, parents: Vec<ObjectId>, message: &str) -> ObjectId {
            let sig = gix_actor::Signature {
                name: "Tester".into(),
                email: "tester@example.com".into(),
                // Fixed timestamp → deterministic object ids.
                time: gix_date::Time {
                    seconds: 1_000_000,
                    offset: 0,
                },
            };
            let commit = gix_object::Commit {
                tree,
                parents: parents.into_iter().collect(),
                author: sig.clone(),
                committer: sig,
                encoding: None,
                message: message.into(),
                extra_headers: Vec::new(),
            };
            self.repo.write_object(&commit).expect("write commit").detach()
        }

        fn annotated_tag(&self, target: ObjectId, target_kind: gix_object::Kind, name: &str) -> ObjectId {
            let tag = gix_object::Tag {
                target,
                target_kind,
                name: name.into(),
                tagger: Some(gix_actor::Signature {
                    name: "Tester".into(),
                    email: "tester@example.com".into(),
                    time: gix_date::Time {
                        seconds: 1_000_000,
                        offset: 0,
                    },
                }),
                message: "tag message".into(),
                signature: None,
            };
            self.repo.write_object(&tag).expect("write tag").detach()
        }
    }

    /// Build a pack for `tips`/`boundaries` and return `(object_count, pack trailer, pack bytes)`.
    fn build(odb: &Odb, tips: Vec<ObjectId>, boundaries: Vec<ObjectId>) -> Result<(Outcome, Vec<u8>), Error> {
        let mut out = Vec::new();
        let mut progress = gix_utils::progress::Discard;
        let outcome = write_pack(
            odb.clone(),
            tips,
            boundaries,
            Kind::Sha1,
            &mut out,
            &mut progress,
            &AtomicBool::new(false),
        )?;
        Ok((outcome, out))
    }

    /// Index a freshly built pack back and return the exact set of object ids it contains — the
    /// `git index-pack` half of the design's "build → index-back → object-set equality" oracle.
    fn indexed_object_ids(pack: &[u8], odb: &Odb) -> HashSet<ObjectId> {
        let dir = gix_testtools::tempfile::tempdir().expect("tempdir");
        let mut cursor = std::io::Cursor::new(pack);
        let mut progress = gix_utils::progress::Discard;
        let outcome = gix_pack::Bundle::write_to_directory(
            &mut cursor,
            Some(dir.path()),
            &mut progress,
            &AtomicBool::new(false),
            Some(odb.clone()),
            Kind::Sha1,
            gix_pack::bundle::write::Options {
                thread_limit: Some(1),
                iteration_mode: gix_pack::data::input::Mode::Verify,
                index_version: gix_pack::index::Version::default(),
                // Upstream added these in the gix-zlib split; use the struct's own defaults.
                alloc_limit_bytes: None,
                compression: gix_zlib::Compression::BEST_SPEED,
            },
        )
        .expect("index the pack back");
        let index =
            gix_pack::index::File::at(outcome.index_path.expect("index written"), Kind::Sha1).expect("open index");
        index.iter().map(|e| e.oid).collect()
    }

    fn set(ids: impl IntoIterator<Item = ObjectId>) -> HashSet<ObjectId> {
        ids.into_iter().collect()
    }

    // --- boundaries_from_advertised ------------------------------------------------------------

    #[test]
    fn boundaries_intersect_the_local_odb_and_read_peeled_tag_and_object() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let base_tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, fx.blob(b"x"))]);
        let commit = fx.commit(base_tree, vec![], "c");
        let tag = fx.annotated_tag(commit, gix_object::Kind::Commit, "v1");
        let absent = ObjectId::from_hex(b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();

        let advertised = vec![
            Ref::Direct {
                full_ref_name: "refs/heads/main".into(),
                object: commit,
            },
            // An advertised ref we do NOT have locally is filtered out (silent, v1).
            Ref::Direct {
                full_ref_name: "refs/heads/absent".into(),
                object: absent,
            },
            // An annotated tag contributes BOTH its tag value and its peeled object.
            Ref::Peeled {
                full_ref_name: "refs/tags/v1".into(),
                tag,
                object: commit,
            },
        ];
        let boundaries = boundaries_from_advertised(&advertised, &odb);
        assert_eq!(
            set(boundaries),
            set([commit, tag]),
            "present ref values (incl. Peeled.tag) are kept, absent ones dropped, no duplicates"
        );
    }

    // --- core build → index-back parity --------------------------------------------------------

    #[test]
    fn single_commit_pack_contains_the_whole_reachable_set() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let blob = fx.blob(b"hello");
        let tree = fx.tree(vec![("hello.txt", gix_object::tree::EntryKind::Blob, blob)]);
        let commit = fx.commit(tree, vec![], "root");

        let (outcome, pack) = build(&odb, vec![commit], vec![]).expect("pack builds");
        assert_eq!(outcome.object_count, 3);
        assert!(outcome.pack_hash.is_some());
        assert_eq!(indexed_object_ids(&pack, &odb), set([commit, tree, blob]));
    }

    #[test]
    fn empty_tips_produce_a_valid_zero_object_pack() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let (outcome, pack) = build(&odb, vec![], vec![]).expect("pack builds");
        assert_eq!(outcome.object_count, 0);
        assert!(outcome.pack_hash.is_some(), "even an empty pack has a trailing hash");
        // A valid V2 pack with zero objects: 12-byte header (`PACK`, version 2, count 0) + a 20-byte
        // SHA-1 trailer.
        assert_eq!(pack.len(), 32);
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(&pack[8..12], &[0, 0, 0, 0], "the object count in the header is zero");
    }

    /// Review F2: multiple boundaries (two independent lines merged). KNOWN DEVIATION pinned here:
    /// for a MERGE tip, `TreeAdditionsComparedToAncestor` (the counting mode gitoxide's own pack
    /// create uses) may include a blob that is in the merge's tree but reachable from ANOTHER
    /// boundary line (here `xb`) — a harmless over-inclusion (the server already has it and
    /// dedups; costs bytes only), so strict `rev-list --objects` EQUALITY holds for linear history
    /// but relaxes to "superset, with no commit/tree from any boundary history and extras limited
    /// to blobs present in the tip's tree" at merges. Documented here + module docs.
    #[test]
    fn multi_boundary_merge_excludes_both_histories() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let xa = fx.blob(b"line-a");
        let ta = fx.tree(vec![("a", gix_object::tree::EntryKind::Blob, xa)]);
        let a = fx.commit(ta, vec![], "A");
        let xb = fx.blob(b"line-b");
        let tb = fx.tree(vec![("b", gix_object::tree::EntryKind::Blob, xb)]);
        let b = fx.commit(tb, vec![], "B");
        // Merge M of the two independent lines, adding one new blob.
        let xm = fx.blob(b"merge");
        let tm = fx.tree(vec![
            ("a", gix_object::tree::EntryKind::Blob, xa),
            ("b", gix_object::tree::EntryKind::Blob, xb),
            ("m", gix_object::tree::EntryKind::Blob, xm),
        ]);
        let m = fx.commit(tm, vec![a, b], "M");

        let (outcome, pack) = build(&odb, vec![m], vec![a, b]).expect("pack builds");
        let ids = indexed_object_ids(&pack, &odb);
        // Strict rev-list set is {M, Tm, Xm}; the tree-diff heuristic ALSO ships xa/xb (blobs in
        // M's tree contributed by the boundary lines) — assert the exact observed contract:
        assert!(
            ids.is_superset(&set([m, tm, xm])),
            "everything genuinely new is present"
        );
        for leaked in [a, b, ta, tb] {
            assert!(
                !ids.contains(&leaked),
                "no boundary COMMIT or root TREE may leak (scrub law): {leaked}"
            );
        }
        let extras: std::collections::HashSet<_> = ids.difference(&set([m, tm, xm])).copied().collect();
        assert!(
            extras.is_subset(&set([xa, xb])),
            "over-inclusion is limited to blobs present in the merge tip's tree, got {extras:?}"
        );
        assert_eq!(outcome.object_count as usize, ids.len());
    }

    #[test]
    fn incremental_a_then_b_packs_only_bs_new_objects() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let xa = fx.blob(b"a");
        let ta = fx.tree(vec![("a", gix_object::tree::EntryKind::Blob, xa)]);
        let a = fx.commit(ta, vec![], "A");

        let xb = fx.blob(b"b");
        let tb = fx.tree(vec![
            ("a", gix_object::tree::EntryKind::Blob, xa),
            ("b", gix_object::tree::EntryKind::Blob, xb),
        ]);
        let b = fx.commit(tb, vec![a], "B");

        let (outcome, pack) = build(&odb, vec![b], vec![a]).expect("pack builds");
        let ids = indexed_object_ids(&pack, &odb);
        // rev-list --objects B --not A == {B, Tb, Xb}: A, Ta, Xa are shared and excluded.
        assert_eq!(ids, set([b, tb, xb]));
        assert_eq!(outcome.object_count, 3);
        assert!(!ids.contains(&a), "A itself must not leak");
        assert!(!ids.contains(&ta), "A's root tree must not leak (boundary scrub)");
        assert!(!ids.contains(&xa), "the shared blob must not leak");
    }

    #[test]
    fn shared_base_boundary_parity_excludes_the_shared_base() {
        // B1: push `feature` to a remote that also advertises `main`; the shared base is hidden via
        // `main` and excluded from the pack, an equality with `rev-list --objects F --not main`.
        let fx = Fixture::new();
        let odb = fx.odb();
        let x0 = fx.blob(b"base");
        let t0 = fx.tree(vec![("base", gix_object::tree::EntryKind::Blob, x0)]);
        let base = fx.commit(t0, vec![], "base");

        // main = base -> M
        let xm = fx.blob(b"main");
        let tm = fx.tree(vec![
            ("base", gix_object::tree::EntryKind::Blob, x0),
            ("main", gix_object::tree::EntryKind::Blob, xm),
        ]);
        let main = fx.commit(tm, vec![base], "M");

        // feature = base -> F
        let xf = fx.blob(b"feature");
        let tf = fx.tree(vec![
            ("base", gix_object::tree::EntryKind::Blob, x0),
            ("feature", gix_object::tree::EntryKind::Blob, xf),
        ]);
        let feature = fx.commit(tf, vec![base], "F");

        let advertised = vec![Ref::Direct {
            full_ref_name: "refs/heads/main".into(),
            object: main,
        }];
        let boundaries = boundaries_from_advertised(&advertised, &odb);
        assert!(
            boundaries.contains(&main),
            "the unrelated branch's tip is a boundary even though we do not push to it"
        );

        let (_outcome, pack) = build(&odb, vec![feature], boundaries).expect("pack builds");
        let ids = indexed_object_ids(&pack, &odb);
        assert_eq!(ids, set([feature, tf, xf]), "exact rev-list parity");
        for shared in [base, t0, x0] {
            assert!(!ids.contains(&shared), "the shared base {shared} must be excluded");
        }
    }

    #[test]
    fn boundary_scrub_removes_only_the_leaked_objects() {
        // B4: the tree-diff expansion leaks the hidden parent commit + its root tree; assert the
        // scrub removes exactly those, i.e. object-set equality with the rev-list oracle. A two-hop
        // feature branch makes the hidden frontier sit a commit *below* the boundary tip, which a
        // boundary-tip-only closure would miss but the frontier-based scrub catches.
        let fx = Fixture::new();
        let odb = fx.odb();
        let x0 = fx.blob(b"0");
        let t0 = fx.tree(vec![("0", gix_object::tree::EntryKind::Blob, x0)]);
        let c0 = fx.commit(t0, vec![], "c0");

        // main tip sits at c0's child, so the boundary is c1 while the feature branches off c0.
        let xm = fx.blob(b"m");
        let tm = fx.tree(vec![
            ("0", gix_object::tree::EntryKind::Blob, x0),
            ("m", gix_object::tree::EntryKind::Blob, xm),
        ]);
        let c1 = fx.commit(tm, vec![c0], "c1-main");

        let xf = fx.blob(b"f");
        let tf = fx.tree(vec![
            ("0", gix_object::tree::EntryKind::Blob, x0),
            ("f", gix_object::tree::EntryKind::Blob, xf),
        ]);
        let feature = fx.commit(tf, vec![c0], "feature");

        // Boundary is the main tip c1; the hidden frontier parent of `feature` is c0 (a commit below
        // the boundary), plus its root tree t0 — both must be scrubbed.
        let (_outcome, pack) = build(&odb, vec![feature], vec![c1]).expect("pack builds");
        let ids = indexed_object_ids(&pack, &odb);
        assert_eq!(ids, set([feature, tf, xf]));
        assert!(!ids.contains(&c0), "the hidden frontier parent commit is scrubbed");
        assert!(!ids.contains(&t0), "the hidden frontier parent's root tree is scrubbed");
    }

    // --- tip normalization (B5) ----------------------------------------------------------------

    #[test]
    fn blob_tip_round_trips_verbatim() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let blob = fx.blob(b"loose blob tip");
        let (outcome, pack) = build(&odb, vec![blob], vec![]).expect("pack builds");
        assert_eq!(outcome.object_count, 1);
        assert_eq!(indexed_object_ids(&pack, &odb), set([blob]));
    }

    #[test]
    fn tree_tip_is_refused() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, fx.blob(b"x"))]);
        let err = build(&odb, vec![tree], vec![]).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedTipType { id } if id == tree),
            "a bare tree tip is refused with a named error, got {err:?}"
        );
    }

    #[test]
    fn annotated_tag_tip_emits_the_tag_and_its_target_history() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let blob = fx.blob(b"content");
        let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, blob)]);
        let commit = fx.commit(tree, vec![], "c");
        let tag = fx.annotated_tag(commit, gix_object::Kind::Commit, "v1");

        let (_outcome, pack) = build(&odb, vec![tag], vec![]).expect("pack builds");
        let ids = indexed_object_ids(&pack, &odb);
        assert_eq!(
            ids,
            set([tag, commit, tree, blob]),
            "the tag object plus its target's full history are packed"
        );
    }

    #[test]
    fn annotated_tag_with_boundary_target_packs_only_the_tag() {
        // When the server already has the tag's target commit, only the tag object is new.
        let fx = Fixture::new();
        let odb = fx.odb();
        let blob = fx.blob(b"content");
        let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, blob)]);
        let commit = fx.commit(tree, vec![], "c");
        let tag = fx.annotated_tag(commit, gix_object::Kind::Commit, "v1");

        let (_outcome, pack) = build(&odb, vec![tag], vec![commit]).expect("pack builds");
        assert_eq!(
            indexed_object_ids(&pack, &odb),
            set([tag]),
            "the target history is hidden by the boundary, leaving only the tag object"
        );
    }

    // --- progress + interrupt ------------------------------------------------------------------

    #[derive(Clone)]
    struct IdRecorder {
        ids: std::sync::Arc<std::sync::Mutex<Vec<gix_utils::progress::Id>>>,
    }

    impl gix_utils::progress::Count for IdRecorder {
        fn set(&self, _step: gix_utils::progress::Step) {}
        fn step(&self) -> gix_utils::progress::Step {
            0
        }
        fn inc_by(&self, _step: gix_utils::progress::Step) {}
        fn counter(&self) -> gix_utils::progress::StepShared {
            gix_utils::progress::Discard.counter()
        }
    }

    impl gix_utils::progress::Progress for IdRecorder {
        fn init(&mut self, _max: Option<gix_utils::progress::Step>, _unit: Option<gix_utils::progress::Unit>) {}
        fn set_name(&mut self, _name: String) {}
        fn name(&self) -> Option<String> {
            None
        }
        fn id(&self) -> gix_utils::progress::Id {
            gix_utils::progress::UNKNOWN
        }
        fn message(&self, _level: gix_utils::progress::MessageLevel, _message: String) {}
    }

    impl gix_utils::progress::NestedProgress for IdRecorder {
        type SubProgress = gix_utils::progress::Discard;
        fn add_child(&mut self, _name: impl Into<String>) -> Self::SubProgress {
            gix_utils::progress::Discard
        }
        fn add_child_with_id(&mut self, _name: impl Into<String>, id: gix_utils::progress::Id) -> Self::SubProgress {
            self.ids.lock().unwrap().push(id);
            gix_utils::progress::Discard
        }
    }

    #[test]
    fn emits_count_objects_and_write_pack_progress_ids() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, fx.blob(b"x"))]);
        let commit = fx.commit(tree, vec![], "c");

        let mut recorder = IdRecorder {
            ids: Default::default(),
        };
        let mut out = Vec::new();
        write_pack(
            odb.clone(),
            vec![commit],
            vec![],
            Kind::Sha1,
            &mut out,
            &mut recorder,
            &AtomicBool::new(false),
        )
        .expect("pack builds");

        let ids = recorder.ids.lock().unwrap();
        let count: gix_utils::progress::Id = ProgressId::CountObjects.into();
        let write: gix_utils::progress::Id = ProgressId::WritePack.into();
        assert!(ids.contains(&count), "CountObjects id emitted");
        assert!(ids.contains(&write), "WritePack id emitted");
    }

    #[test]
    fn interrupt_before_writing_yields_no_bytes() {
        let fx = Fixture::new();
        let odb = fx.odb();
        let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, fx.blob(b"x"))]);
        let commit = fx.commit(tree, vec![], "c");

        let mut out = Vec::new();
        let mut progress = gix_utils::progress::Discard;
        let err = write_pack(
            odb,
            vec![commit],
            vec![],
            Kind::Sha1,
            &mut out,
            &mut progress,
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Interrupted));
        assert!(out.is_empty(), "no pack bytes are written when interrupted up front");
    }

    /// A writer that flips `flag` to `true` after its first write, to trip the mid-write interrupt.
    struct FlipOnWrite<'a> {
        inner: Vec<u8>,
        flag: &'a AtomicBool,
    }
    impl std::io::Write for FlipOnWrite<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.flag.store(true, Ordering::Relaxed);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    #[test]
    fn interrupt_mid_write_is_reported() {
        let fx = Fixture::new();
        let odb = fx.odb();
        // Several objects so the entry stream spans more than one `next()` chunk-write.
        let mut tip = None;
        for i in 0..5 {
            let blob = fx.blob(format!("content {i}").as_bytes());
            let tree = fx.tree(vec![("f", gix_object::tree::EntryKind::Blob, blob)]);
            tip = Some(fx.commit(tree, tip.into_iter().collect(), "c"));
        }
        let tip = tip.expect("built a chain");

        let flag = AtomicBool::new(false);
        let mut out = FlipOnWrite {
            inner: Vec::new(),
            flag: &flag,
        };
        let mut progress = gix_utils::progress::Discard;
        let err = write_pack(odb, vec![tip], vec![], Kind::Sha1, &mut out, &mut progress, &flag).unwrap_err();
        assert!(
            matches!(err, Error::Interrupted),
            "mid-write interrupt is surfaced, got {err:?}"
        );
    }
}
