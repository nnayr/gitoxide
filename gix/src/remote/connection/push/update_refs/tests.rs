//! Tests for the push tracking-ref bookkeeping (`gpx09` / design `P9`).
//!
//! Three tiers, mirroring 05-outcome-bookkeeping §"Test design":
//! * **unit** — canned plumbing `Outcome`s over a fixture repo: correlation (the plan-driven
//!   left-join S1), every [`Mode`], the suppression gates, dry-run.
//! * **reverse-map** — the pure [`tracking_ref_name`](super::tracking_ref_name) helper: dst × fetch-spec
//!   set → tracking ref (or `None`), incl. first-match and a parity pin against the canonical
//!   `branch_remote_tracking_ref_name` mapping.
//! * **integration `file://`** — a real `git-receive-pack` with a configured tracking spec: the ref
//!   moves on ok-update, vanishes on delete-ok, and is untouched on ng / dry-run / a non-branch dst.

use gix_hash::ObjectId;
use gix_protocol::push::{Outcome as Report, RefRejectReason, RefUpdateStatus, UnpackStatus};
use gix_ref::{FullName, Target, transaction::PreviousValue};

use super::super::plan::{Force, Mapping, PlannedUpdates, Source, SpecIndex, Verdict};
use super::update::{Mode, SkipReason};
use super::{tracking_ref_name, update};
use crate::bstr::BStr;
use crate::remote::fetch::RefLogMessage;

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

fn oid(n: u8) -> ObjectId {
    ObjectId::from_hex(format!("{n:040x}").as_bytes()).expect("valid sha1 hex")
}

fn fname(s: &str) -> FullName {
    FullName::try_from(s).expect("valid full ref name")
}

fn fetch_spec(s: &str) -> gix_refspec::RefSpec {
    gix_refspec::parse(BStr::new(s), gix_refspec::parse::Operation::Fetch)
        .expect("valid fetch refspec")
        .to_owned()
}

/// The canonical two-sided tracking spec (`origin`).
fn origin_spec() -> Vec<gix_refspec::RefSpec> {
    vec![fetch_spec("+refs/heads/*:refs/remotes/origin/*")]
}

/// One mapping. `new == None` marks a delete (so `local` is `None` too, as the plan guarantees).
fn m(remote: &str, verdict: Verdict, new: Option<ObjectId>, advertised: Option<ObjectId>) -> Mapping {
    Mapping {
        local: new.map(|id| Source::Ref {
            name: fname(remote),
            id,
        }),
        remote: fname(remote),
        advertised,
        new,
        force: Force::No,
        spec_index: SpecIndex::ExplicitInRemote(0),
        verdict,
        update_index: None,
    }
}

/// A `PlannedUpdates` over `mappings`; `update()` reads only `mappings`, so the rest is empty.
fn plan(mappings: Vec<Mapping>) -> PlannedUpdates {
    PlannedUpdates {
        mappings,
        updates: Vec::new(),
        tips: Vec::new(),
        refspecs: Vec::new(),
        extra_refspecs: Vec::new(),
        remote_refs: Vec::new(),
    }
}

fn ok(name: &str) -> RefUpdateStatus {
    RefUpdateStatus::Ok {
        name: name.into(),
        details: None,
    }
}

fn ng(name: &str, reason: &str, class: RefRejectReason) -> RefUpdateStatus {
    RefUpdateStatus::Rejected {
        name: name.into(),
        reason: reason.into(),
        class,
    }
}

fn report(unpack: UnpackStatus, refs: Vec<RefUpdateStatus>) -> Report {
    Report {
        unpack_status: unpack,
        refs,
        server_protocol_version: gix_transport::Protocol::V1,
    }
}

fn empty_repo() -> (crate::Repository, gix_testtools::tempfile::TempDir) {
    let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
    let mut repo = crate::init(tmp.path()).expect("init repo");
    // An isolated repo has no configured user; a generic fallback lets the tracking-ref reflog write.
    repo.committer_or_set_generic_fallback().expect("committer fallback");
    (repo, tmp)
}

fn run(
    repo: &crate::Repository,
    plan: &PlannedUpdates,
    report: Option<&Report>,
    fetch_specs: &[gix_refspec::RefSpec],
    atomic_active: bool,
    dry_run: bool,
) -> super::update::Outcome {
    update(
        repo,
        RefLogMessage::Prefixed { action: "push".into() },
        plan,
        report,
        fetch_specs,
        atomic_active,
        dry_run,
    )
    .expect("bookkeeping succeeds")
}

// ── unit: correlation + every Mode ───────────────────────────────────────────────────────────────

#[test]
fn up_to_date_mapping_reports_up_to_date_with_no_edit() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m(
        "refs/heads/main",
        Verdict::UpToDate,
        Some(oid(1)),
        Some(oid(1)),
    )]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates.len(), 1);
    assert_eq!(out.updates[0].mode, Mode::UpToDate);
    assert_eq!(out.updates[0].edit_index, None);
    assert!(out.edits.is_empty());
}

#[test]
fn every_local_reject_verdict_rides_along_losslessly() {
    let (repo, _t) = empty_repo();
    for v in [
        Verdict::RejectedNonFastForward,
        Verdict::RejectedAlreadyExists,
        Verdict::RejectedFetchFirst,
        Verdict::RejectedNeedsForce,
    ] {
        let p = plan(vec![m("refs/heads/main", v, Some(oid(2)), Some(oid(1)))]);
        // The report carries nothing for a never-sent mapping — the left-join's left arm.
        let out = run(
            &repo,
            &p,
            Some(&report(UnpackStatus::Ok, vec![])),
            &origin_spec(),
            false,
            false,
        );
        assert_eq!(
            out.updates[0].mode,
            Mode::RejectedLocal(v),
            "verdict {v:?} rides along verbatim"
        );
        assert_eq!(out.updates[0].edit_index, None);
    }
}

/// The REQUIRED S1 unit: plan `{1 local-reject, 1 ok}`, report `{only the ok}` — both Updates present
/// with correct Modes (the locally-rejected mapping was never sent, so it has no server status).
#[test]
fn plan_driven_left_join_one_local_reject_one_ok() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![
        m(
            "refs/heads/main",
            Verdict::RejectedNonFastForward,
            Some(oid(2)),
            Some(oid(1)),
        ),
        m("refs/heads/feature", Verdict::Create, Some(oid(3)), None),
    ]);
    // Only the accepted create appears in the server report.
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/feature")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates.len(), 2, "one Update per mapping, in plan order");
    assert_eq!(
        out.updates[0].mode,
        Mode::RejectedLocal(Verdict::RejectedNonFastForward),
        "the never-sent mapping keeps its local verdict"
    );
    assert_eq!(
        out.updates[1].mode,
        Mode::TrackingRefUpdated,
        "the accepted create moved its tracking ref"
    );
}

#[test]
fn server_ok_on_non_branch_dst_skips_not_a_branch() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/tags/v1", Verdict::Create, Some(oid(4)), None)]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/tags/v1")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::TrackingRefSkipped(SkipReason::NotABranch));
    assert!(out.edits.is_empty(), "a tag push touches no tracking ref");
}

#[test]
fn server_ok_branch_without_matching_fetch_spec_skips() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(5)), None)]);
    // No fetch specs → nothing reverse-maps `refs/heads/main`.
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/main")])),
        &[],
        false,
        false,
    );
    assert_eq!(
        out.updates[0].mode,
        Mode::TrackingRefSkipped(SkipReason::NoMatchingFetchSpec)
    );
    assert!(out.edits.is_empty());
}

#[test]
fn server_ng_is_rejected_by_server_with_class_and_reason() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(6)), None)]);
    let out = run(
        &repo,
        &p,
        Some(&report(
            UnpackStatus::Ok,
            vec![ng(
                "refs/heads/main",
                "non-fast-forward",
                RefRejectReason::NonFastForward,
            )],
        )),
        &origin_spec(),
        false,
        false,
    );
    match &out.updates[0].mode {
        Mode::RejectedByServer { reason, class } => {
            assert_eq!(reason.as_slice(), b"non-fast-forward");
            assert_eq!(*class, RefRejectReason::NonFastForward);
        }
        other => panic!("expected RejectedByServer, got {other:?}"),
    }
    assert!(out.edits.is_empty(), "a server rejection moves no tracking ref");
}

#[test]
fn unpack_failure_suppresses_all_tracking_edits() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(7)), None)]);
    let out = run(
        &repo,
        &p,
        Some(&report(
            UnpackStatus::Failed("index-pack failed".into()),
            vec![ok("refs/heads/main")],
        )),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(
        out.updates[0].mode,
        Mode::Ok,
        "an unpack failure suppresses bookkeeping"
    );
    assert!(out.edits.is_empty());
    assert!(
        repo.refs
            .try_find(fname("refs/remotes/origin/main").as_ref())
            .unwrap()
            .is_none(),
        "no tracking ref was written"
    );
}

#[test]
fn atomic_rollback_suppresses_even_the_ok_ref() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![
        m("refs/heads/ok", Verdict::Create, Some(oid(8)), None),
        m("refs/heads/bad", Verdict::Create, Some(oid(9)), None),
    ]);
    // atomic negotiated: a single `ng` reverts the whole push, so the "ok" ref must not move either.
    let out = run(
        &repo,
        &p,
        Some(&report(
            UnpackStatus::Ok,
            vec![
                ok("refs/heads/ok"),
                ng("refs/heads/bad", "atomic push failure", RefRejectReason::Other),
            ],
        )),
        &origin_spec(),
        true, // atomic_active
        false,
    );
    assert_eq!(
        out.updates[0].mode,
        Mode::Ok,
        "the ok ref is suppressed under atomic rollback"
    );
    assert!(matches!(out.updates[1].mode, Mode::RejectedByServer { .. }));
    assert!(out.edits.is_empty(), "atomic rollback touches no tracking ref");
}

#[test]
fn non_atomic_ng_does_not_suppress_the_sibling_ok() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![
        m("refs/heads/ok", Verdict::Create, Some(oid(10)), None),
        m("refs/heads/bad", Verdict::Create, Some(oid(11)), None),
    ]);
    let out = run(
        &repo,
        &p,
        Some(&report(
            UnpackStatus::Ok,
            vec![
                ok("refs/heads/ok"),
                ng("refs/heads/bad", "denyCurrentBranch", RefRejectReason::Other),
            ],
        )),
        &origin_spec(),
        false, // NOT atomic — the ng is per-ref only
        false,
    );
    assert_eq!(
        out.updates[0].mode,
        Mode::TrackingRefUpdated,
        "the accepted ref still moves"
    );
    assert!(matches!(out.updates[1].mode, Mode::RejectedByServer { .. }));
    assert_eq!(out.edits.len(), 1);
}

#[test]
fn sent_but_unreported_is_a_correlation_gap_not_a_panic() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(12)), None)]);
    // A sendable mapping, but the report has no status for it (bijection defensively broken).
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::CorrelationGap);
    assert!(out.edits.is_empty());
}

#[test]
fn dry_run_sendable_mapping_reports_dry_run_and_writes_nothing() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(13)), None)]);
    // Dry-run: no report, no ref touched — but the sendable mapping is recorded as DryRun.
    let out = run(&repo, &p, None, &origin_spec(), false, true);
    assert_eq!(out.updates[0].mode, Mode::DryRun);
    assert!(out.edits.is_empty());
    assert!(
        repo.refs
            .try_find(fname("refs/remotes/origin/main").as_ref())
            .unwrap()
            .is_none(),
        "dry-run wrote no tracking ref"
    );
}

#[test]
fn delete_ok_without_a_tracking_ref_is_plain_ok() {
    let (repo, _t) = empty_repo();
    // A delete (new/local None); the tracking ref does not exist, so there is nothing local to remove.
    let p = plan(vec![m("refs/heads/gone", Verdict::Delete, None, Some(oid(14)))]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/gone")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::Ok);
    assert!(out.edits.is_empty());
}

// ── unit: tracking-ref edits actually applied (fixture repo, real ref store) ─────────────────────

#[test]
fn accepted_create_writes_the_tracking_ref_and_reflog() {
    let (repo, _t) = empty_repo();
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(20)), None)]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/main")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::TrackingRefUpdated);
    assert_eq!(out.updates[0].edit_index, Some(0));
    // The edit is a direct Update to the pushed oid with the "update by push" reflog context.
    let edit = &out.edits[0];
    assert_eq!(edit.name.as_bstr(), b"refs/remotes/origin/main".as_slice());
    match &edit.change {
        gix_ref::transaction::Change::Update { new, log, .. } => {
            assert_eq!(*new, Target::Object(oid(20)));
            assert_eq!(log.message.as_slice(), b"push: update by push");
        }
        other => panic!("expected an Update edit, got {other:?}"),
    }
    // And it landed in the store.
    let found = repo.refs.try_find(fname("refs/remotes/origin/main").as_ref()).unwrap();
    assert_eq!(found.map(|r| r.target), Some(Target::Object(oid(20))));
}

#[test]
fn accepted_update_moves_an_existing_tracking_ref() {
    let (repo, _t) = empty_repo();
    // Seed the tracking ref at an old value.
    seed_direct(&repo, "refs/remotes/origin/main", oid(30));
    let p = plan(vec![m(
        "refs/heads/main",
        Verdict::FastForward,
        Some(oid(31)),
        Some(oid(30)),
    )]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/main")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::TrackingRefUpdated);
    match &out.edits[0].change {
        gix_ref::transaction::Change::Update { expected, new, .. } => {
            assert_eq!(*new, Target::Object(oid(31)));
            assert_eq!(*expected, PreviousValue::MustExistAndMatch(Target::Object(oid(30))));
        }
        other => panic!("expected Update, got {other:?}"),
    }
    let found = repo.refs.try_find(fname("refs/remotes/origin/main").as_ref()).unwrap();
    assert_eq!(found.map(|r| r.target), Some(Target::Object(oid(31))));
}

#[test]
fn accepted_delete_removes_the_tracking_ref() {
    let (repo, _t) = empty_repo();
    seed_direct(&repo, "refs/remotes/origin/topic", oid(40));
    let p = plan(vec![m("refs/heads/topic", Verdict::Delete, None, Some(oid(40)))]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/topic")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(out.updates[0].mode, Mode::TrackingRefUpdated);
    assert!(matches!(
        out.edits[0].change,
        gix_ref::transaction::Change::Delete { .. }
    ));
    assert!(
        repo.refs
            .try_find(fname("refs/remotes/origin/topic").as_ref())
            .unwrap()
            .is_none(),
        "the tracking ref was removed"
    );
}

#[test]
fn symbolic_tracking_ref_is_skipped_not_overwritten() {
    let (repo, _t) = empty_repo();
    seed_symbolic(&repo, "refs/remotes/origin/main", "refs/heads/main");
    let p = plan(vec![m("refs/heads/main", Verdict::Create, Some(oid(50)), None)]);
    let out = run(
        &repo,
        &p,
        Some(&report(UnpackStatus::Ok, vec![ok("refs/heads/main")])),
        &origin_spec(),
        false,
        false,
    );
    assert_eq!(
        out.updates[0].mode,
        Mode::TrackingRefSkipped(SkipReason::SymbolicTrackingRef)
    );
    assert!(out.edits.is_empty(), "a symbolic tracking ref is left untouched");
    // Still symbolic.
    let found = repo
        .refs
        .try_find(fname("refs/remotes/origin/main").as_ref())
        .unwrap()
        .unwrap();
    assert!(matches!(found.target, Target::Symbolic(_)));
}

fn seed_direct(repo: &crate::Repository, name: &str, id: ObjectId) {
    repo.edit_reference(gix_ref::transaction::RefEdit {
        change: gix_ref::transaction::Change::Update {
            log: gix_ref::transaction::LogChange {
                mode: gix_ref::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: "seed".into(),
            },
            expected: PreviousValue::MustNotExist,
            new: Target::Object(id),
        },
        name: fname(name),
        deref: false,
    })
    .expect("seed direct ref");
}

fn seed_symbolic(repo: &crate::Repository, name: &str, target: &str) {
    repo.edit_reference(gix_ref::transaction::RefEdit {
        change: gix_ref::transaction::Change::Update {
            log: gix_ref::transaction::LogChange {
                mode: gix_ref::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: "seed".into(),
            },
            expected: PreviousValue::MustNotExist,
            new: Target::Symbolic(fname(target)),
        },
        name: fname(name),
        deref: false,
    })
    .expect("seed symbolic ref");
}

// ── reverse-map (pure `tracking_ref_name`) ───────────────────────────────────────────────────────

/// Parity pin: the canonical `+refs/heads/*:refs/remotes/origin/*` maps `refs/heads/main` to
/// `refs/remotes/origin/main` — byte-identical to `config::branch::branch_remote_tracking_ref_name`.
#[test]
fn reverse_map_default_spec_matches_branch_tracking_helper() {
    let got = tracking_ref_name(&origin_spec(), fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
    assert_eq!(got, Some(fname("refs/remotes/origin/main")));
}

#[test]
fn reverse_map_non_branch_dst_is_none() {
    let got = tracking_ref_name(&origin_spec(), fname("refs/tags/v1").as_ref(), gix_hash::Kind::Sha1);
    assert_eq!(got, None);
}

#[test]
fn reverse_map_without_a_matching_spec_is_none() {
    let got = tracking_ref_name(&[], fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
    assert_eq!(got, None);
}

#[test]
fn reverse_map_first_match_wins_on_ambiguity() {
    let specs = vec![
        fetch_spec("+refs/heads/*:refs/remotes/origin/*"),
        fetch_spec("+refs/heads/*:refs/remotes/backup/*"),
    ];
    let got = tracking_ref_name(&specs, fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
    assert_eq!(got, Some(fname("refs/remotes/origin/main")));
}

#[test]
fn reverse_map_ignores_one_sided_fetch_specs() {
    // A source-only spec (no destination) cannot define a tracking ref.
    let specs = vec![fetch_spec("refs/heads/main")];
    let got = tracking_ref_name(&specs, fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1);
    assert_eq!(got, None);
}

#[test]
fn reverse_map_honours_a_narrow_spec() {
    // A spec that only maps `release/*` does not reverse-map `refs/heads/main`.
    let specs = vec![fetch_spec("+refs/heads/release/*:refs/remotes/origin/release/*")];
    assert_eq!(
        tracking_ref_name(&specs, fname("refs/heads/main").as_ref(), gix_hash::Kind::Sha1),
        None
    );
    assert_eq!(
        tracking_ref_name(&specs, fname("refs/heads/release/1").as_ref(), gix_hash::Kind::Sha1),
        Some(fname("refs/remotes/origin/release/1"))
    );
}

// ── integration: real `git-receive-pack` over file:// with a configured tracking spec ────────────

mod integration {
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::AtomicBool;

    use super::super::super::send_pack::{Outcome, Status};
    use super::super::update::{Mode, SkipReason};
    use crate::remote::Direction;

    fn git(args: &[&str], cwd: &Path) {
        let (ok, _) = git_capture(args, cwd);
        assert!(ok, "git {args:?} in {} failed", cwd.display());
    }

    fn git_capture(args: &[&str], cwd: &Path) -> (bool, String) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00 +0000")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00 +0000")
            .output()
            .expect("the `git` binary is available");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        )
    }

    /// A local work repo (one commit on `main`) + an empty bare remote. Returns `(tmp, repo, local, bare)`.
    fn scenario() -> (
        gix_testtools::tempfile::TempDir,
        crate::Repository,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let bare = root.join("remote.git");
        let local = root.join("local");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        git(&["init", "--bare", "-q"], &bare);
        git(&["init", "-q", "-b", "main"], &local);
        std::fs::write(local.join("f"), "one").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c1"], &local);
        let mut repo = crate::open_opts(&local, crate::open::Options::isolated()).expect("open local");
        // Needed for the tracking-ref reflog: an isolated open has no configured committer.
        repo.committer_or_set_generic_fallback().expect("committer fallback");
        (tmp, repo, local, bare)
    }

    /// Push `specs` over `file://bare` with a `refs/remotes/origin/*` tracking (fetch) spec attached,
    /// so the gpx09 bookkeeping has a reverse-map to work with.
    fn push_tracked(repo: &crate::Repository, bare: &Path, specs: &[&str], dry_run: bool) -> Outcome {
        repo.remote_at(bare.to_str().unwrap())
            .expect("valid file:// remote")
            .with_refspecs(specs.iter().copied(), Direction::Push)
            .expect("valid push refspecs")
            .with_refspecs(Some("+refs/heads/*:refs/remotes/origin/*"), Direction::Fetch)
            .expect("valid fetch refspec")
            .connect(Direction::Push)
            .expect("connect for push")
            .prepare_push(crate::progress::Discard, Default::default())
            .expect("prepare ok")
            .with_dry_run(dry_run)
            .send(crate::progress::Discard, &AtomicBool::new(false))
            .expect("send ok")
    }

    fn tracking(repo: &crate::Repository, name: &str) -> Option<gix_hash::ObjectId> {
        repo.refs
            .try_find(gix_ref::FullName::try_from(name).unwrap().as_ref())
            .unwrap()
            .and_then(|r| r.target.try_id().map(ToOwned::to_owned))
    }

    #[test]
    fn tracking_ref_moves_on_accepted_create() {
        let (_t, repo, local, bare) = scenario();
        let (_ok, head) = git_capture(&["rev-parse", "HEAD"], &local);
        let out = push_tracked(&repo, &bare, &["refs/heads/main:refs/heads/main"], false);
        assert!(matches!(out.status, Status::Pushed { .. }));
        assert_eq!(
            tracking(&repo, "refs/remotes/origin/main").map(|id| id.to_string()),
            Some(head),
            "the tracking ref now points at the pushed commit"
        );
        let update_refs = match out.status {
            Status::Pushed { update_refs, .. } => update_refs,
            other => panic!("expected Pushed, got {other:?}"),
        };
        assert_eq!(update_refs.updates[0].mode, Mode::TrackingRefUpdated);
    }

    #[test]
    fn tracking_ref_vanishes_on_accepted_delete() {
        let (_t, repo, local, bare) = scenario();
        git(&["branch", "topic"], &local);
        push_tracked(&repo, &bare, &["refs/heads/topic:refs/heads/topic"], false);
        assert!(
            tracking(&repo, "refs/remotes/origin/topic").is_some(),
            "tracking seeded"
        );

        let out = push_tracked(&repo, &bare, &[":refs/heads/topic"], false);
        let update_refs = match out.status {
            Status::Pushed { update_refs, .. } => update_refs,
            other => panic!("expected Pushed, got {other:?}"),
        };
        assert_eq!(update_refs.updates[0].mode, Mode::TrackingRefUpdated);
        assert!(
            tracking(&repo, "refs/remotes/origin/topic").is_none(),
            "the tracking ref was removed on delete-ok"
        );
    }

    #[test]
    fn tracking_ref_untouched_on_server_ng() {
        let (_t, repo, local, bare) = scenario();
        git(&["branch", "keep"], &local);
        push_tracked(&repo, &bare, &["refs/heads/keep:refs/heads/keep"], false);
        git(&["config", "receive.denyDeletes", "true"], &bare);
        let before = tracking(&repo, "refs/remotes/origin/keep");

        // The delete is refused server-side (`ng`); the tracking ref must stay put.
        let out = push_tracked(&repo, &bare, &[":refs/heads/keep"], false);
        let update_refs = match out.status {
            Status::Pushed { update_refs, .. } => update_refs,
            other => panic!("expected Pushed, got {other:?}"),
        };
        assert!(matches!(update_refs.updates[0].mode, Mode::RejectedByServer { .. }));
        assert_eq!(
            tracking(&repo, "refs/remotes/origin/keep"),
            before,
            "a server rejection leaves the tracking ref unchanged"
        );
    }

    #[test]
    fn tracking_ref_untouched_on_dry_run() {
        let (_t, repo, _local, bare) = scenario();
        let out = push_tracked(&repo, &bare, &["refs/heads/main:refs/heads/main"], true);
        let update_refs = match out.status {
            Status::NothingToPush { dry_run, update_refs } => {
                assert!(dry_run);
                update_refs
            }
            other => panic!("expected NothingToPush, got {other:?}"),
        };
        assert_eq!(update_refs.updates[0].mode, Mode::DryRun);
        assert!(
            tracking(&repo, "refs/remotes/origin/main").is_none(),
            "dry-run wrote no tracking ref"
        );
    }

    #[test]
    fn non_branch_dst_is_skipped_but_pushed() {
        let (_t, repo, local, bare) = scenario();
        git(&["tag", "v1"], &local);
        let out = push_tracked(&repo, &bare, &["refs/tags/v1:refs/tags/v1"], false);
        let update_refs = match out.status {
            Status::Pushed { update_refs, .. } => update_refs,
            other => panic!("expected Pushed, got {other:?}"),
        };
        assert_eq!(
            update_refs.updates[0].mode,
            Mode::TrackingRefSkipped(SkipReason::NotABranch)
        );
        assert!(
            tracking(&repo, "refs/remotes/origin/v1").is_none(),
            "a tag push creates no tracking ref"
        );
    }
}
