//! M2 (`gp01-u03`) contractual suites for `gix_protocol::push::push()` — the network-transport
//! milestone (plan §5-M2, §6.3-4, §6.4). Suite names are contractual:
//! `push::{daemon, thin_pack, empty_pack, deny_non_fast_forwards, sha256_remote, https}`.
//!
//! The `empty_pack`, `deny_non_fast_forwards`, and `sha256_remote` suites (plus the daemon
//! `host_refs_untouched_by_rolfdb_ref_lifecycle` case) close the small real-server coverage holes of
//! plan §6.3 items 1/5/9/10 (`rolfdb-gp01-covholes`, testplan G7/G10/G11): they promote to a live
//! `git-receive-pack` what M1 had proven only against the in-memory mock (`dummy_pack`, the `caps()`
//! object-format string).
//!
//! What M2 proves that M1 did not: the (transport-generic) `push()` core drives a real
//! `git-receive-pack` over **network** transports — `git://` (git-daemon) and `git+https`
//! (git-http-backend) — not only the local `file://` process spawn; the **thin-pack** path
//! (`allow_thin_pack=true`, realized by the caller's pack closure) is applied by a real server and
//! leaves it `git fsck`-clean (the §6.3-4 "server can apply it" gate that unblocks flipping thinness
//! on, R1); and `report-status-v2` is negotiated + parsed off a real server's wire, not just canned
//! bytes. sha256 hardening and the v2 *parser* were already contractual at M1.
//!
//! TEST-ENV DIVERGENCE (per the plan §6 infra note): the fork-side suite invokes the real `git`
//! binary — `git daemon`, `git http-backend`, `git-receive-pack`, `git fsck`, `git pack-objects`.
//! All are dev/test dependencies of the FORK suite only, never rolfdb production.
//!
//! Unix-only: relies on `git daemon`/`git-receive-pack` process spawns and `/dev/null` config paths.

#![cfg(all(unix, feature = "push", feature = "blocking-client"))]
#![allow(unexpected_cfgs)] // `push_https_test` / `push_tls_test` are set via RUSTFLAGS by the `m2-https` / `m2-tls` sync targets

mod support;

// -------------------------------------------------------------------------------------------------
// push::daemon — real git-receive-pack over git:// (git-daemon), a stateful network transport
// -------------------------------------------------------------------------------------------------
mod push {
    mod daemon {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// The full single-ref lifecycle — create, fast-forward update, delete — over git://, the
        /// cheapest real network transport. Proves the M1 core is transport-generic (§5-M2).
        #[test]
        fn create_update_delete_round_trip() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            let daemon = GitDaemon::serve(&base);
            let url = daemon.url("remote.git");

            // create at A (full pack).
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_url(&url, &[create(REF, &a)], Some(full_a), Options::default(), no_auth)
                .expect("create over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created at A over git://");

            // fast-forward update to B (incremental pack, boundary=A).
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url(&url, &[update(REF, &a, &b)], Some(inc), Options::default(), no_auth)
                .expect("update over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "update accepted");
            assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced to B over git://");

            // delete (no pack sent).
            let out =
                push_over_url(&url, &[delete(REF, &b)], None, Options::default(), no_auth).expect("delete over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "delete accepted");
            let (_o, err) = {
                let o = std::process::Command::new("git")
                    .current_dir(&remote)
                    .args(["rev-parse", "--verify", "--quiet", REF])
                    .output()
                    .expect("git rev-parse");
                (o.stdout.clone(), o.status)
            };
            assert!(!err.success(), "ref is gone after delete over git://");
        }

        /// Opting into `report-status-v2` against a real v2-advertising server (git daemon) drives the
        /// v2 echo + v2 parser end-to-end without breaking the push. NOTE: a *successful* create emits
        /// no `option` lines, so a v2 success report is byte-identical to v1 on the wire — this proves
        /// the v2 opt-in path is wired and round-trips, NOT that v2-specific bytes differ (the v2
        /// `option`-line parsing is proven on canned bytes by M1's
        /// `report_status_v2_option_lines_populate_details`).
        #[test]
        fn report_status_v2_negotiated_over_the_wire() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            let daemon = GitDaemon::serve(&base);
            let url = daemon.url("remote.git");

            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let opts = Options {
                report_status_v2: true,
                ..Default::default()
            };
            let out = push_over_url(&url, &[create(REF, &a)], Some(full_a), opts, no_auth)
                .expect("create with report-status-v2");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "v2-reported create accepted");
            assert_eq!(out.refs.len(), 1, "one per-ref status parsed from the v2 report");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created under v2 reporting");
        }

        /// The server-side CAS (layer b, §2.1) refuses an update whose leased `old-oid` is not the
        /// ref's current value → `ng` per-ref with `unpack ok`. `unpack_status == Ok` can only be
        /// reported after the pack was sent and unpacked, so the rejection is the server's ref check,
        /// not a client pre-flight. (This leases an oid the server never held — a stale-lease CAS
        /// rejection; it is not a genuine interleaved concurrent move, which the two-phase porcelain
        /// covers elsewhere.)
        #[test]
        fn stale_lease_is_rejected_by_server_cas() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            let daemon = GitDaemon::serve(&base);
            let url = daemon.url("remote.git");

            // Server is at A.
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            push_over_url(&url, &[create(REF, &a)], Some(full_a), Options::default(), no_auth).expect("seed A");

            // Build B and C; lease against a WRONG old (C) that the server never held. The
            // advertisement will show A, but plan-time validation is bypassed here (we hand a raw
            // Update): the server's CAS must reject old=C.
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let c_hex = commit_file(&src, "a.txt", "three");
            let c = oid_sha1(&c_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url(&url, &[update(REF, &c, &b)], Some(inc), Options::default(), no_auth)
                .expect("push completes at the protocol level even when the ref is rejected");
            assert_eq!(
                out.unpack_status,
                UnpackStatus::Ok,
                "pack unpacked fine; the ref is what is refused"
            );
            match out.refs.first().expect("one per-ref status") {
                gix_protocol::push::RefUpdateStatus::Rejected { .. } => {}
                other => panic!("stale lease must be an ng/Rejected, got {other:?}"),
            }
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref unchanged after the rejected CAS");
        }

        /// §6.3-1: the host's own refs (`refs/heads/*` + `HEAD`) MUST be untouched by our rolfdb-ref
        /// create/update/delete lifecycle. Seed `refs/heads/main` (with `HEAD` pinned to it) BEFORE
        /// the rolfdb push, run the full lifecycle on `refs/rolfdb/data` over git://, then assert the
        /// host branch and `HEAD` resolve to the IDENTICAL oid afterward — the round-trip test above
        /// only left this implicit.
        #[test]
        fn host_refs_untouched_by_rolfdb_ref_lifecycle() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);

            // Seed a genuine host branch on the remote and pin HEAD to it (deterministic regardless
            // of the host git's init.defaultBranch).
            let host_hex = commit_file(&src, "host.txt", "host-content");
            push_git(&src, &remote, &format!("{host_hex}:refs/heads/main"));
            set_head(&remote, "refs/heads/main");
            let main_before = remote_ref(&remote, "refs/heads/main");
            let head_before = remote_ref(&remote, "HEAD");
            assert_eq!(main_before, host_hex, "host branch seeded at the host commit");
            assert_eq!(head_before, host_hex, "HEAD resolves to the host branch");

            let daemon = GitDaemon::serve(&base);
            let url = daemon.url("remote.git");

            // Full create/update/delete lifecycle on OUR ref — every write is over refs/rolfdb/data.
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[host_hex.as_str()]);
            push_over_url(&url, &[create(REF, &a)], Some(full_a), Options::default(), no_auth).expect("create");

            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            push_over_url(&url, &[update(REF, &a, &b)], Some(inc), Options::default(), no_auth).expect("update");

            push_over_url(&url, &[delete(REF, &b)], None, Options::default(), no_auth).expect("delete");

            // The arbiter: the host's refs never moved through any of it.
            assert_eq!(
                remote_ref(&remote, "refs/heads/main"),
                main_before,
                "host refs/heads/main is byte-identical after the rolfdb-ref lifecycle"
            );
            assert_eq!(
                remote_ref(&remote, "HEAD"),
                head_before,
                "host HEAD is byte-identical after the rolfdb-ref lifecycle"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::thin_pack — the §6.3-4 gate: a caller-built THIN pack is applied by a real server and
    // leaves it fsck-clean (unblocks flipping allow_thin_pack on; R1). Driven over file:// (the gate
    // is about the pack bytes, not the transport).
    // ---------------------------------------------------------------------------------------------
    mod thin_pack {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// Seed the remote with A (full pack), build B thin against the A boundary, push it, and
        /// assert the server completes the thin pack (`index-pack --fix-thin`) and stays fsck-clean —
        /// under BOTH the default and the `unpackLimit=1` (force-index-pack) receive paths.
        #[test]
        fn incremental_thin_is_applied_and_fsck_clean() {
            for force_index_pack in [false, true] {
                let base = Scratch::new();
                let (src, remote) = (base.join("src"), base.join("remote.git"));
                init_bare(&base, &remote);
                init_work(&base, &src);
                if force_index_pack {
                    // unpackLimit=1 forces receive-pack down the index-pack path (--fix-thin) rather
                    // than unpack-objects, exercising thin completion on the server.
                    git_config(&remote, "receive.unpackLimit", "1");
                }

                // create at A with a full pack so the server holds A's objects as the delta base.
                let a_hex = commit_file(&src, "big.txt", &"content-line\n".repeat(200));
                let a = oid_sha1(&a_hex);
                let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
                push_over_file(&remote, &[create(REF, &a)], Some(full_a));
                assert_eq!(remote_ref(&remote, REF), a_hex, "seeded A");

                // Build B thin against A: entries may delta against A's objects (server-known).
                let b_hex = commit_file(&src, "big.txt", &"content-line\nedited\n".repeat(200));
                let b = oid_sha1(&b_hex);
                let thin = git_pack_thin(&src, &[b_hex.as_str()], &[a_hex.as_str()]);

                let out = push_over_url(
                    &format!("file://{}", remote.to_str().unwrap()),
                    &[update(REF, &a, &b)],
                    Some(thin),
                    Options::default(),
                    no_auth,
                )
                .expect("thin push over file");
                assert_eq!(
                    out.unpack_status,
                    UnpackStatus::Ok,
                    "server applied the thin pack (force_index_pack={force_index_pack})"
                );
                assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced to B via thin pack");
                // The arbiter: the completed thin pack must leave the ODB whole.
                fsck_clean(&remote);
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::empty_pack — the §6.3-5 gate: a VALID 0-object pack is accepted by a real
    // git-receive-pack when the server already holds every referenced object. Over file:// (the gate
    // is about the pack bytes, not the transport). The M1 `dummy_pack` cases are mock fixtures
    // (trailer-less, never seen by a real server) — this is the proof against a live receive-pack.
    // ---------------------------------------------------------------------------------------------
    mod empty_pack {
        use crate::support::*;
        use gix_protocol::push::UnpackStatus;

        /// Seed A with a full pack, then create a SECOND ref pointing at the already-present A while
        /// streaming a valid 0-object pack. The server has every referenced object, so `unpack ok`
        /// and the mirror ref is created — a real 0-object acceptance, not the mock `dummy_pack`.
        #[test]
        fn zero_object_pack_accepted_when_objects_present() {
            const MIRROR: &str = "refs/rolfdb/mirror";
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);

            // Seed A with a real full pack so the server holds A's objects.
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            push_over_file(&remote, &[create(REF, &a)], Some(full_a));
            assert_eq!(remote_ref(&remote, REF), a_hex, "seeded A");

            // Re-point a NEW ref at the already-present A with a 0-object pack (header + trailer, no
            // objects). A real receive-pack accepts it because it needs to add no objects.
            let empty = git_empty_pack(&src);
            assert_eq!(pack_object_count(&empty), 0, "the pack carries zero objects");
            let out = push_over_file(&remote, &[create(MIRROR, &a)], Some(empty));
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "server accepted the 0-object pack");
            assert_eq!(
                remote_ref(&remote, MIRROR),
                a_hex,
                "mirror ref created at the already-present A from a 0-object pack"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::deny_non_fast_forwards — the §6.3-9 gate: with receive.denyNonFastForwards=true, a
    // genuine non-fast-forward update carrying the CORRECT lease is refused by the SERVER (`ng
    // non-fast-forward`) — surfacing as RefUpdateStatus::Rejected, NEVER an Err. Over file://.
    // ---------------------------------------------------------------------------------------------
    mod deny_non_fast_forwards {
        use crate::support::*;
        use gix_protocol::push::{Options, RefUpdateStatus, UnpackStatus};

        // `receive.denyNonFastForwards` only guards BRANCH refs, so the non-ff subject is a
        // `refs/heads/*` ref (an ordinary `refs/rolfdb/*` ref is exempt and the server would accept
        // the rewind). The rolfdb production ref is fast-forward-only by construction; this law is
        // about the client faithfully surfacing the SERVER's `ng non-fast-forward`, whatever the ref.
        const BRANCH: &str = "refs/heads/target";

        /// Seed A→B (a fast-forward chain) on a branch, then push a divergent C (child of A, NOT a
        /// descendant of B) with the correct lease (expected_old=B). `denyNonFastForwards` makes the
        /// server refuse it: the pack still unpacks (`unpack ok`) but the ref update is an `ng
        /// non-fast-forward`. The push completes at the protocol level — a rejection is a value, not
        /// an `Err` — and the remote ref stays at B.
        #[test]
        fn genuine_non_ff_with_correct_lease_is_server_rejected() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "receive.denyNonFastForwards", "true");

            // Seed A, then fast-forward to B (child of A) — on a branch ref.
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            push_over_file(
                &remote,
                &[create(BRANCH, &a)],
                Some(git_pack(&src, &[a_hex.as_str()], &[])),
            );
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            push_over_file(
                &remote,
                &[update(BRANCH, &a, &b)],
                Some(git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()])),
            );
            assert_eq!(remote_ref(&remote, BRANCH), b_hex, "server advanced to B");

            // Build C divergent from B: reset the work tree back to A and commit a different edit, so
            // C is a child of A and NOT reachable from B → moving B→C is a genuine non-fast-forward.
            run({
                let mut c = git(&src);
                c.args(["reset", "--hard", &a_hex]);
                c
            });
            let c_hex = commit_file(&src, "a.txt", "three");
            let c = oid_sha1(&c_hex);
            // Pack C's new objects against the already-present A boundary (the server has A).
            let pack_c = git_pack(&src, &[c_hex.as_str()], &[a_hex.as_str()]);

            let out = push_over_url(
                &format!("file://{}", remote.to_str().unwrap()),
                &[update(BRANCH, &b, &c)],
                Some(pack_c),
                Options::default(),
                no_auth,
            )
            .expect("push completes at the protocol level even when the server rejects the ref");
            assert_eq!(
                out.unpack_status,
                UnpackStatus::Ok,
                "the pack unpacked fine; the ref update is what the server refuses"
            );
            match out.refs.first().expect("one per-ref status") {
                RefUpdateStatus::Rejected { reason, .. } => {
                    let reason = String::from_utf8_lossy(reason);
                    assert!(
                        reason.contains("non-fast-forward") || reason.contains("non-fast forward"),
                        "server reports a non-fast-forward rejection, got {reason:?}"
                    );
                }
                other => panic!("denyNonFastForwards must be an ng/Rejected, never an Err, got {other:?}"),
            }
            assert_eq!(
                remote_ref(&remote, BRANCH),
                b_hex,
                "ref unchanged after the rejected non-ff"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::sha256_remote — the §6.3-10 gate against a REAL advertisement: a `git init --bare
    // --object-format=sha256` remote handshaked over file:// advertises object-format=sha256; a
    // sha1 push must refuse at the precheck with Error::HashKindMismatch, emitting ZERO wire bytes
    // (F3). The M1 `hash_kind` suite proves this on a MOCK caps() string; this closes it on the real
    // server's advertised object-format (testplan G11).
    // ---------------------------------------------------------------------------------------------
    mod sha256_remote {
        use crate::support::*;
        use gix_protocol::push::Error;

        /// Handshake a real sha256 bare repo over file://, then drive push() with a sha1 update. The
        /// hash-kind precheck refuses it BEFORE any request is made — HashKindMismatch { local: Sha1,
        /// server: "sha256" } — and not one byte reaches the transport.
        ///
        /// A host git without sha256 support (< 2.29) FAILS this test rather than silently passing
        /// (a silent skip would mask G11 as closed); set `ROLFDB_ALLOW_SHA256_SKIP=1` to opt such a
        /// host out explicitly.
        #[test]
        fn sha1_push_against_real_sha256_advertisement_is_refused_before_wire() {
            let base = Scratch::new();
            if !sha256_supported(&base) {
                assert!(
                    std::env::var_os("ROLFDB_ALLOW_SHA256_SKIP").is_some_and(|v| v == "1"),
                    "host git lacks --object-format=sha256 (needs git >= 2.29); \
                     set ROLFDB_ALLOW_SHA256_SKIP=1 to skip this law explicitly"
                );
                eprintln!("skipping sha256-remote law: ROLFDB_ALLOW_SHA256_SKIP=1");
                return;
            }
            let remote = base.join("remote.git");
            init_bare_object_format(&base, &remote, "sha256");

            // The REAL advertisement — its capabilities carry object-format=sha256.
            let hs = handshake_over_file(&remote);

            // A sha1 local oid → local ODB kind Sha1, mismatching the server's sha256 advertisement.
            let a = oid_sha1("cccccccccccccccccccccccccccccccccccccccc");
            let (err, sent) = run_push_err_with_handshake(hs, &[create(REF, &a)]);
            match err {
                Error::HashKindMismatch { local, server } => {
                    assert_eq!(local, gix_hash::Kind::Sha1, "local ODB is sha1");
                    assert_eq!(
                        server, "sha256",
                        "server object-format taken from the REAL advertisement"
                    );
                }
                other => panic!("expected HashKindMismatch from a real sha256 remote, got {other:?}"),
            }
            assert!(
                sent.is_empty(),
                "refused BEFORE any bytes hit the wire against the real remote (F3)"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::https — real git-http-backend over http:// (stateless GET-advert + single POST). The
    // rolfdb-facing production-shaped transport (§6.4, R3). Gated on `push_https_test` because it
    // needs an http-client feature compiled into gix-transport (else connect() fails on the scheme)
    // and, for the auth leg, the gix-sec dev-dep. The `m2-https` sync target enables both.
    // ---------------------------------------------------------------------------------------------
    #[cfg(push_https_test)]
    mod https {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// Create + fast-forward update over http:// against git-http-backend — the stateless smart-
        /// http flow (GET info/refs?service=git-receive-pack, then POST git-receive-pack) and the
        /// `WriteMode::Binary → Unbounded` streaming request body (§3.4, R3). No auth.
        #[test]
        fn create_then_update_over_http() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            // git-http-backend only serves receive-pack when http.receivepack is enabled.
            git_config(&remote, "http.receivepack", "true");
            let backend = HttpBackend::serve(&base, HttpAuth::None);
            let url = backend.url("remote.git");

            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_url(&url, &[create(REF, &a)], Some(full_a), Options::default(), no_auth)
                .expect("create over http://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "http create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created over http://");

            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url(&url, &[update(REF, &a, &b)], Some(inc), Options::default(), no_auth)
                .expect("update over http://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "http update accepted");
            assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced over http://");
        }

        /// A larger pack over http proves the streaming (unbounded) request body: `WriteMode::Binary
        /// → PostBodyDataKind::Unbounded` makes reqwest send the POST body as `Transfer-Encoding:
        /// chunked` rather than a single buffered `Content-Length` body (R3, §3.4) — load-bearing for
        /// rolfdb's multi-MiB parts. The proof is that the server observed the POST arrive as MULTIPLE
        /// chunks, not the pack's byte size (framing is chosen by `WriteMode`, not size).
        #[test]
        fn large_pack_streams_over_http() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "http.receivepack", "true");
            let backend = HttpBackend::serve(&base, HttpAuth::None);
            let url = backend.url("remote.git");

            // ~1 MiB of low-compressibility content so the pack body spans many chunks.
            let mut big = String::with_capacity(1_200_000);
            for i in 0..40_000u64 {
                use std::fmt::Write as _;
                let _ = writeln!(big, "line-{i}-{}", i * 2654435761u64 % 97);
            }
            let a_hex = commit_file(&src, "big.txt", &big);
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_url(&url, &[create(REF, &a)], Some(full_a), Options::default(), no_auth)
                .expect("large create over http://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "large http pack accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created from streamed pack");
            assert!(
                backend.last_post_chunks() > 1,
                "the POST body streamed as multiple chunks (Binary→Unbounded), got {} chunk(s)",
                backend.last_post_chunks()
            );
        }

        /// Basic-auth challenge → credential-helper retry (§6.4). The backend 401s the first
        /// (unauthenticated) request; gix invokes the `authenticate` closure and retries with the
        /// Authorization header, then the push succeeds.
        #[test]
        fn basic_auth_challenge_is_retried() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "http.receivepack", "true");
            let backend = HttpBackend::serve(&base, HttpAuth::Basic);
            let url = backend.url("remote.git");

            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_url(
                &url,
                &[create(REF, &a)],
                Some(full_a),
                Options::default(),
                static_credentials,
            )
            .expect("authenticated create over http://");
            assert_eq!(
                out.unpack_status,
                UnpackStatus::Ok,
                "auth-gated http create accepted after retry"
            );
            assert_eq!(
                remote_ref(&remote, REF),
                a_hex,
                "ref created over authenticated http://"
            );
        }
    }

    // ---------------------------------------------------------------------------------------------
    // push::tls — the git+https leg over REAL TLS (gp01-u03-fu3, testplan G8). The m2-https harness
    // above builds the reqwest/rustls stack but connects over plain http://; this connects over a
    // rustls TLS listener presenting a self-signed rcgen cert. It proves the production reqwest/rustls
    // transport does a real TLS handshake and ENFORCES certificate verification (an untrusted
    // self-signed cert is rejected), and — via a rustls client that trusts the cert — that the CGI
    // genuinely serves the smart-http advertisement over that same TLS endpoint. And — via the fu4
    // TLS-trust patch (issue #1109) — that a client trusting the cert as `http.sslCAInfo` completes a
    // REAL green push through the PRODUCTION reqwest/rustls transport (the capability upstream's
    // reqwest backend lacked). See the module note in tests/support/mod.rs.
    //
    // Gated on `push_tls_test` (the `m2-tls` sync target), which pulls the rustls + rcgen dev-deps.
    // ---------------------------------------------------------------------------------------------
    #[cfg(push_tls_test)]
    mod tls {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// The production reqwest/rustls transport performs a REAL TLS handshake against a self-signed
        /// server and REJECTS it — certificate verification is enforced, never a silent success. The
        /// server records the ClientHello (the client genuinely spoke TLS), and the handshake returns
        /// an `Err`.
        #[test]
        fn reqwest_rustls_rejects_untrusted_self_signed() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            // Repo setup mirrors the trusting companion for parity only: the TLS handshake is
            // rejected before any HTTP request reaches the CGI bridge, so nothing below touches it.
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "http.receivepack", "true");
            let backend = TlsBackend::serve(&base);
            let url = backend.url("remote.git");

            let err = try_handshake_over_url(&url)
                .expect_err("reqwest/rustls must reject the untrusted self-signed cert, not return a handshake");
            // Surface the transport error chain under --nocapture. NB: gitoxide's reqwest backend
            // flattens the reqwest error to a generic IO message ("error sending request for url …"),
            // dropping the nested rustls cause — so the *wording* cannot name the cert. We therefore
            // prove the rejection is a certificate-verification decision structurally, on the server
            // side, rather than by string-matching:
            eprintln!("reqwest/rustls rejection chain: {err}");
            // (1) The client genuinely spoke TLS to us — it sent a ClientHello.
            assert!(
                backend.saw_tls_client_hello(),
                "the server observed a TLS ClientHello from the reqwest client (real TLS was attempted)"
            );
            // (2) …yet no TLS handshake ever completed: the client verified our certificate, distrusted
            // it, and aborted with a fatal alert before finishing. ClientHello-but-no-completion is the
            // exact signature of a client-side certificate rejection — verification is enforced, not a
            // no-op. (The companion `trusting_client_completes_advertisement_over_tls` test proves the
            // same server + cert DO complete for a client that trusts it, so trust is the only variable.)
            assert!(
                !backend.completed_tls_handshake(),
                "the reqwest client aborted the TLS handshake — it distrusted the self-signed cert"
            );
        }

        /// The trust differential: a rustls client that TRUSTS the same self-signed cert completes the
        /// full smart-http advertisement over the identical TLS endpoint. Same server, same cert — so
        /// the only thing that turns the reqwest rejection above into a success here is trust, pinning
        /// that rejection to certificate verification (not a malformed cert or a broken CGI bridge).
        #[test]
        fn trusting_client_completes_advertisement_over_tls() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "http.receivepack", "true");
            // Seed a branch so the advertisement carries a concrete oid (proves the CGI truly ran).
            let a_hex = commit_file(&src, "a.txt", "one");
            push_git(&src, &remote, &format!("{a_hex}:refs/heads/main"));
            let backend = TlsBackend::serve(&base);

            let response = tls_get_advertisement(&backend, "remote.git");
            assert!(
                response.contains("200"),
                "smart-http advertisement returned 200 over TLS, got:\n{response}"
            );
            assert!(
                response.contains("# service=git-receive-pack"),
                "the receive-pack advertisement arrived over TLS, got:\n{response}"
            );
            assert!(
                response.contains(&a_hex),
                "the seeded ref's oid {a_hex} appears in the TLS advertisement, got:\n{response}"
            );
            assert!(
                backend.saw_tls_client_hello(),
                "the trusting client spoke TLS to the server"
            );
            assert!(
                backend.completed_tls_handshake(),
                "the trusting client completed the TLS handshake against the same self-signed cert"
            );
        }

        /// fu4: the trust differential completed END-TO-END through the PRODUCTION reqwest/rustls
        /// transport. A client that trusts the server's self-signed cert (handed to it as
        /// `http.sslCAInfo`) drives a real green push over `https://` — the capability upstream's
        /// reqwest backend lacked (https://github.com/GitoxideLabs/gitoxide/issues/1109). Same server +
        /// cert as `reqwest_rustls_rejects_untrusted_self_signed`; the CA bundle (trust) is the ONLY
        /// variable that turns that rejection into a completed handshake and an accepted push.
        #[test]
        fn reqwest_rustls_trusted_ca_completes_green_push() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            git_config(&remote, "http.receivepack", "true");
            let backend = TlsBackend::serve(&base);
            let url = backend.url("remote.git");

            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let ca = backend.write_ca_pem(&base);
            let out = push_over_url_trusting_ca(&url, &ca, &[create(REF, &a)], Some(full_a), Options::default())
                .expect("trusted create over https:// (production reqwest/rustls, fu4)");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "trusted TLS create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created over trusted https://");
            assert!(
                backend.saw_tls_client_hello(),
                "the reqwest client spoke TLS to the server"
            );
            assert!(
                backend.completed_tls_handshake(),
                "the trusting reqwest client completed the TLS handshake (cert accepted via ssl_ca_info)"
            );
        }
    }
}
