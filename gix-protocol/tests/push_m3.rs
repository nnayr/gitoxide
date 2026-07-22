//! M3 (`gp01-u04`) contractual suites for the **async** `gix_protocol::push::push()` — the async
//! parity milestone (plan §5-M3, §3.3, §3.5). Suite names are contractual:
//! `push::{create_update, delete_only, rejected, refused, interrupt}`.
//!
//! What M3 proves: the async orchestrator twin drives the same v1 receive-pack flow as the blocking
//! core over an **async** transport — the create/update pack path streams via an `AsyncFnOnce`
//! `write_pack` closure and parses the report into an [`Outcome`]; the delete-only path sends no pack
//! and terminates with exactly ONE flush (F4); and an `ng` report surfaces as
//! [`RefUpdateStatus::Rejected`]. The report parser is the same pure `parse_report` the blocking twin
//! uses, reached through the async reader.
//!
//! Fully in-memory: an async `MockTransport` under `futures_lite::future::block_on` — no real `git`,
//! no sockets, no RNG/sleeps/wall-clock. The pure builders + the wire-byte scanner are reused from
//! `tests/support` (async-only drivers live behind `#[cfg(feature = "async-client")]` there so the
//! shared support still compiles for the blocking suites).

#![cfg(all(feature = "push", feature = "async-client"))]
#![allow(unexpected_cfgs)] // `push_async_daemon_test` is set via RUSTFLAGS by the `m3-daemon` sync target

mod support;

// ---------------------------------------------------------------------------------------------
// push::create_update — the pack path: async write_pack closure → parsed Outcome (unpack ok + ok)
// ---------------------------------------------------------------------------------------------
mod push {
    mod create_update {
        use crate::support::*;
        use gix_protocol::push::{RefUpdateStatus, UnpackStatus};

        /// A create over the async transport streams a pack and parses `unpack ok` + a per-ref `ok`.
        #[test]
        fn create_streams_pack_and_parses_ok() {
            let new = oid_sha1("1111111111111111111111111111111111111111");
            let updates = [create(REF, &new)];
            let outcome = run_push_ok_async(
                caps("report-status delete-refs ofs-delta object-format=sha1"),
                advertise(&[]),
                &updates,
                dummy_pack(),
                ok_report(REF),
            );
            assert_eq!(
                outcome.unpack_status,
                UnpackStatus::Ok,
                "unpack ok parsed off the async wire"
            );
            assert_eq!(outcome.refs.len(), 1, "exactly one per-ref status");
            match &outcome.refs[0] {
                RefUpdateStatus::Ok { name, .. } => assert_eq!(name, REF, "the ok ref name is echoed verbatim"),
                other => panic!("expected Ok status, got {other:?}"),
            }
        }

        /// An update (non-null lease) likewise streams the pack and parses `ok`.
        #[test]
        fn update_streams_pack_and_parses_ok() {
            let old = oid_sha1("2222222222222222222222222222222222222222");
            let new = oid_sha1("3333333333333333333333333333333333333333");
            let updates = [update(REF, &old, &new)];
            let outcome = run_push_ok_async(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[(REF, &old)]),
                &updates,
                dummy_pack(),
                ok_report(REF),
            );
            assert_eq!(outcome.unpack_status, UnpackStatus::Ok);
            assert!(
                matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF),
                "update parsed as Ok for {REF}"
            );
        }

        /// The pack path sends the command list, exactly ONE flush, then the raw pack bytes (F4): the
        /// same framing law the blocking suite asserts, now over the async writer.
        #[test]
        fn pack_path_emits_single_flush_then_pack() {
            let new = oid_sha1("4444444444444444444444444444444444444444");
            let updates = [create(REF, &new)];
            let sent = run_push_capture_async(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &updates,
                dummy_pack(),
                ok_report(REF),
            );
            let scan = scan_command_list(&sent);
            assert_eq!(scan.flushes, 1, "exactly one flush precedes the pack (F4)");
            assert_eq!(
                scan.pack.as_deref().map(|p| &p[..4]),
                Some(&b"PACK"[..]),
                "the raw pack follows the single flush"
            );
            assert_eq!(
                scan.lines_with_caps(),
                1,
                "capabilities ride on the first command line only"
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::delete_only — no pack, exactly one flush (into_read's single terminator, F4)
    // -----------------------------------------------------------------------------------------
    mod delete_only {
        use crate::support::*;
        use gix_protocol::push::{RefUpdateStatus, UnpackStatus};

        /// A delete-only push sends no pack and terminates with exactly one flush; the report parses.
        #[test]
        fn delete_only_single_flush_no_pack() {
            let old = oid_sha1("5555555555555555555555555555555555555555");
            let updates = [delete(REF, &old)];
            let sent = run_push_capture_async(
                caps("report-status delete-refs object-format=sha1"),
                advertise(&[(REF, &old)]),
                &updates,
                None, // delete-only: the write_pack closure is never called
                ok_report(REF),
            );
            let scan = scan_command_list(&sent);
            assert_eq!(
                scan.flushes, 1,
                "delete-only emits the single into_read terminator (F4)"
            );
            assert!(scan.pack.is_none(), "delete-only sends no pack after the flush");
        }

        /// The delete-only report still parses into an Ok outcome.
        #[test]
        fn delete_only_parses_ok() {
            let old = oid_sha1("6666666666666666666666666666666666666666");
            let updates = [delete(REF, &old)];
            let outcome = run_push_ok_async(
                caps("report-status delete-refs object-format=sha1"),
                advertise(&[(REF, &old)]),
                &updates,
                None,
                ok_report(REF),
            );
            assert_eq!(outcome.unpack_status, UnpackStatus::Ok);
            assert!(matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF));
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::rejected — an `ng` report → RefUpdateStatus::Rejected (verbatim reason preserved)
    // -----------------------------------------------------------------------------------------
    mod rejected {
        use crate::support::*;
        use gix_protocol::push::{RefUpdateStatus, UnpackStatus};

        /// `unpack ok` but `ng <ref> <reason>` parses as Rejected with the verbatim reason.
        #[test]
        fn ng_report_parses_as_rejected() {
            let new = oid_sha1("7777777777777777777777777777777777777777");
            let updates = [create(REF, &new)];
            let report = report_lines(&["unpack ok", &format!("ng {REF} non-fast-forward")]);
            let outcome = run_push_ok_async(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &updates,
                dummy_pack(),
                report,
            );
            assert_eq!(
                outcome.unpack_status,
                UnpackStatus::Ok,
                "the pack unpacked; the ref was refused"
            );
            match &outcome.refs[0] {
                RefUpdateStatus::Rejected { name, reason, .. } => {
                    assert_eq!(name, REF, "rejected ref name echoed verbatim");
                    assert_eq!(reason, "non-fast-forward", "the ng reason is preserved verbatim");
                }
                other => panic!("expected Rejected status, got {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::refused — the async preflight/parse refusals: HashKindMismatch (F3) and NoCommands
    // (F5) fail BEFORE any wire byte; a report missing a per-ref status is an Err, not a panic.
    // -----------------------------------------------------------------------------------------
    mod refused {
        use crate::support::*;
        use gix_protocol::push::Error;

        /// An `object-format=sha256` remote against a sha1 update is refused with `HashKindMismatch`
        /// BEFORE any byte hits the async wire — F3 preflight fires ahead of `transport.request`.
        #[test]
        fn sha256_remote_refused_before_any_async_byte() {
            let local = oid_sha1("cccccccccccccccccccccccccccccccccccccccc"); // sha1 local oid
            let (err, sent) = run_push_err_async(
                caps("report-status object-format=sha256"), // sha256 remote
                advertise(&[]),
                &[create(REF, &local)],
                no_report(),
            );
            match err {
                Error::HashKindMismatch { local, server } => {
                    assert_eq!(local, gix_hash::Kind::Sha1, "local ODB is sha1");
                    assert_eq!(server, "sha256", "server object-format preserved verbatim");
                }
                other => panic!("expected HashKindMismatch, got {other:?}"),
            }
            assert!(sent.is_empty(), "refused BEFORE any bytes hit the async wire (F3)");
        }

        /// An empty update list is `NoCommands` before the transport is touched (F5).
        #[test]
        fn empty_update_list_is_no_commands() {
            let (err, sent) = run_push_err_async(caps("report-status"), advertise(&[]), &[], no_report());
            assert!(
                matches!(err, Error::NoCommands),
                "push(&[]) -> Error::NoCommands, got {err:?}"
            );
            assert!(sent.is_empty(), "no wire bytes on the empty-command refusal (F5)");
        }

        /// A report with no per-ref status for the sent command surfaces as `MissingRefStatus` — an
        /// error through the async reader, never a panic.
        #[test]
        fn report_missing_ref_status_is_error_not_panic() {
            let new = oid_sha1("8888888888888888888888888888888888888888");
            let report = report_lines(&["unpack ok"]); // unpack line only — no `ok`/`ng` for REF
            let (err, _sent) = run_push_err_async(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &[create(REF, &new)],
                report,
            );
            assert!(
                matches!(
                    err,
                    Error::Response(gix_protocol::push::response::Error::MissingRefStatus { .. })
                ),
                "a sent command with no reported status -> MissingRefStatus, got {err:?}"
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::interrupt — the async twin of the §6.3-11 abort lane (`push_interrupt.rs`, testplan-
    // fuse G1): should_interrupt observed mid-`write_pack` → typed `Error::WritePack`, no report
    // read, only the truncated pack prefix on the wire.
    // -----------------------------------------------------------------------------------------
    mod interrupt {
        use crate::support::*;

        /// Mid-pack abort over the async transport: `Error::WritePack`, the garbage report is never
        /// parsed (else the error would be `Response`), and the wire ends at the truncated prefix
        /// after the single pack-path flush (F4).
        #[test]
        fn mid_pack_abort_is_typed_error_and_reads_no_report() {
            let new = oid_sha1("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            let pack = dummy_pack().expect("a pack for the create path");
            let cut = pack.len() / 2;
            let (err, sent) = run_push_interrupt_async(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &[create(REF, &new)],
                pack.clone(),
                cut,
                tripwire_report(),
            );
            assert_writepack_interrupt(&err);
            let scan = scan_command_list(&sent);
            assert_eq!(
                scan.flushes, 1,
                "the single pack-path flush precedes the aborted pack (F4)"
            );
            assert_eq!(
                scan.pack.as_deref(),
                Some(&pack[..cut]),
                "exactly the truncated prefix reached the async wire"
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::wire_features — the async twins of the M3 wire features (rolfdb-gp01-m3feat): push-options
    // (§1.3) and side-band-64k report demux (§3.5), over the in-memory AsyncMockTransport. The
    // blocking golden/real-server proofs live in push_m3feat.rs; here we prove the async orchestrator +
    // async response reader handle the same framing byte-for-byte.
    // -----------------------------------------------------------------------------------------
    mod wire_features {
        use crate::support::*;
        use gix_protocol::push::{Options, RefUpdateStatus, UnpackStatus};

        /// Async push-options: the pack path emits the command-list flush, the option pkt-lines, their
        /// own flush, then the pack — two flushes, options verbatim and in order.
        #[test]
        fn push_options_pack_path_async() {
            let a = oid_sha1("1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a");
            let opts = Options {
                push_options: vec!["alpha".into(), "key=val".into()],
                ..Default::default()
            };
            let sent = run_push_capture_async_opts(
                caps("report-status ofs-delta push-options object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
                opts,
            );
            let wire = scan_push_wire(&sent);
            assert_eq!(wire.option_strings(), vec!["alpha".to_string(), "key=val".to_string()]);
            assert_eq!(wire.flushes, 2, "command-list flush + push-options' own flush");
            assert_eq!(wire.pack.as_deref().map(|p| &p[..4]), Some(&b"PACK"[..]));
            assert!(
                wire.command_lines[0].windows(12).any(|w| w == b"push-options"),
                "push-options echoed in the first command line"
            );
        }

        /// Async delete-only + push-options: two flushes, no pack (the async mirror of the F4-careful
        /// blocking framing).
        #[test]
        fn push_options_delete_only_two_flushes_no_pack_async() {
            let a = oid_sha1("2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b");
            let opts = Options {
                push_options: vec!["gone".into()],
                ..Default::default()
            };
            let sent = run_push_capture_async_opts(
                caps("report-status delete-refs push-options object-format=sha1"),
                advertise(&[(REF, &a)]),
                &[delete(REF, &a)],
                None,
                ok_report(REF),
                opts,
            );
            let wire = scan_push_wire(&sent);
            assert_eq!(wire.option_strings(), vec!["gone".to_string()]);
            assert_eq!(wire.flushes, 2, "delete-only + push-options sends two flushes, not one");
            assert!(wire.pack.is_none(), "delete-only sends no pack even with push-options");
        }

        /// Async push-options against an unadvertised cap is refused (F5), before any wire bytes —
        /// parity with the blocking law.
        #[test]
        fn push_options_without_cap_is_missing_server_feature_async() {
            let a = oid_sha1("3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c");
            let opts = Options {
                push_options: vec!["nope".into()],
                ..Default::default()
            };
            let (err, sent) = run_push_err_async_opts(
                caps("report-status"), // no push-options advertised
                advertise(&[]),
                &[create(REF, &a)],
                no_report(),
                opts,
            );
            assert!(
                matches!(
                    err,
                    gix_protocol::push::Error::MissingServerFeature {
                        feature: "push-options",
                        ..
                    }
                ),
                "unadvertised push-options is refused: {err:?}"
            );
            assert!(sent.is_empty(), "refused before any async wire bytes");
        }

        /// Async side-band-64k: a band-1-wrapped report demuxes exactly like the plain report, and the
        /// cap is echoed on the wire.
        #[test]
        fn sideband_report_demuxed_async() {
            let a = oid_sha1("4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d");
            let opts = Options {
                sideband: true,
                ..Default::default()
            };
            let outcome = run_push_ok_async_opts(
                caps("report-status side-band-64k object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                sideband_report(&ok_report(REF)),
                opts.clone(),
            );
            assert_eq!(outcome.unpack_status, UnpackStatus::Ok);
            assert!(matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF));

            let sent = run_push_capture_async_opts(
                caps("report-status side-band-64k object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                sideband_report(&ok_report(REF)),
                opts,
            );
            let scan = scan_command_list(&sent);
            assert!(
                scan.lines[0].windows(13).any(|w| w == b"side-band-64k"),
                "side-band-64k echoed in the first command line"
            );
        }

        /// Async side-band demux is robust to band-1 fragmentation with band-2/3 packets interleaved.
        #[test]
        fn sideband_fragmented_with_side_bands_async() {
            let a = oid_sha1("5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e");
            let rep = ok_report(REF);
            let mid = rep.len() / 2;
            let report = sideband_report_chunked(
                &[&rep[..mid], &rep[mid..]],
                &[(2, b"remote: counting"), (3, b"remote: a notice")],
            );
            let outcome = run_push_ok_async_opts(
                caps("report-status side-band-64k object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                report,
                Options {
                    sideband: true,
                    ..Default::default()
                },
            );
            assert_eq!(outcome.unpack_status, UnpackStatus::Ok);
            assert!(matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF));
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::daemon — the ONE real-binary async transport (testplan gap G2, plan §6.4). Everything
    // above drives the async twin over an in-memory `AsyncMockTransport`; this promotes it to a LIVE
    // `git-receive-pack` reached over `git://` via the async-std TCP connector — the only real
    // transport `client::async_io::connect` supports (file://, http/https, ssh have NO async
    // connector upstream; see docs/process/gix-push-impl-workflow.md §5). It is the async mirror of
    // the blocking `push_m2.rs::push::daemon::create_update_delete_round_trip`.
    //
    // Gated on `push_async_daemon_test` (RUSTFLAGS, `m3-daemon` sync target) because the async
    // connector compiles only under `gix-transport/async-std`, which the default M3 build omits.
    #[cfg(push_async_daemon_test)]
    mod daemon {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// The full single-ref lifecycle — create, fast-forward update, delete — over `git://`,
        /// driven by the **async** `push()` against a real `git daemon`. Proves the async M3 core is
        /// transport-generic against a live server, not just the in-memory mock (§5-M3, plan §6.4).
        #[test]
        fn create_update_delete_round_trip_async() {
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
            let out = push_over_url_async(&url, &[create(REF, &a)], Some(full_a), Options::default())
                .expect("async create over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "async create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created at A over async git://");

            // fast-forward update to B (incremental pack, boundary=A).
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url_async(&url, &[update(REF, &a, &b)], Some(inc), Options::default())
                .expect("async update over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "async update accepted");
            assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced to B over async git://");

            // delete (no pack sent).
            let out = push_over_url_async(&url, &[delete(REF, &b)], None, Options::default())
                .expect("async delete over git://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "async delete accepted");
            assert!(
                !remote_has_ref(&remote, REF),
                "ref is gone after async delete over git://"
            );
        }

        /// An `ng` per-ref rejection from a real server surfaces as [`UnpackStatus::Ok`] +
        /// `RefUpdateStatus::Rejected` over the async wire: a stale-lease CAS refusal (the leased
        /// `old-oid` was never the ref's value) is the server's ref check, never an `Err`. The async
        /// twin of the blocking `daemon::stale_lease_is_rejected_by_server_cas`.
        #[test]
        fn stale_lease_rejected_by_server_cas_async() {
            use gix_protocol::push::RefUpdateStatus;

            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            let daemon = GitDaemon::serve(&base);
            let url = daemon.url("remote.git");

            // Establish the ref at A on the server.
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            push_over_url_async(&url, &[create(REF, &a)], Some(full_a), Options::default())
                .expect("async seed create over git://");

            // Push an update leasing a stale `old-oid` the server never held → server `ng`.
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let stale = oid_sha1("dddddddddddddddddddddddddddddddddddddddd");
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url_async(&url, &[update(REF, &stale, &b)], Some(inc), Options::default())
                .expect("a server CAS rejection is Ok(outcome), never an Err");
            assert_eq!(
                out.unpack_status,
                UnpackStatus::Ok,
                "the pack unpacked; the ref was refused by the server CAS, not the client"
            );
            assert!(
                matches!(&out.refs[0], RefUpdateStatus::Rejected { name, .. } if name == REF),
                "stale lease → server ng → Rejected, got {:?}",
                out.refs[0]
            );
            assert_eq!(
                remote_ref(&remote, REF),
                a_hex,
                "the ref is unchanged after the CAS rejection"
            );
        }
    }
}
