//! M1 (`gp01-u02`) contractual suites for `gix_protocol::push::push()` — the v1 blocking
//! single-ref core (plan §3, §5-M1, §6.2-6.3). Suite names are contractual:
//! `push::{command_golden, empty_and_shapes, flush_framing, hash_kind, validate, response,
//! boundary_walk}`.
//!
//! Determinism: no RNG, no sleeps, no wall-clock in the assertions. Commit oids are pinned by fixed
//! identity + `GIT_*_DATE`; the golden wire bytes are diffed against a live `GIT_TRACE_PACKET=1 git
//! push` capture (the empirical oracle, never our own encoder). The mock transport is fully
//! in-memory. SHA-256 sub-laws self-skip when the `gix-hash/sha256` feature is off (the M1 test
//! target enables it) so this file compiles in any feature configuration.
//!
//! TEST-ENV DIVERGENCE (deliberate, per the plan §6 infra note): the fork-side suite invokes the
//! real `git` binary (`file://` runs `git-receive-pack`; `GIT_TRACE_PACKET=1` is the byte oracle).
//! `git` is a dev/test dependency of the FORK suite only — never rolfdb production.
//!
//! Unix-only: `file://` + real `git-receive-pack` and `/dev/null` config paths.

#![cfg(all(unix, feature = "push", feature = "blocking-client"))]

mod support;

// ---------------------------------------------------------------------------------------------
// push::command_golden — command-list wire bytes diffed against a real git push (§6.2, F2/F3/H1)
// ---------------------------------------------------------------------------------------------
mod push {
    mod command_golden {
        use crate::support::*;
        use std::collections::BTreeSet;

        /// A `create` command triple byte-matches git's own, caps ride on the first line only.
        #[test]
        fn create_triple_matches_git_and_caps_first_line_only() {
            let base = Scratch::new();
            let (src, oracle) = (base.join("src"), base.join("oracle.git"));
            init_bare(&base, &oracle);
            init_work(&base, &src);
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);

            let git_triples = git_push_triples(&src, &oracle, &format!("{a_hex}:{REF}"));
            let expected = format!("{} {a_hex} {REF}", zeros(40));
            assert_eq!(
                git_triples,
                once(expected.clone()),
                "git's own create triple is the oracle"
            );

            // Our encoder, driven through the public push() over the mock transport, must emit the
            // SAME triple bytes — and the caps only on the first (only) line.
            let sent = run_push_capture(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
            );
            let cmd = scan_command_list(&sent);
            assert_eq!(cmd.triples(), once(expected), "our create triple == git's, byte for byte");
            assert_eq!(cmd.lines_with_caps(), 1, "capabilities appear on the FIRST line only");
        }

        /// An `update` command triple (real old-oid → new-oid) byte-matches git's own.
        #[test]
        fn update_triple_matches_git() {
            let base = Scratch::new();
            let (src, oracle) = (base.join("src"), base.join("oracle.git"));
            init_bare(&base, &oracle);
            init_work(&base, &src);
            let a_hex = commit_file(&src, "a.txt", "one");
            push_git(&src, &oracle, &format!("{a_hex}:{REF}"));
            let b_hex = commit_file(&src, "a.txt", "two");
            let (a, b) = (oid_sha1(&a_hex), oid_sha1(&b_hex));

            let git_triples = git_push_triples(&src, &oracle, &format!("{b_hex}:{REF}"));
            let expected = format!("{a_hex} {b_hex} {REF}");
            assert_eq!(git_triples, once(expected.clone()), "git's own update triple is the oracle");

            let sent = run_push_capture(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[(REF, &a)]),
                &[update(REF, &a, &b)],
                dummy_pack(),
                ok_report(REF),
            );
            assert_eq!(scan_command_list(&sent).triples(), once(expected), "our update triple == git's");
        }

        /// A `delete` command triple (old-oid → zero) byte-matches git's own, and sends NO pack.
        #[test]
        fn delete_triple_matches_git() {
            let base = Scratch::new();
            let (src, oracle) = (base.join("src"), base.join("oracle.git"));
            init_bare(&base, &oracle);
            init_work(&base, &src);
            let a_hex = commit_file(&src, "a.txt", "one");
            push_git(&src, &oracle, &format!("{a_hex}:{REF}"));
            let a = oid_sha1(&a_hex);

            let git_triples = git_push_triples(&src, &oracle, &format!(":{REF}"));
            let expected = format!("{a_hex} {} {REF}", zeros(40));
            assert_eq!(git_triples, once(expected.clone()), "git's own delete triple is the oracle");

            let sent = run_push_capture(
                caps("report-status delete-refs ofs-delta object-format=sha1"),
                advertise(&[(REF, &a)]),
                &[delete(REF, &a)],
                None, // delete-only: no pack
                ok_report(REF),
            );
            let cmd = scan_command_list(&sent);
            assert_eq!(cmd.triples(), once(expected), "our delete triple == git's");
            assert!(cmd.pack.is_none(), "a delete-only push sends no pack");
        }

        /// Multi-ref: caps on the first line only; each subsequent line is a bare triple (no NUL).
        #[test]
        fn multi_ref_caps_on_first_line_only() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let sent = run_push_capture(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &[create("refs/rolfdb/data", &a), create("refs/rolfdb/other", &b)],
                dummy_pack(),
                multi_ok_report(&["refs/rolfdb/data", "refs/rolfdb/other"]),
            );
            let cmd = scan_command_list(&sent);
            assert_eq!(cmd.lines.len(), 2, "two command pkt-lines");
            assert_eq!(cmd.lines_with_caps(), 1, "caps on the FIRST line only");
            assert!(
                !cmd.lines[1].contains(&0u8),
                "the second command line carries no NUL/caps"
            );
            let expected: BTreeSet<String> = [
                format!("{} {a} refs/rolfdb/data", zeros(40)),
                format!("{} {b} refs/rolfdb/other", zeros(40)),
            ]
            .into_iter()
            .collect();
            assert_eq!(cmd.triples(), expected, "both triples are well-formed");
        }

        /// The zero-id width tracks the negotiated object-format: 40 hex for SHA-1, 64 for SHA-256.
        #[test]
        fn zero_id_width_sha1_and_sha256() {
            // SHA-1: create's old-id is 40 zeros.
            let a = oid_sha1("abcabcabcabcabcabcabcabcabcabcabcabcabca");
            let sent = run_push_capture(
                caps("report-status object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
            );
            let triple = scan_command_list(&sent).triples().into_iter().next().unwrap();
            assert_eq!(triple.split(' ').next().unwrap(), zeros(40), "sha1 zero-id is 40 hex");

            // SHA-256: needs the sha256 hash variant; self-skip when the feature is off.
            let Some(new256) = sha256_oid("11") else {
                eprintln!("skipping sha256 width law: gix-hash/sha256 not enabled");
                return;
            };
            let sent = run_push_capture(
                caps("report-status object-format=sha256"),
                advertise(&[]),
                &[create(REF, &new256)],
                dummy_pack(),
                ok_report(REF),
            );
            let triple = scan_command_list(&sent).triples().into_iter().next().unwrap();
            assert_eq!(triple.split(' ').next().unwrap(), zeros(64), "sha256 zero-id is 64 hex");
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::empty_and_shapes — early refusals are Err VALUES, before any wire bytes (F2, F5)
    // -----------------------------------------------------------------------------------------
    mod empty_and_shapes {
        use crate::support::*;
        use gix_protocol::push::Error;

        #[test]
        fn empty_updates_is_no_commands() {
            let (err, sent) = run_push_err(caps("report-status"), advertise(&[]), &[], no_report());
            assert!(matches!(err, Error::NoCommands), "push(&[]) -> Error::NoCommands, got {err:?}");
            assert!(sent.is_empty(), "no bytes written for an empty command list");
        }

        #[test]
        fn push_options_without_cap_is_missing_server_feature() {
            let a = oid_sha1("1234123412341234123412341234123412341234");
            let mut opts = gix_protocol::push::Options::default();
            opts.push_options = vec!["do-thing".into()];
            let (err, sent) = run_push_err_opts(
                caps("report-status"), // no push-options advertised
                advertise(&[]),
                &[create(REF, &a)],
                no_report(),
                opts,
            );
            match err {
                Error::MissingServerFeature { feature, .. } => {
                    assert_eq!(feature, "push-options", "the struct variant names the missing feature");
                }
                other => panic!("expected MissingServerFeature, got {other:?}"),
            }
            assert!(sent.is_empty(), "no bytes written when the request is refused");
        }

        #[test]
        fn delete_without_delete_refs_is_missing_server_feature() {
            let a = oid_sha1("1234123412341234123412341234123412341234");
            let (err, _sent) = run_push_err(
                caps("report-status"), // no delete-refs
                advertise(&[(REF, &a)]),
                &[delete(REF, &a)],
                no_report(),
            );
            assert!(
                matches!(err, Error::MissingServerFeature { feature: "delete-refs", .. }),
                "delete without delete-refs -> MissingServerFeature, got {err:?}"
            );
        }

        #[test]
        fn atomicity_required_without_cap_is_missing_server_feature() {
            let a = oid_sha1("1234123412341234123412341234123412341234");
            let mut opts = gix_protocol::push::Options::default();
            opts.atomic = gix_protocol::push::Atomicity::Required;
            let (err, _sent) = run_push_err_opts(
                caps("report-status"), // no atomic
                advertise(&[]),
                &[create(REF, &a)],
                no_report(),
                opts,
            );
            assert!(
                matches!(err, Error::MissingServerFeature { feature: "atomic", .. }),
                "Atomicity::Required without atomic -> MissingServerFeature, got {err:?}"
            );
        }

        #[test]
        fn sideband_opt_in_is_missing_server_feature() {
            let a = oid_sha1("1234123412341234123412341234123412341234");
            let mut opts = gix_protocol::push::Options::default();
            opts.sideband = true;
            let (err, sent) = run_push_err_opts(
                caps("report-status side-band-64k"),
                advertise(&[]),
                &[create(REF, &a)],
                no_report(),
                opts,
            );
            assert!(
                matches!(err, Error::MissingServerFeature { feature: "side-band-64k", .. }),
                "Options::sideband is refused, not silently ignored, got {err:?}"
            );
            assert!(sent.is_empty(), "refused before any bytes hit the wire");
        }

        /// A null oid in a non-fixed command slot is a caller error the type does not catch; the
        /// encoder trips a debug assert on it rather than writing a bogus zero-id (fix 3b).
        #[test]
        #[should_panic(expected = "null object id in a Create command")]
        fn null_oid_slot_trips_debug_assert() {
            let null = gix_hash::ObjectId::null(gix_hash::Kind::Sha1);
            let _ = run_push_capture(
                caps("report-status object-format=sha1"),
                advertise(&[]),
                &[create(REF, &null)],
                dummy_pack(),
                ok_report(REF),
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::flush_framing — the delete-only path sends EXACTLY one flush-pkt; the pack path
    // writes one explicit flush then the raw pack, never a double terminator (F4)
    // -----------------------------------------------------------------------------------------
    mod flush_framing {
        use crate::support::*;

        #[test]
        fn delete_only_writes_exactly_one_flush_and_no_pack() {
            let a = oid_sha1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let sent = run_push_capture(
                caps("report-status delete-refs"),
                advertise(&[(REF, &a)]),
                &[delete(REF, &a)],
                None,
                ok_report(REF),
            );
            let cmd = scan_command_list(&sent);
            assert_eq!(cmd.flushes, 1, "delete-only sends EXACTLY one flush-pkt");
            assert!(cmd.pack.is_none(), "delete-only sends no pack (no bytes after the flush)");
        }

        #[test]
        fn pack_path_writes_one_flush_then_raw_pack() {
            let a = oid_sha1("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            let sent = run_push_capture(
                caps("report-status ofs-delta"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
            );
            let cmd = scan_command_list(&sent);
            assert_eq!(cmd.flushes, 1, "exactly one flush terminates the command list before the pack");
            let pack = cmd.pack.expect("a create sends a pack");
            assert_eq!(&pack[..4], b"PACK", "the raw pack follows immediately after the single flush");
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::hash_kind — object-format != local ODB kind is HashKindMismatch, BEFORE any bytes (F3)
    // -----------------------------------------------------------------------------------------
    mod hash_kind {
        use crate::support::*;
        use gix_protocol::push::Error;

        #[test]
        fn sha256_remote_against_sha1_odb_is_refused_before_wire() {
            let a = oid_sha1("cccccccccccccccccccccccccccccccccccccccc"); // sha1 local oid
            let (err, sent) = run_push_err(
                caps("report-status object-format=sha256"), // sha256 remote
                advertise(&[]),
                &[create(REF, &a)],
                no_report(),
            );
            match err {
                Error::HashKindMismatch { local, server } => {
                    assert_eq!(local, gix_hash::Kind::Sha1, "local ODB is sha1");
                    assert_eq!(server, "sha256", "server object-format preserved verbatim");
                }
                other => panic!("expected HashKindMismatch, got {other:?}"),
            }
            assert!(sent.is_empty(), "refused BEFORE any bytes hit the wire (F3)");
        }

        #[test]
        fn matching_sha1_object_format_proceeds() {
            let a = oid_sha1("dddddddddddddddddddddddddddddddddddddddd");
            let outcome = run_push_ok(
                caps("report-status object-format=sha1"),
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
            );
            assert_eq!(outcome.unpack_status, gix_protocol::push::UnpackStatus::Ok);
        }

        #[test]
        fn absent_object_format_defaults_to_local_and_proceeds() {
            let a = oid_sha1("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
            let outcome = run_push_ok(
                caps("report-status"), // no object-format advertised (older server)
                advertise(&[]),
                &[create(REF, &a)],
                dummy_pack(),
                ok_report(REF),
            );
            assert_eq!(outcome.unpack_status, gix_protocol::push::UnpackStatus::Ok);
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::validate — plan_from_advertisement: leases + the boundary/thin_bases split (F1, F11)
    // -----------------------------------------------------------------------------------------
    mod validate {
        use crate::support::*;
        use gix_protocol::push::plan_from_advertisement;
        use gix_protocol::push::validate::Error as ValidateError;

        #[test]
        fn match_returns_boundary_and_thin_bases_with_invariant() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let hs = handshake(caps("report-status"), advertise(&[(REF, &a)]));
            let adv = plan_from_advertisement(&[update(REF, &a, &b)], &hs).expect("lease matches");
            assert_eq!(adv.boundary, Some(a), "boundary is OUR ref's advertised oid");
            assert!(adv.thin_bases.contains(&a), "thin_bases is the full advertised set");
            assert!(
                adv.boundary.map_or(true, |bnd| adv.thin_bases.contains(&bnd)),
                "INVARIANT: boundary ∈ thin_bases when Some"
            );
        }

        #[test]
        fn stale_lease_is_reported() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let x = oid_sha1("9999999999999999999999999999999999999999");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let hs = handshake(caps("report-status"), advertise(&[(REF, &a)]));
            let err = plan_from_advertisement(&[update(REF, &x, &b)], &hs).unwrap_err();
            assert!(
                matches!(err, ValidateError::StaleLease { actual: Some(act), expected: Some(exp), .. } if act == a && exp == x),
                "stale lease surfaces expected vs advertised, got {err:?}"
            );
        }

        #[test]
        fn create_against_existing_ref_is_stale() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let hs = handshake(caps("report-status"), advertise(&[(REF, &a)]));
            let err = plan_from_advertisement(&[create(REF, &b)], &hs).unwrap_err();
            assert!(
                matches!(err, ValidateError::StaleLease { expected: None, actual: Some(act), .. } if act == a),
                "create over an existing ref is stale, never a blind overwrite, got {err:?}"
            );
        }

        #[test]
        fn expected_but_missing_is_stale() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let hs = handshake(caps("report-status"), advertise(&[]));
            let err = plan_from_advertisement(&[update(REF, &a, &b)], &hs).unwrap_err();
            assert!(
                matches!(err, ValidateError::StaleLease { actual: None, expected: Some(exp), .. } if exp == a),
                "update of an absent ref is stale, got {err:?}"
            );
        }

        #[test]
        fn empty_repo_create_has_no_boundary() {
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let hs = handshake(caps("report-status"), advertise(&[]));
            let adv = plan_from_advertisement(&[create(REF, &b)], &hs).expect("create into empty repo");
            assert_eq!(adv.boundary, None, "a create has no walk boundary");
            assert!(adv.thin_bases.is_empty(), "empty repo advertises no thin bases");
        }

        /// A hidden ref (absent from the advertisement though it exists) reads as "does not exist":
        /// an update surfaces as StaleLease{actual:None}, NEVER a blind overwrite (F11).
        #[test]
        fn hidden_ref_update_is_stale_not_blind_overwrite() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let c = oid_sha1("cccccccccccccccccccccccccccccccccccccccc");
            // The advertisement carries an unrelated head, but NOT our (hidden) ref.
            let hs = handshake(caps("report-status"), advertise(&[("refs/heads/main", &c)]));
            let err = plan_from_advertisement(&[update(REF, &a, &b)], &hs).unwrap_err();
            assert!(
                matches!(err, ValidateError::StaleLease { actual: None, .. }),
                "a hidden ref reads as absent -> StaleLease, never a blind overwrite, got {err:?}"
            );
        }

        /// Foreign advertised refs (refs/heads/*) go to thin_bases; our ref alone is the boundary.
        #[test]
        fn foreign_refs_go_to_thin_bases_not_boundary() {
            let a = oid_sha1("1111111111111111111111111111111111111111");
            let b = oid_sha1("2222222222222222222222222222222222222222");
            let c = oid_sha1("cccccccccccccccccccccccccccccccccccccccc");
            let hs = handshake(caps("report-status"), advertise(&[(REF, &a), ("refs/heads/main", &c)]));
            let adv = plan_from_advertisement(&[update(REF, &a, &b)], &hs).expect("lease matches");
            assert_eq!(adv.boundary, Some(a), "boundary is our ref, not the foreign head");
            assert!(adv.thin_bases.contains(&c), "the foreign head oid is a thin base");
            assert!(adv.thin_bases.contains(&a), "our ref oid is also a thin base");
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::response — v1 ok/ng, unpack failure, v2 option lines, garbage-never-panics (F10)
    // -----------------------------------------------------------------------------------------
    mod response {
        use crate::support::*;
        use gix_protocol::push::{Error, RefRejectReason, RefUpdateStatus, UnpackStatus};

        fn push_delete_with_report(report: Vec<u8>) -> Result<gix_protocol::push::Outcome, Error> {
            let a = oid_sha1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            try_push(
                caps("report-status delete-refs"),
                advertise(&[(REF, &a)]),
                &[delete(REF, &a)],
                None,
                report,
            )
        }

        #[test]
        fn v1_ok() {
            let out = push_delete_with_report(ok_report(REF)).expect("ok report parses");
            assert_eq!(out.unpack_status, UnpackStatus::Ok);
            assert_eq!(out.refs.len(), 1);
            assert!(matches!(&out.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF));
        }

        #[test]
        fn v1_ng_reason_is_verbatim_and_class_advisory() {
            for (reason, class) in [
                ("fetch first", RefRejectReason::FetchFirst),
                ("stale info", RefRejectReason::StaleInfo),
                ("non-fast-forward", RefRejectReason::NonFastForward),
                ("already exists", RefRejectReason::AlreadyExists),
                ("cannot lock ref, quibble", RefRejectReason::Other),
            ] {
                let report = report_lines(&["unpack ok", &format!("ng {REF} {reason}")]);
                let out = push_delete_with_report(report).expect("ng report parses");
                assert_eq!(out.unpack_status, UnpackStatus::Ok, "unpack still ok for a ref-level ng");
                match &out.refs[0] {
                    RefUpdateStatus::Rejected { name, reason: got, class: got_class } => {
                        assert_eq!(name, REF);
                        assert_eq!(got, reason.as_bytes(), "reason preserved VERBATIM");
                        assert_eq!(*got_class, class, "class is the advisory classification");
                    }
                    other => panic!("expected Rejected, got {other:?}"),
                }
            }
        }

        #[test]
        fn unpack_failure_is_unpack_status_failed() {
            let report = report_lines(&["unpack index-pack failed", &format!("ng {REF} unpacker error")]);
            let out = push_delete_with_report(report).expect("failure report parses");
            assert_eq!(out.unpack_status, UnpackStatus::Failed("index-pack failed".into()));
            assert!(matches!(&out.refs[0], RefUpdateStatus::Rejected { .. }));
        }

        #[test]
        fn report_status_v2_option_lines_populate_details() {
            let old = "1111111111111111111111111111111111111111";
            let new = "2222222222222222222222222222222222222222";
            let report = report_lines(&[
                "unpack ok",
                &format!("ok {REF}"),
                &format!("option old-oid {old}"),
                &format!("option new-oid {new}"),
                "option forced-update",
            ]);
            let out = push_delete_with_report(report).expect("v2 report parses");
            match &out.refs[0] {
                RefUpdateStatus::Ok { details: Some(d), .. } => {
                    assert_eq!(d.old_oid, Some(oid_sha1(old)));
                    assert_eq!(d.new_oid, Some(oid_sha1(new)));
                    assert!(d.forced_update, "forced-update option recorded");
                }
                other => panic!("expected Ok with details, got {other:?}"),
            }
        }

        #[test]
        fn missing_per_ref_status_is_error() {
            // unpack ok but no ok/ng for our sent ref.
            let report = report_lines(&["unpack ok"]);
            let err = push_delete_with_report(report).unwrap_err();
            assert!(
                matches!(err, Error::Response(gix_protocol::push::response::Error::MissingRefStatus { .. })),
                "a sent command with no reported status -> MissingRefStatus, got {err:?}"
            );
        }

        #[test]
        fn garbage_report_is_err_never_panics() {
            // Not a valid pkt-line stream at all.
            let err = push_delete_with_report(b"this is not a packetline stream".to_vec());
            assert!(err.is_err(), "garbage report -> Err (no panic)");

            // Valid pkt-lines, but no leading `unpack` line.
            let report = report_lines(&["garbage line with no unpack"]);
            let err = push_delete_with_report(report).unwrap_err();
            assert!(
                matches!(err, Error::Response(gix_protocol::push::response::Error::MissingUnpackStatus)),
                "a report without an unpack line -> MissingUnpackStatus, got {err:?}"
            );
        }
    }

    // -----------------------------------------------------------------------------------------
    // push::boundary_walk — real git-receive-pack over file://: incremental pack + foreign refs (F1)
    // -----------------------------------------------------------------------------------------
    mod boundary_walk {
        use crate::support::*;

        #[test]
        fn create_then_incremental_update_over_file() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);

            // First push: create at A with a FULL pack (revs = A).
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_pack = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_file(&remote, &[create(REF, &a)], Some(full_pack));
            assert_eq!(out.unpack_status, gix_protocol::push::UnpackStatus::Ok, "create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created at A");

            // Seed a foreign head on the remote so the next advertisement carries an unrelated oid.
            let c_hex = commit_file(&src, "c.txt", "sea");
            let c = oid_sha1(&c_hex);
            push_git(&src, &remote, &format!("{c_hex}:refs/heads/main"));

            // Second push: B (child of A). plan_from_advertisement must return boundary == A and
            // put the foreign head into thin_bases.
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let hs = handshake_over_file(&remote);
            let adv = gix_protocol::push::plan_from_advertisement(&[update(REF, &a, &b)], &hs)
                .expect("lease matches A");
            assert_eq!(adv.boundary, Some(a), "boundary is our ref (A), not the foreign head");
            assert!(adv.thin_bases.contains(&c), "the foreign refs/heads/main oid is a thin base");

            // The incremental pack (B minus the A boundary) carries FEWER objects than a full B pack:
            // it excludes A's history — the F1 walk realized by the caller.
            let incremental = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let full_b = git_pack(&src, &[b_hex.as_str()], &[]);
            assert!(
                pack_object_count(&incremental) < pack_object_count(&full_b),
                "incremental pack (boundary=A) excludes A's history: {} < {}",
                pack_object_count(&incremental),
                pack_object_count(&full_b)
            );

            let out = push_over_file(&remote, &[update(REF, &a, &b)], Some(incremental));
            assert_eq!(out.unpack_status, gix_protocol::push::UnpackStatus::Ok, "incremental update accepted");
            assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced to B");
        }
    }
}
