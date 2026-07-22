//! M3 wire-feature suites (`rolfdb-gp01-m3feat`) for the two deferred plumbing legs of
//! `gix_protocol::push::push()` — **push-options** (plan §1.3, §3.4) and **side-band-64k** report
//! demux (§3.5) — in the BLOCKING build. The async twins live in `push_m3.rs`.
//!
//! Both features default OFF; these suites drive them explicitly. Determinism matches the M1 suites:
//! no RNG/sleeps/wall-clock. The push-options framing is pinned against a live
//! `GIT_TRACE_PACKET=1 git push --push-option` capture (the empirical oracle, never our own encoder),
//! exactly as `push_m1::command_golden` pins the command triples. Both legs are additionally proven
//! end-to-end against a real `git-receive-pack` over `file://` — git surfaces push-options to its
//! hooks and frames the report on the side-band when we negotiate it, so the real binary is the
//! ground truth for both.
//!
//! Unix-only: `file://` + real `git-receive-pack`, and the executable pre-receive hook.

#![cfg(all(unix, feature = "push", feature = "blocking-client"))]

mod support;

mod push {
    // =========================================================================================
    // push::push_options — the option pkt-line block (§1.3): command-list flush, then the options
    // as their own pkt-lines terminated by their OWN flush, then the pack (delete-only: no pack).
    // =========================================================================================
    mod push_options {
        mod command_golden {
            use crate::support::*;

            /// Extract every `push>` (client send-pack) pkt-line payload from a `GIT_TRACE_PACKET`
            /// capture of `git push <extra_args> <spec>` — the empirical oracle for git's own framing.
            fn git_send_payloads(
                src: &std::path::Path,
                oracle: &std::path::Path,
                extra_args: &[&str],
                spec: &str,
            ) -> Vec<String> {
                let mut c = git(src);
                c.env("GIT_TRACE_PACKET", "1").arg("push").arg("-q");
                for a in extra_args {
                    c.arg(a);
                }
                c.arg(oracle.to_str().unwrap()).arg(spec);
                let (_out, trace) = run(c);
                String::from_utf8_lossy(&trace)
                    .lines()
                    .filter_map(|l| l.split_once("push> ").map(|(_, p)| p.trim_end().to_string()))
                    .collect()
            }

            /// A create + two push-options frames byte-exactly like git: command line (caps incl.
            /// `push-options` on the first line), command-list flush, each option as its own pkt-line
            /// (no trailing LF), the options' own flush, then the pack.
            #[test]
            fn create_with_push_options_matches_git() {
                let base = Scratch::new();
                let (src, oracle) = (base.join("src"), base.join("oracle.git"));
                init_bare(&base, &oracle);
                git_config(&oracle, "receive.advertisePushOptions", "true");
                init_work(&base, &src);
                let a_hex = commit_file(&src, "a.txt", "one");
                let a = oid_sha1(&a_hex);

                // Oracle: git frames EACH option as its own standalone `push>` pkt-line payload.
                let git_payloads = git_send_payloads(
                    &src,
                    &oracle,
                    &["--push-option=alpha", "--push-option=key=val"],
                    &format!("{a_hex}:{REF}"),
                );
                assert!(
                    git_payloads.iter().any(|p| p == "alpha") && git_payloads.iter().any(|p| p == "key=val"),
                    "git writes each push-option verbatim as its own pkt-line (no LF); got {git_payloads:?}"
                );

                // Ours, driven through the public push() over the mock, must frame the same way.
                let opts = gix_protocol::push::Options {
                    push_options: vec!["alpha".into(), "key=val".into()],
                    ..Default::default()
                };
                let sent = run_push_capture_opts(
                    caps("report-status ofs-delta push-options object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    ok_report(REF),
                    opts,
                );
                let wire = scan_push_wire(&sent);
                assert_eq!(
                    wire.command_triples(),
                    once(format!("{} {a_hex} {REF}", zeros(40))),
                    "the create triple is unchanged by push-options"
                );
                assert_eq!(
                    wire.option_strings(),
                    vec!["alpha".to_string(), "key=val".to_string()],
                    "our option pkt-lines == git's, verbatim and in order"
                );
                assert_eq!(wire.flushes, 2, "command-list flush + push-options' own flush");
                assert!(
                    wire.command_lines[0].windows(12).any(|w| w == b"push-options"),
                    "push-options is echoed in the first command line's cap list"
                );
                let pack = wire.pack.expect("a create sends a pack after the push-options flush");
                assert_eq!(&pack[..4], b"PACK", "the raw pack follows the push-options flush");
            }

            /// A delete-only push with push-options sends the command, the command-list flush, the
            /// options + their own flush, and NO pack — two flushes total (pinned vs git's own).
            #[test]
            fn delete_only_with_push_options_two_flushes_no_pack() {
                let base = Scratch::new();
                let (src, oracle) = (base.join("src"), base.join("oracle.git"));
                init_bare(&base, &oracle);
                git_config(&oracle, "receive.advertisePushOptions", "true");
                init_work(&base, &src);
                let a_hex = commit_file(&src, "a.txt", "one");
                push_git(&src, &oracle, &format!("{a_hex}:{REF}"));
                let a = oid_sha1(&a_hex);

                // Oracle: git's delete-with-options also writes each option as its own pkt-line.
                let git_payloads = git_send_payloads(&src, &oracle, &["--push-option=gone"], &format!(":{REF}"));
                assert!(
                    git_payloads.iter().any(|p| p == "gone"),
                    "git frames the option even on a delete-only push; got {git_payloads:?}"
                );

                let opts = gix_protocol::push::Options {
                    push_options: vec!["gone".into()],
                    ..Default::default()
                };
                let sent = run_push_capture_opts(
                    caps("report-status delete-refs push-options object-format=sha1"),
                    advertise(&[(REF, &a)]),
                    &[delete(REF, &a)],
                    None,
                    ok_report(REF),
                    opts,
                );
                let wire = scan_push_wire(&sent);
                assert_eq!(
                    wire.command_triples(),
                    once(format!("{a_hex} {} {REF}", zeros(40))),
                    "the delete triple is unchanged by push-options"
                );
                assert_eq!(wire.option_strings(), vec!["gone".to_string()]);
                assert_eq!(
                    wire.flushes, 2,
                    "delete-only + push-options sends TWO flushes (command list + push-options), not one"
                );
                assert!(
                    wire.pack.is_none(),
                    "a delete-only push sends no pack even with push-options"
                );
            }

            /// Option order is preserved verbatim, and the caps ride only on the first command line.
            #[test]
            fn multi_option_order_preserved() {
                let a = oid_sha1("1234123412341234123412341234123412341234");
                let opts = gix_protocol::push::Options {
                    push_options: vec!["first".into(), "second".into(), "third=3".into()],
                    ..Default::default()
                };
                let sent = run_push_capture_opts(
                    caps("report-status push-options object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    ok_report(REF),
                    opts,
                );
                let wire = scan_push_wire(&sent);
                assert_eq!(
                    wire.option_strings(),
                    vec!["first".to_string(), "second".to_string(), "third=3".to_string()],
                    "push-options are sent in the caller's order"
                );
            }
        }

        mod real_server {
            use crate::support::*;

            /// Make `path` executable (0o755) — the pre-receive hook must be runnable.
            fn make_executable(path: &std::path::Path) {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(path, perms).unwrap();
            }

            /// End-to-end over a real `git-receive-pack`: push-options reach the server's pre-receive
            /// hook exactly as sent. A pre-receive hook records every `GIT_PUSH_OPTION_*` to a file we
            /// then read back — proving our wire framing is what git's own receive-pack decodes.
            #[test]
            fn push_options_reach_receive_pack_hook() {
                let base = Scratch::new();
                let (src, remote) = (base.join("src"), base.join("remote.git"));
                init_bare(&base, &remote);
                git_config(&remote, "receive.advertisePushOptions", "true");

                // A pre-receive hook that dumps the received push-options (one per line) into the repo.
                let hook = remote.join("hooks/pre-receive");
                std::fs::write(
                    &hook,
                    "#!/bin/sh\n\
                     out=\"$(pwd)/push-options-seen\"\n\
                     : > \"$out\"\n\
                     n=${GIT_PUSH_OPTION_COUNT:-0}\n\
                     i=0\n\
                     while [ \"$i\" -lt \"$n\" ]; do\n\
                     v=$(eval echo \"\\$GIT_PUSH_OPTION_$i\")\n\
                     printf '%s\\n' \"$v\" >> \"$out\"\n\
                     i=$((i+1))\n\
                     done\n\
                     exit 0\n",
                )
                .unwrap();
                make_executable(&hook);

                init_work(&base, &src);
                let a_hex = commit_file(&src, "a.txt", "one");
                let a = oid_sha1(&a_hex);

                if !advertises_capability(&remote, "push-options") {
                    eprintln!("skipping: host git-receive-pack does not advertise push-options");
                    return;
                }

                let pack = git_pack(&src, &[&a_hex], &[]);
                let opts = gix_protocol::push::Options {
                    push_options: vec!["opt-one".into(), "key=val".into()],
                    ..Default::default()
                };
                let outcome = push_over_file_opts(&remote, &[create(REF, &a)], Some(pack), opts);
                assert!(
                    matches!(outcome.unpack_status, gix_protocol::push::UnpackStatus::Ok),
                    "the server unpacked our pack: {outcome:?}"
                );
                assert_eq!(remote_ref(&remote, REF), a_hex, "the ref was created at the pushed oid");

                let seen = std::fs::read_to_string(remote.join("push-options-seen")).expect("hook recorded options");
                let lines: Vec<&str> = seen.lines().collect();
                assert_eq!(
                    lines,
                    vec!["opt-one", "key=val"],
                    "the server's hook saw our push-options verbatim and in order"
                );
            }
        }
    }

    // =========================================================================================
    // push::sideband — side-band-64k report demux (§3.5): band 1 = report, band 2 = progress,
    // band 3 = remote error. Default OFF; opting in echoes the cap and demuxes.
    // =========================================================================================
    mod sideband {
        mod demux {
            use crate::support::*;
            use gix_protocol::push::{Options, RefUpdateStatus, UnpackStatus};

            fn sideband_opts() -> Options {
                Options {
                    sideband: true,
                    ..Default::default()
                }
            }

            /// A band-1-wrapped report parses exactly like the plain report, and side-band-64k is
            /// echoed in the first command line's cap list.
            #[test]
            fn sideband_report_is_demuxed() {
                let a = oid_sha1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
                let report = sideband_report(&ok_report(REF));
                let outcome = run_push_ok_opts(
                    caps("report-status side-band-64k object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    report,
                    sideband_opts(),
                );
                assert!(matches!(outcome.unpack_status, UnpackStatus::Ok));
                assert_eq!(outcome.refs.len(), 1);
                assert!(
                    matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF),
                    "the band-1 report demuxes to the same Ok status as a plain report: {outcome:?}"
                );

                // The cap is echoed on the wire.
                let sent = run_push_capture_opts(
                    caps("report-status side-band-64k object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    sideband_report(&ok_report(REF)),
                    sideband_opts(),
                );
                let cmd = scan_command_list(&sent);
                assert!(
                    cmd.lines[0].windows(13).any(|w| w == b"side-band-64k"),
                    "side-band-64k is echoed in the first command line"
                );
            }

            /// Demux is robust to band-1 fragmentation, and band 2 (progress) + band 3 (error) packets
            /// are routed away from the report stream (never corrupting the parse).
            #[test]
            fn sideband_fragmented_with_progress_and_error_bands() {
                let a = oid_sha1("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
                let rep = ok_report(REF);
                let mid = rep.len() / 2;
                let report = sideband_report_chunked(
                    &[&rep[..mid], &rep[mid..]],
                    &[(2, b"remote: counting objects"), (3, b"remote: a non-fatal notice")],
                );
                let outcome = run_push_ok_opts(
                    caps("report-status side-band-64k object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    report,
                    sideband_opts(),
                );
                assert!(matches!(outcome.unpack_status, UnpackStatus::Ok));
                assert!(
                    matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF),
                    "report split across band-1 packets (with band 2/3 interleaved) still parses: {outcome:?}"
                );
            }

            /// The POSITIVE routing proof (review F3): band-2 and band-3 payloads actually REACH
            /// the caller's progress. A non-progress-shaped band-2 text arrives via `set_name`
            /// (`translate_to_progress`'s fallback) and a band-3 text via `fail` →
            /// `message(Failure)`; a `CaptureProgress` records both.
            #[test]
            fn sideband_band2_and_band3_are_routed_to_progress() {
                let a = oid_sha1("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
                let report = sideband_report_chunked(
                    &[&ok_report(REF)],
                    &[(2, b"remote: hello band two"), (3, b"remote: band three notice")],
                );
                let capture = crate::support::CaptureProgress::default();
                let outcome = run_push_ok_opts_with_progress(
                    caps("report-status side-band-64k object-format=sha1"),
                    advertise(&[]),
                    &[create(REF, &a)],
                    dummy_pack(),
                    report,
                    sideband_opts(),
                    capture.clone(),
                );
                assert!(matches!(outcome.unpack_status, UnpackStatus::Ok));
                let names = capture.texts("name").join(" | ");
                assert!(
                    names.contains("remote: hello band two"),
                    "band-2 payload routed to the progress sink via set_name, got: {names:?}"
                );
                let fails = capture.texts("msg:Failure").join(" | ");
                assert!(
                    fails.contains("remote: band three notice"),
                    "band-3 payload routed as a Failure-level message, got: {fails:?}"
                );
            }

            /// A band-1-wrapped `ng` report demuxes to a Rejected status (verbatim reason preserved),
            /// exactly as on the plain path.
            #[test]
            fn sideband_ng_report_is_rejected() {
                let a = oid_sha1("cccccccccccccccccccccccccccccccccccccccc");
                let b = oid_sha1("dddddddddddddddddddddddddddddddddddddddd");
                let report = sideband_report(&report_lines(&["unpack ok", &format!("ng {REF} fetch first")]));
                let outcome = run_push_ok_opts(
                    caps("report-status side-band-64k object-format=sha1"),
                    advertise(&[(REF, &a)]),
                    &[update(REF, &a, &b)],
                    dummy_pack(),
                    report,
                    sideband_opts(),
                );
                match &outcome.refs[0] {
                    RefUpdateStatus::Rejected { name, reason, .. } => {
                        assert_eq!(name, REF);
                        assert_eq!(reason, "fetch first", "the ng reason survives the demux verbatim");
                    }
                    other => panic!("expected Rejected, got {other:?}"),
                }
            }
        }

        mod real_server {
            use crate::support::*;
            use gix_protocol::push::{Options, RefUpdateStatus, UnpackStatus};

            /// End-to-end over a real `git-receive-pack`: when we negotiate side-band-64k the server
            /// multiplexes the report onto the side-band, and our demux recovers it. This exercises
            /// the real framing (not a canned mock), the ground truth for §3.5.
            #[test]
            fn real_receive_pack_sideband_report_is_demuxed() {
                let base = Scratch::new();
                let (src, remote) = (base.join("src"), base.join("remote.git"));
                init_bare(&base, &remote);
                init_work(&base, &src);
                let a_hex = commit_file(&src, "a.txt", "one");
                let a = oid_sha1(&a_hex);

                if !advertises_capability(&remote, "side-band-64k") {
                    eprintln!("skipping: host git-receive-pack does not advertise side-band-64k");
                    return;
                }

                let pack = git_pack(&src, &[&a_hex], &[]);
                let opts = Options {
                    sideband: true,
                    ..Default::default()
                };
                let outcome = push_over_file_opts(&remote, &[create(REF, &a)], Some(pack), opts);
                assert!(
                    matches!(outcome.unpack_status, UnpackStatus::Ok),
                    "the sideband-wrapped report unpacks Ok: {outcome:?}"
                );
                assert!(
                    matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF),
                    "the ref status demuxes from the real sideband report: {outcome:?}"
                );
                assert_eq!(
                    remote_ref(&remote, REF),
                    a_hex,
                    "the ref was created over the sideband path"
                );
            }

            /// Both legs at once: push-options AND a side-band-64k report over the same real push.
            #[test]
            fn push_options_and_sideband_together() {
                let base = Scratch::new();
                let (src, remote) = (base.join("src"), base.join("remote.git"));
                init_bare(&base, &remote);
                git_config(&remote, "receive.advertisePushOptions", "true");
                init_work(&base, &src);
                let a_hex = commit_file(&src, "a.txt", "one");
                let a = oid_sha1(&a_hex);

                if !advertises_capability(&remote, "push-options") || !advertises_capability(&remote, "side-band-64k") {
                    eprintln!("skipping: host git-receive-pack lacks push-options and/or side-band-64k");
                    return;
                }

                let pack = git_pack(&src, &[&a_hex], &[]);
                let opts = Options {
                    push_options: vec!["combo".into()],
                    sideband: true,
                    ..Default::default()
                };
                let outcome = push_over_file_opts(&remote, &[create(REF, &a)], Some(pack), opts);
                assert!(
                    matches!(outcome.unpack_status, UnpackStatus::Ok),
                    "unpacked Ok: {outcome:?}"
                );
                assert!(
                    matches!(&outcome.refs[0], RefUpdateStatus::Ok { name, .. } if name == REF),
                    "both legs compose: {outcome:?}"
                );
                assert_eq!(remote_ref(&remote, REF), a_hex);
            }
        }
    }
}
