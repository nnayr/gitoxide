//! The interrupt/abort fault lane (`rolfdb-gp01-interrupt`, plan §6.3-11, testplan-fuse G1) for the
//! **blocking** `gix_protocol::push::push()`. Suite names are contractual: `push::interrupt`.
//!
//! The contract under test: `should_interrupt` is the CALLER's abort channel — push() hands it
//! through to the `write_pack` closure (whose pack machinery, `gix-pack` in production, observes it
//! and bails). When the stream aborts mid-pack the push MUST
//!   1. surface the abort as the typed [`Error::WritePack`] carrying the closure's error verbatim
//!      (never a panic, never success),
//!   2. read NO report — the response parser must never run on a connection whose pack was cut
//!      short (proven by handing the mock a garbage report that would error if parsed, and by the
//!      error being `WritePack`, not `Response`),
//!   3. leave the remote ref unmoved (proven against a real `git-receive-pack` over `file://`),
//!   4. return in bounded time — no hang waiting for a report that can never come (the real-server
//!      case runs under a watchdog timeout).
//!
//! The mock cases are fully in-memory and deterministic (no RNG, no sleeps); the real-server case
//! uses the same `file://` + real-`git` harness as the M1/M2 suites (a dev-dependency of the FORK
//! suite only, never rolfdb production). Unix-only, like `push_m1.rs`.

#![cfg(all(unix, feature = "push", feature = "blocking-client"))]

mod support;

mod push {
    mod interrupt {
        use crate::support::*;

        /// Interrupt MID-pack: half the pack is on the wire when the closure observes the flag and
        /// bails. push() -> `Error::WritePack`; the garbage report is never parsed; the wire holds
        /// the command list, exactly ONE flush (F4), and only the truncated pack prefix.
        #[test]
        fn mid_pack_abort_is_typed_error_and_reads_no_report() {
            let new = oid_sha1("9999999999999999999999999999999999999999");
            let pack = dummy_pack().expect("a pack for the create path");
            let cut = pack.len() / 2;
            let (err, sent) = run_push_interrupt(
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
                "exactly the truncated prefix reached the wire — nothing streamed past the abort"
            );
        }

        /// Abort observed AT ENTRY (`cut == 0`, zero bytes written): the closure bails before its
        /// first write — push() itself never polls the flag, so this is the earliest the caller's
        /// machinery can abort. Same typed error; ZERO pack bytes follow the flush.
        #[test]
        fn preflipped_abort_streams_zero_pack_bytes() {
            let new = oid_sha1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            let pack = dummy_pack().expect("a pack for the create path");
            let (err, sent) = run_push_interrupt(
                caps("report-status ofs-delta object-format=sha1"),
                advertise(&[]),
                &[create(REF, &new)],
                pack,
                0,
                tripwire_report(),
            );
            assert_writepack_interrupt(&err);
            let scan = scan_command_list(&sent);
            assert_eq!(
                scan.flushes, 1,
                "the command list still terminates with its one flush (F4)"
            );
            assert!(
                scan.pack.is_none(),
                "zero pack bytes after the flush — the abort preceded the first write"
            );
        }

        /// The real-server lane: abort mid-pack against a live `git-receive-pack` over `file://`.
        /// The push errors with `WritePack`, returns within the watchdog bound (no hang waiting for
        /// a report, assertion 4), and the remote ref is NEVER created (assertion 3). Assertion 2
        /// (no report read) is not re-proven here — the `WritePack` error implies it (the mock
        /// tripwire cases carry the direct proof).
        #[test]
        fn real_receive_pack_ref_unmoved_and_no_hang() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);

            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let pack = git_pack(&src, &[a_hex.as_str()], &[]);
            let cut = pack.len() / 2;

            // Watchdog: the push runs on a worker thread; a hang fails the recv_timeout below
            // instead of wedging the whole suite (a bounded failure detector, not a sleep).
            let (tx, rx) = std::sync::mpsc::channel();
            let remote_path = remote.clone();
            let updates = [create(REF, &a)];
            std::thread::spawn(move || {
                tx.send(push_over_file_interrupted(&remote_path, &updates, pack, cut))
                    .expect("watchdog receiver alive");
            });
            let err = rx
                .recv_timeout(std::time::Duration::from_secs(60))
                .expect("interrupted push returns in bounded time — no hang on the missing report");

            assert_writepack_interrupt(&err);
            assert!(
                !remote_has_ref(&remote, REF),
                "the aborted create never moved the remote: {REF} must not exist"
            );
        }
    }
}
