//! M2 (`gp01-u03-fu1`, gap **G8**) `#[ignore]`-gated ssh smoke test for `gix_protocol::push::push()`:
//! the full blocking single-ref lifecycle (create → fast-forward update → delete) over `git+ssh://`
//! against a REAL, test-local `sshd`.
//!
//! Why it exists: ssh is a §5-M2 deliverable and a rolfdb production transport (F15). The push() core
//! is transport-generic and is already exercised over `git://` (daemon) and `git+https://` in
//! `push_m2.rs`, so this is a real-transport *confirmation*, not new module code — it proves push()
//! drives a real `git-receive-pack` over the one transport gix implements by spawning the `ssh`
//! BINARY (rather than an in-process client).
//!
//! Why it is `#[ignore]`-gated (discover with `cargo test -- --ignored`): it spawns a real OpenSSH
//! `sshd` and depends on the host environment in ways the daemon/http suites do not. Run it via the
//! dedicated sync target — `scripts/gix-push-sync.sh ssh` — which is deliberately NOT wired into
//! `all`.
//!
//! Environment it needs (all self-checked at fixture start where possible):
//!   * `/usr/sbin/sshd`, `ssh`, and `ssh-keygen` present (macOS/BSD/Linux OpenSSH).
//!   * A `git-receive-pack` reachable from the CURRENT USER's login shell — that is the remote
//!     command `sshd` runs. The stock system git (`/usr/bin/git-receive-pack`) satisfies this on the
//!     standard `sshd` PATH; an exotic login shell that scrubs `PATH` could hide it.
//!   * The ability to bind a loopback port and for the current user to ssh into their own account via
//!     a generated key (a throwaway `authorized_keys` the fixture writes — the real `~/.ssh` is never
//!     touched; the client uses `-F none` + a pinned `known_hosts`).
//!
//! In a locked-down sandbox that blocks `sshd` or self-ssh, the fixture panics with the captured
//! `sshd` log rather than silently passing.
//!
//! Unix-only, like the rest of the real-server suites (`git-receive-pack` process spawns, `/dev/null`
//! config paths, 0600 key perms).

#![cfg(all(unix, feature = "push", feature = "blocking-client"))]

mod support;

mod push {
    mod ssh {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        /// The full single-ref lifecycle — create, fast-forward update, delete — over `git+ssh://`.
        /// Byte-for-byte the same assertions as the `daemon::create_update_delete_round_trip` case,
        /// but driven through a real `ssh` process against a real `sshd`, confirming the transport-
        /// generic core over the ssh transport (§5-M2, F15).
        #[test]
        #[ignore = "spawns a real sshd; run via `scripts/gix-push-sync.sh ssh` (cargo test -- --ignored)"]
        fn create_update_delete_round_trip() {
            let base = Scratch::new();
            let (src, remote) = (base.join("src"), base.join("remote.git"));
            init_bare(&base, &remote);
            init_work(&base, &src);
            let server = SshServer::serve(&base);
            // Absolute remote path so `git-receive-pack '<path>'` resolves on the remote regardless of
            // the login shell's cwd.
            let url = server.url(&remote);

            // create at A (full pack).
            let a_hex = commit_file(&src, "a.txt", "one");
            let a = oid_sha1(&a_hex);
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_ssh(&server, &url, &[create(REF, &a)], Some(full_a), Options::default())
                .expect("create over git+ssh://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "create accepted");
            assert_eq!(remote_ref(&remote, REF), a_hex, "ref created at A over git+ssh://");

            // fast-forward update to B (incremental pack, boundary=A).
            let b_hex = commit_file(&src, "a.txt", "two");
            let b = oid_sha1(&b_hex);
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_ssh(&server, &url, &[update(REF, &a, &b)], Some(inc), Options::default())
                .expect("update over git+ssh://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "update accepted");
            assert_eq!(remote_ref(&remote, REF), b_hex, "ref advanced to B over git+ssh://");

            // delete (no pack sent).
            let out = push_over_ssh(&server, &url, &[delete(REF, &b)], None, Options::default())
                .expect("delete over git+ssh://");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "delete accepted");
            let gone = std::process::Command::new("git")
                .current_dir(&remote)
                .args(["rev-parse", "--verify", "--quiet", REF])
                .output()
                .expect("git rev-parse");
            assert!(!gone.status.success(), "ref is gone after delete over git+ssh://");
        }
    }
}
