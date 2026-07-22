//! Hosted-interop smoke test (`rolfdb-gp01-u03-fu2`, partial — the lifecycle core): the full
//! blocking single-ref create → fast-forward update → delete lifecycle over `git+https://` against
//! a REAL EXTERNAL hosted remote (GitHub/GitLab), with token Basic auth through the credential
//! seam. This is the first proof of the fork against infrastructure we do not control — real TLS,
//! real HTTP/2→smart-http bridging, a real hosted receive-pack with its own hooks and replication.
//!
//! `#[ignore]`-gated AND environment-driven (manual/nightly by design, plan §6.4 — never CI):
//!   * `ROLFDB_HOSTED_URL`   — the https clone URL of a scratch repo this test MAY MUTATE
//!                             (pushes and deletes `refs/rolfdb/interop-test`; never touches
//!                             `refs/heads/*`).
//!   * `ROLFDB_HOSTED_USER`  — username for Basic auth (for GitHub tokens any non-empty value).
//!   * `ROLFDB_HOSTED_TOKEN` — the token/password.
//!
//! Run via `scripts/gix-push-sync.sh hosted` (builds with the reqwest-rustls stack — this is also
//! the fork's first REAL production-TLS push, closing the loop fu3's enforcement proof left open
//! at the trusted-path level: a public CA the platform verifier already trusts).
//!
//! The remaining fu2 items (hosted `ng`-prose matrix, hidden-ref F11, replica-lag → `Err(Backend)`
//! never NFF-retried) stay on the bead; this file is where they land.

#![cfg(all(unix, feature = "push", feature = "blocking-client", push_https_test))]

mod support;

mod push {
    mod hosted {
        use crate::support::*;
        use gix_protocol::push::{Options, UnpackStatus};

        const INTEROP_REF: &str = "refs/rolfdb/interop-test";

        fn env(name: &str) -> Option<String> {
            std::env::var(name).ok().filter(|v| !v.is_empty())
        }

        fn hosted_credentials(
            action: gix_protocol::credentials::helper::Action,
        ) -> gix_protocol::credentials::protocol::Result {
            use gix_protocol::credentials::helper::Action;
            match action {
                Action::Get(ctx) => Ok(Some(gix_protocol::credentials::protocol::Outcome {
                    identity: gix_sec::identity::Account {
                        username: env("ROLFDB_HOSTED_USER").expect("ROLFDB_HOSTED_USER set").into(),
                        password: env("ROLFDB_HOSTED_TOKEN").expect("ROLFDB_HOSTED_TOKEN set").into(),
                        oauth_refresh_token: None,
                    },
                    next: ctx.into(),
                })),
                Action::Store(_) | Action::Erase(_) => Ok(None),
            }
        }

        /// The full lifecycle against the hosted remote: create at A (full pack), fast-forward to B
        /// (incremental pack, boundary=A), delete — asserting the server's advertisement reflects
        /// each step. Byte-for-byte the daemon round-trip's shape, but the server is the real
        /// hosted product.
        #[test]
        #[ignore = "external + credentialed; set ROLFDB_HOSTED_{URL,USER,TOKEN}; run via scripts/gix-push-sync.sh hosted"]
        fn create_update_delete_round_trip_against_hosted_remote() {
            let url = match env("ROLFDB_HOSTED_URL") {
                Some(u) => u,
                None => {
                    panic!("ROLFDB_HOSTED_URL not set — this test needs a scratch hosted repo it may mutate")
                }
            };

            // Local history: A then B (child of A), built with the deterministic fixture helpers.
            let base = Scratch::new();
            let src = base.join("src");
            init_work(&base, &src);
            let a_hex = commit_file(&src, "interop.txt", "one");
            let a = oid_sha1(&a_hex);
            let b_hex = commit_file(&src, "interop.txt", "two");
            let b = oid_sha1(&b_hex);

            // Hygiene: if a previous aborted run left the ref behind, delete it first (best-effort).
            let advertised = handshake_over_url(&url, hosted_credentials).refs.unwrap_or_default();
            if let Some(old) = advertised.iter().find_map(|r| match r {
                gix_protocol::handshake::Ref::Direct { full_ref_name, object } if full_ref_name == INTEROP_REF => {
                    Some(*object)
                }
                _ => None,
            }) {
                eprintln!("pre-clean: deleting leftover {INTEROP_REF} at {old}");
                push_over_url(
                    &url,
                    &[delete(INTEROP_REF, &old)],
                    None,
                    Options::default(),
                    hosted_credentials,
                )
                .expect("pre-clean delete");
            }

            // 1. CREATE at A with a full pack.
            let full_a = git_pack(&src, &[a_hex.as_str()], &[]);
            let out = push_over_url(
                &url,
                &[create(INTEROP_REF, &a)],
                Some(full_a),
                Options::default(),
                hosted_credentials,
            )
            .expect("create over hosted https");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "hosted server accepted the create");
            let adv = handshake_over_url(&url, hosted_credentials);
            assert!(
                advertised_has(&adv, INTEROP_REF, &a),
                "hosted advertisement shows {INTEROP_REF} at A after the create"
            );

            // 2. FAST-FORWARD update to B with an incremental pack (boundary = A).
            let inc = git_pack(&src, &[b_hex.as_str()], &[a_hex.as_str()]);
            let out = push_over_url(
                &url,
                &[update(INTEROP_REF, &a, &b)],
                Some(inc),
                Options::default(),
                hosted_credentials,
            )
            .expect("update over hosted https");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "hosted server accepted the update");
            let adv = handshake_over_url(&url, hosted_credentials);
            assert!(
                advertised_has(&adv, INTEROP_REF, &b),
                "hosted advertisement shows {INTEROP_REF} at B after the update"
            );

            // 3. DELETE (no pack).
            let out = push_over_url(
                &url,
                &[delete(INTEROP_REF, &b)],
                None,
                Options::default(),
                hosted_credentials,
            )
            .expect("delete over hosted https");
            assert_eq!(out.unpack_status, UnpackStatus::Ok, "hosted server accepted the delete");
            let adv = handshake_over_url(&url, hosted_credentials);
            assert!(
                !adv.refs
                    .unwrap_or_default()
                    .iter()
                    .any(|r| ref_name_of(r) == INTEROP_REF),
                "hosted advertisement no longer lists {INTEROP_REF} after the delete"
            );
        }

        fn advertised_has(hs: &gix_protocol::Handshake, name: &str, oid: &gix_hash::ObjectId) -> bool {
            hs.refs.as_deref().unwrap_or(&[]).iter().any(|r| match r {
                gix_protocol::handshake::Ref::Direct { full_ref_name, object } => {
                    full_ref_name == name && object == oid
                }
                _ => false,
            })
        }

        fn ref_name_of(r: &gix_protocol::handshake::Ref) -> &bstr::BStr {
            use gix_protocol::handshake::Ref::*;
            match r {
                Direct { full_ref_name, .. }
                | Peeled { full_ref_name, .. }
                | Symbolic { full_ref_name, .. }
                | Unborn { full_ref_name, .. } => full_ref_name.as_ref(),
            }
        }
    }
}
