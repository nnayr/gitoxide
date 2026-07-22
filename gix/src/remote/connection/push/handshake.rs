//! The receive-pack handshake for push (task `gpx04`), the twin of fetch's
//! [`ref_map_by_ref`][crate::remote::connection::ref_map].
//!
//! Where fetch performs `handshake(Service::UploadPack)` and then continues into ls-refs/ref-map, push
//! performs `handshake(Service::ReceivePack)` and **stops at the handshake**: for `git-receive-pack` the
//! server's ref advertisement *is* the handshake response (there is no separate ls-refs round-trip), so
//! [`receive_pack_handshake_by_ref`][ConnectionDetached::receive_pack_handshake_by_ref] is exactly
//! `ref_map_by_ref` minus the ref-map prefetch. It extracts the advertisement with
//! [`refs.take()`][gix_protocol::Handshake] behind a
//! [`MissingRefAdvertisement`][super::prepare::Error::MissingRefAdvertisement] guard and stores the
//! (now ref-less) handshake on the connection for later inspection.
//!
//! Connect itself is unchanged: [`Remote::connect(Direction::Push)`][crate::Remote::connect()] already
//! resolves the push url + protocol version (`connect.rs`), so this module adds no connect-side code.
//!
//! # Errors
//!
//! Unlike fetch — whose standalone `ref_map` operation owns a [`ref_map::Error`][crate::remote::connection::ref_map::Error]
//! — the receive-pack handshake is not a public operation of its own (it exists only inside `prepare_push`),
//! so it reports through the flat [`prepare::Error`][super::prepare::Error] that `gpx02` defined for exactly
//! this reason. There is deliberately no `handshake::Error` twin.

use gix_features::progress::Progress;
#[cfg(feature = "async-network-client")]
use gix_transport::client::async_io::Transport;
#[cfg(feature = "blocking-network-client")]
use gix_transport::client::blocking_io::Transport;

use crate::remote::connection::ConnectionDetached;

/// Take the ref advertisement out of a completed receive-pack `handshake`, or fail with
/// [`prepare::Error::MissingRefAdvertisement`][super::prepare::Error::MissingRefAdvertisement] if the
/// server sent none.
///
/// `git-receive-pack` always advertises its refs inline as part of the V0/V1 handshake — an empty
/// repository advertises the empty list, not `None` — so the guard only trips when the response carried
/// no inline advertisement (e.g. a V2 handshake, which defers refs to a separate `ls-refs` push has no
/// equivalent of); the reported `version` explains why.
#[allow(clippy::result_large_err)]
#[allow(dead_code)] // exercised by the guard unit test + `receive_pack_handshake_by_ref`; consumer lands in gpx08.
fn advertisement_from_handshake(
    handshake: &mut gix_protocol::Handshake,
) -> Result<Vec<gix_protocol::handshake::Ref>, super::prepare::Error> {
    let version = handshake.server_protocol_version;
    handshake
        .refs
        .take()
        .ok_or(super::prepare::Error::MissingRefAdvertisement { version })
}

impl<T> ConnectionDetached<'_, T>
where
    T: Transport,
{
    /// Perform the `git-receive-pack` handshake and return the server's ref advertisement, storing the
    /// handshake on `self` for later inspection.
    ///
    /// This is the push twin of [`ref_map_by_ref`][crate::remote::connection::ref_map]: it configures
    /// credentials + transport identically, swaps [`Service::UploadPack`][gix_transport::Service::UploadPack]
    /// for [`Service::ReceivePack`][gix_transport::Service::ReceivePack], and stops at the handshake — the
    /// receive-pack advertisement needs no ls-refs follow-up. `handshake_parameters` are passed straight
    /// through, mirroring `ref_map`'s `Options::handshake_parameters`.
    #[allow(clippy::result_large_err)]
    #[allow(dead_code)] // consumed by `gpx07`'s `prepare_push`.
    #[gix_protocol::bisync::bisync]
    pub(crate) async fn receive_pack_handshake_by_ref(
        &mut self,
        repo: &crate::Repository,
        mut progress: impl Progress,
        handshake_parameters: Vec<(String, Option<String>)>,
    ) -> Result<Vec<gix_protocol::handshake::Ref>, super::prepare::Error> {
        let _span = gix_trace::coarse!("remote::Connection::receive_pack_handshake()");
        let mut credentials_storage;
        let url = self.transport.inner.to_url();
        let authenticate = match self.authenticate.as_mut() {
            Some(f) => f,
            None => {
                // Fall back to the configured credential cascade, mirroring fetch's `ref_map`
                // (upstream refactored this from an explicit-url scoping to a lazy per-action-url
                // cascade in `configured_credentials_for_current_url`). The transport is already
                // connected to the resolved push url (`connect(Direction::Push)`), so the cascade
                // derives credentials for exactly that url from each `Get` action's context.
                credentials_storage = self.configured_credentials_for_current_url(repo);
                &mut credentials_storage
            }
        };

        if self.transport_options.is_none() {
            self.transport_options = repo
                .transport_options(url.as_ref(), self.remote.name().map(crate::remote::Name::as_bstr))
                .map_err(|err| super::prepare::Error::GatherTransportConfig {
                    source: err,
                    url: url.into_owned(),
                })?;
        }
        if let Some(config) = self.transport_options.as_ref() {
            self.transport.inner.configure(&**config)?;
        }
        let mut handshake = gix_protocol::handshake(
            &mut self.transport.inner,
            gix_transport::Service::ReceivePack,
            authenticate,
            handshake_parameters,
            &mut progress,
        )
        .await?;

        let refs = advertisement_from_handshake(&mut handshake)?;
        self.handshake = Some(handshake);
        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::advertisement_from_handshake;
    use crate::remote::push;

    #[test]
    fn missing_ref_advertisement_guard() {
        let mut with_refs = gix_protocol::Handshake {
            server_protocol_version: gix_transport::Protocol::V1,
            refs: Some(Vec::new()),
            v1_shallow_updates: None,
            capabilities: gix_transport::client::Capabilities::default(),
        };
        assert!(
            advertisement_from_handshake(&mut with_refs)
                .expect("empty advertisement is Some(vec![]), not None")
                .is_empty(),
            "the empty-repo advertisement round-trips as an empty ref list"
        );
        assert!(
            with_refs.refs.is_none(),
            "the advertisement is taken out of the handshake so the stored copy no longer carries it"
        );

        let mut without_refs = gix_protocol::Handshake {
            server_protocol_version: gix_transport::Protocol::V2,
            refs: None,
            v1_shallow_updates: None,
            capabilities: gix_transport::client::Capabilities::default(),
        };
        assert!(
            matches!(
                advertisement_from_handshake(&mut without_refs),
                Err(push::prepare::Error::MissingRefAdvertisement {
                    version: gix_transport::Protocol::V2
                })
            ),
            "a receive-pack handshake without an inline ref advertisement is the MissingRefAdvertisement \
             guard case, and reports the version that explains the miss"
        );
    }

    /// `file://` integration for `gpx04` (pre-G4, before `prepare_push`/`send` exist): drive
    /// `connect(Direction::Push)` + the receive-pack handshake against a real empty bare repo and pin the
    /// two acceptance facts — the empty-repo advertisement is `Some(vec![])`, and a `protocol.version=2`
    /// config still yields a working V1 receive-pack handshake (the §1.6 pin; if this ever fails, add the
    /// V2→V1 clamp per `01-foundations.md`).
    #[cfg(feature = "blocking-network-client")]
    mod file_transport {
        use std::path::Path;

        fn git(args: &[&str], cwd: &Path) {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .status()
                .expect("the `git` binary is available for the receive-pack handshake test");
            assert!(status.success(), "git {args:?} failed");
        }

        /// Create an empty bare remote + a local repo whose config is seeded with `extra_local_config`
        /// (a flat list of `key value` pairs), returning `(tempdir, opened local repo, bare-repo path)`.
        // NB: refer to our own crate as `crate::`, not `gix::` — the self-name routes through the crate's
        // public view, which hides the `pub(crate)` `receive_pack_handshake_by_ref` this test drives.
        fn scenario(
            extra_local_config: &[(&str, &str)],
        ) -> (gix_testtools::tempfile::TempDir, crate::Repository, std::path::PathBuf) {
            let tmp = gix_testtools::tempfile::TempDir::new().expect("tempdir");
            let root = tmp.path();
            let bare = root.join("remote.git");
            let local = root.join("local");
            std::fs::create_dir_all(&bare).expect("mkdir bare");
            std::fs::create_dir_all(&local).expect("mkdir local");
            git(&["init", "--bare", "--quiet"], &bare);
            git(&["init", "--quiet"], &local);
            for (key, value) in extra_local_config {
                git(&["config", key, value], &local);
            }
            let repo = crate::open_opts(&local, crate::open::Options::isolated()).expect("open local repo");
            (tmp, repo, bare)
        }

        fn receive_pack_advertisement(
            repo: &crate::Repository,
            bare: &Path,
        ) -> (Vec<gix_protocol::handshake::Ref>, gix_protocol::Handshake) {
            // Detach so the repo borrow from `remote_at`/`connect` is released, then drive the by-ref twin
            // directly (the same shape as `Connection::ref_map` → `ConnectionDetached::ref_map_by_ref`).
            let mut detached = repo
                .remote_at(bare.to_str().expect("utf-8 path"))
                .expect("valid file:// remote")
                .connect(crate::remote::Direction::Push)
                .expect("connect for push")
                .into_detached();
            let refs = detached
                .receive_pack_handshake_by_ref(repo, crate::progress::Discard, Vec::new())
                .expect("receive-pack handshake succeeds against an empty bare repo");
            let handshake = detached.handshake.expect("handshake stored on the connection");
            (refs, handshake)
        }

        #[test]
        fn empty_bare_remote_advertises_no_refs() {
            let (_tmp, repo, bare) = scenario(&[]);
            let (refs, handshake) = receive_pack_advertisement(&repo, &bare);
            assert!(
                refs.is_empty(),
                "an empty bare repo advertises the empty ref list, got {refs:?}"
            );
            assert!(
                handshake.refs.is_none(),
                "the advertisement was taken out of the stored handshake"
            );
        }

        #[test]
        fn protocol_v2_config_still_yields_working_v1_receive_pack_handshake() {
            let (_tmp, repo, bare) = scenario(&[("protocol.version", "2")]);
            let (refs, handshake) = receive_pack_advertisement(&repo, &bare);
            assert!(
                refs.is_empty(),
                "even with protocol.version=2 the empty-repo receive-pack advertisement is empty, got {refs:?}"
            );
            assert_eq!(
                handshake.server_protocol_version,
                gix_transport::Protocol::V1,
                "git-receive-pack only advertises V1, so a requested V2 handshake downgrades transparently \
                 (§1.6 pin — if this fails, adopt the V2→V1 clamp fallback)"
            );
        }
    }
}
