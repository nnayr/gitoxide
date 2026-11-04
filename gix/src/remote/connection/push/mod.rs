//! The push connection module, sibling of [`fetch`][super::fetch]: where fetch **receives** a pack,
//! push **sends** one via `gix_protocol::push`.
//!
//! Porcelain **skeleton** (bead `rolfdb-gpx-p0`). The `gpx01`..`gpx10` units add — mirroring
//! `connection/fetch/` file-for-file — `config`/`send_pack`/`update_refs`, the
//! `Connection::prepare_push` entry point, and the `Prepare`/`PrepareDetached` builders, all under
//! the same feature gates and `#[gix_protocol::bisync::bisync]` twin discipline.
//!
//! `gpx02` lands the **type foundations** only (no orchestration): the terminal [`Error`] (in
//! [`error`]), the [`prepare::Error`] of `prepare_push`, the [`PrepareOptions`] input, and the
//! pack-phase [`ProgressId`]. The plan/send flow is filled in by `gpx05`..`gpx09`.

mod error;
pub use error::Error;

/// Push-side config reads (task `gpx03`), private twin of fetch's `mod config`. See [`config`].
mod config;

/// The receive-pack handshake (task `gpx04`), push twin of fetch's `ref_map`. Reports through
/// [`prepare::Error`] (no standalone `handshake::Error`); see the module docs.
pub mod handshake;

/// The pack driver (`gpx06`/P6): builds the pack a push streams to `git-receive-pack`.
pub mod pack;

/// The push plan (gpx05): refspec → command list + lease. See [`plan::PlannedUpdates`].
pub mod plan;

/// The local tracking-ref bookkeeping (gpx09/P9): correlate the server report to the plan and move
/// the `refs/remotes/<remote>/*` tracking refs. Wired with `#[path]` and re-exported as
/// [`remote::push::refs`](crate::remote::push::refs), exactly like fetch's `refs`.
#[path = "update_refs/mod.rs"]
pub mod refs;

/// The orchestration (gpx08/P7+P8): `Connection::prepare_push().send()` — compose the receive-pack
/// handshake (gpx04), the sync [`plan`] (gpx05), the [`pack`] driver (gpx06) and `gix_protocol::push`
/// into the terminal [`Outcome`](send_pack::Outcome). Self-contained: it wires its own plan adapter
/// against [`plan::plan_inner`] rather than gpx07's `plan()` (the two are fused later).
pub mod send_pack;

///
pub mod prepare {
    use crate::bstr::BString;

    /// The error returned by the push `prepare_push()` step.
    ///
    /// A deliberate structural divergence from `fetch`'s prepare step, which reports through the
    /// erased [`gix::Error`](crate::Error): push keeps this typed enum because callers recover from
    /// [`MissingRefSpecs`](Error::MissingRefSpecs) and a stale lease in [`Plan`](Error::Plan) specifically.
    /// Unlike fetch, whose handshake/ls-refs step is a standalone public operation, push has no
    /// standalone advertisement op (the ReceivePack handshake exists only inside `prepare_push`), so the
    /// transport/credential/handshake failures are **inlined flat** here, each carrying the erased
    /// [`gix::Error`](crate::Error) of the failing step. The `Plan` variant (stale leases surface at
    /// prepare time) is appended by gpx05.
    ///
    /// gpx07 handshake-path audit (gpx02 owed note): every fallible call in
    /// `receive_pack_handshake_by_ref` is already wrapped —
    /// `Transport::configure` ⇒ [`ConfigureTransport`](Error::ConfigureTransport),
    /// `gix_protocol::handshake` ⇒ [`Handshake`](Error::Handshake),
    /// credential/transport-config each have their own variant, and the missing-advertisement guard is
    /// [`MissingRefAdvertisement`](Error::MissingRefAdvertisement). No bare
    /// [`transport::client::Error`](gix_protocol::transport::client::Error) escapes the prepare
    /// path (it only appears on the *send* terminal, [`push::Error::Client`](super::Error)), so no
    /// `Client` variant is needed here.
    ///
    /// Retryability is exposed through [`gix_error::classify()`] on the source chain, so a retryable
    /// handshake failure stays retryable.
    #[derive(Debug)]
    #[expect(missing_docs)]
    pub enum Error {
        MissingRefSpecs,
        GatherTransportConfig {
            url: BString,
            source: gix_error::Error,
        },
        ConfigureTransport(gix_error::Error),
        Handshake(gix_error::Error),
        ConfigureCredentials(gix_error::Error),
        MissingRefAdvertisement {
            version: gix_protocol::transport::Protocol,
        },
        /// A stale force-with-lease or a malformed refspec set surfaces from the sync `plan()` step
        /// (gpx05) as a prepare-time abort — C-git parity for whole-push failures.
        Plan(super::plan::Error),
        /// The local reference snapshot (or `HEAD` state) that feeds the plan could not be read.
        /// Additive gpx08 variant so the self-contained plan adapter (`send_pack::plan_from_repo`)
        /// can surface a ref-store failure rather than swallow it; gpx07's `plan()` adapter shares it.
        CollectRefs(Box<dyn std::error::Error + Send + Sync + 'static>),
        /// The `push.atomic` configuration default (read at prepare time to seed the [`Atomicity`]
        /// the `with_atomic` builder overrides) could not be parsed under a strict-config open.
        /// Additive gpx10 variant — `push.pushOption` has no parse error, so only `push.atomic`
        /// contributes a fallible config read to the prepare path.
        ///
        /// [`Atomicity`]: gix_protocol::push::Atomicity
        AtomicConfig(gix_error::Error),
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Error::MissingRefSpecs => {
                    f.write_str("Cannot perform a meaningful push operation without any configured ref-specs")
                }
                Error::GatherTransportConfig { url, .. } => {
                    write!(f, "Failed to configure the transport before connecting to {url:?}")
                }
                Error::ConfigureTransport(_) => f.write_str("Failed to configure the transport layer"),
                Error::Handshake(err) | Error::ConfigureCredentials(err) => std::fmt::Display::fmt(err, f),
                Error::MissingRefAdvertisement { version } => write!(
                    f,
                    "Refusing to push without an inline ref advertisement — receive-pack always speaks \
                     protocol V0/V1, but the server answered with {version:?}"
                ),
                Error::Plan(err) => std::fmt::Display::fmt(err, f),
                Error::CollectRefs(_) => f.write_str("Failed to read the local references while planning the push"),
                Error::AtomicConfig(_) => f.write_str("Could not read the 'push.atomic' configuration"),
            }
        }
    }

    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Error::MissingRefSpecs => Some(const { &gix_error::ClassificationMarker::VALIDATION }),
                Error::GatherTransportConfig { source, .. } => Some(source),
                Error::ConfigureTransport(err)
                | Error::Handshake(err)
                | Error::ConfigureCredentials(err)
                | Error::AtomicConfig(err) => Some(err),
                Error::MissingRefAdvertisement { .. } => Some(const { &gix_error::ClassificationMarker::UNSUPPORTED }),
                Error::Plan(err) => std::error::Error::source(err),
                Error::CollectRefs(err) => Some(&**err),
            }
        }
    }

    impl From<super::plan::Error> for Error {
        fn from(err: super::plan::Error) -> Self {
            Error::Plan(err)
        }
    }
}

/// Options for `Connection::prepare_push()`, the push analogue of
/// [`ref_map::Options`](crate::remote::ref_map::Options).
///
/// Unlike `ref_map::Options` it carries no `prefix_from_spec_as_filter_on_remote`: receive-pack
/// speaks protocol V0/V1 only, so the advertisement arrives whole with the handshake and cannot be
/// server-side filtered (a V2 `ls-refs` feature that has no push equivalent).
#[derive(Debug, Clone, Default)]
pub struct PrepareOptions {
    /// Parameters in the form of `(name, optional value)` to add to the receive-pack handshake, for
    /// custom servers. Mirrors `ref_map::Options::handshake_parameters`.
    pub handshake_parameters: Vec<(String, Option<String>)>,
    /// Refspecs to push in addition to (and at higher priority than) the remote's configured
    /// `remote.<name>.push` specs, without persisting them on the remote. Empty by default; a
    /// non-empty value also satisfies the empty-config case, so `prepare_push` need not fail with
    /// [`prepare::Error::MissingRefSpecs`]. The priority MERGE with the configured specs lands in gpx08.
    pub extra_refspecs: Vec<gix_refspec::RefSpec>,
    /// The force-with-lease policy (Q2), set via [`with_force_with_lease`](Self::with_force_with_lease).
    /// [`AdvertisedOnly`](plan::LeasePolicy::AdvertisedOnly) by default: the wire CAS against the
    /// advertisement is the only lease, and a `+`-spec alone governs non-fast-forwards.
    ///
    /// gpx02's review deferred the lease builder here (the `PrepareOptions::lease` fix note); gpx07
    /// will migrate it onto the `Prepare` builder so a late `with_force_with_lease` can re-validate
    /// against the advertisement at send time. Until then this is where `prepare_push` reads the
    /// policy to hand the sync `plan()`.
    pub force_with_lease: plan::LeasePolicy,
}

impl PrepareOptions {
    /// Apply `--force-with-lease` semantics (Q2): pin the expected remote value via `lease`. A
    /// satisfied lease grants force at plan time, a violated one aborts with
    /// [`plan::Error::StaleLease`]. Infallible, by gitoxide builder convention.
    pub fn with_force_with_lease(mut self, lease: plan::Lease) -> Self {
        self.force_with_lease = plan::LeasePolicy::ForceWithLease(lease);
        self
    }
}

/// The progress ids emitted by the push pack-build phase (gpx06), mirroring the pattern of
/// [`clone::checkout::main_worktree::ProgressId`](crate::clone::checkout::main_worktree::ProgressId).
#[derive(Debug, Copy, Clone)]
pub enum ProgressId {
    /// The number of objects counted while traversing tips (down to the advertised boundaries) to
    /// determine what the pack must contain.
    CountObjects,
    /// The number of objects written into the pack streamed to the server.
    WritePack,
}

impl From<ProgressId> for gix_utils::progress::Id {
    fn from(v: ProgressId) -> Self {
        match v {
            ProgressId::CountObjects => *b"PSCO",
            ProgressId::WritePack => *b"PSWP",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::remote::push;
    use gix_error::ErrorExt;

    fn is_spurious(err: &(dyn std::error::Error + 'static)) -> bool {
        gix_error::classify(err).can_retry_lenient()
    }

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::from(kind)
    }

    /// Errors that arise once the pack was sent never count as retryable, as `IsSpuriousError` did
    /// before: the server may already have applied the ref updates, so a re-push is not idempotent.
    fn assert_not_retryable(err: &(dyn std::error::Error + 'static), what: &str) {
        assert!(!gix_error::classify(err).can_retry(), "{what}: strict retry policy");
        assert!(
            !gix_error::classify(err).can_retry_lenient(),
            "{what}: lenient retry policy"
        );
    }

    #[test]
    fn prepare_missing_ref_specs_is_not_spurious_and_reads_like_fetch() {
        let err = push::prepare::Error::MissingRefSpecs;
        assert!(!is_spurious(&err));
        assert_eq!(
            err.to_string(),
            "Cannot perform a meaningful push operation without any configured ref-specs"
        );
    }

    #[test]
    fn client_errors_forward_spuriousness() {
        // `send()` wraps plumbing failures as `Push(..)`, so pin that nested shape; the direct
        // terminal `Client` variant is kept as a separately supported shape.
        let nested = push::Error::Push(gix_protocol::push::Error::Client(
            io(std::io::ErrorKind::ConnectionReset).into(),
        ));
        assert!(is_spurious(&nested), "a reset before the pack was sent is spurious");
        assert!(
            gix_error::classify(&push::Error::Push(gix_protocol::push::Error::Client(
                io(std::io::ErrorKind::TimedOut).into()
            )))
            .can_retry(),
            "a timeout before the pack was sent is retryable under the strict policy too"
        );
        let direct = push::Error::Client(io(std::io::ErrorKind::ConnectionReset).into());
        assert!(is_spurious(&direct));
    }

    #[test]
    fn handshake_failures_stay_spurious() {
        let err =
            push::prepare::Error::Handshake(gix_error::Error::from_error(io(std::io::ErrorKind::ConnectionReset)));
        assert!(
            is_spurious(&err),
            "the handshake is the one prepare step that forwards spuriousness"
        );
    }

    #[test]
    fn failures_after_the_pack_was_sent_are_not_retryable() {
        use std::io::ErrorKind::{ConnectionReset, TimedOut};
        for kind in [ConnectionReset, TimedOut] {
            assert_not_retryable(
                &push::Error::Push(gix_protocol::push::Error::Response(
                    gix_protocol::push::response::Error::Io(io(kind)),
                )),
                "Push(Response(Io))",
            );
            assert_not_retryable(&push::Error::Push(gix_protocol::push::Error::Io(io(kind))), "Push(Io)");
            assert_not_retryable(
                &push::Error::Push(gix_protocol::push::Error::WritePack(Box::new(io(kind)))),
                "Push(WritePack)",
            );
            assert_not_retryable(&push::Error::OpenObjectStore(io(kind)), "OpenObjectStore");
        }
    }

    #[test]
    fn tracking_ref_bookkeeping_failures_are_not_retryable_even_on_lock_contention() {
        use super::refs::update::Error;
        for err in [
            Error::EditReferences(gix_error::retryable("the reference lock is held elsewhere").raise()),
            Error::FindReference(gix_error::Error::from_error(io(std::io::ErrorKind::TimedOut))),
        ] {
            assert_not_retryable(&push::Error::UpdateRefs(err), "UpdateRefs");
        }
    }

    #[test]
    fn pack_failures_are_not_retryable() {
        use super::pack::Error;
        let transport_reset = || gix_error::Error::from_error(io(std::io::ErrorKind::ConnectionReset));
        let retryable = || gix_error::retryable("looks transient").raise();
        for err in [
            Error::PackWrite(transport_reset()),
            Error::Find(retryable()),
            Error::Count(retryable()),
            Error::IterEntries(retryable()),
            Error::Traverse(retryable()),
            Error::Decode(retryable()),
            Error::MergeRepairDiff(Box::new(io(std::io::ErrorKind::TimedOut))),
        ] {
            assert_not_retryable(&push::Error::Pack(err), "Pack");
        }
    }

    #[test]
    fn post_send_failures_keep_their_cause_in_the_message() {
        let err = push::Error::Push(gix_protocol::push::Error::Response(
            gix_protocol::push::response::Error::Io(io(std::io::ErrorKind::ConnectionReset)),
        ));
        assert!(
            format!("{err:#}").contains("connection reset"),
            "the I/O cause stays visible for diagnostics, got: {err:#}"
        );
        let err = push::Error::UpdateRefs(super::refs::update::Error::EditReferences(
            gix_error::message("lock held").raise(),
        ));
        assert!(
            format!("{err:#}").contains("lock held"),
            "the bookkeeping cause stays visible for diagnostics, got: {err:#}"
        );
    }

    #[test]
    fn pack_errors_map_into_push_error_and_are_not_spurious() {
        // The orchestration boundary (gpx08's `send()`) lifts a pack-build failure into the terminal
        // error via `#[from]`; it is a local fault, so it never reports as spurious.
        let err: push::Error = super::pack::Error::Interrupted.into();
        assert!(matches!(err, push::Error::Pack(super::pack::Error::Interrupted)));
        assert!(!is_spurious(&err));
    }

    #[test]
    fn incompatible_object_hash_is_not_spurious() {
        let err = push::Error::IncompatibleObjectHash {
            local: gix_hash::Kind::Sha1,
            remote: gix_hash::Kind::Sha256,
        };
        assert!(!is_spurious(&err));
    }

    #[test]
    fn both_error_enums_are_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<push::Error>();
        assert_send_sync_static::<push::prepare::Error>();
    }

    #[test]
    fn progress_ids_are_distinct() {
        let count: gix_utils::progress::Id = push::ProgressId::CountObjects.into();
        let write: gix_utils::progress::Id = push::ProgressId::WritePack.into();
        assert_ne!(count, write);
    }

    #[test]
    fn prepare_options_default_is_empty() {
        let opts = push::PrepareOptions::default();
        assert!(opts.extra_refspecs.is_empty());
        assert!(opts.handshake_parameters.is_empty());
    }

    /// Compile-time proof that `remote::push::RefLogMessage` **is** `remote::fetch::RefLogMessage`
    /// (reuse, not a twin — gpx02 amendment "RefLogMessage == fetch's"): the identity body
    /// type-checks only if the two paths name one and the same type.
    #[allow(dead_code)]
    fn reflog_message_is_the_fetch_type(m: crate::remote::fetch::RefLogMessage) -> push::RefLogMessage {
        m
    }

    /// Compile-time proof that the plumbing vocabulary is re-exported at the porcelain path as the
    /// **same** `gix_protocol::push` types (not twins). `Outcome` is deliberately not among them.
    #[allow(dead_code)]
    fn plumbing_vocab_is_reexported(a: push::Atomicity) -> gix_protocol::push::Atomicity {
        a
    }
    // Identity (not mere accessibility) for the rest of the vocab: each type-checks only if the
    // facade name IS the plumbing type (glm review — an accidental twin would slip a Some-check).
    #[allow(dead_code)]
    fn plumbing_vocab_identity_ref_update(v: push::RefUpdate) -> gix_protocol::push::RefUpdate {
        v
    }
    #[allow(dead_code)]
    fn plumbing_vocab_identity_status(v: push::RefUpdateStatus) -> gix_protocol::push::RefUpdateStatus {
        v
    }
    #[allow(dead_code)]
    fn plumbing_vocab_identity_reject(v: push::RefRejectReason) -> gix_protocol::push::RefRejectReason {
        v
    }
    #[allow(dead_code)]
    fn plumbing_vocab_identity_unpack(v: push::UnpackStatus) -> gix_protocol::push::UnpackStatus {
        v
    }
}
