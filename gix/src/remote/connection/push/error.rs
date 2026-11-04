//! The terminal error of a push — the `send()` verb's error (gpx08 drives it).

/// The error returned by the push `send()` terminal.
///
/// Mirrors the terminal-verb error of [`fetch`](crate::remote::fetch) in its own file, re-exported as
/// `Error` from [`push`](crate::remote::push), but stays a typed enum: callers recover from
/// [`MissingServerFeature`](Error::MissingServerFeature) and the nested pack, plumbing and tracking-ref
/// failures specifically. Its variant-by-variant relationship to `fetch`'s former error is audited in
/// `docs/design/gix-push-porcelain/01-foundations.md` (P1). The six fetch-only variants with no push
/// producer (`PackIndexVersion`, `LoadAlternates`, `RemovePackKeepFile`, `NoMapping`,
/// `RejectShallowRemoteConfig`, `NegotiationAlgorithmConfig`) are dropped; `ThinConfig`/`PushDefaultConfig`
/// are added for the push-side config keys, carrying the erased [`gix::Error`](crate::Error) of the
/// failed config read. Later units append their own variants (`UpdateRefs` with gpx09) — the normal
/// gitoxide evolution mode for a non-`#[non_exhaustive]` error enum. gpx08 (the `send()` terminal) adds
/// the pack-driver ([`Pack`](Error::Pack)) and its object-store bootstrap
/// ([`OpenObjectStore`](Error::OpenObjectStore)) plus the pre-wire capability gate
/// ([`MissingServerFeature`](Error::MissingServerFeature)).
///
/// Whether a failure is worth retrying is answered by [`gix_error::classify()`] over the source chain.
/// It reaches the transport and plumbing sources of failures that happen *before* the pack is sent (and
/// of the handshake), so those stay retryable. Everything that can happen once the server may have applied
/// the push, or that is a local fault, is **not** retryable: [`Pack`](Error::Pack),
/// [`OpenObjectStore`](Error::OpenObjectStore), [`UpdateRefs`](Error::UpdateRefs) and the plumbing's
/// post-send variants hide their cause from classification (see
/// [`gix_protocol::push::Error`]), while their `Display` still names it.
#[derive(Debug)]
#[expect(missing_docs)]
pub enum Error {
    Push(gix_protocol::push::Error),
    PackThreads(gix_error::Error),
    ThinConfig(gix_error::Error),
    PushDefaultConfig(gix_error::Error),
    IncompatibleObjectHash {
        local: gix_hash::Kind,
        remote: gix_hash::Kind,
    },
    Client(gix_protocol::transport::client::Error),
    /// A local failure while building the pack to stream to `git-receive-pack`.
    ///
    /// `send()` (gpx08) drives the pack driver (`pack`) inside the
    /// `gix_protocol::push` closure and re-raises the closure's typed error through a side channel
    /// (the plumbing itself erases it into `WritePack(Box<dyn Error>)`, which `send()` replaces with the
    /// typed error). This includes a failure while streaming the pack bytes to the transport, which is
    /// [`pack::Error::PackWrite`](super::pack::Error::PackWrite). Never classified as retryable: every
    /// `pack::Error` hides its cause from classification.
    Pack(super::pack::Error),
    /// A dedicated pack-capable object store could not be opened to build the pack (see
    /// `pack::write_pack` for why `repo.objects` cannot be used directly).
    OpenObjectStore(std::io::Error),
    /// A required server capability was not advertised — the push is refused **before any wire bytes**
    /// (the porcelain twin of the plumbing's own pre-flight gate, e.g. `with_atomic(Required)` against
    /// a server that does not advertise `atomic`; design amendment S6).
    MissingServerFeature {
        /// The capability name the push required but the server did not advertise.
        feature: &'static str,
    },
    /// The local tracking-ref bookkeeping after a successful send failed (gpx09/P9). The server has
    /// already applied the push (`ng`s are data on [`Status::Pushed`](super::send_pack::Status), not
    /// this error); only the *local* `refs/remotes/<remote>/*` transaction faulted. Never classified as retryable, even
    /// on lock contention: the push was already applied, so re-pushing is not the remedy.
    UpdateRefs(super::refs::update::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Push(err) => std::fmt::Display::fmt(err, f),
            Error::PackThreads(_) => f.write_str(
                "The value to configure pack threads should be 0 to auto-configure or the amount of threads to use",
            ),
            Error::ThinConfig(_) => f.write_str("Could not obtain the 'push.thin' configuration"),
            Error::PushDefaultConfig(_) => f.write_str("Could not parse the 'push.default' configuration"),
            Error::IncompatibleObjectHash { local, remote } => write!(
                f,
                "Cannot push to a remote that uses {remote} while local repository uses {local} for object hashes"
            ),
            Error::Client(err) => std::fmt::Display::fmt(err, f),
            Error::Pack(err) => std::fmt::Display::fmt(err, f),
            Error::OpenObjectStore(err) => {
                f.write_str("Failed to open a pack-capable object store for building the pack to push")?;
                write_causes(f, err)
            }
            Error::MissingServerFeature { feature } => write!(
                f,
                "The server did not advertise the {feature:?} capability required by this push"
            ),
            Error::UpdateRefs(err) => {
                f.write_str("Failed to update the local tracking references after the push")?;
                write_causes(f, err)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // Transparent variants: only their own cause is the source.
            Error::Push(err) => std::error::Error::source(err),
            Error::Client(err) => std::error::Error::source(err),
            Error::Pack(err) => std::error::Error::source(err),
            Error::PackThreads(err) | Error::ThinConfig(err) | Error::PushDefaultConfig(err) => Some(err),
            // The causes of these stay out of classification (but in `Display`): a local fault is not
            // transient, and after the server accepted the push a re-push is not the remedy.
            Error::OpenObjectStore(_) => None,
            Error::UpdateRefs(_) => Some(const { &gix_error::ClassificationMarker::CONFLICT }),
            Error::IncompatibleObjectHash { .. } => Some(const { &gix_error::ClassificationMarker::UNSUPPORTED }),
            Error::MissingServerFeature { .. } => Some(const { &gix_error::ClassificationMarker::UNSUPPORTED }),
        }
    }
}

impl From<gix_protocol::push::Error> for Error {
    fn from(err: gix_protocol::push::Error) -> Self {
        Error::Push(err)
    }
}

impl From<gix_protocol::transport::client::Error> for Error {
    fn from(err: gix_protocol::transport::client::Error) -> Self {
        Error::Client(err)
    }
}

impl From<super::pack::Error> for Error {
    fn from(err: super::pack::Error) -> Self {
        Error::Pack(err)
    }
}

impl From<super::refs::update::Error> for Error {
    fn from(err: super::refs::update::Error) -> Self {
        Error::UpdateRefs(err)
    }
}

/// Append `err` and its causes to `f` as `: <err>: <cause>…`, for variants that must not expose their cause
/// through [`source()`](std::error::Error::source) but whose message should still name it.
pub(super) fn write_causes(
    f: &mut std::fmt::Formatter<'_>,
    err: &(dyn std::error::Error + 'static),
) -> std::fmt::Result {
    write!(f, ": {err}")?;
    let mut source = err.source();
    while let Some(cause) = source {
        if !cause.is::<gix_error::ClassificationMarker>() {
            write!(f, ": {cause}")?;
        }
        source = cause.source();
    }
    Ok(())
}
