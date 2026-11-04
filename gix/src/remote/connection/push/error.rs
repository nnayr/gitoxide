//! The terminal error of a push — the `send()` verb's error (gpx08 drives it).

use crate::config;

/// The error returned by the push `send()` terminal.
///
/// Mirrors [`fetch`](crate::remote::fetch)'s split — the terminal-verb error lives in its own file,
/// re-exported as `Error` from [`push`](crate::remote::push) — and its variant-by-variant relationship to
/// `fetch`'s error is audited in `docs/design/gix-push-porcelain/01-foundations.md` (P1). The six
/// fetch-only variants with no push producer (`PackIndexVersion`, `LoadAlternates`,
/// `RemovePackKeepFile`, `NoMapping`, `RejectShallowRemoteConfig`, `NegotiationAlgorithmConfig`) are
/// dropped; `ThinConfig`/`PushDefaultConfig` are added for the push-side config keys. Later units
/// append their own variants (`UpdateRefs` with gpx09) — the normal gitoxide evolution mode for a
/// non-`#[non_exhaustive]` error enum. gpx08 (the `send()` terminal) adds the pack-driver
/// ([`Pack`](Error::Pack)) and its object-store bootstrap ([`OpenObjectStore`](Error::OpenObjectStore))
/// plus the pre-wire capability gate ([`MissingServerFeature`](Error::MissingServerFeature)).
///
/// Implements [`IsSpuriousError`](gix_protocol::transport::IsSpuriousError) by forwarding the
/// transport/plumbing sources; everything else is non-spurious.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    Push(#[from] gix_protocol::push::Error),
    #[error("The value to configure pack threads should be 0 to auto-configure or the amount of threads to use")]
    PackThreads(#[from] config::unsigned_integer::Error),
    #[error("Could not obtain the 'push.thin' configuration")]
    ThinConfig(#[from] config::boolean::Error),
    #[error("Could not parse the 'push.default' configuration")]
    PushDefaultConfig(#[from] config::key::GenericErrorWithValue),
    #[error("Cannot push to a remote that uses {remote} while local repository uses {local} for object hashes")]
    IncompatibleObjectHash {
        local: gix_hash::Kind,
        remote: gix_hash::Kind,
    },
    #[error(transparent)]
    Client(#[from] gix_protocol::transport::client::Error),
    /// A local failure while building the pack to stream to `git-receive-pack`.
    ///
    /// `send()` (gpx08) drives the pack driver (`pack`) inside the
    /// `gix_protocol::push` closure and re-raises the closure's typed error through a side channel
    /// (the plumbing itself erases it into `WritePack(Box<dyn Error>)`). Non-spurious — every
    /// `pack::Error` is a local object-database/I/O fault, never a retryable
    /// transport hiccup (the pack driver's own `IsSpuriousError` is always `false`).
    #[error(transparent)]
    Pack(#[from] super::pack::Error),
    /// A dedicated pack-capable object store could not be opened to build the pack (see
    /// `pack::write_pack` for why `repo.objects` cannot be used directly).
    #[error("Failed to open a pack-capable object store for building the pack to push")]
    OpenObjectStore(#[source] std::io::Error),
    /// A required server capability was not advertised — the push is refused **before any wire bytes**
    /// (the porcelain twin of the plumbing's own pre-flight gate, e.g. `with_atomic(Required)` against
    /// a server that does not advertise `atomic`; design amendment S6).
    #[error("The server did not advertise the {feature:?} capability required by this push")]
    MissingServerFeature {
        /// The capability name the push required but the server did not advertise.
        feature: &'static str,
    },
    /// The local tracking-ref bookkeeping after a successful send failed (gpx09/P9). The server has
    /// already applied the push (`ng`s are data on [`Status::Pushed`](super::send_pack::Status), not
    /// this error); only the *local* `refs/remotes/<remote>/*` transaction faulted. Non-spurious.
    #[error("Failed to update the local tracking references after the push")]
    UpdateRefs(#[from] super::refs::update::Error),
}

impl gix_protocol::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Push(err) => err.is_spurious(),
            Error::Client(err) => err.is_spurious(),
            _ => false,
        }
    }
}
