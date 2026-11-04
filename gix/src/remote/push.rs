//! Push support for [`Remote`][crate::Remote]s, mirroring [`fetch`][crate::remote::fetch] for the
//! send (`git push`) direction: where fetch **receives** a pack, push **sends** one via
//! `gix_protocol::push`.
//!
//! Porcelain fork landed by the `gpx01`..`gpx10` family (skeleton bead `rolfdb-gpx-p0`). This facade
//! mirrors [`remote::fetch`](crate::remote::fetch) — an ungated module whose items are individually gated;
//! porcelain types come from `connection::push`, plumbing vocabulary from
//! `gix_protocol::push`. `gpx02` wires the type foundations (errors, options, progress, and the
//! re-exports below); the `prepare_push().send()` flow and its `Prepare`/`Outcome`/`Status`/`plan`
//! types land with `gpx05`..`gpx09`.

/// Porcelain types owned by the push connection module (`gpx02`: errors + options + progress).
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::connection::push::{Error, PrepareOptions, ProgressId, prepare};

/// The push-plan module (`gpx05`), re-exported so `plan::Error` and the plan vocabulary are reachable
/// as `remote::push::plan::*`, mirroring `remote::fetch::refmap`.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::connection::push::plan;

/// The push-plan vocabulary (`gpx05`), surfaced at the `remote::push` root for convenience (the plan
/// itself, its per-ref mappings, the lease policy, and the refspec-source index).
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::connection::push::plan::{
    Force, Lease, LeasePolicy, Mapping, PlannedUpdates, Source, SpecIndex, Verdict,
};
/// The orchestration surface (`gpx08`): the [`Prepare`](super::connection::push::send_pack::Prepare)
/// builder returned by [`Connection::prepare_push`](crate::remote::Connection::prepare_push), and the
/// [`Outcome`](super::connection::push::send_pack::Outcome)/[`Status`](super::connection::push::send_pack::Status)
/// it produces. `refs` (the tracking-ref bookkeeping) lands with `gpx09`.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::connection::push::send_pack::{Outcome, Prepare, Status};

/// The tracking-ref bookkeeping (`gpx09`), re-exported so `refs::Update`/`refs::Mode`/`refs::update`
/// are reachable as `remote::push::refs::*`, mirroring `remote::fetch::refs`.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::connection::push::refs;

/// The way reflog messages are composed when writing ref updates after a push. This is deliberately
/// [`fetch`](super::fetch)'s type reused **verbatim** (never a twin — see the OVERVIEW "REUSE
/// fetch's type" ruling), so a `push: <context>` message composes exactly as `fetch: <context>` does.
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use super::fetch::RefLogMessage;

/// Plumbing vocabulary from [`gix_protocol::push`] that appears in the porcelain push API surface.
///
/// [`gix_protocol::push::Outcome`] is intentionally **not** re-exported here: the porcelain grows its
/// own `push::Outcome` (gpx08), and re-exporting the plumbing one would collide with it. The plumbing
/// report stays reachable as `gix::protocol::push::Outcome` (and, later, as the payload of the
/// porcelain `Status`).
#[cfg(any(feature = "blocking-network-client", feature = "async-network-client"))]
pub use gix_protocol::push::{Atomicity, RefRejectReason, RefUpdate, RefUpdateStatus, UnpackStatus};

/// Access to the push-specific state carried by a detached remote, the send-direction siblings of the
/// fetch-side accessors on `RemoteDetached` in `remote::access` (`name`/`fetch_refspecs`).
///
/// `gpx01` (E1): before this, the detached push path dropped the push url/specs on the floor —
/// `From<Remote>` discarded them and there was nothing to read them back. These read the multi-URL
/// push fields that `From<Remote>` now carries (upstream #2696), and `gpx07`/`gpx08` consume them.
//
// gpx07 wired the real caller of `push_refspecs()`: the `plan()` repo adapter
// (`connection::push::plan`). `push_url()` mirrors `Remote::url(Direction::Push)` for the detached
// form and is exercised by this module's tests; the receive-pack handshake no longer scopes
// credentials by an explicit url (upstream moved that to the lazy `configured_credentials_for_
// current_url` cascade), so `push_url()` awaits a gpx08+ consumer. Both call sites are `pub(crate)`
// scaffolding only ROOTED by a `pub` API in gpx08 (`prepare_push`); until then a non-test
// `cargo check` sees the chain as unreached, so the accessors keep a minimal method-level
// `dead_code` allow (dropped when gpx08 lands).
impl crate::types::RemoteDetached {
    /// Return the set of ref-specs used for pushing, which may be empty, in order of occurrence in the configuration.
    // Caller wired (gpx07): the `plan()` repo adapter. Still dead in a non-test `cargo check` until
    // gpx08's `pub prepare_push` roots the chain; the test build roots it via the adapter's own tests.
    #[allow(dead_code)]
    pub(crate) fn push_refspecs(&self) -> &[gix_refspec::RefSpec] {
        &self.push_specs
    }

    /// Return the push URL with rewrites from `url.<base>.pushInsteadOf`, falling back to the fetch URL.
    ///
    /// The precedence is `pushUrl`-alias → `pushUrl` → fetch URL (rewritten via `pushInsteadOf`),
    /// mirroring [`Remote::url(Direction::Push)`][crate::Remote::url] — a detached remote with only a
    /// fetch URL is still pushable to that URL, exactly like an attached one.
    // Test-rooted (this module) until a gpx08+ consumer arrives; kept as the detached mirror of
    // `Remote::url(Direction::Push)`. Dead in a non-test `cargo check`, hence the method-level allow.
    #[allow(dead_code)]
    pub(crate) fn push_url(&self) -> Option<&gix_url::Url> {
        // Mirror `Remote::url(Direction::Push)` on the detached form (upstream #2696 made remotes
        // multi-URL): prefer the explicit `push_urls` (rewritten via `push_url_aliases`), else fall
        // back to the fetch `urls` rewritten via the push-specific `url_push_aliases` (pushInsteadOf).
        // Returns the first resolved url, exactly like `Remote::url`.
        let (urls, aliases): (&[gix_url::Url], &[Option<gix_url::Url>]) = if self.push_urls.is_empty() {
            (&self.urls, &self.url_push_aliases)
        } else {
            (&self.push_urls, &self.push_url_aliases)
        };
        urls.iter()
            .zip(aliases)
            .map(|(url, alias)| alias.as_ref().unwrap_or(url))
            .next()
    }
}

#[cfg(test)]
mod tests {
    use gix_refspec::{RefSpec, parse::Operation};

    use crate::{bstr::BStr, remote::Direction, types::RemoteDetached};

    fn url(s: &str) -> gix_url::Url {
        gix_url::Url::try_from(s).expect("valid url")
    }

    fn push_spec(s: &str) -> RefSpec {
        gix_refspec::parse(BStr::new(s), Operation::Push)
            .expect("valid push refspec")
            .to_owned()
    }

    /// A detached remote with the given URL state; all refspecs default to empty. Mirrors upstream's
    /// multi-URL shape (#2696): each scalar becomes a one-element vec with a matching alias slot.
    fn detached(fetch_url: Option<&str>, push_url: Option<&str>, push_url_alias: Option<&str>) -> RemoteDetached {
        let urls: Vec<_> = fetch_url.map(url).into_iter().collect();
        let push_urls: Vec<_> = push_url.map(url).into_iter().collect();
        RemoteDetached {
            name: None,
            url_aliases: vec![None; urls.len()],
            url_push_aliases: vec![None; urls.len()],
            urls,
            fetch_specs: Vec::new(),
            // One alias slot per explicit push url (the alias applies only when a push url exists).
            push_url_aliases: push_url.map(|_| push_url_alias.map(url)).into_iter().collect(),
            push_urls,
            push_specs: Vec::new(),
            fetch_tags: Default::default(),
        }
    }

    #[test]
    fn push_refspecs_round_trip() {
        let mut d = detached(Some("https://example.com/a"), None, None);
        let specs = vec![
            push_spec("refs/heads/main:refs/heads/main"),
            push_spec("+refs/heads/topic:refs/heads/topic"),
        ];
        d.push_specs = specs.clone();
        assert_eq!(
            d.push_refspecs(),
            specs.as_slice(),
            "the push refspecs are returned verbatim"
        );
    }

    #[test]
    fn push_url_precedence_is_alias_then_push_then_fetch() {
        // `pushUrl`-alias wins over everything.
        let d = detached(
            Some("https://example.com/fetch"),
            Some("https://example.com/push"),
            Some("https://example.com/alias"),
        );
        assert_eq!(d.push_url(), Some(&url("https://example.com/alias")));

        // No alias → the raw `pushUrl`.
        let d = detached(
            Some("https://example.com/fetch"),
            Some("https://example.com/push"),
            None,
        );
        assert_eq!(d.push_url(), Some(&url("https://example.com/push")));

        // Only a fetch url → fall back to it (the three-way divergence from fetch's two-way getter).
        let d = detached(Some("https://example.com/fetch"), None, None);
        assert_eq!(d.push_url(), Some(&url("https://example.com/fetch")));

        // No url at all → `None`.
        let d = detached(None, None, None);
        assert_eq!(d.push_url(), None);
    }

    #[test]
    fn from_remote_preserves_push_state() {
        // Parity anti-regression for the E1 bug: `From<Remote>` used to drop the push url + specs.
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let repo = crate::init(tmp.path()).expect("init repo");
        let remote = repo
            .remote_at("https://example.com/fetch")
            .expect("fetch url")
            .with_push_url("https://example.com/push")
            .expect("push url")
            .with_refspecs(Some("refs/heads/main:refs/heads/main"), Direction::Push)
            .expect("push refspec");

        let expected_push_url = remote.url(Direction::Push).expect("push url resolves").to_owned();
        let expected_push_specs = remote.refspecs(Direction::Push).to_vec();

        let detached = remote.detached();

        assert_eq!(
            detached.push_url(),
            Some(&expected_push_url),
            "the push url survives detaching"
        );
        assert_eq!(
            detached.push_refspecs(),
            expected_push_specs.as_slice(),
            "the push refspecs survive detaching",
        );
    }
}
