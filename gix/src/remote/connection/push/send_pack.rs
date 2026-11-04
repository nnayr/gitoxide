//! The push orchestration (`gpx08` / design `P7` [`prepare_push`] + `P8` [`send`]) — the send-direction
//! twin of fetch's `prepare_fetch`/`Prepare`/`receive()` ([`connection/fetch/`](super::super::fetch)).
//!
//! [`Connection::prepare_push`] performs the receive-pack handshake (gpx04), turns the advertisement
//! into an immutable [`plan`](super::plan) (gpx05) via the self-contained [`plan_from_repo`] adapter,
//! and hands the whole thing to [`Prepare`]. [`Prepare::send`] then drives the 10-step terminal:
//! wire-silent short-circuit → hash precheck → atomicity gate → assemble the [`pack`](super::pack)
//! driver's `write_pack` closure (gpx06) → `gix_protocol::push` → gpx09 tracking-ref bookkeeping
//! ([`refs::update`](super::refs::update)) → assemble the [`Outcome`].
//!
//! # Self-contained against `plan_inner` (gpx07 runs concurrently)
//! gpx07 lands the canonical `plan()` repo adapter (wiring the four oracles to a [`Repository`]) plus
//! the reflog/tracking-ref bookkeeping. This unit does **not** depend on it: [`plan_from_repo`] here
//! is a minimal adapter over [`plan::plan_inner`] built from what the `blocking-network-client` /
//! `async-network-client` gates already provide (no `revision` feature — see the `resolve_rev` note),
//! so gpx08 is testable on its own. The two adapters are reconciled at fuse time.
//!
//! # `bisync` seam
//! Only [`prepare_push`](Connection::prepare_push) is `#[bisync]` (it awaits the gpx04 handshake).
//! [`send`](Prepare::send) is **blocking-only** in v1 (`#[cfg(feature = "blocking-network-client")]`):
//! the plumbing orchestrator `gix_protocol::push` is blocking-only until plumbing M3, and the async
//! `write_pack` bridge is a later unit's job (the original gpx10 "async parity" scope, deferred; the
//! delivered gpx10 is the push-options + sideband surface below). Under `async-network-client` a
//! [`Prepare`] therefore has no `send` yet — exactly as designed (04-orchestration §bisync seam).

// Only the blocking-only `send()` uses the interrupt flag; the `async-network-client` gate compiles
// `prepare_push` but not `send` (v1), so the import is blocking-scoped to stay warning-clean there.
#[cfg(feature = "blocking-network-client")]
use std::sync::atomic::AtomicBool;

#[cfg(feature = "async-network-client")]
use gix_transport::client::async_io::Transport;
#[cfg(feature = "blocking-network-client")]
use gix_transport::client::blocking_io::Transport;

use gix_hash::ObjectId;
use gix_protocol::handshake;
use gix_ref::FullName;

use super::plan::{self, Ancestry, HeadState, LeasePolicy, LocalRef, PlannedUpdates};
use super::{PrepareOptions, config, prepare};
use crate::Progress;
use crate::bstr::BString;
use crate::remote::connection::ConnectionDetached;
use crate::remote::fetch::RefLogMessage;

/// The status of a completed [`Prepare::send`], the push analogue of
/// [`fetch::Status`](crate::remote::fetch::Status).
///
/// `ng` (a per-ref server refusal) is **data**, carried inside `Pushed.report`, never an `Err` — only
/// a transport/plumbing failure is an `Err` (the load-bearing invariant, 04-orchestration §Verdict).
///
/// The tracking-ref bookkeeping (`refs/remotes/<remote>/*` edits + reflog) that 05-outcome-bookkeeping
/// attaches to both variants rides the `update_refs` field, filled by gpx09's [`refs::update`](super::refs::update):
/// even a wire-silent send records a per-mapping disposition (local pre-verdicts, dry-run), and a real
/// push additionally moves the tracking refs.
#[derive(Debug, Clone)]
pub enum Status {
    /// No wire bytes were sent: a dry-run, an all-up-to-date plan, or a plan with no sendable command
    /// (every mapping resolved to a local pre-verdict). The wire-silence law (design amendment S9).
    NothingToPush {
        /// `true` iff the silence was because dry-run was requested (vs. genuinely nothing to do).
        dry_run: bool,
        /// Per-mapping dispositions (no ref was touched): local pre-verdicts, or `DryRun` for the
        /// sendable-but-suppressed mappings of a dry-run.
        update_refs: super::refs::update::Outcome,
    },
    /// A push was sent to the server; carries its report and the pack statistics.
    Pushed {
        /// The plumbing report — `unpack` status plus one `ok`/`ng` per command, in wire order.
        report: gix_protocol::push::Outcome,
        /// Statistics from building the pack, or `None` for a delete-only push (which sends no pack).
        write_pack: Option<super::pack::Outcome>,
        /// The tracking-ref bookkeeping: which `refs/remotes/<remote>/*` refs were moved (or removed),
        /// plus a per-mapping disposition correlating the server report back to the plan (gpx09).
        update_refs: super::refs::update::Outcome,
    },
}

/// The outcome of a [`Prepare::send`], mirroring [`fetch::Outcome`](crate::remote::fetch::Outcome):
/// the resolved [`plan`](super::plan) (fetch's `ref_map` twin), the server handshake, and the status.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The fully-resolved push plan (the send-direction analogue of fetch's `ref_map`).
    pub plan: PlannedUpdates,
    /// The handshake performed with the server (its ref advertisement was moved into `plan`).
    pub handshake: gix_protocol::Handshake,
    /// What happened.
    pub status: Status,
}

impl<'auth, 'repo, T> crate::remote::Connection<'_, 'auth, 'repo, T>
where
    T: Transport,
{
    /// Perform the receive-pack handshake and resolve the push plan, returning a [`Prepare`] whose
    /// builders configure the upcoming [`send`](Prepare::send). The send-direction twin of
    /// [`prepare_fetch`](crate::remote::Connection::prepare_fetch).
    ///
    /// The transport is consumed here; from this point on the plan is immutable (its `expected_old`
    /// leases are the advertised oids, lease-policy-independent — 04-orchestration §"plan immutable").
    #[allow(clippy::result_large_err)]
    #[gix_protocol::bisync::bisync]
    pub async fn prepare_push(
        self,
        progress: impl Progress,
        options: PrepareOptions,
    ) -> Result<Prepare<'auth, 'repo, T>, prepare::Error> {
        let repo = self.remote.repo;
        let inner = self.into_detached().prepare_push(repo, progress, options).await?;
        Ok(Prepare { inner, repo })
    }
}

impl<'remote, T> ConnectionDetached<'remote, T>
where
    T: Transport,
{
    #[allow(clippy::result_large_err)]
    #[gix_protocol::bisync::bisync]
    pub(crate) async fn prepare_push(
        mut self,
        repo: &crate::Repository,
        progress: impl Progress,
        options: PrepareOptions,
    ) -> Result<PrepareDetached<'remote, T>, prepare::Error> {
        // Q1 empty-spec guard (mirror fetch/mod.rs:165) — a non-empty `extra_refspecs` satisfies it.
        if self.remote.push_refspecs().is_empty() && options.extra_refspecs.is_empty() {
            return Err(prepare::Error::MissingRefSpecs);
        }
        // gpx04 handshake as Service::ReceivePack — the advertisement *is* the response (no ls-refs).
        let remote_refs = self
            .receive_pack_handshake_by_ref(repo, progress, options.handshake_parameters)
            .await?;
        // The remote's short name (owned so the `self.remote` borrow ends before `self` is moved),
        // used to reverse-map a destination to its `refs/remotes/<name>/*` tracking ref for a lease.
        let remote_name = self.remote.name().map(|n| n.as_bstr().to_string());
        // The sync gpx05 plan over the advertisement. Structural + plan-resolution failures (incl. a
        // stale force-with-lease) abort here; per-ref rejects ride along inside `PlannedUpdates`.
        let plan = plan_from_repo(
            repo,
            self.remote.push_refspecs(),
            &options.extra_refspecs,
            &remote_refs,
            options.force_with_lease,
            remote_name.as_deref(),
        )?;
        // gpx10 config defaults: `push.pushOption` seeds the default push-options (C-git: sent as if
        // each were `--push-option=<value>` when the builder names none) and `push.atomic` seeds the
        // Atomicity. Both are the initial values the with_push_options/with_atomic builders override.
        // Reading them here (before the builders run) is what makes the builder an override of config.
        let push_options = config::push_options(repo);
        let atomicity = config::atomic(repo).map_err(prepare::Error::AtomicConfig)?; // strict-config parse failure ⇒ prepare::Error::AtomicConfig
        Ok(PrepareDetached {
            con: Some(self),
            plan,
            dry_run: false,
            atomicity,
            push_options,
            sideband: false,
            reflog_message: None,
        })
    }
}

/// A repository-attached preparation for a push, produced by
/// [`prepare_push`](crate::remote::Connection::prepare_push). Configure it with the builder methods,
/// then call [`send`](Self::send).
///
/// `repo`/`con` are read only by the blocking-only [`send`](Self::send); under `async-network-client`
/// (which compiles `prepare_push` but not `send` in v1) they are legitimately unused until gpx10.
#[cfg_attr(not(feature = "blocking-network-client"), allow(dead_code))]
pub struct Prepare<'remote, 'repo, T>
where
    T: Transport,
{
    inner: PrepareDetached<'remote, T>,
    repo: &'repo crate::Repository,
}

/// A repository-detached preparation for a push (the borrow-free core of [`Prepare`]).
#[cfg_attr(not(feature = "blocking-network-client"), allow(dead_code))]
pub(crate) struct PrepareDetached<'remote, T>
where
    T: Transport,
{
    con: Option<ConnectionDetached<'remote, T>>,
    plan: PlannedUpdates,
    dry_run: bool,
    atomicity: gix_protocol::push::Atomicity,
    // gpx10: the push-options + sideband surface over the delivered plumbing (Options::push_options /
    // Options::sideband). Seeded from config (push.pushOption / push.atomic) at prepare time and
    // overridable by the with_push_options/with_sideband/with_atomic builders; threaded into the
    // plumbing Options in send().
    push_options: Vec<BString>,
    sideband: bool,
    // Written by `with_reflog_message`, consumed by gpx09's `refs::update` after a successful send to
    // compose the tracking-ref reflog lines; defaults to `Prefixed { action: "push" }` when unset.
    reflog_message: Option<RefLogMessage>,
}

impl<T> PrepareDetached<'_, T>
where
    T: Transport,
{
    /// The [`Handshake`](gix_protocol::Handshake) stored in `con.handshake` by `prepare_push` — the
    /// borrow-free core of [`Prepare::handshake`]. Not gated on `blocking-network-client`, so the
    /// capability inspection is available under both network-client gates (`send` is blocking-only,
    /// but reading the advertisement is not). Panics only if called after `send()` consumed it.
    pub(crate) fn handshake(&self) -> &gix_protocol::Handshake {
        self.con
            .as_ref()
            .and_then(|con| con.handshake.as_ref())
            .expect("handshake stored by prepare_push, taken only by send()")
    }
}

/// Builders — infallible, by gitoxide convention (a capability/lease failure surfaces at `send()`,
/// design amendment S6). The plan is immutable, so none of these can invalidate [`ref_updates()`](Prepare::ref_updates).
impl<T> Prepare<'_, '_, T>
where
    T: Transport,
{
    /// The resolved wire commands (the sendable subset of the plan), for inspection before `send()`.
    pub fn ref_updates(&self) -> &[gix_protocol::push::RefUpdate] {
        &self.inner.plan.updates
    }

    /// The full plan, including the non-sendable per-ref pre-verdicts (fetch's `ref_map` twin).
    pub fn plan(&self) -> &PlannedUpdates {
        &self.inner.plan
    }

    /// The [`Handshake`](gix_protocol::Handshake) performed by
    /// [`prepare_push`](crate::remote::Connection::prepare_push), for inspecting the server's
    /// *capabilities* before [`send`](Self::send) — e.g. whether `side-band-64k`/`atomic` are
    /// advertised, so a caller can negotiate `remote:` output when-advertised. The advertisement's
    /// `refs` were moved into the [`plan`](Self::plan), so this reads capabilities, not the ref list.
    ///
    /// The send-direction twin of the accessor fetch offers on its own `Prepare`.
    pub fn handshake(&self) -> &gix_protocol::Handshake {
        self.inner.handshake()
    }

    /// If enabled, no change is made on the server: the plan is resolved but no wire bytes are sent,
    /// yielding [`Status::NothingToPush { dry_run: true, .. }`](Status::NothingToPush).
    pub fn with_dry_run(mut self, enabled: bool) -> Self {
        self.inner.dry_run = enabled;
        self
    }

    /// The `atomic` capability policy (Q3). [`Required`](gix_protocol::push::Atomicity::Required)
    /// against a server that does not advertise `atomic` fails `send()` with
    /// [`Error::MissingServerFeature`](super::Error::MissingServerFeature) before any wire bytes.
    pub fn with_atomic(mut self, atomicity: gix_protocol::push::Atomicity) -> Self {
        self.inner.atomicity = atomicity;
        self
    }

    /// Set the reflog message used when the tracking refs are updated after the push. Reuses fetch's
    /// [`RefLogMessage`](crate::remote::fetch::RefLogMessage) verbatim (never a twin). Consumed by gpx09's
    /// bookkeeping; stored here so a caller can set it before `send()`.
    pub fn with_reflog_message(mut self, reflog_message: RefLogMessage) -> Self {
        self.inner.reflog_message = Some(reflog_message);
        self
    }

    /// The push-options (gpx10) to send after the command-list flush — one pkt-line each, verbatim
    /// and in order (git's `--push-option`). **Replaces** the `push.pushOption` config default read
    /// at prepare time, mirroring git (a command-line `--push-option` suppresses the config); pass an
    /// empty vector to send none. A non-empty value against a server that does not advertise
    /// `push-options` fails `send()` with [`Error::MissingServerFeature`](super::Error::MissingServerFeature)
    /// before any wire bytes — the option is never silently dropped (plumbing law F5). Empty (the
    /// default when config sets none) sends no option block and echoes no cap, so the push is
    /// byte-identical to one without options.
    pub fn with_push_options(mut self, push_options: Vec<BString>) -> Self {
        self.inner.push_options = push_options;
        self
    }

    /// Request `side-band-64k` for the report (gpx10). When enabled **and** advertised, the server
    /// band-multiplexes its response and the plumbing demux routes band 2 (progress) and band 3
    /// (remote errors) to the `progress` passed to [`send`](Self::send) — a real
    /// [`NestedProgress`](gix_utils::progress::NestedProgress) sink then observes the server's
    /// `remote:` output. Enabled against a server that does not advertise `side-band-64k` fails
    /// `send()` with [`Error::MissingServerFeature`](super::Error::MissingServerFeature) before any
    /// wire bytes. `false` (the default) keeps the report as plain pkt-lines, byte-identical to a push
    /// that never negotiates it.
    ///
    /// An explicit boolean (rather than progress-implied) keeps the negotiation deterministic and
    /// independent of whether the caller happens to pass a discarding vs. recording progress sink.
    pub fn with_sideband(mut self, enabled: bool) -> Self {
        self.inner.sideband = enabled;
        self
    }
}

impl<T> Prepare<'_, '_, T>
where
    T: Transport,
{
    /// Send the push and report what happened. `ng` is data; only a transport failure is an `Err`.
    ///
    /// Blocking-only in v1 (see the module `bisync` note). In dry-run / all-up-to-date /
    /// no-mapping cases it returns [`Status::NothingToPush`] having written **zero** request bytes.
    #[cfg(feature = "blocking-network-client")]
    pub fn send<P>(self, progress: P, should_interrupt: &AtomicBool) -> Result<Outcome, super::Error>
    where
        P: gix_utils::progress::NestedProgress,
        P::SubProgress: 'static,
    {
        let Prepare { inner, repo } = self;
        inner.send(repo, progress, should_interrupt)
    }
}

#[cfg(feature = "blocking-network-client")]
impl<T> PrepareDetached<'_, T>
where
    T: Transport,
{
    fn send<P>(
        mut self,
        repo: &crate::Repository,
        progress: P,
        should_interrupt: &AtomicBool,
    ) -> Result<Outcome, super::Error>
    where
        P: gix_utils::progress::NestedProgress,
        P::SubProgress: 'static,
    {
        // Take the connection + handshake once (mirror receive_pack.rs); neither touches the wire.
        let mut con = self.con.take().expect("send() can only be called once");
        let mut handshake = con.handshake.take().expect("send() can only be called once");

        // Step: object-format hash precheck (design amendment B10; ORDER per fused review #5 —
        // the zero-byte refusals run BEFORE the dry-run short-circuit so `--dry-run` faithfully
        // reports the refusal a real push would hit, while wire-silence is preserved either way) — a friendly re-map to
        // IncompatibleObjectHash; `gix_protocol::push` re-checks and returns HashKindMismatch anyway.
        // We only surface the friendly error when the advertised algorithm is one we can REPRESENT
        // locally (a `gix_hash::Kind` — the `Sha256` variant only exists under the `sha256` feature):
        // an unrepresentable-but-different algorithm (e.g. a sha256 remote in a sha1-only build) falls
        // through to the plumbing precheck, which refuses it pre-wire regardless (design amendment B10).
        let local_hash = repo.object_hash();
        if let Some(advertised) = handshake
            .capabilities
            .capability("object-format")
            .and_then(|c| c.value())
        {
            let parsed: Option<gix_hash::Kind> = std::str::from_utf8(advertised).ok().and_then(|s| s.parse().ok());
            if let Some(remote) = parsed
                && remote != local_hash
            {
                return Err(super::Error::IncompatibleObjectHash {
                    local: local_hash,
                    remote,
                });
            }
        }

        // Step: capability gates (design amendment S6) — a required-but-unadvertised capability is
        // refused before any wire bytes, the porcelain twin of the plumbing preflight. Each yields
        // the friendly, uniform `super::Error::MissingServerFeature { feature }` and, running BEFORE
        // the wire-silence short-circuit (fused review #5), also fires under `--dry-run` so a dry-run
        // faithfully reports the refusal a real push would hit. The plumbing re-checks every one of
        // these inside `select_capabilities` and refuses identically — this is defense-in-depth for a
        // friendlier error surface + a byte-provable refusal (the WireSilenceTripwire never fires).
        if matches!(self.atomicity, gix_protocol::push::Atomicity::Required)
            && !handshake.capabilities.contains("atomic")
        {
            return Err(super::Error::MissingServerFeature { feature: "atomic" });
        }
        // gpx10: push-options opted in (non-empty) require the server to advertise `push-options`;
        // side-band-64k opted in requires the server to advertise `side-band-64k`. Never silently
        // dropped (plumbing law F5 / the sideband parity).
        if !self.push_options.is_empty() && !handshake.capabilities.contains("push-options") {
            return Err(super::Error::MissingServerFeature {
                feature: "push-options",
            });
        }
        if self.sideband && !handshake.capabilities.contains("side-band-64k") {
            return Err(super::Error::MissingServerFeature {
                feature: "side-band-64k",
            });
        }

        // Step: wire-silent short-circuit (design amendment S9). dry-run, all-up-to-date, and
        // no-mapping (every mapping locally pre-verdicted) all reduce to "no sendable command" and
        // MUST emit ZERO request bytes — we return before `transport.request()` is ever reached.
        // NB: runs AFTER the zero-byte refusal gates above (fused review #5).
        if self.dry_run || self.plan.updates.is_empty() {
            // Bookkeeping still runs (report `None`): it records the per-mapping dispositions — local
            // pre-verdicts and, for a dry-run, `DryRun` — but touches no ref (dry_run suppresses the
            // transaction, and a no-sendable plan has no server `ok` to move a tracking ref for).
            let update_refs = self.run_bookkeeping(repo, &con, None, false)?;
            return Ok(Outcome {
                plan: self.plan,
                handshake,
                status: Status::NothingToPush {
                    dry_run: self.dry_run,
                    update_refs,
                },
            });
        }

        // NB (fused review #4): no send-time lease re-validation in v1 — the lease is frozen at
        // prepare (PrepareOptions carries it; there is no late with_force_with_lease builder on
        // Prepare), so the prepare->send TOCTOU window the design's step list guarded against
        // cannot occur. Revisit if a late lease builder is ever added.

        // Step: assemble the gpx06 pack driver's `write_pack` closure. Build a DEDICATED pack-capable
        // odb handle (repo.objects is a memory::Proxy that does NOT implement gix_pack::Find — see
        // pack::write_pack's rustdoc) with prevent_pack_unload() set, as the pack pipeline requires.
        let mut db = gix_odb::at(repo.git_dir().join("objects"), repo.object_hash())
            .and_then(gix_odb::Handle::into_arc)
            .map_err(super::Error::OpenObjectStore)?;
        db.prevent_pack_unload();
        let boundaries = super::pack::boundaries_from_advertised(&self.plan.remote_refs, &db);
        let (write_pack_inner, stats) =
            super::pack::make_write_pack(db, self.plan.tips.clone(), boundaries, local_hash);
        // Side-channel for the typed pack error (fused review #1): the plumbing erases the
        // closure's error into WritePack(Box<dyn Error>); we stash the real pack::Error here and
        // re-raise it as Error::Pack after the call, so MissingObject/UnsupportedTipType/
        // Interrupted keep their types.
        let pack_error: std::rc::Rc<std::cell::RefCell<Option<super::pack::Error>>> =
            std::rc::Rc::new(std::cell::RefCell::new(None));
        let pack_error_in = std::rc::Rc::clone(&pack_error);
        let write_pack = move |out: &mut dyn std::io::Write,
                               progress: &mut dyn gix_utils::progress::DynNestedProgress,
                               should_interrupt: &std::sync::atomic::AtomicBool|
              -> Result<(), std::io::Error> {
            write_pack_inner(out, progress, should_interrupt).map_err(|e| {
                let msg = e.to_string();
                *pack_error_in.borrow_mut() = Some(e);
                std::io::Error::other(msg)
            })
        };

        // Step: assemble Context/Options (design amendment S3) and invoke the plumbing orchestrator.
        // gpx10 threads the push-options + sideband surface into the delivered plumbing Options; the
        // capability gates above already refused an opted-in-but-unadvertised request, so here the
        // plumbing's own `select_capabilities` will find every wanted cap advertised.
        let options = gix_protocol::push::Options {
            atomic: self.atomicity,
            report_status_v2: false,
            push_options: std::mem::take(&mut self.push_options),
            quiet: false,
            sideband: self.sideband,
        };
        let context = gix_protocol::push::Context {
            handshake: &mut handshake,
            transport: &mut con.transport.inner,
            user_agent: repo.config.user_agent_tuple(),
            trace_packetlines: con.trace,
        };
        let report = gix_protocol::push::push(
            &self.plan.updates,
            write_pack,
            progress,
            should_interrupt,
            context,
            options,
        )
        .map_err(|e| match pack_error.borrow_mut().take() {
            Some(pe) => super::Error::Pack(pe),
            None => super::Error::Push(e),
        })?;

        // Step: vestigial V2 end-of-interaction guard — receive-pack is always V1 (§1.6), so there is
        // nothing to do here; the `SendFlushOnDrop` on `con` performs the graceful teardown on drop.

        // Step: gpx09 tracking-ref bookkeeping — correlate the report to the plan and move the
        // `refs/remotes/<remote>/*` tracking refs in one transaction. `atomic` is "active" (a single
        // `ng` rolls back the whole push, so all tracking edits are suppressed) iff it was actually
        // negotiated: `Required` (the S6 gate above already proved it advertised) or `WhenAdvertised`
        // against an advertising server (design amendment B15).
        let atomic_active = match self.atomicity {
            gix_protocol::push::Atomicity::Required => true,
            gix_protocol::push::Atomicity::WhenAdvertised => handshake.capabilities.contains("atomic"),
            gix_protocol::push::Atomicity::Disabled => false,
        };
        let update_refs = self.run_bookkeeping(repo, &con, Some(&report), atomic_active)?;

        // Step: read back the pack statistics (None for a delete-only push, whose closure never ran)
        // and assemble the Outcome.
        let write_pack = stats.borrow_mut().take();
        Ok(Outcome {
            plan: self.plan,
            handshake,
            status: Status::Pushed {
                report,
                write_pack,
                update_refs,
            },
        })
    }

    /// Run the gpx09 tracking-ref bookkeeping ([`refs::update`](super::refs::update)) with this
    /// prepare's reflog message (defaulting to `Prefixed { action: "push" }`) and the remote's fetch
    /// specs. `report` is the plumbing report, or `None` on a wire-silent send; `atomic_active` marks
    /// whether the `atomic` capability was negotiated (only consulted when a report is present).
    fn run_bookkeeping(
        &mut self,
        repo: &crate::Repository,
        con: &ConnectionDetached<'_, T>,
        report: Option<&gix_protocol::push::Outcome>,
        atomic_active: bool,
    ) -> Result<super::refs::update::Outcome, super::Error> {
        let message = self
            .reflog_message
            .take()
            .unwrap_or_else(|| RefLogMessage::Prefixed { action: "push".into() });
        Ok(super::refs::update(
            repo,
            message,
            &self.plan,
            report,
            &con.remote.fetch_specs,
            atomic_active,
            self.dry_run,
        )?)
    }
}

/// Build a [`PlannedUpdates`] from a real [`Repository`] plus the receive-pack advertisement — the
/// self-contained gpx08 adapter over the pure [`plan::plan_inner`] (gpx07 lands the canonical one).
///
/// It snapshots the local refs and `HEAD`, then injects the four oracles `plan_inner` needs:
/// * `has_object` — [`Repository::has_object`].
/// * `ancestry` — a feature-independent commit-graph walk ([`ancestry_of`]); the `revision` feature
///   (hence `merge_base`) is **not** enabled by the network-client gates, so we walk directly.
/// * `resolve_rev` — always `None` in v1: rev-spec push sources (`HEAD~2:dst`) need
///   [`rev_parse_single`](crate::Repository::rev_parse_single), which is `#[cfg(feature = "revision")]`
///   and unavailable under this gate. gpx07's adapter (which brings `revision` in) wires it; a
///   by-name / by-oid push — every gpx08 acceptance case — never consults it.
/// * `tracking_ref_value` — the remote-tracking ref of a destination under `refs/heads/*`
///   (`refs/remotes/<remote>/<branch>`), for a `Lease::TrackingRef` force-with-lease.
#[allow(clippy::result_large_err)]
fn plan_from_repo(
    repo: &crate::Repository,
    push_refspecs: &[gix_refspec::RefSpec],
    extra_refspecs: &[gix_refspec::RefSpec],
    remote_refs: &[handshake::Ref],
    lease: LeasePolicy,
    remote_name: Option<&str>,
) -> Result<PlannedUpdates, prepare::Error> {
    let local_refs = collect_local_refs(repo)?;
    let head = collect_head(repo);

    let mut has_object = |id: &gix_hash::oid| repo.has_object(id);
    let mut ancestry = |old: &gix_hash::oid, new: &gix_hash::oid| ancestry_of(repo, old, new);
    let mut resolve_rev = |_spec: &crate::bstr::BStr| -> Option<ObjectId> { None };
    let mut tracking_ref_value = |dst: &FullName| -> Option<ObjectId> { tracking_ref_value_of(repo, remote_name, dst) };

    plan::plan_inner(
        push_refspecs,
        extra_refspecs,
        &local_refs,
        head,
        remote_refs,
        lease,
        &mut has_object,
        &mut ancestry,
        &mut resolve_rev,
        &mut tracking_ref_value,
    )
    .map_err(prepare::Error::Plan)
}

/// Snapshot every direct-target local reference as a [`LocalRef`]. Symbolic refs are skipped (their
/// referent is snapshotted on its own). `peeled` is left `None`: it only feeds `match_lhs`'s
/// object-id-needle matching against a tag's peeled target — a fetch-flavoured matching feature no
/// gpx08 case exercises; gpx07's adapter populates it.
#[allow(clippy::result_large_err)]
fn collect_local_refs(repo: &crate::Repository) -> Result<Vec<LocalRef>, prepare::Error> {
    let platform = repo
        .references()
        .map_err(|e| prepare::Error::CollectRefs(Box::new(e)))?;
    let iter = platform.all().map_err(|e| prepare::Error::CollectRefs(Box::new(e)))?;
    let mut out = Vec::new();
    for reference in iter {
        let reference = match reference {
            Ok(r) => r,
            // A single unreadable ref (e.g. a transiently bad loose ref) is skipped, not fatal —
            // the push simply won't offer it, exactly as it wouldn't offer a ref that doesn't exist.
            Err(_) => continue,
        };
        let Some(target) = reference.target().try_id().map(ToOwned::to_owned) else {
            continue; // symbolic ref: its referent is snapshotted separately
        };
        out.push(LocalRef {
            name: reference.name().to_owned(),
            target,
            peeled: None,
        });
    }
    Ok(out)
}

/// Snapshot `HEAD` for the plan: a symbolic HEAD becomes [`HeadState::Symbolic`] (referent + resolved
/// id), a detached HEAD [`HeadState::Detached`], and an unborn HEAD (or any read failure) `None`.
fn collect_head(repo: &crate::Repository) -> Option<HeadState> {
    let head = repo.head().ok()?;
    match head.kind {
        crate::head::Kind::Detached { target, .. } => Some(HeadState::Detached { id: target }),
        crate::head::Kind::Symbolic(referent) => {
            let id = referent.target.try_id()?.to_owned();
            Some(HeadState::Symbolic {
                referent: referent.name,
                id,
            })
        }
        crate::head::Kind::Unborn(_) => None,
    }
}

/// The remote-tracking ref value for a `Lease::TrackingRef` — the permissive v1 recipe (Q5): a
/// destination under `refs/heads/<branch>` maps to `refs/remotes/<remote>/<branch>`. Returns the
/// value that ref currently points at, or `None` when there is no such tracking ref (or no remote
/// name), which surfaces as [`plan::Error::LeaseTrackingRefMissing`].
fn tracking_ref_value_of(repo: &crate::Repository, remote_name: Option<&str>, dst: &FullName) -> Option<ObjectId> {
    use crate::bstr::ByteSlice;
    let remote = remote_name?;
    let branch = dst.as_bstr().to_str().ok()?.strip_prefix("refs/heads/")?;
    let tracking = format!("refs/remotes/{remote}/{branch}");
    let mut reference = repo.try_find_reference(tracking.as_str()).ok()??;
    reference.peel_to_id().ok().map(crate::Id::detach)
}

/// Is `old` an ancestor of `new`? A feature-independent commit-graph walk (no `merge_base`, which the
/// network-client gate does not enable): both must be commits, else ancestry is
/// [`Ancestry::NotComparable`] (⇒ `RejectedNeedsForce`). Walks `new`'s ancestry looking for `old`.
fn ancestry_of(repo: &crate::Repository, old: &gix_hash::oid, new: &gix_hash::oid) -> Ancestry {
    let is_commit = |id: &gix_hash::oid| {
        matches!(
            repo.find_object(id.to_owned()).map(|o| o.kind),
            Ok(gix_object::Kind::Commit)
        )
    };
    if !is_commit(old) || !is_commit(new) {
        return Ancestry::NotComparable;
    }
    if old == new {
        return Ancestry::Ancestor;
    }
    let old = old.to_owned();
    let walk = gix_traverse::commit::Simple::new(Some(new.to_owned()), repo.objects.clone());
    for info in walk {
        match info {
            Ok(info) => {
                if info.id == old {
                    return Ancestry::Ancestor;
                }
            }
            // A traversal error (missing/corrupt commit) means we cannot prove ancestry; treat it as
            // not-an-ancestor rather than panicking — the wire CAS still protects correctness.
            Err(_) => return Ancestry::NotAncestor,
        }
    }
    Ancestry::NotAncestor
}

#[cfg(all(test, feature = "blocking-network-client"))]
mod tests {
    use std::any::Any;
    use std::borrow::Cow;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::AtomicBool;

    use gix_hash::ObjectId;
    use gix_protocol::handshake::Ref;
    use gix_protocol::push::RefUpdate;
    use gix_transport::Service;
    use gix_transport::client::blocking_io::{RequestWriter, SetServiceResponse, Transport};
    use gix_transport::client::{Error as TransportError, MessageKind, TransportWithoutIO, WriteMode};

    use super::*;
    use crate::bstr::{BStr, ByteSlice};

    // ── unit-level fixtures: a wire-silence tripwire transport ──────────────────────────────────

    /// A [`Transport`] whose `request()` PANICS: driving it proves a code path is wire-silent, since
    /// any attempt to open an update-request (the only way push writes bytes) trips the panic. `send()`
    /// short-circuits before `request()` on every wire-silent / pre-wire-refusal path, so a test that
    /// completes without panicking has *proven* zero request bytes were written — the byte-countable
    /// UNIT form of the wire-silence law (design amendment S9).
    struct WireSilenceTripwire;

    impl TransportWithoutIO for WireSilenceTripwire {
        fn to_url(&self) -> Cow<'_, BStr> {
            Cow::Borrowed(b"tripwire://".as_bstr())
        }
        fn connection_persists_across_multiple_requests(&self) -> bool {
            // `false` so `SendFlushOnDrop`'s graceful teardown is a no-op (it only writes a flush for
            // stateful transports) — the Drop path must not touch `request()` either.
            false
        }
        fn configure(&mut self, _config: &dyn Any) -> gix_error::Result<()> {
            Ok(())
        }
    }

    impl Transport for WireSilenceTripwire {
        fn handshake<'a>(
            &mut self,
            _service: Service,
            _extra_parameters: &'a [(&'a str, Option<&'a str>)],
        ) -> Result<SetServiceResponse<'_>, TransportError> {
            unreachable!("prepare_push performs the handshake; send() never re-handshakes")
        }
        fn request(
            &mut self,
            _write_mode: WriteMode,
            _on_into_read: MessageKind,
            _trace: bool,
        ) -> Result<RequestWriter<'_>, TransportError> {
            panic!("send() wrote to the wire on a path that must be wire-silent (zero request bytes)")
        }
    }

    fn oid(n: u8) -> ObjectId {
        ObjectId::from_hex(format!("{n:040x}").as_bytes()).expect("valid sha1 hex")
    }

    fn caps(list: &str) -> gix_transport::client::Capabilities {
        gix_transport::client::Capabilities::from_bytes(format!("\0{list}").as_bytes())
            .expect("valid capabilities")
            .0
    }

    fn handshake(cap_list: &str, refs: Vec<Ref>) -> gix_protocol::Handshake {
        gix_protocol::Handshake {
            server_protocol_version: gix_transport::Protocol::V1,
            refs: Some(refs),
            v1_shallow_updates: None,
            capabilities: caps(cap_list),
        }
    }

    fn empty_remote() -> crate::types::RemoteDetached {
        crate::types::RemoteDetached {
            name: None,
            urls: Vec::new(),
            url_aliases: Vec::new(),
            url_push_aliases: Vec::new(),
            fetch_specs: Vec::new(),
            push_urls: Vec::new(),
            push_url_aliases: Vec::new(),
            push_specs: Vec::new(),
            fetch_tags: Default::default(),
        }
    }

    fn plan_with(updates: Vec<RefUpdate>) -> PlannedUpdates {
        let tips = updates
            .iter()
            .filter_map(|u| match u {
                RefUpdate::Create { new, .. } | RefUpdate::Update { new, .. } => Some(*new),
                RefUpdate::Delete { .. } => None,
            })
            .collect();
        PlannedUpdates {
            mappings: Vec::new(),
            updates,
            tips,
            refspecs: Vec::new(),
            extra_refspecs: Vec::new(),
            remote_refs: Vec::new(),
        }
    }

    /// Build a detached prepare over the tripwire transport with the given plan / handshake / flags.
    fn tripwire_prepare(
        plan: PlannedUpdates,
        hs: gix_protocol::Handshake,
        dry_run: bool,
        atomicity: gix_protocol::push::Atomicity,
    ) -> PrepareDetached<'static, WireSilenceTripwire> {
        let con = ConnectionDetached {
            remote: empty_remote(),
            authenticate: None,
            transport_options: None,
            transport: gix_protocol::SendFlushOnDrop::new(WireSilenceTripwire, false),
            handshake: Some(hs),
            trace: false,
        };
        PrepareDetached {
            con: Some(con),
            plan,
            dry_run,
            atomicity,
            push_options: Vec::new(),
            sideband: false,
            reflog_message: None,
        }
    }

    fn empty_repo() -> (crate::Repository, gix_testtools::tempfile::TempDir) {
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let repo = crate::init(tmp.path()).expect("init repo");
        (repo, tmp)
    }

    // ── wire-silence UNIT law (design amendment S9) ─────────────────────────────────────────────

    #[test]
    fn wire_silence_dry_run_writes_no_request_bytes() {
        let (repo, _tmp) = empty_repo();
        // A non-empty plan that WOULD send, but dry-run makes it wire-silent.
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        let prep = tripwire_prepare(plan, handshake("report-status", vec![]), true, Default::default());
        let out = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect("dry-run send is Ok and wire-silent (the tripwire never fired)");
        assert!(
            matches!(out.status, Status::NothingToPush { dry_run: true, .. }),
            "dry-run yields NothingToPush{{dry_run:true}}, got {:?}",
            out.status
        );
    }

    #[test]
    fn wire_silence_empty_plan_writes_no_request_bytes() {
        // An all-up-to-date / no-mapping plan resolves to zero sendable commands and MUST be silent.
        let (repo, _tmp) = empty_repo();
        let prep = tripwire_prepare(
            plan_with(vec![]),
            handshake("report-status", vec![]),
            false,
            Default::default(),
        );
        let out = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect("empty-plan send is Ok and wire-silent");
        assert!(
            matches!(out.status, Status::NothingToPush { dry_run: false, .. }),
            "an empty plan yields NothingToPush{{dry_run:false}}, got {:?}",
            out.status
        );
    }

    // ── the B10 hash-mismatch gate (pre-wire, byte-provable — fused review #6) ──────────────────

    /// A sha256-advertising server against a sha1 repo refuses with `IncompatibleObjectHash` and
    /// PROVABLY writes zero request bytes (the tripwire transport panics on `request()`).
    #[test]
    fn incompatible_hash_errors_before_any_wire_bytes() {
        let (repo, _tmp) = empty_repo();
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        let prep = tripwire_prepare(
            plan,
            handshake("report-status object-format=sha256", vec![]),
            false,
            Default::default(),
        );
        let err = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect_err("a hash-incompatible remote is refused pre-wire");
        assert!(
            matches!(err, super::super::Error::IncompatibleObjectHash { .. }),
            "the refusal is the friendly IncompatibleObjectHash, got {err:?}"
        );
    }

    /// Fused review #5 (ruling): the zero-byte refusal gates run BEFORE the dry-run short-circuit,
    /// so a dry-run faithfully reports the refusal a real push would hit.
    #[test]
    fn dry_run_still_surfaces_pre_wire_refusals() {
        let (repo, _tmp) = empty_repo();
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        let prep = tripwire_prepare(
            plan,
            handshake("report-status", vec![]),
            true, // dry-run
            gix_protocol::push::Atomicity::Required,
        );
        let err = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect_err("dry-run must still refuse what a real push would refuse");
        assert!(matches!(
            err,
            super::super::Error::MissingServerFeature { feature: "atomic" }
        ));
    }

    // ── the S6 atomicity gate (pre-wire capability refusal) ─────────────────────────────────────

    #[test]
    fn atomic_required_without_server_support_errors_before_any_wire_bytes() {
        let (repo, _tmp) = empty_repo();
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        // Server advertises report-status but NOT atomic; Required must refuse before request().
        let prep = tripwire_prepare(
            plan,
            handshake("report-status", vec![]),
            false,
            gix_protocol::push::Atomicity::Required,
        );
        let err = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect_err("Atomicity::Required against a non-atomic server is refused");
        assert!(
            matches!(err, super::super::Error::MissingServerFeature { feature: "atomic" }),
            "the refusal is a friendly MissingServerFeature, got {err:?}"
        );
    }

    // ── file:// integration (real git-receive-pack), mirroring the gpx04 suite conventions ──────

    fn git(args: &[&str], cwd: &Path) {
        let ok = git_capture(args, cwd).0;
        assert!(ok, "git {args:?} in {} failed", cwd.display());
    }

    /// Run `git args` in `cwd` with a fixed identity/date (deterministic oids); returns
    /// `(success, stdout-trimmed)`.
    fn git_capture(args: &[&str], cwd: &Path) -> (bool, String) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00 +0000")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00 +0000")
            .output()
            .expect("the `git` binary is available");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        )
    }

    /// The oid a ref points at on the served repo (its stored value, unpeeled), or `None` if absent.
    fn server_ref_raw(bare: &Path, refname: &str) -> Option<String> {
        let (ok, out) = git_capture(&["rev-parse", "--verify", "-q", refname], bare);
        ok.then_some(out)
    }

    /// A local work repo with a single commit on `main`, plus an empty bare remote. Returns
    /// `(tempdir, opened local repo, local path, bare path)`.
    fn scenario() -> (
        gix_testtools::tempfile::TempDir,
        crate::Repository,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let bare = root.join("remote.git");
        let local = root.join("local");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        git(&["init", "--bare", "-q"], &bare);
        git(&["init", "-q", "-b", "main"], &local);
        std::fs::write(local.join("f"), "one").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c1"], &local);
        let repo = crate::open_opts(&local, crate::open::Options::isolated()).expect("open local");
        (tmp, repo, local, bare)
    }

    /// Drive `prepare_push().send()` for `specs` with the given options/builder, over `file://bare`.
    fn push(
        repo: &crate::Repository,
        bare: &Path,
        specs: &[&str],
        options: PrepareOptions,
        dry_run: bool,
    ) -> Result<Outcome, PushFailure> {
        let prepared = repo
            .remote_at(bare.to_str().unwrap())
            .expect("valid file:// remote")
            .with_refspecs(specs.iter().copied(), crate::remote::Direction::Push)
            .expect("valid push refspecs")
            .connect(crate::remote::Direction::Push)
            .expect("connect for push")
            .prepare_push(crate::progress::Discard, options)
            .map_err(PushFailure::Prepare)?
            .with_dry_run(dry_run);
        prepared
            .send(crate::progress::Discard, &AtomicBool::new(false))
            .map_err(PushFailure::Send)
    }

    #[derive(Debug)]
    enum PushFailure {
        Prepare(prepare::Error),
        Send(super::super::Error),
    }

    // ── gpx10 push-options + sideband surface ───────────────────────────────────────────────────

    /// A [`NestedProgress`](gix_utils::progress::NestedProgress) that RECORDS what reaches it — the
    /// porcelain twin of the plumbing suite's `CaptureProgress`, proving that a side-band-64k push
    /// routes the server's band-2 (`remote:`) output all the way to the caller's progress sink (via
    /// the plumbing demux's `translate_to_progress` → `set_name` on a "remote" child). Children share
    /// the same event log (clone of the `Arc`), so a band-2 payload recorded on the "remote" child is
    /// observable here.
    #[derive(Clone, Default)]
    struct CaptureProgress {
        events: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl CaptureProgress {
        fn record(&self, kind: &str, text: String) {
            self.events.lock().unwrap().push((kind.to_string(), text));
        }
        /// `true` iff any recorded event text (of any kind) contains `needle`.
        fn any_text_contains(&self, needle: &str) -> bool {
            self.events.lock().unwrap().iter().any(|(_, t)| t.contains(needle))
        }
    }

    impl gix_utils::progress::Count for CaptureProgress {
        fn set(&self, _step: usize) {}
        fn step(&self) -> usize {
            0
        }
        fn inc_by(&self, _step: usize) {}
        fn counter(&self) -> gix_utils::progress::StepShared {
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::default())
        }
    }

    impl gix_utils::progress::Progress for CaptureProgress {
        fn init(&mut self, _max: Option<usize>, _unit: Option<gix_utils::progress::Unit>) {}
        fn set_max(&mut self, _max: Option<usize>) -> Option<usize> {
            None
        }
        fn set_name(&mut self, name: String) {
            self.record("name", name);
        }
        fn name(&self) -> Option<String> {
            None
        }
        fn id(&self) -> gix_utils::progress::Id {
            gix_utils::progress::UNKNOWN
        }
        fn message(&self, level: gix_utils::progress::MessageLevel, message: String) {
            self.record(&format!("msg:{level:?}"), message);
        }
    }

    impl gix_utils::progress::NestedProgress for CaptureProgress {
        type SubProgress = Self;
        fn add_child(&mut self, _name: impl Into<String>) -> Self {
            self.clone()
        }
        fn add_child_with_id(&mut self, _name: impl Into<String>, _id: gix_utils::progress::Id) -> Self {
            self.clone()
        }
    }

    /// Drive `prepare_push().send()` over `file://bare`, optionally overriding the push-options via the
    /// builder (`None` leaves the `push.pushOption` config default in place — the C-git "no
    /// `--push-option` on the command line" case) and toggling sideband, with a caller-supplied
    /// `progress` sink for the send.
    fn push_send<P>(
        repo: &crate::Repository,
        bare: &Path,
        specs: &[&str],
        push_options: Option<Vec<BString>>,
        sideband: bool,
        progress: P,
    ) -> Result<Outcome, PushFailure>
    where
        P: gix_utils::progress::NestedProgress,
        P::SubProgress: 'static,
    {
        let mut prepared = repo
            .remote_at(bare.to_str().unwrap())
            .expect("valid file:// remote")
            .with_refspecs(specs.iter().copied(), crate::remote::Direction::Push)
            .expect("valid push refspecs")
            .connect(crate::remote::Direction::Push)
            .expect("connect for push")
            .prepare_push(crate::progress::Discard, Default::default())
            .map_err(PushFailure::Prepare)?
            .with_sideband(sideband);
        if let Some(options) = push_options {
            prepared = prepared.with_push_options(options);
        }
        prepared
            .send(progress, &AtomicBool::new(false))
            .map_err(PushFailure::Send)
    }

    /// Make `path` executable (0o755) — a git hook must be runnable.
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// Install an executable `hooks/<name>` in the bare repo with the given `#!/bin/sh` body.
    fn install_hook(bare: &Path, name: &str, body: &str) {
        let hook = bare.join("hooks").join(name);
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, body).unwrap();
        make_executable(&hook);
    }

    // ── unit: the MissingServerFeature gates are friendly AND byte-provably wire-silent ─────────

    #[test]
    fn push_options_without_server_support_errors_before_any_wire_bytes() {
        let (repo, _tmp) = empty_repo();
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        // Server advertises report-status but NOT push-options; requesting one must refuse pre-wire.
        let mut prep = tripwire_prepare(plan, handshake("report-status", vec![]), false, Default::default());
        prep.push_options = vec!["opt".into()];
        let err = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect_err("push-options against a non-advertising server is refused");
        assert!(
            matches!(
                err,
                super::super::Error::MissingServerFeature {
                    feature: "push-options"
                }
            ),
            "the refusal is the friendly porcelain MissingServerFeature, got {err:?}"
        );
    }

    #[test]
    fn sideband_without_server_support_errors_before_any_wire_bytes() {
        let (repo, _tmp) = empty_repo();
        let plan = plan_with(vec![RefUpdate::Create {
            name: gix_ref::FullName::try_from("refs/heads/x").unwrap(),
            new: oid(1),
        }]);
        // Server advertises report-status but NOT side-band-64k; opting in must refuse pre-wire.
        let mut prep = tripwire_prepare(plan, handshake("report-status", vec![]), false, Default::default());
        prep.sideband = true;
        let err = prep
            .send(&repo, crate::progress::Discard, &AtomicBool::new(false))
            .expect_err("sideband against a non-advertising server is refused");
        assert!(
            matches!(
                err,
                super::super::Error::MissingServerFeature {
                    feature: "side-band-64k"
                }
            ),
            "the refusal is the friendly porcelain MissingServerFeature, got {err:?}"
        );
    }

    #[test]
    fn create_round_trips_and_reports_pushed() {
        let (_tmp, repo, local, bare) = scenario();
        let (_ok, head) = git_capture(&["rev-parse", "HEAD"], &local);

        let out = push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("push ok");
        match out.status {
            Status::Pushed { report, write_pack, .. } => {
                assert_eq!(report.refs.len(), 1, "one command reported");
                assert!(
                    matches!(report.unpack_status, gix_protocol::push::UnpackStatus::Ok),
                    "server unpacked the pack"
                );
                let wp = write_pack.expect("a create sends a pack");
                assert!(
                    wp.object_count >= 3,
                    "commit + tree + blob at least, got {}",
                    wp.object_count
                );
            }
            other => panic!("expected Pushed, got {other:?}"),
        }
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/main"),
            Some(head),
            "the server ref now points at HEAD"
        );
    }

    /// gpx08 fuse residual: `with_atomic(WhenAdvertised)` ("atomic if available") against a real
    /// `git-receive-pack` — which DOES advertise `atomic` — negotiates it and the push succeeds
    /// (`Pushed`). The positive path complementing gpx08's `Required`-without-support refusal unit
    /// (S6): `WhenAdvertised` is the silent-downgrade policy, so here it upgrades and applies cleanly.
    #[test]
    fn atomic_when_advertised_pushes_against_an_atomic_server() {
        let (_tmp, repo, local, bare) = scenario();
        let (_ok, head) = git_capture(&["rev-parse", "HEAD"], &local);
        let out = repo
            .remote_at(bare.to_str().unwrap())
            .expect("valid file:// remote")
            .with_refspecs(["refs/heads/main:refs/heads/main"], crate::remote::Direction::Push)
            .expect("valid push refspecs")
            .connect(crate::remote::Direction::Push)
            .expect("connect for push")
            .prepare_push(crate::progress::Discard, Default::default())
            .expect("prepare ok")
            .with_atomic(gix_protocol::push::Atomicity::WhenAdvertised)
            .send(crate::progress::Discard, &AtomicBool::new(false))
            .expect("an atomic-capable server accepts the WhenAdvertised push");
        // Pin the precondition the test name claims: the server DID advertise `atomic`, so the
        // WhenAdvertised path actually negotiated it (fused review #2; true client-sent-cap
        // verification would need a spy transport this layer can't observe).
        assert!(
            out.handshake.capabilities.contains("atomic"),
            "the server advertised the atomic capability the WhenAdvertised push relies on"
        );
        match out.status {
            Status::Pushed { report, .. } => {
                assert!(
                    matches!(report.unpack_status, gix_protocol::push::UnpackStatus::Ok),
                    "the atomic push unpacked"
                );
                assert!(
                    matches!(report.refs[0], gix_protocol::push::RefUpdateStatus::Ok { .. }),
                    "the single ref was applied atomically"
                );
            }
            other => panic!("expected Pushed, got {other:?}"),
        }
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/main"),
            Some(head),
            "the atomic push landed on the server"
        );
    }

    #[test]
    fn fast_forward_update_moves_the_server_ref() {
        let (_tmp, repo, local, bare) = scenario();
        push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("initial push");
        std::fs::write(local.join("f"), "two").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c2"], &local);
        let (_ok, head2) = git_capture(&["rev-parse", "HEAD"], &local);

        let out = push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("ff push");
        assert!(matches!(out.status, Status::Pushed { .. }));
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/main"),
            Some(head2),
            "the server ref fast-forwarded"
        );
    }

    #[test]
    fn delete_round_trip_removes_the_server_ref_and_sends_no_pack() {
        let (_tmp, repo, local, bare) = scenario();
        git(&["branch", "topic"], &local);
        push(
            &repo,
            &bare,
            &["refs/heads/topic:refs/heads/topic"],
            Default::default(),
            false,
        )
        .expect("seed topic");
        assert!(
            server_ref_raw(&bare, "refs/heads/topic").is_some(),
            "topic seeded on the server"
        );

        let out = push(&repo, &bare, &[":refs/heads/topic"], Default::default(), false).expect("delete push");
        match out.status {
            Status::Pushed { write_pack, report, .. } => {
                assert!(write_pack.is_none(), "a delete-only push sends no pack");
                assert!(matches!(report.refs[0], gix_protocol::push::RefUpdateStatus::Ok { .. }));
            }
            other => panic!("expected Pushed, got {other:?}"),
        }
        assert!(
            server_ref_raw(&bare, "refs/heads/topic").is_none(),
            "the server ref is gone"
        );
    }

    #[test]
    fn dry_run_is_wire_silent_and_touches_nothing() {
        let (_tmp, repo, _local, bare) = scenario();
        let out = push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            true,
        )
        .expect("dry-run ok");
        assert!(
            matches!(out.status, Status::NothingToPush { dry_run: true, .. }),
            "dry-run yields NothingToPush{{dry_run:true}}, got {:?}",
            out.status
        );
        assert!(
            server_ref_raw(&bare, "refs/heads/main").is_none(),
            "dry-run created nothing on the server"
        );
    }

    #[test]
    fn non_fast_forward_without_force_is_rejected_locally_and_is_wire_silent() {
        let (_tmp, repo, local, bare) = scenario();
        // main: c1 -> c2 on the server.
        std::fs::write(local.join("f"), "two").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c2"], &local);
        push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("seed c2");
        let (_ok, c2) = git_capture(&["rev-parse", "HEAD"], &local);
        // A branch parked at c1 (an ancestor of the server tip) — pushing it onto main is a rewind.
        git(&["branch", "rewind", "HEAD~1"], &local);

        let out = push(
            &repo,
            &bare,
            &["refs/heads/rewind:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("a locally-rejected push is Ok (wire-silent), not Err");
        assert!(
            matches!(out.status, Status::NothingToPush { dry_run: false, .. }),
            "no sendable command ⇒ wire-silent NothingToPush, got {:?}",
            out.status
        );
        let mapping = out
            .plan
            .mappings
            .iter()
            .find(|m| m.remote.as_bstr() == b"refs/heads/main".as_bstr());
        assert_eq!(
            mapping.map(|m| m.verdict),
            Some(super::super::plan::Verdict::RejectedNonFastForward),
            "the mapping carries the local non-ff pre-verdict"
        );
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/main"),
            Some(c2),
            "the server tip is untouched"
        );
    }

    #[test]
    fn stale_exact_lease_aborts_at_prepare_time() {
        let (_tmp, repo, local, bare) = scenario();
        push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect("seed main");
        std::fs::write(local.join("f"), "two").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c2"], &local);

        // Lease against a value the server does NOT advertise ⇒ StaleLease before any wire byte.
        let options = PrepareOptions::default().with_force_with_lease(super::super::plan::Lease::Exact(oid(7)));
        let err = push(&repo, &bare, &["refs/heads/main:refs/heads/main"], options, false)
            .expect_err("a stale exact lease aborts the push");
        match err {
            PushFailure::Prepare(prepare::Error::Plan(super::super::plan::Error::StaleLease { .. })) => {}
            other => panic!("expected a prepare-time StaleLease, got {other:?}"),
        }
    }

    #[test]
    fn annotated_tag_round_trips_object_and_peel() {
        let (_tmp, repo, local, bare) = scenario();
        git(&["tag", "-a", "v1", "-m", "annotated v1"], &local);
        let (_ok, tag_oid) = git_capture(&["rev-parse", "v1"], &local);
        let (_ok, peeled) = git_capture(&["rev-parse", "v1^{}"], &local);
        assert_ne!(tag_oid, peeled, "v1 is a real annotated-tag OBJECT");

        let out = push(&repo, &bare, &["refs/tags/v1:refs/tags/v1"], Default::default(), false).expect("tag push");
        assert!(matches!(out.status, Status::Pushed { .. }));
        assert_eq!(
            server_ref_raw(&bare, "refs/tags/v1"),
            Some(tag_oid),
            "the server tag ref stores the TAG object oid (never the peeled commit)"
        );
        let (_ok, server_peeled) = git_capture(&["rev-parse", "refs/tags/v1^{}"], &bare);
        assert_eq!(server_peeled, peeled, "the tag peels to the same commit on the server");
    }

    #[test]
    fn multi_ref_mixed_ok_and_server_ng_is_data_not_err() {
        let (_tmp, repo, local, bare) = scenario();
        // Seed a ref to delete, then forbid deletions server-side so the delete comes back as `ng`.
        git(&["branch", "keep"], &local);
        push(
            &repo,
            &bare,
            &["refs/heads/keep:refs/heads/keep"],
            Default::default(),
            false,
        )
        .expect("seed keep");
        git(&["config", "receive.denyDeletes", "true"], &bare);
        let (_ok, keep_oid) = git_capture(&["rev-parse", "refs/heads/keep"], &local);

        // One create (server ok) + one delete of `keep` (server ng: denyDeletes) in a single push.
        let out = push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/fresh", ":refs/heads/keep"],
            Default::default(),
            false,
        )
        .expect("a per-ref server rejection is DATA, so the push itself is Ok");
        let report = match out.status {
            Status::Pushed { report, .. } => report,
            other => panic!("expected Pushed, got {other:?}"),
        };
        let mut oks = 0usize;
        let mut ngs = 0usize;
        for r in &report.refs {
            match r {
                gix_protocol::push::RefUpdateStatus::Ok { .. } => oks += 1,
                gix_protocol::push::RefUpdateStatus::Rejected { name, .. } => {
                    ngs += 1;
                    assert_eq!(
                        name.as_bstr(),
                        b"refs/heads/keep".as_bstr(),
                        "the delete is the rejected ref"
                    );
                }
            }
        }
        assert_eq!(
            (oks, ngs),
            (1, 1),
            "one ok (create) and one ng (delete) reported per-ref"
        );
        assert!(
            server_ref_raw(&bare, "refs/heads/fresh").is_some(),
            "the accepted create landed"
        );
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/keep"),
            Some(keep_oid),
            "the rejected delete left the ref in place"
        );
    }

    #[test]
    fn interrupt_mid_push_fails_and_leaves_the_server_ref_absent() {
        let (_tmp, repo, _local, bare) = scenario();
        let interrupt = AtomicBool::new(true); // pre-tripped: the pack driver bails before writing.
        let result = repo
            .remote_at(bare.to_str().unwrap())
            .expect("remote")
            .with_refspecs(["refs/heads/main:refs/heads/main"], crate::remote::Direction::Push)
            .expect("specs")
            .connect(crate::remote::Direction::Push)
            .expect("connect")
            .prepare_push(crate::progress::Discard, Default::default())
            .expect("prepare ok")
            .send(crate::progress::Discard, &interrupt);
        assert!(
            matches!(
                result,
                Err(crate::remote::connection::push::Error::Pack(
                    crate::remote::connection::push::pack::Error::Interrupted
                ))
            ),
            "the interrupt surfaces as the TYPED pack error, not an erased WritePack box (review #2): {result:?}"
        );
        assert!(
            server_ref_raw(&bare, "refs/heads/main").is_none(),
            "the server never applied the ref (no complete pack arrived)"
        );
    }

    // ── real-server (file://): push-options reach the receive-pack hooks (mirrors the plumbing
    //    m3feat `push_options_reach_receive_pack_hook`) ────────────────────────────────────────────

    /// The `#!/bin/sh` pre-receive hook that dumps every `GIT_PUSH_OPTION_*` (one per line) into
    /// `push-options-seen` at the bare repo root — the empirical proof of what receive-pack decoded.
    const DUMP_PUSH_OPTIONS_HOOK: &str = "#!/bin/sh\n\
         out=\"$(pwd)/push-options-seen\"\n\
         : > \"$out\"\n\
         n=${GIT_PUSH_OPTION_COUNT:-0}\n\
         i=0\n\
         while [ \"$i\" -lt \"$n\" ]; do\n\
         v=$(eval echo \"\\$GIT_PUSH_OPTION_$i\")\n\
         printf '%s\\n' \"$v\" >> \"$out\"\n\
         i=$((i+1))\n\
         done\n\
         exit 0\n";

    /// End-to-end over a real `git-receive-pack`: the push-options set via `with_push_options` reach
    /// the server's pre-receive hook verbatim and in order — proving our porcelain threads them into
    /// the plumbing Options and the wire framing is what receive-pack decodes. Mirrors the plumbing
    /// m3feat suite, one layer up.
    #[test]
    fn push_options_reach_receive_pack_hook() {
        let (_tmp, repo, _local, bare) = scenario();
        git(&["config", "receive.advertisePushOptions", "true"], &bare);
        install_hook(&bare, "pre-receive", DUMP_PUSH_OPTIONS_HOOK);
        let (_ok, head) = git_capture(&["rev-parse", "HEAD"], &_local);

        let result = push_send(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Some(vec!["opt-one".into(), "key=val".into()]),
            false,
            crate::progress::Discard,
        );
        let out = match result {
            Ok(out) => out,
            Err(PushFailure::Send(super::super::Error::MissingServerFeature {
                feature: "push-options",
            })) => {
                eprintln!("skipping: host git-receive-pack does not advertise push-options");
                return;
            }
            Err(other) => panic!("push failed: {other:?}"),
        };
        assert!(matches!(out.status, Status::Pushed { .. }), "the push landed");
        assert_eq!(
            server_ref_raw(&bare, "refs/heads/main"),
            Some(head),
            "the ref was created at HEAD"
        );

        let seen = std::fs::read_to_string(bare.join("push-options-seen")).expect("hook recorded options");
        assert_eq!(
            seen.lines().collect::<Vec<_>>(),
            vec!["opt-one", "key=val"],
            "the server's hook saw our push-options verbatim and in order"
        );
    }

    /// The `push.pushOption` config default flows into the push when the `with_push_options` builder
    /// is NOT called (C-git: config options apply when the command line names none), and the builder
    /// OVERRIDES the config when it is. One scenario, two pushes, proving both halves of the ingestion.
    #[test]
    fn push_pushoption_config_default_reaches_hook_and_builder_overrides() {
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let bare = root.join("remote.git");
        let local = root.join("local");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        git(&["init", "--bare", "-q"], &bare);
        git(&["config", "receive.advertisePushOptions", "true"], &bare);
        install_hook(&bare, "pre-receive", DUMP_PUSH_OPTIONS_HOOK);
        git(&["init", "-q", "-b", "main"], &local);
        std::fs::write(local.join("f"), "one").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c1"], &local);
        // Open the pushing repo with `push.pushOption` configured (the config-default source).
        let repo = crate::open_opts(
            &local,
            crate::open::Options::isolated().config_overrides([
                "push.pushOption=cfg-alpha".to_string(),
                "push.pushOption=cfg-beta".to_string(),
            ]),
        )
        .expect("open local with push.pushOption");

        // (1) No builder override → the config defaults reach the hook, in order.
        match push_send(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            None,
            false,
            crate::progress::Discard,
        ) {
            Ok(out) => assert!(matches!(out.status, Status::Pushed { .. })),
            Err(PushFailure::Send(super::super::Error::MissingServerFeature {
                feature: "push-options",
            })) => {
                eprintln!("skipping: host git-receive-pack does not advertise push-options");
                return;
            }
            Err(other) => panic!("config-default push failed: {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(bare.join("push-options-seen"))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            vec!["cfg-alpha", "cfg-beta"],
            "the push.pushOption config defaults reached the hook when no builder override was set"
        );

        // (2) A builder override REPLACES the config defaults (git's --push-option suppresses config).
        git(&["branch", "topic"], &local);
        push_send(
            &repo,
            &bare,
            &["refs/heads/topic:refs/heads/topic"],
            Some(vec!["override-only".into()]),
            false,
            crate::progress::Discard,
        )
        .expect("override push");
        assert_eq!(
            std::fs::read_to_string(bare.join("push-options-seen"))
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            vec!["override-only"],
            "with_push_options replaced the config defaults, not appended to them"
        );
    }

    // ── real-server (file://): a side-band-64k push routes the server's band-2 (`remote:`) output
    //    to the caller's NestedProgress (the porcelain twin of the plumbing m3feat band-2 proof) ────

    /// End-to-end over a real `git-receive-pack`: with `with_sideband(true)` the server multiplexes
    /// its response, and a pre-receive hook's stderr (delivered on band 2) reaches the caller's
    /// [`NestedProgress`] through the plumbing demux — proven by a `CaptureProgress` recording the
    /// hook's marker. Self-skips if the host receive-pack does not advertise `side-band-64k`.
    #[test]
    fn sideband_routes_remote_hook_output_to_progress() {
        let (_tmp, repo, _local, bare) = scenario();
        // A pre-receive hook whose stderr the server forwards on band 2 when sideband is negotiated.
        install_hook(
            &bare,
            "pre-receive",
            "#!/bin/sh\necho 'PORCELAIN_SIDEBAND_MARKER' >&2\nexit 0\n",
        );
        let capture = CaptureProgress::default();

        let result = push_send(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            None,
            true,
            capture.clone(),
        );
        let out = match result {
            Ok(out) => out,
            Err(PushFailure::Send(super::super::Error::MissingServerFeature {
                feature: "side-band-64k",
            })) => {
                eprintln!("skipping: host git-receive-pack does not advertise side-band-64k");
                return;
            }
            Err(other) => panic!("sideband push failed: {other:?}"),
        };
        assert!(
            matches!(out.status, Status::Pushed { .. }),
            "the sideband-wrapped report demuxed and the push landed: {:?}",
            out.status
        );
        assert!(
            capture.any_text_contains("PORCELAIN_SIDEBAND_MARKER"),
            "the server's band-2 hook output reached the caller's progress sink"
        );
    }

    /// SHA-256 remote against a SHA-1 local repo ⇒ a friendly `IncompatibleObjectHash` before any
    /// wire bytes. Gated on the `sha256` feature: the `gix_hash::Kind::Sha256` variant (and thus the
    /// friendly re-map) only exists when it is compiled in — the same self-skip discipline the
    /// plumbing suite uses for its sha256 laws. Also self-skips if the local `git` predates
    /// `--object-format`.
    #[cfg(feature = "sha256")]
    #[test]
    fn sha256_remote_is_incompatible_object_hash() {
        let tmp = gix_testtools::tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let bare = root.join("remote.git");
        let local = root.join("local");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::create_dir_all(&local).unwrap();
        if !git_capture(&["init", "--bare", "-q", "--object-format=sha256", "."], &bare).0 {
            eprintln!("skipping: this git does not support --object-format=sha256");
            return;
        }
        git(&["init", "-q", "-b", "main"], &local); // sha1 local (the default)
        std::fs::write(local.join("f"), "one").unwrap();
        git(&["add", "f"], &local);
        git(&["commit", "-q", "-m", "c1"], &local);
        let repo = crate::open_opts(&local, crate::open::Options::isolated()).expect("open local");

        let err = push(
            &repo,
            &bare,
            &["refs/heads/main:refs/heads/main"],
            Default::default(),
            false,
        )
        .expect_err("a sha256 remote is refused");
        assert!(
            matches!(
                err,
                PushFailure::Send(super::super::Error::IncompatibleObjectHash {
                    local: gix_hash::Kind::Sha1,
                    ..
                })
            ),
            "the refusal is a friendly IncompatibleObjectHash, got {err:?}"
        );
    }

    // ── gpx11: the `Prepare::handshake()` capability accessor ───────────────────────────────────

    /// After `prepare_push` over a real `file://` `git-receive-pack`, `Prepare::handshake()` exposes
    /// the server's advertised capabilities — the accessor the sideband when-advertised default (gpx12)
    /// reads before `send()`. `report-status` is always advertised by git; `side-band-64k`/`atomic`
    /// capability probes resolve (git advertises both, but the assertion is on the *probe working*, not
    /// on a specific server's cap set). Reads capabilities, not refs (moved into the plan).
    #[test]
    fn prepare_push_exposes_handshake_capabilities() {
        let (_tmp, repo, _local, bare) = scenario();
        let prepared = repo
            .remote_at(bare.to_str().unwrap())
            .expect("valid file:// remote")
            .with_refspecs(["refs/heads/main:refs/heads/main"], crate::remote::Direction::Push)
            .expect("valid push refspecs")
            .connect(crate::remote::Direction::Push)
            .expect("connect for push")
            .prepare_push(crate::progress::Discard, Default::default())
            .expect("prepare ok");
        let handshake = prepared.handshake();
        assert!(
            handshake.capabilities.contains("report-status"),
            "git-receive-pack always advertises report-status"
        );
        // The capability probes the gpx12 sideband/atomic negotiation relies on resolve without panic
        // (advertised or not); a real git-receive-pack advertises both.
        assert!(
            handshake.capabilities.contains("side-band-64k"),
            "git-receive-pack advertises side-band-64k (the when-advertised sideband probe)"
        );
        assert!(
            handshake.capabilities.contains("atomic"),
            "git-receive-pack advertises atomic (the atomic capability probe)"
        );
    }
}
