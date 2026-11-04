use gix::bstr::BString;

use crate::OutputFormat;

pub struct Options {
    pub format: OutputFormat,
    pub dry_run: bool,
    /// The remote name or URL to push to; `None` resolves via the §1.2 defaulting chain. Plain
    /// `Option<String>` like fetch's `remote` (the §1.2 resolver wants a `&str`), never `AsBString`.
    pub remote: Option<String>,
    /// If non-empty, override the ref-specs otherwise configured on the remote (mirror of fetch).
    pub ref_specs: Vec<BString>,
    /// Rewrite every effective spec to its `+`-form (`--force`), §1.3.
    pub force: bool,
    /// `--force-with-lease`: pin the expected remote value to the local tracking ref (bare form).
    pub force_with_lease: bool,
    /// `--atomic`: require the `atomic` capability.
    pub atomic: bool,
    /// `--no-atomic`: disable atomic, overriding a `push.atomic=true` config seed.
    pub no_atomic: bool,
    /// `-o/--push-option`, repeatable and in order; replaces the `push.pushOption` config seed.
    pub push_options: Vec<BString>,
    /// `--sideband`/`--no-sideband` tri-state: `None` = default (when-advertised, §2.4), `Some(true)`
    /// forces it on (may fail `MissingServerFeature`), `Some(false)` forces it off.
    pub sideband: Option<bool>,
    /// `-H/--handshake-info`: print the `Outcome.handshake` debug block, fetch parity.
    pub handshake_info: bool,
    /// `-u/--set-upstream` (gpx17): after a successful send, write `branch.<n>.{remote,merge}` for
    /// every qualifying branch mapping (RATIFY-8). Composes with every other flag.
    pub set_upstream: bool,
}

pub const PROGRESS_RANGE: std::ops::RangeInclusive<u8> = 1..=3;

pub(crate) mod function {
    use gix::{
        Result,
        bstr::{BString, ByteSlice},
        error::{ErrorExt, ResultExt, bail, message},
    };

    use super::Options;
    use crate::OutputFormat;

    pub fn push<P>(
        repo: gix::Repository,
        mut progress: P,
        mut out: impl std::io::Write,
        mut err: impl std::io::Write,
        Options {
            format,
            dry_run,
            remote,
            ref_specs,
            force,
            force_with_lease,
            atomic,
            no_atomic,
            push_options,
            sideband,
            handshake_info,
            set_upstream,
        }: Options,
    ) -> Result<()>
    where
        P: gix::NestedProgress,
        P::SubProgress: 'static,
    {
        // The requested atomic policy, reported in the JSON `atomic` field (§2.2). We report the
        // flag-level intent — the config seed (`push.atomic`) is read inside `prepare_push` and the CLI
        // must not re-read it (§"Config seeding"), so a bare push labels its policy `when-advertised`.
        #[cfg(feature = "serde")]
        let atomic_label = if no_atomic {
            "disabled"
        } else if atomic {
            "required"
        } else {
            "when-advertised"
        };

        // gpx17: keep the verbatim `--remote` argument — the resolver below shadows `remote`, and for
        // an unnamed (URL) remote the upstream config value is the URL the user actually typed
        // (RATIFY-12), falling back to the resolved push url when the remote came from defaulting.
        let verbatim_remote = remote.clone();
        let mut remote = by_name_or_url_for_push(&repo, remote.as_deref())?;
        // Refspec resolution (§1.3/§1.4): explicit args override the configured specs (mirror of
        // fetch); `--force` rewrites each *effective* spec to its `+`-form before handing them over.
        let effective_specs: Option<Vec<BString>> = if !ref_specs.is_empty() {
            Some(if force { force_rewrite(&ref_specs) } else { ref_specs })
        } else if force {
            // No explicit args: rewrite the remote's *configured* push specs in place.
            let configured: Vec<BString> = remote
                .refspecs(gix::remote::Direction::Push)
                .iter()
                .map(|spec| spec.to_ref().to_bstring())
                .collect();
            Some(force_rewrite(&configured))
        } else {
            None
        };
        if let Some(specs) = effective_specs {
            remote.replace_refspecs(specs.iter(), gix::remote::Direction::Push)?;
        }

        let remote_name = remote.name().map(|n| n.as_bstr().to_string());
        let push_url = remote
            .url(gix::remote::Direction::Push)
            .map_or_else(|| BString::from("<unknown>"), gix::Url::to_bstring);

        let mut prepare_options = gix::remote::push::PrepareOptions::default();
        if force_with_lease {
            prepare_options = prepare_options.with_force_with_lease(gix::remote::push::Lease::TrackingRef);
        }

        let prepared = remote
            .connect(gix::remote::Direction::Push)?
            .prepare_push(&mut progress, prepare_options)
            .map_err(|e| map_prepare_error(e, remote_name.as_deref(), push_url.as_bstr()))?;

        let mut prepared = prepared.with_dry_run(dry_run);
        // Atomicity: only override the config-seeded default when a flag was given (§1.1).
        if no_atomic {
            prepared = prepared.with_atomic(gix::remote::push::Atomicity::Disabled);
        } else if atomic {
            prepared = prepared.with_atomic(gix::remote::push::Atomicity::Required);
        }
        if !push_options.is_empty() {
            prepared = prepared.with_push_options(push_options);
        }
        // Sideband (§2.4): forced on/off, or default to when-advertised via the gpx11 handshake accessor.
        let sideband_on = match sideband {
            Some(enabled) => enabled,
            None => prepared.handshake().capabilities.contains("side-band-64k"),
        };
        let prepared = prepared.with_sideband(sideband_on);

        // Route side-band-64k band-2 (`remote:`) output: record it while still delegating the rest of
        // progress to the real sink, then replay it on stderr after the send (so the per-ref table on
        // stdout stays clean). Verbose mode still shows the progress tree via the delegated inner sink.
        let remote_messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let capture = RemoteCapture {
            inner: progress,
            messages: std::sync::Arc::clone(&remote_messages),
            is_remote: false,
        };
        let outcome = prepared
            .send(capture, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| map_push_error(e, remote_name.as_deref(), push_url.as_bstr()))?;

        let messages = remote_messages.lock().expect("no panic while sending").clone();

        // gpx17: `-u/--set-upstream` — qualify, write, and report BEFORE rendering so the JSON
        // document can carry the outcome (RATIFY-13). The write happens here, after `send()` returned
        // `Ok` and before the exit decision, so a partially-rejected push (exit 1) still records
        // upstream for its qualifying branches (git's per-ref loop). The prepared connection consumed
        // its borrow of `repo` inside `send`, so `repo.common_dir()` is callable again.
        let upstream_edits = if set_upstream {
            upstream::qualifying(&outcome)
        } else {
            Vec::new()
        };
        let upstream_remote: BString = match &remote_name {
            Some(name) => name.as_str().into(),
            None => verbatim_remote.map_or_else(|| push_url.clone(), BString::from),
        };
        let upstream_write_error: Option<String> = {
            let to_write: Vec<&upstream::Edit> = upstream_edits.iter().filter(|e| !e.would).collect();
            if to_write.is_empty() {
                None
            } else {
                let config_path = repo.common_dir().join("config");
                upstream::write_config(&config_path, upstream_remote.as_bstr(), &to_write)
                    .err()
                    .map(|e| format!("to {} failed: {e:#}", config_path.display()))
            }
        };

        // Output: the per-ref table (human) or the JSON document (§2.2) on stdout; notes on stderr in
        // both. The exit decision (§2.3) is identical for both formats.
        match format {
            OutputFormat::Human => {
                if handshake_info {
                    writeln!(out, "Handshake Information").or_error()?;
                    writeln!(out, "\t{:?}", outcome.handshake).or_error()?;
                }
                for line in &messages {
                    writeln!(err, "remote: {line}").or_error()?;
                }
                write_human_table(&mut out, push_url.as_bstr(), &outcome).or_error()?;
            }
            #[cfg(feature = "serde")]
            OutputFormat::Json => {
                if handshake_info {
                    // stdout is reserved for the document, so the handshake block goes to stderr.
                    writeln!(err, "Handshake Information").or_error()?;
                    writeln!(err, "\t{:?}", outcome.handshake).or_error()?;
                }
                let su = set_upstream.then(|| {
                    (
                        upstream_edits.as_slice(),
                        upstream_remote.as_bstr(),
                        upstream_write_error.as_deref(),
                    )
                });
                write_json_document(&mut out, atomic_label, push_url.as_bstr(), &outcome, messages, su)?;
            }
        }
        write_notes(&mut err, &outcome).or_error()?;
        // gpx17: the per-branch upstream notes follow the pack-stat line (RATIFY-11: stderr). A write
        // failure suppresses the success lines and — after everything is rendered — forces exit 1
        // (RATIFY-10, house `UpdateRefs` parity; a deliberate deviation from git's exit 0).
        upstream::write_upstream_notes(
            &mut err,
            upstream_remote.as_bstr(),
            &upstream_edits,
            upstream_write_error.as_deref(),
        )
        .or_error()?;
        Report::from_outcome(&outcome).into_result()?;
        if upstream_write_error.is_some() {
            bail!("the push was accepted by the server, but writing upstream configuration failed");
        }
        Ok(())
    }

    /// Resolve the remote to push to — the push twin of
    /// [`by_name_or_url`](crate::repository::remote::by_name_or_url), i.e. the body of gix's
    /// `find_fetch_remote` with `Direction::Fetch` swapped to `Direction::Push` in the two `None`
    /// branches (§1.2). A gitoxide-core-local helper; promoting it to a `gix::Repository::find_push_remote`
    /// twin beside `find_fetch_remote` is a clean upstream follow-up (RATIFY notes / §1.2).
    pub(crate) fn by_name_or_url_for_push<'repo>(
        repo: &'repo gix::Repository,
        name_or_url: Option<&str>,
    ) -> Result<gix::Remote<'repo>> {
        use gix::remote::Direction::Push;
        Ok(match name_or_url {
            Some(name) => match repo.try_find_remote(name).and_then(std::result::Result::ok) {
                Some(remote) => remote,
                None => repo.remote_at(gix::url::parse(name)?)?,
            },
            None => repo
                .head()?
                .into_remote(Push)
                .transpose()?
                .map(Ok)
                .or_else(|| repo.find_default_remote(Push))
                .ok_or_else(|| {
                    message(
                        "no remote found to push to — set 'remote.pushDefault', configure a remote, or pass --remote",
                    )
                    .not_found()
                    .raise()
                })??,
        })
    }

    /// Rewrite each spec to its `+`-form (`--force`, §1.3): prefix `+` to every spec that does not
    /// already start with `+` and is not a negative spec (`^…` must stay bare — `+^…` is invalid).
    /// Idempotent: an already-`+`-prefixed spec is left untouched.
    pub(crate) fn force_rewrite(specs: &[BString]) -> Vec<BString> {
        specs
            .iter()
            .map(|spec| {
                if spec.first() == Some(&b'+') || spec.first() == Some(&b'^') {
                    spec.clone()
                } else {
                    let mut forced = BString::from("+");
                    forced.extend_from_slice(spec);
                    forced
                }
            })
            .collect()
    }

    /// gpx17 `-u/--set-upstream`: qualification, the locked config write, and the stderr notes.
    /// CLI-only — the porcelain never touches `branch.*` (hard constraint).
    pub(crate) mod upstream {
        use gix::bstr::{BStr, BString, ByteSlice};
        use gix::error::ResultExt;

        /// One qualifying branch mapping: the config edit to make (or that WOULD be made under
        /// `--dry-run`), plus the names the stderr/JSON reporting needs.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub(crate) struct Edit {
            /// The full local ref name (`refs/heads/<short>`).
            pub local: BString,
            /// The shortened local branch name — the `branch.<short>.*` subsection.
            pub short: BString,
            /// The full destination refname — the `branch.<short>.merge` value (RATIFY-8; a rename
            /// records the *destination*, so `merge` may differ from `refs/heads/<short>`).
            pub merge: BString,
            /// The shortened destination name, for the `'<remote>/<dst>'` message text.
            pub dst_short: BString,
            /// `true` under `--dry-run`: report `Would set upstream`, write nothing.
            pub would: bool,
        }

        /// The qualifying mappings of a push outcome (RATIFY-14): a local-branch source pushed to a
        /// branch destination, not a delete, whose per-ref mode proves the update durably landed —
        /// `UpToDate` (up-to-date pushes still set upstream, git parity), `TrackingRefUpdated`, or
        /// `TrackingRefSkipped` (the tracking-ref side is bookkeeping, the server applied the push).
        /// **Plain `Ok` is deliberately EXCLUDED** [ratified: RATIFY-14, settled by code]: for a
        /// branch-shaped non-delete mapping it is only reachable under global suppression (unpack
        /// failure / atomic rollback), i.e. the update did NOT land. The `match` is wildcard-free so
        /// a new `Mode` variant breaks the build here, not the semantics.
        pub(crate) fn qualifying(outcome: &gix::remote::push::Outcome) -> Vec<Edit> {
            use gix::refs::Category;
            use gix::remote::push::refs::Mode;
            use gix::remote::push::{Source, Status};
            let dry_run = matches!(&outcome.status, Status::NothingToPush { dry_run: true, .. });
            let update_refs = match &outcome.status {
                Status::NothingToPush { update_refs, .. } | Status::Pushed { update_refs, .. } => update_refs,
            };
            outcome
                .plan
                .mappings
                .iter()
                .zip(update_refs.updates.iter())
                .filter_map(|(mapping, update)| {
                    let name = match mapping.local.as_ref()? {
                        Source::Ref { name, .. } => name,
                        // A raw object-id or detached-HEAD source has no branch to configure (the
                        // plan pre-resolves a born symbolic HEAD to its branch, so `Detached` really
                        // is detached).
                        Source::ObjectId(_) | Source::Detached { .. } => return None,
                    };
                    if !matches!(name.category(), Some(Category::LocalBranch)) {
                        return None;
                    }
                    // Branch-shaped destination + non-delete (`new` present).
                    if !matches!(mapping.remote.category(), Some(Category::LocalBranch)) {
                        return None;
                    }
                    mapping.new?;
                    let would = match &update.mode {
                        Mode::DryRun => true,
                        // `UpToDate` under a dry-run outcome is still only a would-set.
                        Mode::UpToDate => dry_run,
                        Mode::TrackingRefUpdated | Mode::TrackingRefSkipped(_) => false,
                        // RATIFY-14: `Ok` here means suppressed/rolled-back — not durably applied.
                        Mode::Ok | Mode::RejectedByServer { .. } | Mode::RejectedLocal(_) | Mode::CorrelationGap => {
                            return None;
                        }
                    };
                    Some(Edit {
                        local: name.as_bstr().to_owned(),
                        short: name.as_ref().shorten().to_owned(),
                        merge: mapping.remote.as_bstr().to_owned(),
                        dst_short: mapping.remote.as_ref().shorten().to_owned(),
                        would,
                    })
                })
                .collect()
        }

        /// Write `branch.<short>.{remote,merge}` for every edit into `config_path` — the in-tree
        /// locked-overwrite recipe [ratified: RATIFY-15, settled by code], mirroring clone's
        /// `reinitialize_with_object_hash`. NOT `config_snapshot_mut` (its `commit` is memory-only),
        /// NOT `new_section` (duplicates a pre-existing `[branch "<n>"]` stanza), NOT
        /// `write_to_local_config` (non-truncating — corrupts on a shrinking rewrite).
        /// `set_raw_value_by` overwrites-or-creates, so the write is idempotent; all edits share one
        /// lock, so the file mutation is all-or-nothing.
        pub(crate) fn write_config(
            config_path: &std::path::Path,
            remote_value: &BStr,
            edits: &[&Edit],
        ) -> gix::Result<()> {
            let mut file =
                gix::config::File::from_path_no_includes(config_path.to_owned(), gix::config::Source::Local)?;
            for edit in edits {
                file.set_raw_value_by("branch", Some(edit.short.as_bstr()), "remote", remote_value)?;
                file.set_raw_value_by("branch", Some(edit.short.as_bstr()), "merge", edit.merge.as_bstr())?;
            }
            let mut lock = gix::lock::File::acquire_to_update_resource(
                config_path,
                gix::lock::acquire::Fail::Immediately,
                None,
                0,
            )?;
            file.write_to_filter(&mut lock, |s| s.meta().source == gix::config::Source::Local)
                .or_error()?;
            lock.commit().or_error()?;
            Ok(())
        }

        /// The per-branch stderr notes (RATIFY-11), after the pack-stat line: git's
        /// `branch '<short>' set up to track '<remote>/<dst>'.` wording per written branch, the
        /// no-period `Would set upstream of '<src>' to '<dst>' of '<remote>'` line per dry-run
        /// branch, and — on a failed write — ONE error line with every success line suppressed
        /// (never claim a write that did not land).
        pub(crate) fn write_upstream_notes(
            mut err: impl std::io::Write,
            remote_value: &BStr,
            edits: &[Edit],
            write_error: Option<&str>,
        ) -> std::io::Result<()> {
            for edit in edits.iter().filter(|e| e.would) {
                writeln!(
                    err,
                    "Would set upstream of '{src}' to '{dst}' of '{remote_value}'",
                    src = edit.short,
                    dst = edit.dst_short,
                )?;
            }
            let written: Vec<&Edit> = edits.iter().filter(|e| !e.would).collect();
            if written.is_empty() {
                return Ok(());
            }
            match write_error {
                Some(msg) => writeln!(
                    err,
                    "error: the push was accepted by the server, but writing upstream configuration {msg}"
                )?,
                None => {
                    for edit in written {
                        writeln!(
                            err,
                            "branch '{short}' set up to track '{remote_value}/{dst}'.",
                            short = edit.short,
                            dst = edit.dst_short,
                        )?;
                    }
                }
            }
            Ok(())
        }
    }

    /// The disposition text for one mapping (§4.3): a wildcard-free `match` over the per-ref
    /// [`Mode`](gix::remote::push::refs::Mode) so a new variant breaks the build, not the output. The
    /// verb (for the modes that carry one) comes from the mapping's plan [`Verdict`].
    pub(crate) fn disposition(mode: &gix::remote::push::refs::Mode, verdict: &gix::remote::push::Verdict) -> String {
        use gix::remote::push::Verdict;
        use gix::remote::push::refs::{Mode, SkipReason};
        let verb = verb_of(verdict);
        match mode {
            Mode::UpToDate => "up to date".into(),
            Mode::DryRun => format!("dry-run: would {verb}"),
            Mode::Ok => "ok".into(),
            Mode::TrackingRefUpdated => format!("{verb}, tracking ref updated"),
            Mode::TrackingRefSkipped(reason) => {
                let why = match reason {
                    SkipReason::NotABranch => "not a branch",
                    SkipReason::NoMatchingFetchSpec => "no fetch spec",
                    SkipReason::SymbolicTrackingRef => "symbolic",
                };
                format!("{verb} (no tracking ref: {why})")
            }
            Mode::RejectedByServer { reason, .. } => format!("rejected by server: {reason}"),
            Mode::RejectedLocal(verdict) => match verdict {
                Verdict::RejectedNonFastForward => {
                    "rejected: non-fast-forward (fetch first, or use '+<spec>'/--force)".into()
                }
                Verdict::RejectedFetchFirst => {
                    "rejected: remote value unknown locally — run 'gix fetch <remote>' first".into()
                }
                Verdict::RejectedAlreadyExists => "rejected: tag already exists on the remote".into(),
                Verdict::RejectedNeedsForce => "rejected: not a commit update — requires '+<spec>'/--force".into(),
                // The non-rejected verdicts never appear inside `RejectedLocal`; name them explicitly so
                // the outer match stays wildcard-free and a plan-verdict rename breaks the build.
                Verdict::Create | Verdict::FastForward | Verdict::Forced | Verdict::Delete | Verdict::UpToDate => {
                    "rejected".into()
                }
            },
            Mode::CorrelationGap => "no server status received (report truncated?)".into(),
        }
    }

    /// The C-git-style verb for a mapping's plan [`Verdict`], used by the `DryRun`/`TrackingRef*`
    /// dispositions (§4.3). The `Rejected*`/`UpToDate` verdicts never reach a verb-using mode.
    fn verb_of(verdict: &gix::remote::push::Verdict) -> &'static str {
        use gix::remote::push::Verdict;
        match verdict {
            Verdict::Create => "create",
            Verdict::FastForward => "fast-forward",
            Verdict::Forced => "force",
            Verdict::Delete => "delete",
            Verdict::UpToDate
            | Verdict::RejectedAlreadyExists
            | Verdict::RejectedFetchFirst
            | Verdict::RejectedNeedsForce
            | Verdict::RejectedNonFastForward => "update",
        }
    }

    /// The exit decision (§2.3): how many mappings were refused (local or server), out of how many, and
    /// whether the server failed to unpack the pack. `into_result` renders the final `Err` (exit 1).
    pub(crate) struct Report {
        rejected: usize,
        total: usize,
        unpack_failed: bool,
    }

    impl Report {
        /// Compute the exit decision from a push outcome — format-independent (§2.3): human and JSON
        /// mode share this, so `-f json` never changes the exit code.
        pub(crate) fn from_outcome(outcome: &gix::remote::push::Outcome) -> Report {
            let update_refs = update_refs_of(outcome);
            let rejected = update_refs.updates.iter().filter(|u| is_rejected(&u.mode)).count();
            Report {
                rejected,
                total: update_refs.updates.len(),
                unpack_failed: unpack_failed(outcome),
            }
        }

        pub(crate) fn into_result(self) -> Result<()> {
            if self.unpack_failed {
                bail!("push failed: the server could not unpack the sent pack");
            }
            if self.rejected > 0 {
                bail!(
                    "push rejected: {} of {} ref update(s) refused",
                    self.rejected,
                    self.total
                );
            }
            Ok(())
        }
    }

    /// The per-mapping tracking-ref bookkeeping of a push outcome (present on both `Status` variants).
    fn update_refs_of(outcome: &gix::remote::push::Outcome) -> &gix::remote::push::refs::update::Outcome {
        use gix::remote::push::Status;
        match &outcome.status {
            Status::NothingToPush { update_refs, .. } | Status::Pushed { update_refs, .. } => update_refs,
        }
    }

    /// Whether the server failed to unpack the pack (`unpack <err>`), forcing exit 1 (§4.3 trailer).
    fn unpack_failed(outcome: &gix::remote::push::Outcome) -> bool {
        use gix::remote::push::{Status, UnpackStatus};
        matches!(
            &outcome.status,
            Status::Pushed { report, .. } if matches!(report.unpack_status, UnpackStatus::Failed(_))
        )
    }

    /// Human render (§2.1): the `To <url>` headline + the spec-grouped per-ref table on `out`. Mirrors
    /// the *structure* of fetch's `print_updates` with the three sanctioned enrichments (the `To <url>`
    /// headline, the `<old>..<new>` oid range, and the `*`/`-` create/delete markers). Stderr notes are
    /// [`write_notes`]; the exit decision is [`Report::from_outcome`].
    pub(crate) fn write_human_table(
        mut out: impl std::io::Write,
        url: &gix::bstr::BStr,
        outcome: &gix::remote::push::Outcome,
    ) -> std::io::Result<()> {
        writeln!(out, "To {url}")?;
        let plan = &outcome.plan;
        let update_refs = update_refs_of(outcome);
        let mut last_spec: Option<gix::remote::push::plan::SpecIndex> = None;
        for (mapping, update) in plan.mappings.iter().zip(update_refs.updates.iter()) {
            if last_spec != Some(mapping.spec_index) {
                last_spec = Some(mapping.spec_index);
                if let Some(spec) = mapping.spec_index.get(&plan.refspecs, &plan.extra_refspecs) {
                    spec.to_ref().write_to(&mut out)?;
                    writeln!(out)?;
                }
            }
            write_mapping_line(&mut out, mapping, update)?;
        }
        Ok(())
    }

    /// The non-ref notes on stderr (§2.1), emitted in both human and JSON mode: the unpack-failure
    /// error, the `DRY-RUN:` trailer, `Everything up-to-date`, and the pack stat line.
    pub(crate) fn write_notes(
        mut err: impl std::io::Write,
        outcome: &gix::remote::push::Outcome,
    ) -> std::io::Result<()> {
        use gix::remote::push::{Status, UnpackStatus};
        let (report, write_pack, dry_run) = match &outcome.status {
            Status::NothingToPush { dry_run, .. } => (None, None, *dry_run),
            Status::Pushed { report, write_pack, .. } => (Some(report), write_pack.as_ref(), false),
        };
        if let Some(UnpackStatus::Failed(msg)) = report.map(|r| &r.unpack_status) {
            writeln!(err, "error: the server failed to unpack the sent pack: {msg}")?;
        }
        let rejected = update_refs_of(outcome).updates.iter().any(|u| is_rejected(&u.mode));
        if dry_run {
            writeln!(err, "DRY-RUN: No ref was updated on the remote.")?;
        } else if matches!(outcome.status, Status::NothingToPush { .. }) && !rejected {
            writeln!(err, "Everything up-to-date")?;
        }
        if report.is_some() {
            match write_pack {
                Some(stats) => writeln!(err, "sent pack: {} objects", stats.object_count)?,
                None => writeln!(err, "no pack needed (delete-only)")?,
            }
        }
        Ok(())
    }

    /// The human render + notes + exit decision in one call (the gpx12 unit entry point). Human mode's
    /// `push()` inlines these three; JSON mode swaps [`write_human_table`] for the DTO writer.
    #[cfg(test)]
    pub(crate) fn write_report(
        out: impl std::io::Write,
        err: impl std::io::Write,
        url: &gix::bstr::BStr,
        outcome: &gix::remote::push::Outcome,
    ) -> Result<Report> {
        write_human_table(out, url, outcome).or_error()?;
        write_notes(err, outcome).or_error()?;
        Ok(Report::from_outcome(outcome))
    }

    /// Whether a per-ref [`Mode`](gix::remote::push::refs::Mode) counts as a rejection for the exit
    /// decision (§2.3): a local pre-verdict rejection, a server `ng`, or a correlation gap.
    fn is_rejected(mode: &gix::remote::push::refs::Mode) -> bool {
        use gix::remote::push::refs::Mode;
        matches!(
            mode,
            Mode::RejectedLocal(_) | Mode::RejectedByServer { .. } | Mode::CorrelationGap
        )
    }

    /// One tab-indented per-ref line (§2.1): the `<old>..<new>` range (or `*`/`-` marker), the
    /// `<src> -> <dst>` endpoints, and the `[<disposition>]` tail.
    fn write_mapping_line(
        mut out: impl std::io::Write,
        mapping: &gix::remote::push::Mapping,
        update: &gix::remote::push::refs::Update,
    ) -> std::io::Result<()> {
        let disp = disposition(&update.mode, &mapping.verdict);
        let dst = mapping.remote.as_ref().shorten();
        match (mapping.advertised, mapping.new) {
            // Delete: no source, `-` marker.
            (_, None) => writeln!(out, "\t- {dst} [{disp}]"),
            // Create: no advertised old value, `*` marker.
            (None, Some(_)) => {
                let src = source_name(mapping.local.as_ref());
                writeln!(out, "\t* {src} -> {dst} [{disp}]")
            }
            // Update / up-to-date: `<old>..<new>` range.
            (Some(old), Some(new)) => {
                let src = source_name(mapping.local.as_ref());
                writeln!(
                    out,
                    "\t{old}..{new} {src} -> {dst} [{disp}]",
                    old = old.to_hex_with_len(7),
                    new = new.to_hex_with_len(7)
                )
            }
        }
    }

    /// The `<src>` column: the shortened local ref name, a short oid for an object-id source, or
    /// `HEAD` for a detached-HEAD source (§2.1). Empty for a delete (no local side).
    fn source_name(local: Option<&gix::remote::push::Source>) -> String {
        use gix::remote::push::Source;
        match local {
            Some(Source::Ref { name, .. }) => name.as_ref().shorten().to_string(),
            Some(Source::ObjectId(id)) => id.to_hex_with_len(7).to_string(),
            Some(Source::Detached { .. }) => "HEAD".to_string(),
            None => String::new(),
        }
    }

    /// Map a `prepare_push` failure to a CLI-facing error (§4.1): actionable variants gain a hint or a
    /// connection/handshake context via `.context`, the rest surface their verbatim library message.
    fn map_prepare_error(
        err: gix::remote::push::prepare::Error,
        remote_name: Option<&str>,
        url: &gix::bstr::BStr,
    ) -> gix::Error {
        use gix::remote::push::prepare::Error;
        match err {
            // FC3: name the `remote.<name>.push` config key only when the remote actually has a name;
            // an anonymous URL-remote has no such key to configure.
            Error::MissingRefSpecs => match remote_name {
                Some(remote) => message!(
                    "nothing to push: no ref-specs given and none configured for remote {remote:?}\n\
                     hint: pass a ref-spec (e.g. 'gix push refs/heads/main'), or configure remote.{remote}.push\n\
                     hint: expansion of 'push.default' is not yet supported by gix"
                )
                .validation()
                .raise(),
                None => message!(
                    "nothing to push: no ref-specs given and none configured for the remote\n\
                     hint: pass a ref-spec (e.g. 'gix push refs/heads/main')\n\
                     hint: expansion of 'push.default' is not yet supported by gix"
                )
                .validation()
                .raise(),
            },
            Error::Plan(gix::remote::push::plan::Error::StaleLease { .. }) => {
                err.and_raise(message("hint: run 'gix fetch <remote>' and re-inspect before forcing"))
            }
            // §4.1: the connection-setup variants say which url we could not reach.
            Error::GatherTransportConfig { .. } | Error::ConfigureTransport(_) | Error::ConfigureCredentials(_) => {
                err.and_raise(message!("failed to set up the connection to {url}"))
            }
            Error::Handshake(_) => err.and_raise(message!("could not talk to {url} (receive-pack handshake failed)")),
            Error::MissingRefAdvertisement { .. } | Error::Plan(_) | Error::CollectRefs(_) | Error::AtomicConfig(_) => {
                gix::Error::from_error(err)
            }
        }
    }

    /// Map a `send` failure to a CLI-facing error (§4.2): `MissingServerFeature` gets the actionable
    /// per-feature hint naming the flag to drop; `UpdateRefs` says the push *was* applied server-side;
    /// the connection/protocol/pack variants gain a §4.2 context; the rest surface verbatim.
    fn map_push_error(err: gix::remote::push::Error, _remote_name: Option<&str>, url: &gix::bstr::BStr) -> gix::Error {
        use gix::remote::push::Error;
        match &err {
            Error::MissingServerFeature { feature } => {
                let hint = match *feature {
                    "atomic" => "the server does not advertise atomic pushes — retry without --atomic",
                    "push-options" => {
                        "the server does not advertise push-options — retry without -o/--push-option (also check push.pushOption config)"
                    }
                    "side-band-64k" => "the server does not advertise side-band-64k — retry with --no-sideband",
                    other => return err.and_raise(message!("missing server feature: {other}")),
                };
                err.and_raise(message(hint))
            }
            Error::UpdateRefs(_) => err.and_raise(message(
                "the push was accepted by the server, but updating local tracking refs failed — \
                 run 'gix fetch <remote>' to resynchronize",
            )),
            Error::Client(_) => err.and_raise(message!("connection to {url} failed during the push")),
            Error::Push(_) => err.and_raise(message("the server ended the push unexpectedly")),
            Error::Pack(_) | Error::OpenObjectStore(_) => err.and_raise(message(
                "failed to build the pack to send (local object database problem)",
            )),
            _ => gix::Error::from_error(err),
        }
    }

    /// Write the `-f json` document to `out` (gpx14, §2.2). JSON is only available when
    /// gitoxide-core's `serde` feature is on (the binary's `pretty-cli` enables it); without it
    /// `OutputFormat::Json` does not exist, exactly as for fetch.
    #[cfg(feature = "serde")]
    fn write_json_document(
        mut out: impl std::io::Write,
        atomic_label: &str,
        url: &gix::bstr::BStr,
        outcome: &gix::remote::push::Outcome,
        messages: Vec<String>,
        set_upstream: Option<(&[upstream::Edit], &gix::bstr::BStr, Option<&str>)>,
    ) -> Result<()> {
        let set_upstream = set_upstream.map(|(edits, remote, error)| json::set_upstream_of(edits, remote, error));
        let doc = json::to_document(url, atomic_label, outcome, messages, set_upstream);
        serde_json::to_writer_pretty(&mut out, &doc).or_error()?;
        writeln!(out).or_error()?;
        Ok(())
    }

    /// The `-f json` serde DTO (§2.2) — a CLI-local projection of the push [`Outcome`], so the fork's
    /// gix types never carry serde derives. snake_case fields, full oids, one `updates[]` entry per plan
    /// mapping (the plan-driven left-join guarantees one status per mapping), plus `remote_messages[]`.
    #[cfg(feature = "serde")]
    mod json {
        use serde::{Deserialize, Serialize};

        use super::verb_of;

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct Document {
            pub url: String,
            pub dry_run: bool,
            pub atomic: String,
            pub nothing_to_push: bool,
            /// `null` in `NothingToPush` (no pack was sent, so there is no unpack status).
            pub unpack: Option<Unpack>,
            /// `null` in `NothingToPush` or a delete-only push (no pack written).
            pub pack: Option<Pack>,
            pub updates: Vec<Update>,
            /// side-band-64k band-2 lines; empty unless sideband was negotiated.
            pub remote_messages: Vec<String>,
            /// gpx17 (RATIFY-13): the `-u/--set-upstream` outcome — the one atomic config write plus
            /// its per-branch detail. `null` when the flag is off.
            pub set_upstream: Option<SetUpstream>,
        }

        /// The top-level `-u/--set-upstream` envelope (RATIFY-13): the write is ONE atomic
        /// all-or-nothing action, so its success (`written`) and its single failure (`error`) live
        /// here — a per-`Update` field could not honestly represent either (nor the dry-run
        /// `would-set` state). Per-branch detail lives in `branches[]`.
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct SetUpstream {
            /// Whether the config write happened and succeeded. `false` under `--dry-run`, when no
            /// branch qualified, or when the write failed (see `error`).
            pub written: bool,
            /// The write failure, if any (the push itself was already accepted).
            pub error: Option<String>,
            pub branches: Vec<UpstreamBranch>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct UpstreamBranch {
            /// The full local ref name.
            pub local: String,
            /// The `branch.<short>.*` subsection written.
            pub short: String,
            /// The `branch.<short>.remote` value: the remote name, or the verbatim URL for an
            /// unnamed remote (RATIFY-12).
            pub remote: String,
            /// The `branch.<short>.merge` value (the full destination refname).
            pub merge: String,
            /// `"set"` (written) or `"would-set"` (`--dry-run`).
            pub state: String,
        }

        pub(super) fn set_upstream_of(
            edits: &[super::upstream::Edit],
            remote: &gix::bstr::BStr,
            error: Option<&str>,
        ) -> SetUpstream {
            let wrote_any = edits.iter().any(|e| !e.would);
            SetUpstream {
                written: wrote_any && error.is_none(),
                error: error.map(ToOwned::to_owned),
                branches: edits
                    .iter()
                    .map(|e| UpstreamBranch {
                        local: e.local.to_string(),
                        short: e.short.to_string(),
                        remote: remote.to_string(),
                        merge: e.merge.to_string(),
                        state: if e.would { "would-set" } else { "set" }.to_string(),
                    })
                    .collect(),
            }
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct Unpack {
            pub ok: bool,
            pub error: Option<String>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct Pack {
            pub written_objects: u32,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct Src {
            pub kind: String,
            pub name: Option<String>,
            pub id: String,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
        pub(super) struct Update {
            pub spec: Option<String>,
            pub src: Option<Src>,
            pub dst: String,
            pub old: Option<String>,
            pub new: Option<String>,
            pub force: String,
            pub status: String,
            pub detail: Option<String>,
            pub tracking_ref: Option<String>,
        }

        pub(super) fn to_document(
            url: &gix::bstr::BStr,
            atomic_label: &str,
            outcome: &gix::remote::push::Outcome,
            messages: Vec<String>,
            set_upstream: Option<SetUpstream>,
        ) -> Document {
            use gix::remote::push::{Status, UnpackStatus};
            let (unpack, pack, dry_run) = match &outcome.status {
                Status::NothingToPush { dry_run, .. } => (None, None, *dry_run),
                Status::Pushed { report, write_pack, .. } => {
                    let unpack = match &report.unpack_status {
                        UnpackStatus::Ok => Unpack { ok: true, error: None },
                        UnpackStatus::Failed(msg) => Unpack {
                            ok: false,
                            error: Some(msg.to_string()),
                        },
                    };
                    let pack = write_pack.as_ref().map(|stats| Pack {
                        written_objects: stats.object_count,
                    });
                    (Some(unpack), pack, false)
                }
            };
            let nothing_to_push = matches!(outcome.status, Status::NothingToPush { .. });
            let plan = &outcome.plan;
            let update_refs = super::update_refs_of(outcome);
            let updates = plan
                .mappings
                .iter()
                .zip(update_refs.updates.iter())
                .map(|(mapping, update)| {
                    let spec = mapping
                        .spec_index
                        .get(&plan.refspecs, &plan.extra_refspecs)
                        .map(|s| s.to_ref().to_bstring().to_string());
                    let (status, detail) = status_and_detail(mapping, update, update_refs);
                    Update {
                        spec,
                        src: src_of(mapping.local.as_ref()),
                        dst: mapping.remote.as_bstr().to_string(),
                        old: mapping.advertised.map(|id| id.to_hex().to_string()),
                        new: mapping.new.map(|id| id.to_hex().to_string()),
                        force: force_of(&mapping.force).to_string(),
                        status,
                        detail,
                        tracking_ref: tracking_ref_of(update, update_refs),
                    }
                })
                .collect();
            Document {
                url: url.to_string(),
                dry_run,
                atomic: atomic_label.to_string(),
                nothing_to_push,
                unpack,
                pack,
                updates,
                remote_messages: messages,
                set_upstream,
            }
        }

        fn force_of(force: &gix::remote::push::Force) -> &'static str {
            use gix::remote::push::Force;
            match force {
                Force::No => "no",
                Force::SpecForce => "spec",
                Force::LeaseHeld => "lease-held",
            }
        }

        fn src_of(local: Option<&gix::remote::push::Source>) -> Option<Src> {
            use gix::remote::push::Source;
            match local? {
                Source::Ref { name, id } => Some(Src {
                    kind: "ref".into(),
                    name: Some(name.as_bstr().to_string()),
                    id: id.to_hex().to_string(),
                }),
                Source::ObjectId(id) => Some(Src {
                    kind: "object".into(),
                    name: None,
                    id: id.to_hex().to_string(),
                }),
                Source::Detached { id } => Some(Src {
                    kind: "detached".into(),
                    name: None,
                    id: id.to_hex().to_string(),
                }),
            }
        }

        /// The `refs/remotes/<remote>/*` tracking ref moved for this mapping, if any — the name of the
        /// edit `update.edit_index` points at (only [`Mode::TrackingRefUpdated`] carries one).
        fn tracking_ref_of(
            update: &gix::remote::push::refs::Update,
            update_refs: &gix::remote::push::refs::update::Outcome,
        ) -> Option<String> {
            let edit = update_refs.edits.get(update.edit_index?)?;
            Some(edit.name.as_bstr().to_string())
        }

        /// The §4.3 JSON `status` string (produced by exactly one [`Mode`]) and its `detail` — a
        /// wildcard-free `match`, so a new `Mode` variant breaks the build, not the machine contract.
        fn status_and_detail(
            mapping: &gix::remote::push::Mapping,
            update: &gix::remote::push::refs::Update,
            update_refs: &gix::remote::push::refs::update::Outcome,
        ) -> (String, Option<String>) {
            use gix::remote::push::Verdict;
            use gix::remote::push::refs::{Mode, SkipReason};
            match &update.mode {
                Mode::UpToDate => ("up-to-date".into(), None),
                Mode::DryRun => ("dry-run".into(), Some(verb_of(&mapping.verdict).to_string())),
                Mode::Ok => ("ok".into(), None),
                Mode::TrackingRefUpdated => ("tracking-ref-updated".into(), tracking_ref_of(update, update_refs)),
                Mode::TrackingRefSkipped(reason) => {
                    let why = match reason {
                        SkipReason::NotABranch => "not a branch",
                        SkipReason::NoMatchingFetchSpec => "no fetch spec",
                        SkipReason::SymbolicTrackingRef => "symbolic",
                    };
                    ("tracking-ref-skipped".into(), Some(why.into()))
                }
                Mode::RejectedByServer { reason, .. } => ("rejected-by-server".into(), Some(reason.to_string())),
                Mode::RejectedLocal(verdict) => {
                    let detail = match verdict {
                        Verdict::RejectedNonFastForward => "non-fast-forward",
                        Verdict::RejectedFetchFirst => "fetch-first",
                        Verdict::RejectedAlreadyExists => "already-exists",
                        Verdict::RejectedNeedsForce => "needs-force",
                        Verdict::Create
                        | Verdict::FastForward
                        | Verdict::Forced
                        | Verdict::Delete
                        | Verdict::UpToDate => "rejected",
                    };
                    ("rejected-local".into(), Some(detail.into()))
                }
                Mode::CorrelationGap => ("correlation-gap".into(), None),
            }
        }
    }

    /// A [`NestedProgress`](gix::NestedProgress) that records side-band-64k band-2 (`remote:`) text
    /// while delegating everything else to an inner sink. Band 2 arrives on a child named `remote`
    /// (the plumbing demux routes it there via `RemoteProgress::translate_to_progress`); the child's
    /// `set_name`/`message` text is captured into `messages` for post-send replay (`remote:` lines on
    /// stderr in human mode, `remote_messages[]` in JSON) without dropping the delegated progress tree.
    struct RemoteCapture<P> {
        inner: P,
        messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        is_remote: bool,
    }

    impl<P> RemoteCapture<P> {
        fn record(&self, text: &str) {
            if self.is_remote && !text.is_empty() {
                self.messages
                    .lock()
                    .expect("no panic while recording")
                    .push(text.to_owned());
            }
        }
    }

    impl<P: gix::progress::Count> gix::progress::Count for RemoteCapture<P> {
        fn set(&self, step: usize) {
            self.inner.set(step);
        }
        fn step(&self) -> usize {
            self.inner.step()
        }
        fn inc_by(&self, step: usize) {
            self.inner.inc_by(step);
        }
        fn counter(&self) -> gix::progress::StepShared {
            self.inner.counter()
        }
    }

    impl<P: gix::Progress> gix::Progress for RemoteCapture<P> {
        fn init(&mut self, max: Option<usize>, unit: Option<gix::progress::Unit>) {
            self.inner.init(max, unit);
        }
        fn set_max(&mut self, max: Option<usize>) -> Option<usize> {
            self.inner.set_max(max)
        }
        fn set_name(&mut self, name: String) {
            self.record(&name);
            self.inner.set_name(name);
        }
        fn name(&self) -> Option<String> {
            self.inner.name()
        }
        fn id(&self) -> gix::progress::Id {
            self.inner.id()
        }
        fn message(&self, level: gix::progress::MessageLevel, message: String) {
            self.record(&message);
            self.inner.message(level, message);
        }
    }

    impl<P: gix::NestedProgress> gix::NestedProgress for RemoteCapture<P>
    where
        P::SubProgress: 'static,
    {
        type SubProgress = RemoteCapture<P::SubProgress>;
        fn add_child(&mut self, name: impl Into<String>) -> Self::SubProgress {
            let name = name.into();
            let is_remote = name == "remote";
            RemoteCapture {
                inner: self.inner.add_child(name),
                messages: std::sync::Arc::clone(&self.messages),
                is_remote,
            }
        }
        fn add_child_with_id(&mut self, name: impl Into<String>, id: gix::progress::Id) -> Self::SubProgress {
            let name = name.into();
            let is_remote = name == "remote";
            RemoteCapture {
                inner: self.inner.add_child_with_id(name, id),
                messages: std::sync::Arc::clone(&self.messages),
                is_remote,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use gix::bstr::{BStr, BString, ByteSlice};
        use gix::hash::ObjectId;
        use gix::remote::push::plan::{PlannedUpdates, SpecIndex};
        use gix::remote::push::refs::update::{Outcome as UpdateOutcome, Update};
        use gix::remote::push::refs::{Mode, SkipReason};
        use gix::remote::push::{Force, Mapping, Outcome, Source, Status, Verdict};

        use super::*;

        // ── canned-value constructors (all fields public; no network, no git) ────────────────────

        /// An oid whose short (7-hex) form is `prefix`, right-padded with zeros to a full sha1.
        fn oid(prefix: &str) -> ObjectId {
            ObjectId::from_hex(format!("{prefix:0<40}").as_bytes()).expect("valid sha1 hex")
        }

        fn full(name: &str) -> gix::refs::FullName {
            gix::refs::FullName::try_from(name).expect("valid full ref name")
        }

        fn push_spec(s: &str) -> gix::refspec::RefSpec {
            gix::refspec::parse(BStr::new(s), gix::refspec::parse::Operation::Push)
                .expect("valid push refspec")
                .to_owned()
        }

        fn handshake(caps: &str) -> gix::protocol::Handshake {
            gix::protocol::Handshake {
                server_protocol_version: gix::protocol::transport::Protocol::V1,
                refs: None,
                v1_shallow_updates: None,
                capabilities: gix::protocol::transport::client::Capabilities::from_bytes(
                    format!("\0{caps}").as_bytes(),
                )
                .expect("valid caps")
                .0,
            }
        }

        fn report(unpack: gix::remote::push::UnpackStatus) -> gix::protocol::push::Outcome {
            gix::protocol::push::Outcome {
                unpack_status: unpack,
                refs: Vec::new(),
                server_protocol_version: gix::protocol::transport::Protocol::V1,
            }
        }

        /// Render a canned outcome and return `(stdout, stderr, Report)`.
        fn render(outcome: &Outcome) -> (String, String, Report) {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let report = write_report(&mut out, &mut err, b"file:///x".as_bstr(), outcome).expect("render ok");
            (String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap(), report)
        }

        // ── (a) exhaustive Mode → disposition table ──────────────────────────────────────────────

        #[test]
        fn disposition_table_is_exhaustive_and_matches_the_spec() {
            assert_eq!(disposition(&Mode::UpToDate, &Verdict::UpToDate), "up to date");
            assert_eq!(disposition(&Mode::DryRun, &Verdict::Create), "dry-run: would create");
            assert_eq!(
                disposition(&Mode::DryRun, &Verdict::FastForward),
                "dry-run: would fast-forward"
            );
            assert_eq!(disposition(&Mode::DryRun, &Verdict::Forced), "dry-run: would force");
            assert_eq!(disposition(&Mode::DryRun, &Verdict::Delete), "dry-run: would delete");
            assert_eq!(disposition(&Mode::Ok, &Verdict::Delete), "ok");
            assert_eq!(
                disposition(&Mode::TrackingRefUpdated, &Verdict::FastForward),
                "fast-forward, tracking ref updated"
            );
            assert_eq!(
                disposition(&Mode::TrackingRefSkipped(SkipReason::NotABranch), &Verdict::Create),
                "create (no tracking ref: not a branch)"
            );
            assert_eq!(
                disposition(
                    &Mode::TrackingRefSkipped(SkipReason::NoMatchingFetchSpec),
                    &Verdict::FastForward
                ),
                "fast-forward (no tracking ref: no fetch spec)"
            );
            assert_eq!(
                disposition(
                    &Mode::TrackingRefSkipped(SkipReason::SymbolicTrackingRef),
                    &Verdict::Forced
                ),
                "force (no tracking ref: symbolic)"
            );
            assert_eq!(
                disposition(
                    &Mode::RejectedByServer {
                        reason: "some prose".into(),
                        class: gix::remote::push::RefRejectReason::NonFastForward,
                    },
                    &Verdict::FastForward,
                ),
                "rejected by server: some prose"
            );
            assert_eq!(
                disposition(
                    &Mode::RejectedLocal(Verdict::RejectedNonFastForward),
                    &Verdict::RejectedNonFastForward
                ),
                "rejected: non-fast-forward (fetch first, or use '+<spec>'/--force)"
            );
            assert_eq!(
                disposition(
                    &Mode::RejectedLocal(Verdict::RejectedFetchFirst),
                    &Verdict::RejectedFetchFirst
                ),
                "rejected: remote value unknown locally — run 'gix fetch <remote>' first"
            );
            assert_eq!(
                disposition(
                    &Mode::RejectedLocal(Verdict::RejectedAlreadyExists),
                    &Verdict::RejectedAlreadyExists
                ),
                "rejected: tag already exists on the remote"
            );
            assert_eq!(
                disposition(
                    &Mode::RejectedLocal(Verdict::RejectedNeedsForce),
                    &Verdict::RejectedNeedsForce
                ),
                "rejected: not a commit update — requires '+<spec>'/--force"
            );
            assert_eq!(
                disposition(&Mode::CorrelationGap, &Verdict::FastForward),
                "no server status received (report truncated?)"
            );
        }

        // ── (b) golden human render of a canned mixed outcome ────────────────────────────────────

        /// The full six-way mixed outcome named in TASKS gpx12 Accept (b): ok, forced,
        /// rejected-local, rejected-by-server, up-to-date, delete — each rendered as a FULL LINE
        /// through [`write_human_table`]/`write_mapping_line` (not just the [`disposition`] unit), so
        /// the `*` create marker, the `<old>..<new>` range, and the `-` delete marker are all
        /// exercised alongside the three rejection/up-to-date lines the earlier fixture omitted (FS2).
        #[test]
        fn golden_human_render() {
            let plan = PlannedUpdates {
                mappings: vec![
                    // ok: a create (advertised None ⇒ `*` marker).
                    Mapping {
                        local: Some(Source::Ref {
                            name: full("refs/heads/topic"),
                            id: oid("7f8e9a0"),
                        }),
                        remote: full("refs/heads/topic"),
                        advertised: None,
                        new: Some(oid("7f8e9a0")),
                        force: Force::SpecForce,
                        spec_index: SpecIndex::ExplicitInRemote(0),
                        verdict: Verdict::Create,
                        update_index: Some(0),
                    },
                    // forced: a non-fast-forward overwrite whose tracking ref moved (range line).
                    Mapping {
                        local: Some(Source::Ref {
                            name: full("refs/heads/main"),
                            id: oid("3c4d5e6"),
                        }),
                        remote: full("refs/heads/main"),
                        advertised: Some(oid("89ab12f")),
                        new: Some(oid("3c4d5e6")),
                        force: Force::SpecForce,
                        spec_index: SpecIndex::ExplicitInRemote(1),
                        verdict: Verdict::Forced,
                        update_index: Some(1),
                    },
                    // rejected-local: refused before the wire (non-fast-forward).
                    Mapping {
                        local: Some(Source::Ref {
                            name: full("refs/heads/feature"),
                            id: oid("2222222"),
                        }),
                        remote: full("refs/heads/feature"),
                        advertised: Some(oid("1111111")),
                        new: Some(oid("2222222")),
                        force: Force::No,
                        spec_index: SpecIndex::ExplicitInRemote(2),
                        verdict: Verdict::RejectedNonFastForward,
                        update_index: Some(2),
                    },
                    // rejected-by-server: an `ng` with verbatim server prose.
                    Mapping {
                        local: Some(Source::Ref {
                            name: full("refs/heads/bug"),
                            id: oid("4444444"),
                        }),
                        remote: full("refs/heads/bug"),
                        advertised: Some(oid("3333333")),
                        new: Some(oid("4444444")),
                        force: Force::No,
                        spec_index: SpecIndex::ExplicitInRemote(3),
                        verdict: Verdict::FastForward,
                        update_index: Some(3),
                    },
                    // up-to-date: nothing to do (range line, equal endpoints).
                    Mapping {
                        local: Some(Source::Ref {
                            name: full("refs/heads/done"),
                            id: oid("5555555"),
                        }),
                        remote: full("refs/heads/done"),
                        advertised: Some(oid("5555555")),
                        new: Some(oid("5555555")),
                        force: Force::No,
                        spec_index: SpecIndex::ExplicitInRemote(4),
                        verdict: Verdict::UpToDate,
                        update_index: Some(4),
                    },
                    // delete: no local side (`-` marker).
                    Mapping {
                        local: None,
                        remote: full("refs/heads/gone"),
                        advertised: Some(oid("1122334")),
                        new: None,
                        force: Force::No,
                        spec_index: SpecIndex::ExplicitInRemote(5),
                        verdict: Verdict::Delete,
                        update_index: Some(5),
                    },
                ],
                updates: Vec::new(),
                tips: Vec::new(),
                refspecs: vec![
                    push_spec("+refs/heads/topic:refs/heads/topic"),
                    push_spec("+refs/heads/main:refs/heads/main"),
                    push_spec("refs/heads/feature:refs/heads/feature"),
                    push_spec("refs/heads/bug:refs/heads/bug"),
                    push_spec("refs/heads/done:refs/heads/done"),
                    push_spec(":refs/heads/gone"),
                ],
                extra_refspecs: Vec::new(),
                remote_refs: Vec::new(),
            };
            let update_refs = UpdateOutcome {
                edits: Vec::new(),
                updates: vec![
                    Update::from(Mode::Ok),
                    Update::from(Mode::TrackingRefUpdated),
                    Update::from(Mode::RejectedLocal(Verdict::RejectedNonFastForward)),
                    Update::from(Mode::RejectedByServer {
                        reason: "denied by pre-receive hook".into(),
                        class: gix::remote::push::RefRejectReason::NonFastForward,
                    }),
                    Update::from(Mode::UpToDate),
                    Update::from(Mode::Ok),
                ],
            };
            let outcome = Outcome {
                plan,
                handshake: handshake("report-status"),
                status: Status::Pushed {
                    report: report(gix::remote::push::UnpackStatus::Ok),
                    write_pack: None,
                    update_refs,
                },
            };

            let (stdout, _stderr, report) = render(&outcome);
            let expected = "\
To file:///x
+refs/heads/topic:refs/heads/topic
\t* topic -> topic [ok]
+refs/heads/main:refs/heads/main
\t89ab12f..3c4d5e6 main -> main [force, tracking ref updated]
refs/heads/feature:refs/heads/feature
\t1111111..2222222 feature -> feature [rejected: non-fast-forward (fetch first, or use '+<spec>'/--force)]
refs/heads/bug:refs/heads/bug
\t3333333..4444444 bug -> bug [rejected by server: denied by pre-receive hook]
refs/heads/done:refs/heads/done
\t5555555..5555555 done -> done [up to date]
:refs/heads/gone
\t- gone [ok]
";
            assert_eq!(stdout, expected, "the golden per-ref table");
            // Two of the six mappings are rejections, so the mixed push exits 1 (§2.3).
            let err = report.into_result().expect_err("a mix with rejections exits 1");
            assert!(err.to_string().contains("push rejected: 2 of 6"), "{err}");
        }

        // ── (c) exit decision ────────────────────────────────────────────────────────────────────

        fn simple_mapping(mode: Mode) -> (Mapping, Update) {
            (
                Mapping {
                    local: Some(Source::Ref {
                        name: full("refs/heads/main"),
                        id: oid("a"),
                    }),
                    remote: full("refs/heads/main"),
                    advertised: Some(oid("b")),
                    new: Some(oid("a")),
                    force: Force::No,
                    spec_index: SpecIndex::ExplicitInRemote(0),
                    verdict: Verdict::FastForward,
                    update_index: Some(0),
                },
                Update::from(mode),
            )
        }

        fn outcome_from(modes: Vec<Mode>, status_kind: StatusKind) -> Outcome {
            let pairs: Vec<_> = modes.into_iter().map(simple_mapping).collect();
            let mappings = pairs.iter().map(|(m, _)| m.clone()).collect();
            let updates = pairs.iter().map(|(_, u)| u.clone()).collect();
            let plan = PlannedUpdates {
                mappings,
                updates: Vec::new(),
                tips: Vec::new(),
                refspecs: vec![push_spec("refs/heads/main:refs/heads/main")],
                extra_refspecs: Vec::new(),
                remote_refs: Vec::new(),
            };
            let update_refs = UpdateOutcome {
                edits: Vec::new(),
                updates,
            };
            let status = match status_kind {
                StatusKind::Pushed(unpack) => Status::Pushed {
                    report: report(unpack),
                    write_pack: None,
                    update_refs,
                },
                StatusKind::NothingToPush { dry_run } => Status::NothingToPush { dry_run, update_refs },
            };
            Outcome {
                plan,
                handshake: handshake("report-status"),
                status,
            }
        }

        enum StatusKind {
            Pushed(gix::remote::push::UnpackStatus),
            NothingToPush { dry_run: bool },
        }

        #[test]
        fn exit_clean_push_is_ok() {
            let o = outcome_from(
                vec![Mode::Ok, Mode::TrackingRefUpdated, Mode::UpToDate],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let (_o, _e, report) = render(&o);
            report.into_result().expect("a clean push is Ok (exit 0)");
        }

        #[test]
        fn exit_dry_run_clean_is_ok() {
            let o = outcome_from(
                vec![Mode::DryRun, Mode::DryRun],
                StatusKind::NothingToPush { dry_run: true },
            );
            let (_o, err, report) = render(&o);
            assert!(
                err.contains("DRY-RUN: No ref was updated on the remote."),
                "the dry-run trailer"
            );
            report.into_result().expect("a clean dry-run is Ok (exit 0)");
        }

        #[test]
        fn exit_server_rejection_is_err() {
            let o = outcome_from(
                vec![
                    Mode::Ok,
                    Mode::RejectedByServer {
                        reason: "non-fast-forward".into(),
                        class: gix::remote::push::RefRejectReason::NonFastForward,
                    },
                ],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let (_o, _e, report) = render(&o);
            let err = report.into_result().expect_err("a server ng forces exit 1");
            assert!(err.to_string().contains("push rejected: 1 of 2"), "{err}");
        }

        #[test]
        fn exit_local_rejection_is_err() {
            let o = outcome_from(
                vec![Mode::RejectedLocal(Verdict::RejectedNonFastForward)],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let (_o, _e, report) = render(&o);
            report.into_result().expect_err("a local rejection forces exit 1");
        }

        #[test]
        fn exit_unpack_failure_is_err() {
            let o = outcome_from(
                vec![Mode::Ok],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Failed("index-pack failed".into())),
            );
            let (_o, err, report) = render(&o);
            assert!(
                err.contains("failed to unpack the sent pack: index-pack failed"),
                "{err}"
            );
            report.into_result().expect_err("an unpack failure forces exit 1");
        }

        // ── (d) --force rewrite rules ────────────────────────────────────────────────────────────

        #[test]
        fn force_rewrite_rules() {
            let specs = |v: &[&str]| v.iter().map(|s| BString::from(*s)).collect::<Vec<_>>();
            // plain spec gains a leading `+`
            assert_eq!(
                force_rewrite(&specs(&["refs/heads/main:refs/heads/main"])),
                specs(&["+refs/heads/main:refs/heads/main"])
            );
            // already-`+` is idempotent
            assert_eq!(
                force_rewrite(&specs(&["+refs/heads/x:refs/heads/x"])),
                specs(&["+refs/heads/x:refs/heads/x"])
            );
            // negative spec is exempt (`+^…` is invalid)
            assert_eq!(force_rewrite(&specs(&["^refs/heads/y"])), specs(&["^refs/heads/y"]));
        }

        // ── (f) error variant → message ──────────────────────────────────────────────────────────
        //
        // Every variant with a public unit-test constructor is asserted below. The remaining arms are
        // compile-checked only — their inner error types are gix-internal with no public constructor:
        //   prepare::Error::{GatherTransportConfig, ConfigureCredentials, AtomicConfig}
        //   push::Error::{Pack, PackThreads, ThinConfig, PushDefaultConfig}
        // The connection-setup context arm is exercised through `ConfigureTransport` (same arm as
        // `GatherTransportConfig`/`ConfigureCredentials`); the pack-context arm through
        // `OpenObjectStore` (same arm as `Pack`).

        /// The url all error-mapping tests present as the push target.
        fn err_url() -> &'static BStr {
            b"file:///x".as_bstr()
        }

        #[test]
        fn missing_refspecs_error_is_the_three_line_actionable() {
            let e = map_prepare_error(
                gix::remote::push::prepare::Error::MissingRefSpecs,
                Some("origin"),
                err_url(),
            );
            let msg = format!("{e:#}");
            assert!(
                msg.contains("nothing to push: no ref-specs given and none configured for remote \"origin\""),
                "{msg}"
            );
            assert!(msg.contains("configure remote.origin.push"), "{msg}");
            assert!(
                msg.contains("expansion of 'push.default' is not yet supported"),
                "{msg}"
            );
        }

        #[test]
        fn missing_refspecs_anonymous_remote_omits_the_config_key_hint() {
            // FC3: an anonymous URL-remote (no name) must not tell the user to configure
            // `remote.origin.push` — there is no named remote to configure.
            let e = map_prepare_error(gix::remote::push::prepare::Error::MissingRefSpecs, None, err_url());
            let msg = format!("{e:#}");
            assert!(!msg.contains("remote.origin.push"), "{msg}");
            assert!(!msg.contains("remote \"origin\""), "{msg}");
            assert!(msg.contains("nothing to push"), "{msg}");
            assert!(
                msg.contains("expansion of 'push.default' is not yet supported"),
                "{msg}"
            );
        }

        #[test]
        fn stale_lease_error_carries_the_fetch_first_hint() {
            let e = map_prepare_error(
                gix::remote::push::prepare::Error::Plan(gix::remote::push::plan::Error::StaleLease {
                    destination: full("refs/heads/main"),
                    expected: Some(oid("a")),
                    actual: Some(oid("b")),
                }),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("run 'gix fetch <remote>' and re-inspect before forcing"),
                "{e:#}"
            );
        }

        #[test]
        fn connection_setup_error_names_the_url() {
            // ConfigureTransport shares the §4.1 connection-context arm with GatherTransportConfig and
            // ConfigureCredentials (which have no public constructor).
            let boxed = gix::Error::from_error(std::io::Error::other("boom"));
            let e = map_prepare_error(
                gix::remote::push::prepare::Error::ConfigureTransport(boxed),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("failed to set up the connection to file:///x"),
                "{e:#}"
            );
        }

        #[test]
        fn missing_server_feature_errors_name_the_flag_to_drop() {
            for (feature, needle) in [
                ("atomic", "retry without --atomic"),
                ("push-options", "retry without -o/--push-option"),
                ("side-band-64k", "retry with --no-sideband"),
            ] {
                let e = map_push_error(
                    gix::remote::push::Error::MissingServerFeature { feature },
                    Some("origin"),
                    err_url(),
                );
                assert!(format!("{e:#}").contains(needle), "feature {feature}: {e:#}");
            }
        }

        #[test]
        fn update_refs_error_says_the_push_was_accepted() {
            // The server already applied the push; only the local tracking-ref transaction faulted, so
            // the message must not read like a failed push. Any refs::update::Error suffices — an
            // invalid-name validation error is the one with a public constructor.
            let name_err = gix::validate::reference::name(b"".as_bstr()).expect_err("empty name is invalid");
            let e = map_push_error(
                gix::remote::push::Error::UpdateRefs(name_err.into()),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}")
                    .contains("the push was accepted by the server, but updating local tracking refs failed"),
                "{e:#}"
            );
        }

        #[test]
        fn pack_build_error_names_the_local_object_database() {
            // OpenObjectStore shares the §4.2 pack-context arm with Pack (which has no public
            // constructor).
            let e = map_push_error(
                gix::remote::push::Error::OpenObjectStore(std::io::Error::other("no odb")),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("failed to build the pack to send (local object database problem)"),
                "{e:#}"
            );
        }

        #[test]
        fn handshake_error_names_the_url() {
            // The handshake step reports an erased `gix::Error`; any failure exercises the arm.
            let e = map_prepare_error(
                gix::remote::push::prepare::Error::Handshake(gix::Error::from_error(std::io::Error::other(
                    "empty credentials",
                ))),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("could not talk to file:///x (receive-pack handshake failed)"),
                "{e:#}"
            );
        }

        #[test]
        fn client_error_names_the_url_mid_push() {
            // A transport client::Error is constructible from an io::Error (`Io(#[from] io::Error)`).
            let e = map_push_error(
                gix::remote::push::Error::Client(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into()),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("connection to file:///x failed during the push"),
                "{e:#}"
            );
        }

        #[test]
        fn protocol_push_error_says_the_server_ended_the_push() {
            // NoCommands is the one plumbing push::Error variant with a public unit constructor.
            let e = map_push_error(
                gix::remote::push::Error::Push(gix::protocol::push::Error::NoCommands),
                Some("origin"),
                err_url(),
            );
            assert!(
                format!("{e:#}").contains("the server ended the push unexpectedly"),
                "{e:#}"
            );
        }

        // ── (e) remote defaulting chain (pushDefault > single remote > origin > error) ───────────

        /// A throwaway on-disk repo (gitoxide-core has no `tempfile`/`gix-testtools` dev-dep, so we
        /// roll a minimal unique tempdir with a `Drop` cleanup) whose git config carries `extra`.
        struct TmpRepo {
            dir: std::path::PathBuf,
        }

        impl Drop for TmpRepo {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        impl TmpRepo {
            fn new(extra_config: &str) -> (Self, gix::Repository) {
                use std::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let dir = std::env::temp_dir().join(format!("gpx12-{}-{}", std::process::id(), n));
                std::fs::create_dir_all(&dir).expect("mkdir");
                gix::init(&dir).expect("init repo");
                if !extra_config.is_empty() {
                    let cfg = dir.join(".git").join("config");
                    let mut existing = std::fs::read_to_string(&cfg).unwrap_or_default();
                    existing.push('\n');
                    existing.push_str(extra_config);
                    existing.push('\n');
                    std::fs::write(&cfg, existing).expect("write config");
                }
                let repo = gix::open_opts(&dir, gix::open::Options::isolated()).expect("open repo");
                (Self { dir }, repo)
            }
        }

        #[test]
        fn defaulting_explicit_url_makes_an_anonymous_remote() {
            let (_g, repo) = TmpRepo::new("");
            let remote = by_name_or_url_for_push(&repo, Some("https://example.com/explicit")).expect("url resolves");
            assert_eq!(
                remote.url(gix::remote::Direction::Push).map(gix::Url::to_bstring),
                Some(BString::from("https://example.com/explicit"))
            );
        }

        #[test]
        fn defaulting_explicit_name_resolves_configured_remote() {
            let (_g, repo) = TmpRepo::new("[remote \"origin\"]\n\turl = https://example.com/origin");
            let remote = by_name_or_url_for_push(&repo, Some("origin")).expect("named remote resolves");
            assert_eq!(
                remote.name().map(|n| n.as_bstr().to_string()),
                Some("origin".to_string())
            );
        }

        #[test]
        fn defaulting_honors_push_default_over_single_remote() {
            // Two remotes + remote.pushDefault=other, unborn HEAD (no branch upstream) ⇒ the Push-direction
            // default resolver must pick `other`, proving Direction::Push is threaded (not Fetch).
            let (_g, repo) = TmpRepo::new(
                "[remote \"origin\"]\n\turl = https://example.com/origin\n\
                 [remote \"other\"]\n\turl = https://example.com/other\n\
                 [remote]\n\tpushDefault = other",
            );
            let remote = by_name_or_url_for_push(&repo, None).expect("pushDefault resolves");
            assert_eq!(
                remote.name().map(|n| n.as_bstr().to_string()),
                Some("other".to_string())
            );
        }

        #[test]
        fn defaulting_no_remote_is_the_actionable_error() {
            let (_g, repo) = TmpRepo::new("");
            let err = by_name_or_url_for_push(&repo, None).expect_err("no remote ⇒ error");
            assert!(
                err.to_string().contains("no remote found to push to"),
                "the actionable no-remote error: {err}"
            );
        }

        /// Make `refs/heads/main` exist (a dummy loose ref) so `HEAD` is *born* (symbolic), which is
        /// what makes `head().into_remote(Push)` read `branch.main.{pushRemote,remote}` — an unborn
        /// HEAD short-circuits to `find_default_remote` (see the pushDefault test above).
        fn born_main(dir: &std::path::Path) {
            let refp = dir.join(".git").join("refs").join("heads").join("main");
            std::fs::create_dir_all(refp.parent().expect("refs/heads")).expect("mkdir refs/heads");
            std::fs::write(&refp, format!("{}\n", "1".repeat(40))).expect("write refs/heads/main");
        }

        #[test]
        fn defaulting_honors_branch_push_remote() {
            // `branch.main.pushRemote` is the one path unique to the *push* resolver (FS3): it must win
            // over `remote.pushDefault` and over the single/origin fallbacks. HEAD (born on `main`)
            // resolves through `into_remote(Push)`.
            let (g, repo) = TmpRepo::new(
                "[remote \"origin\"]\n\turl = https://example.com/origin\n\
                 [remote \"deploy\"]\n\turl = https://example.com/deploy\n\
                 [remote]\n\tpushDefault = origin\n\
                 [branch \"main\"]\n\tpushRemote = deploy",
            );
            born_main(&g.dir);
            // Re-open so the freshly-written born ref is picked up as HEAD's referent.
            let repo = gix::open_opts(repo.git_dir(), gix::open::Options::isolated()).expect("reopen");
            let remote = by_name_or_url_for_push(&repo, None).expect("branch.main.pushRemote resolves");
            assert_eq!(
                remote.name().map(|n| n.as_bstr().to_string()),
                Some("deploy".to_string())
            );
        }

        #[test]
        fn defaulting_falls_back_to_single_remote() {
            // No pushRemote, no pushDefault, exactly one remote, unborn HEAD ⇒ the sole remote.
            let (_g, repo) = TmpRepo::new("[remote \"solo\"]\n\turl = https://example.com/solo");
            let remote = by_name_or_url_for_push(&repo, None).expect("single remote resolves");
            assert_eq!(remote.name().map(|n| n.as_bstr().to_string()), Some("solo".to_string()));
        }

        #[test]
        fn defaulting_falls_back_to_origin() {
            // No pushRemote, no pushDefault, several remotes incl. `origin`, unborn HEAD ⇒ `origin`.
            let (_g, repo) = TmpRepo::new(
                "[remote \"origin\"]\n\turl = https://example.com/origin\n\
                 [remote \"other\"]\n\turl = https://example.com/other",
            );
            let remote = by_name_or_url_for_push(&repo, None).expect("origin fallback resolves");
            assert_eq!(
                remote.name().map(|n| n.as_bstr().to_string()),
                Some("origin".to_string())
            );
        }

        #[test]
        fn incompatible_hash_error_is_verbatim() {
            let e = map_push_error(
                gix::remote::push::Error::IncompatibleObjectHash {
                    local: gix::hash::Kind::Sha1,
                    remote: gix::hash::Kind::Sha1,
                },
                None,
                err_url(),
            );
            assert!(format!("{e:#}").contains("object hashes"), "{e:#}");
        }

        // ── gpx14: the -f json DTO (§2.2) ────────────────────────────────────────────────────────

        #[cfg(feature = "serde")]
        fn mapping(
            local: Option<Source>,
            remote: &str,
            advertised: Option<ObjectId>,
            new: Option<ObjectId>,
            force: Force,
            verdict: Verdict,
            spec_index: usize,
        ) -> Mapping {
            Mapping {
                local,
                remote: full(remote),
                advertised,
                new,
                force,
                spec_index: SpecIndex::ExplicitInRemote(spec_index),
                verdict,
                update_index: Some(spec_index),
            }
        }

        #[cfg(feature = "serde")]
        fn json_outcome(
            mappings: Vec<Mapping>,
            modes: Vec<Mode>,
            refspecs: Vec<&str>,
            status_kind: StatusKind,
        ) -> Outcome {
            let update_refs = UpdateOutcome {
                edits: Vec::new(),
                updates: modes.into_iter().map(Update::from).collect(),
            };
            let status = match status_kind {
                StatusKind::Pushed(unpack) => Status::Pushed {
                    report: report(unpack),
                    write_pack: None,
                    update_refs,
                },
                StatusKind::NothingToPush { dry_run } => Status::NothingToPush { dry_run, update_refs },
            };
            Outcome {
                plan: PlannedUpdates {
                    mappings,
                    updates: Vec::new(),
                    tips: Vec::new(),
                    refspecs: refspecs.iter().map(|s| push_spec(s)).collect(),
                    extra_refspecs: Vec::new(),
                    remote_refs: Vec::new(),
                },
                handshake: handshake("report-status"),
                status,
            }
        }

        #[cfg(feature = "serde")]
        #[test]
        fn json_document_of_a_canned_mixed_outcome() {
            let outcome = json_outcome(
                vec![
                    mapping(
                        Some(Source::Ref {
                            name: full("refs/heads/main"),
                            id: oid("3c4d5e6"),
                        }),
                        "refs/heads/main",
                        Some(oid("89ab12f")),
                        Some(oid("3c4d5e6")),
                        Force::No,
                        Verdict::FastForward,
                        0,
                    ),
                    mapping(
                        Some(Source::Ref {
                            name: full("refs/heads/topic"),
                            id: oid("7f8e9a0"),
                        }),
                        "refs/heads/topic",
                        None,
                        Some(oid("7f8e9a0")),
                        Force::SpecForce,
                        Verdict::Create,
                        1,
                    ),
                ],
                vec![Mode::TrackingRefUpdated, Mode::Ok],
                vec!["refs/heads/main:refs/heads/main", "+refs/heads/topic:refs/heads/topic"],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let doc = super::json::to_document(
                b"file:///x".as_bstr(),
                "when-advertised",
                &outcome,
                vec!["hi".into()],
                None,
            );
            let v = serde_json::to_value(&doc).expect("serializes");
            assert_eq!(v["url"], "file:///x");
            assert_eq!(v["dry_run"], false);
            assert_eq!(v["atomic"], "when-advertised");
            assert_eq!(v["nothing_to_push"], false);
            assert_eq!(v["unpack"]["ok"], true);
            assert_eq!(v["pack"], serde_json::Value::Null, "write_pack None ⇒ null pack");
            assert_eq!(v["remote_messages"][0], "hi");
            assert_eq!(v["updates"][0]["spec"], "refs/heads/main:refs/heads/main");
            assert_eq!(v["updates"][0]["src"]["kind"], "ref");
            assert_eq!(v["updates"][0]["src"]["name"], "refs/heads/main");
            assert_eq!(v["updates"][0]["old"], oid("89ab12f").to_hex().to_string());
            assert_eq!(v["updates"][0]["new"], oid("3c4d5e6").to_hex().to_string());
            assert_eq!(v["updates"][0]["force"], "no");
            assert_eq!(v["updates"][0]["status"], "tracking-ref-updated");
            assert_eq!(v["updates"][1]["spec"], "+refs/heads/topic:refs/heads/topic");
            assert_eq!(
                v["updates"][1]["old"],
                serde_json::Value::Null,
                "a create has no old value"
            );
            assert_eq!(v["updates"][1]["force"], "spec");
            assert_eq!(v["updates"][1]["status"], "ok");
        }

        #[cfg(feature = "serde")]
        #[test]
        fn json_round_trips() {
            let outcome = json_outcome(
                vec![mapping(
                    Some(Source::Ref {
                        name: full("refs/heads/main"),
                        id: oid("a"),
                    }),
                    "refs/heads/main",
                    Some(oid("b")),
                    Some(oid("a")),
                    Force::No,
                    Verdict::FastForward,
                    0,
                )],
                vec![Mode::Ok],
                vec!["refs/heads/main:refs/heads/main"],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let doc = super::json::to_document(b"file:///x".as_bstr(), "disabled", &outcome, Vec::new(), None);
            let text = serde_json::to_string(&doc).expect("serialize");
            let back: super::json::Document = serde_json::from_str(&text).expect("deserialize");
            assert_eq!(doc, back, "the DTO round-trips through serde_json");
        }

        #[cfg(feature = "serde")]
        #[test]
        fn json_every_status_is_produced_by_exactly_one_mode() {
            let modes = vec![
                Mode::UpToDate,
                Mode::DryRun,
                Mode::Ok,
                Mode::TrackingRefUpdated,
                Mode::TrackingRefSkipped(SkipReason::NotABranch),
                Mode::RejectedByServer {
                    reason: "x".into(),
                    class: gix::remote::push::RefRejectReason::Other,
                },
                Mode::RejectedLocal(Verdict::RejectedNonFastForward),
                Mode::CorrelationGap,
            ];
            let n = modes.len();
            let mappings: Vec<_> = (0..n)
                .map(|i| {
                    mapping(
                        Some(Source::Ref {
                            name: full("refs/heads/main"),
                            id: oid("a"),
                        }),
                        "refs/heads/main",
                        Some(oid("b")),
                        Some(oid("a")),
                        Force::No,
                        Verdict::FastForward,
                        i,
                    )
                })
                .collect();
            let refspecs: Vec<&str> = vec!["refs/heads/main:refs/heads/main"; n];
            let outcome = json_outcome(
                mappings,
                modes,
                refspecs,
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let doc = super::json::to_document(b"file:///x".as_bstr(), "disabled", &outcome, Vec::new(), None);
            let statuses: Vec<&str> = doc.updates.iter().map(|u| u.status.as_str()).collect();
            let mut sorted = statuses.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                n,
                "each Mode produces a DISTINCT status string: {statuses:?}"
            );
            let expected = [
                "correlation-gap",
                "dry-run",
                "ok",
                "rejected-by-server",
                "rejected-local",
                "tracking-ref-skipped",
                "tracking-ref-updated",
                "up-to-date",
            ];
            assert_eq!(sorted, expected, "the §4.3 status vocabulary");
        }

        #[cfg(feature = "serde")]
        #[test]
        fn json_dry_run_has_true_and_null_pack_and_unpack() {
            let outcome = json_outcome(
                vec![mapping(
                    Some(Source::Ref {
                        name: full("refs/heads/main"),
                        id: oid("a"),
                    }),
                    "refs/heads/main",
                    Some(oid("b")),
                    Some(oid("a")),
                    Force::No,
                    Verdict::FastForward,
                    0,
                )],
                vec![Mode::DryRun],
                vec!["refs/heads/main:refs/heads/main"],
                StatusKind::NothingToPush { dry_run: true },
            );
            let doc = super::json::to_document(b"file:///x".as_bstr(), "disabled", &outcome, Vec::new(), None);
            let v = serde_json::to_value(&doc).expect("serializes");
            assert_eq!(v["dry_run"], true);
            assert_eq!(v["nothing_to_push"], true);
            assert_eq!(v["unpack"], serde_json::Value::Null);
            assert_eq!(v["pack"], serde_json::Value::Null);
            assert_eq!(v["updates"][0]["status"], "dry-run");
            assert_eq!(v["updates"][0]["detail"], "fast-forward");
        }

        #[cfg(feature = "serde")]
        #[test]
        fn json_pack_shape_is_written_objects() {
            let pack = super::json::Pack { written_objects: 3 };
            assert_eq!(serde_json::to_string(&pack).unwrap(), r#"{"written_objects":3}"#);
        }

        #[cfg(feature = "serde")]
        #[test]
        fn exit_decision_is_format_independent() {
            // The same rejected outcome yields the same exit Err whether rendered as human or JSON —
            // Report::from_outcome takes no format, so -f json cannot change the exit code (§2.3).
            let outcome = json_outcome(
                vec![mapping(
                    Some(Source::Ref {
                        name: full("refs/heads/main"),
                        id: oid("a"),
                    }),
                    "refs/heads/main",
                    Some(oid("b")),
                    Some(oid("a")),
                    Force::No,
                    Verdict::FastForward,
                    0,
                )],
                vec![Mode::RejectedLocal(Verdict::RejectedNonFastForward)],
                vec!["refs/heads/main:refs/heads/main"],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            Report::from_outcome(&outcome)
                .into_result()
                .expect_err("a rejection is exit 1 regardless of output format");
        }

        // ── gpx17: -u/--set-upstream (RATIFY-8..15) ──────────────────────────────────────────────

        /// A mapping shaped for the upstream-qualification tests: any source/destination/new-value
        /// combination, spec 0, FastForward verdict (the verdict does not participate in
        /// qualification).
        fn up_mapping(local: Option<Source>, remote: &str, new: Option<ObjectId>) -> Mapping {
            Mapping {
                local,
                remote: full(remote),
                advertised: Some(oid("b")),
                new,
                force: Force::No,
                spec_index: SpecIndex::ExplicitInRemote(0),
                verdict: Verdict::FastForward,
                update_index: Some(0),
            }
        }

        fn up_outcome(pairs: Vec<(Mapping, Mode)>, status_kind: StatusKind) -> Outcome {
            let mappings: Vec<_> = pairs.iter().map(|(m, _)| m.clone()).collect();
            let updates: Vec<_> = pairs.into_iter().map(|(_, mode)| Update::from(mode)).collect();
            let update_refs = UpdateOutcome {
                edits: Vec::new(),
                updates,
            };
            let status = match status_kind {
                StatusKind::Pushed(unpack) => Status::Pushed {
                    report: report(unpack),
                    write_pack: None,
                    update_refs,
                },
                StatusKind::NothingToPush { dry_run } => Status::NothingToPush { dry_run, update_refs },
            };
            Outcome {
                plan: PlannedUpdates {
                    mappings,
                    updates: Vec::new(),
                    tips: Vec::new(),
                    refspecs: vec![push_spec("refs/heads/main:refs/heads/main")],
                    extra_refspecs: Vec::new(),
                    remote_refs: Vec::new(),
                },
                handshake: handshake("report-status"),
                status,
            }
        }

        fn branch_src(name: &str) -> Option<Source> {
            Some(Source::Ref {
                name: full(name),
                id: oid("a"),
            })
        }

        // (a) exhaustive Mode × shape qualification.

        #[test]
        fn upstream_qualifying_modes_and_shapes() {
            use super::upstream::qualifying;
            let pushed = || StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok);

            // The three ok modes write; `UpToDate` under a non-dry-run outcome is a real set.
            for mode in [
                Mode::UpToDate,
                Mode::TrackingRefUpdated,
                Mode::TrackingRefSkipped(SkipReason::NoMatchingFetchSpec),
            ] {
                let o = up_outcome(
                    vec![(
                        up_mapping(branch_src("refs/heads/main"), "refs/heads/main", Some(oid("a"))),
                        mode,
                    )],
                    pushed(),
                );
                let edits = qualifying(&o);
                assert_eq!(edits.len(), 1, "an ok mode qualifies");
                assert!(!edits[0].would, "a non-dry-run ok mode is a real set");
                assert_eq!(edits[0].short, "main");
                assert_eq!(edits[0].merge, "refs/heads/main");
            }

            // RATIFY-14 RED case: plain `Ok` on a branch-shaped non-delete mapping means the update
            // was suppressed/rolled back (unpack failure / atomic rollback) — NO upstream write.
            let o = up_outcome(
                vec![(
                    up_mapping(branch_src("refs/heads/main"), "refs/heads/main", Some(oid("a"))),
                    Mode::Ok,
                )],
                pushed(),
            );
            assert!(
                qualifying(&o).is_empty(),
                "plain Ok is a rolled-back update, never an upstream write (RATIFY-14)"
            );

            // Rejections and the correlation gap never qualify.
            for mode in [
                Mode::RejectedLocal(Verdict::RejectedNonFastForward),
                Mode::RejectedByServer {
                    reason: "no".into(),
                    class: gix::remote::push::RefRejectReason::NonFastForward,
                },
                Mode::CorrelationGap,
            ] {
                let o = up_outcome(
                    vec![(
                        up_mapping(branch_src("refs/heads/main"), "refs/heads/main", Some(oid("a"))),
                        mode,
                    )],
                    pushed(),
                );
                assert!(qualifying(&o).is_empty(), "a refused update never sets upstream");
            }

            // Shape exclusions: delete (no new value), tag destination, raw-object-id source,
            // detached-HEAD source.
            let shapes = [
                up_mapping(None, "refs/heads/main", None),
                up_mapping(branch_src("refs/heads/main"), "refs/tags/v1", Some(oid("a"))),
                up_mapping(Some(Source::ObjectId(oid("a"))), "refs/heads/main", Some(oid("a"))),
                up_mapping(
                    Some(Source::Detached { id: oid("a") }),
                    "refs/heads/main",
                    Some(oid("a")),
                ),
            ];
            for shape in shapes {
                let o = up_outcome(vec![(shape, Mode::TrackingRefUpdated)], pushed());
                assert!(qualifying(&o).is_empty(), "a non-branch shape never sets upstream");
            }

            // Dry run: `DryRun` and `UpToDate` under a dry-run outcome are would-sets.
            let o = up_outcome(
                vec![
                    (
                        up_mapping(branch_src("refs/heads/main"), "refs/heads/main", Some(oid("a"))),
                        Mode::DryRun,
                    ),
                    (
                        up_mapping(branch_src("refs/heads/done"), "refs/heads/done", Some(oid("a"))),
                        Mode::UpToDate,
                    ),
                ],
                StatusKind::NothingToPush { dry_run: true },
            );
            let edits = qualifying(&o);
            assert_eq!(edits.len(), 2);
            assert!(
                edits.iter().all(|e| e.would),
                "every dry-run qualifier is a would-set, never a write"
            );

            // A rename records the DESTINATION as `merge`.
            let o = up_outcome(
                vec![(
                    up_mapping(branch_src("refs/heads/main"), "refs/heads/other", Some(oid("a"))),
                    Mode::TrackingRefUpdated,
                )],
                pushed(),
            );
            let edits = qualifying(&o);
            assert_eq!(edits[0].short, "main");
            assert_eq!(edits[0].merge, "refs/heads/other", "a rename records merge=<dest>");
            assert_eq!(edits[0].dst_short, "other");
        }

        // (b) message goldens.

        fn notes_of(edits: &[super::upstream::Edit], remote: &str, error: Option<&str>) -> String {
            let mut err = Vec::new();
            super::upstream::write_upstream_notes(&mut err, BStr::new(remote), edits, error).expect("notes ok");
            String::from_utf8(err).unwrap()
        }

        fn edit(short: &str, dst: &str, would: bool) -> super::upstream::Edit {
            super::upstream::Edit {
                local: format!("refs/heads/{short}").into(),
                short: short.into(),
                merge: format!("refs/heads/{dst}").into(),
                dst_short: dst.into(),
                would,
            }
        }

        #[test]
        fn upstream_message_goldens() {
            // Plain set + rename set (git wording, trailing period).
            assert_eq!(
                notes_of(
                    &[edit("main", "main", false), edit("main", "other", false)],
                    "origin",
                    None
                ),
                "branch 'main' set up to track 'origin/main'.\nbranch 'main' set up to track 'origin/other'.\n"
            );
            // URL-remote set (RATIFY-12): the verbatim URL is the display value.
            assert_eq!(
                notes_of(&[edit("main", "main", false)], "https://example.com/repo.git", None),
                "branch 'main' set up to track 'https://example.com/repo.git/main'.\n"
            );
            // Would-set: the no-period dry-run line.
            assert_eq!(
                notes_of(&[edit("main", "other", true)], "origin", None),
                "Would set upstream of 'main' to 'other' of 'origin'\n"
            );
            // A failed write prints ONE error line and suppresses every success line.
            let failed = notes_of(
                &[edit("main", "main", false), edit("dev", "dev", false)],
                "origin",
                Some("to /repo/.git/config failed: permission denied"),
            );
            assert_eq!(
                failed,
                "error: the push was accepted by the server, but writing upstream configuration \
                 to /repo/.git/config failed: permission denied\n"
            );
            assert!(!failed.contains("set up to track"), "no success line on a failed write");
        }

        // (c)/(d)/(e) the locked config write against a real file.

        /// A throwaway config file (same tempdir discipline as [`TmpRepo`]).
        struct TmpConfig {
            dir: std::path::PathBuf,
            path: std::path::PathBuf,
        }

        impl Drop for TmpConfig {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        impl TmpConfig {
            fn new(contents: &str) -> Self {
                use std::sync::atomic::{AtomicU64, Ordering};
                static COUNTER: AtomicU64 = AtomicU64::new(0);
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let dir = std::env::temp_dir().join(format!("gpx17-{}-{}", std::process::id(), n));
                std::fs::create_dir_all(&dir).expect("mkdir");
                let path = dir.join("config");
                std::fs::write(&path, contents).expect("seed config");
                TmpConfig { dir, path }
            }

            fn read(&self) -> String {
                std::fs::read_to_string(&self.path).expect("read config")
            }
        }

        #[test]
        fn upstream_write_updates_existing_section_in_place() {
            let cfg = TmpConfig::new(
                "[core]\n\tbare = false\n\
                 [branch \"main\"]\n\tdescription = keepme\n\
                 [include]\n\tpath = decoy.inc\n\
                 [branch \"other\"]\n\tremote = old\n",
            );
            let e = edit("main", "main", false);
            super::upstream::write_config(&cfg.path, BStr::new("origin"), &[&e]).expect("write ok");
            let text = cfg.read();
            // Updated in place: ONE [branch "main"] stanza, unrelated keys preserved.
            assert_eq!(
                text.matches("[branch \"main\"]").count(),
                1,
                "no duplicated stanza (the new_section trap): {text}"
            );
            assert!(text.contains("description = keepme"), "unrelated key preserved: {text}");
            assert!(text.contains("remote = origin"), "{text}");
            assert!(text.contains("merge = refs/heads/main"), "{text}");
            // The include section and the other branch survive byte-for-byte semantics.
            assert!(text.contains("[include]"), "{text}");
            assert!(text.contains("path = decoy.inc"), "include decoy untouched: {text}");
            assert_eq!(
                text.matches("[include]").count(),
                1,
                "include decoy unduplicated: {text}"
            );
            assert!(text.contains("[branch \"other\"]"), "{text}");
            assert!(text.contains("remote = old"), "{text}");
            // Idempotent: a second identical run leaves the file byte-identical.
            super::upstream::write_config(&cfg.path, BStr::new("origin"), &[&e]).expect("rewrite ok");
            assert_eq!(cfg.read(), text, "the write is idempotent (overwrite-or-create)");
        }

        #[test]
        fn upstream_write_batches_all_branches_under_one_lock() {
            let cfg = TmpConfig::new("[core]\n\tbare = false\n");
            let e1 = edit("main", "main", false);
            let e2 = edit("dev", "dev", false);
            super::upstream::write_config(&cfg.path, BStr::new("origin"), &[&e1, &e2]).expect("write ok");
            let text = cfg.read();
            assert!(text.contains("[branch \"main\"]"), "{text}");
            assert!(text.contains("[branch \"dev\"]"), "{text}");
            assert!(!cfg.dir.join("config.lock").exists(), "the lock was committed away");
        }

        #[test]
        fn upstream_write_shrink_leaves_no_trailing_garbage() {
            // RED against a non-truncating writer (the write_to_local_config trap): rewriting the
            // file with SHORTER content must not leave tail bytes of the longer previous version.
            let cfg = TmpConfig::new("[core]\n\tbare = false\n");
            let long = edit("main", "main", false);
            super::upstream::write_config(
                &cfg.path,
                BStr::new("a-very-long-remote-name-that-pads-the-file-out-considerably"),
                &[&long],
            )
            .expect("long write ok");
            super::upstream::write_config(&cfg.path, BStr::new("o"), &[&long]).expect("short write ok");
            let text = cfg.read();
            assert!(
                !text.contains("a-very-long-remote-name"),
                "no residue of the longer value: {text}"
            );
            assert_eq!(text.matches("remote = o\n").count(), 1, "{text}");
            // The rewritten file still parses as valid git config.
            gix::config::File::from_path_no_includes(cfg.path.clone(), gix::config::Source::Local)
                .expect("the shrunk file parses");
        }

        #[test]
        fn upstream_write_unwritable_path_is_err() {
            let missing = std::env::temp_dir()
                .join(format!("gpx17-missing-{}", std::process::id()))
                .join("no-such-dir")
                .join("config");
            let e = edit("main", "main", false);
            super::upstream::write_config(&missing, BStr::new("origin"), &[&e])
                .expect_err("a write to an unwritable path must fail, not silently succeed");
        }

        // (f) JSON goldens.

        #[cfg(feature = "serde")]
        #[test]
        fn json_set_upstream_golden_and_round_trip() {
            // set: a successful write.
            let dto = super::json::set_upstream_of(&[edit("main", "main", false)], BStr::new("origin"), None);
            let v = serde_json::to_value(&dto).expect("serializes");
            assert_eq!(v["written"], true);
            assert_eq!(v["error"], serde_json::Value::Null);
            assert_eq!(v["branches"][0]["local"], "refs/heads/main");
            assert_eq!(v["branches"][0]["short"], "main");
            assert_eq!(v["branches"][0]["remote"], "origin");
            assert_eq!(v["branches"][0]["merge"], "refs/heads/main");
            assert_eq!(v["branches"][0]["state"], "set");

            // would-set: dry run writes nothing.
            let dto = super::json::set_upstream_of(&[edit("main", "other", true)], BStr::new("origin"), None);
            let v = serde_json::to_value(&dto).expect("serializes");
            assert_eq!(v["written"], false, "a dry run never writes");
            assert_eq!(v["branches"][0]["state"], "would-set");
            assert_eq!(v["branches"][0]["merge"], "refs/heads/other");

            // a failed write: written=false, the single error carried in the envelope.
            let dto = super::json::set_upstream_of(&[edit("main", "main", false)], BStr::new("origin"), Some("boom"));
            let v = serde_json::to_value(&dto).expect("serializes");
            assert_eq!(v["written"], false, "a failed write is not written");
            assert_eq!(v["error"], "boom");

            // flag off ⇒ null field on the document; flag on ⇒ the envelope round-trips.
            let outcome = json_outcome(
                vec![mapping(
                    Some(Source::Ref {
                        name: full("refs/heads/main"),
                        id: oid("a"),
                    }),
                    "refs/heads/main",
                    Some(oid("b")),
                    Some(oid("a")),
                    Force::No,
                    Verdict::FastForward,
                    0,
                )],
                vec![Mode::TrackingRefUpdated],
                vec!["refs/heads/main:refs/heads/main"],
                StatusKind::Pushed(gix::remote::push::UnpackStatus::Ok),
            );
            let doc = super::json::to_document(b"file:///x".as_bstr(), "disabled", &outcome, Vec::new(), None);
            let v = serde_json::to_value(&doc).expect("serializes");
            assert_eq!(v["set_upstream"], serde_json::Value::Null, "flag off ⇒ null");
            let dto = super::json::set_upstream_of(&[edit("main", "main", false)], BStr::new("origin"), None);
            let doc = super::json::to_document(b"file:///x".as_bstr(), "disabled", &outcome, Vec::new(), Some(dto));
            let text = serde_json::to_string(&doc).expect("serialize");
            let back: super::json::Document = serde_json::from_str(&text).expect("deserialize");
            assert_eq!(doc, back, "the set_upstream envelope round-trips");
        }
    }
}
