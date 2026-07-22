//! Push-side configuration reads (task `gpx03`/P3), the send-direction twin of
//! [`fetch/config.rs`](super::super::fetch). Three repo-local, synchronous accessors that translate
//! the git config keys the push path cares about into typed values, each returning the terminal
//! [`push::Error`](super::Error) (the `PackThreads`/`ThinConfig`/`PushDefaultConfig` variants that
//! `gpx02` pre-provisioned for exactly these reads).
//!
//! # What lives here (and what deliberately does not)
//! Push at v1 needs `pack.threads` (thread cap for the pack walk), `push.thin` (parsed now, consumed
//! as always-`false` until the plumbing's thin-pack support), `push.default` (a parse hook; Q1 defers
//! refspec expansion), and — added by `gpx10` for the push-options + sideband surface —
//! `push.pushOption` (the multi-valued default push-options, C-git reset semantics) and `push.atomic`
//! (the default [`Atomicity`](gix_protocol::push::Atomicity) policy). Explicitly **absent**, unlike
//! `fetch/config.rs`: `pack.indexVersion` — push writes no `.idx`, so there is no index-version read
//! (the matching `push::Error` variant is dropped too). `remote.<name>.push` is **not** read here
//! either: it is parsed into `Remote.push_specs` at remote-init time (see `gpx01`) and reaches the
//! plan as refspecs, never through this module.
//!
//! # `index_threads` vs fetch — duplicated body, shared key
//! The body is a byte-for-byte twin of `fetch/config.rs`'s `index_threads` apart from the error type:
//! fetch's is private to `connection/fetch` and returns `fetch::Error`, so widening its visibility to
//! share eight lines would couple the two error taxonomies. The OVERVIEW's "reuse fetch's
//! `index_threads`" is therefore honored at the **key** level (`Pack::THREADS` — same key, same
//! semantics, same user-visible message), which is where the contract actually lives.

// SKELETON (mirrors `plan.rs`): none of the three accessors has an in-crate caller yet. `thin()` is
// consumed by the `send()` terminal (`gpx08`) once the plumbing gains thin-pack support; `index_threads()`
// by the pack driver once it offers multi-threaded counting (`gpx06` currently pins single-threaded
// generation for a deterministic byte stream, so it does not read this); `push_default()` once Q1
// ratifies `push.default` expansion (a later unit). The keys and their lenient/strict behavior are
// pinned by the in-module `tests` below regardless. Remove this once a consumer lands.
#![allow(dead_code)]

use gix_protocol::push::Atomicity;

use super::Error;
use crate::{
    Repository,
    bstr::BString,
    config::{
        cache::util::ApplyLeniency,
        tree::{Pack, Push},
    },
};

/// The maximum number of threads to use when counting and delta-compressing objects for the pack,
/// with `None` leaving the choice to the pack engine and `0` meaning "use all logical cores".
///
/// Reads `pack.threads` exactly like the fetch side does for pack indexing (same `Pack::THREADS`
/// key). Malformed values are `Ok(None)` under lenient config (the default for opened repos) and
/// [`Error::PackThreads`] under a strict open.
pub fn index_threads(repo: &Repository) -> Result<Option<usize>, Error> {
    Ok(Pack::THREADS
        .try_into_usize(
            repo.config
                .resolved
                .integer_filter(Pack::THREADS, &mut repo.filter_config_section()),
        )
        .with_leniency(repo.options.lenient_config)?)
}

/// Whether the user asked for thin packs via `push.thin`.
///
/// ### Deviation
///
/// `git` defaults this to `true`; we default to `false` and the v1 pack driver builds full packs
/// unconditionally. A configured `true` is accepted (validated) but has **no effect** until thin-pack
/// support arrives with the plumbing's M2, at which point the default flips to `true` for parity.
/// A malformed value is `Ok(false)` under lenient config and [`Error::ThinConfig`] under a strict open.
pub fn thin(repo: &Repository) -> Result<bool, Error> {
    Ok(Push::THIN
        .enrich_error(
            repo.config
                .resolved
                .boolean_filter(Push::THIN, &mut repo.filter_config_section()),
        )
        .with_leniency(repo.options.lenient_config)?
        .unwrap_or(false))
}

/// The parsed `push.default` strategy, defaulting to [`Simple`](crate::push::Default::Simple) like
/// `git`. A malformed value is `Ok(Simple)` under lenient config and [`Error::PushDefaultConfig`]
/// (whose message names the offending value) under a strict open.
///
/// This is a parse hook only: the v1 push path never expands `push.default` into refspecs (Q1 keeps
/// empty-spec pushes an error rather than a `push.default` expansion), so the accessor exists to pin
/// the parse and its leniency contract now; a later unit wires the expansion.
pub fn push_default(repo: &Repository) -> Result<crate::push::Default, Error> {
    Ok(repo
        .config
        .resolved
        .string_filter(Push::DEFAULT, &mut repo.filter_config_section())
        .map(|value| Push::DEFAULT.try_into_default(value))
        .transpose()
        .with_leniency(repo.options.lenient_config)?
        .unwrap_or_default())
}

/// The default push-options from `push.pushOption`, in configuration order — the values `git push`
/// sends as if each were an explicit `--push-option=<value>` when the command line names none
/// (C-git `push.pushOption`). Consumed by [`prepare_push`](crate::remote::Connection::prepare_push)
/// as the initial value the [`with_push_options`](super::send_pack::Prepare::with_push_options)
/// builder overrides.
///
/// This is a multi-valued key with C-git's **reset** semantics: an empty value clears every option
/// accumulated so far (so a higher-priority config file can wipe a lower-priority one's list). Reads
/// are raw bytes — there is no parse and thus no error path (unlike [`thin`]/[`push_default`]); a
/// missing key yields an empty vector, which leaves the push byte-identical to one with no options.
pub fn push_options(repo: &Repository) -> Vec<BString> {
    let mut out = Vec::new();
    if let Some(values) = repo
        .config
        .resolved
        .strings_filter(Push::PUSH_OPTION, &mut repo.filter_config_section())
    {
        for value in values {
            if value.is_empty() {
                out.clear(); // C-git reset: an empty value wipes the inherited list.
            } else {
                out.push(value); // strings_filter yields owned BStrings directly
            }
        }
    }
    out
}

/// The default [`Atomicity`] policy from `push.atomic`, the initial value the
/// [`with_atomic`](super::send_pack::Prepare::with_atomic) builder overrides.
///
/// `push.atomic=true` maps to [`Atomicity::Required`] (git's `--atomic` refuses against a server that
/// does not advertise `atomic`, so the config default is a hard requirement, not a soft
/// [`WhenAdvertised`](Atomicity::WhenAdvertised)); unset or `false` maps to the rolfdb default
/// [`Atomicity::Disabled`]. A malformed value is `Disabled` under lenient config (the default for
/// opened repos) and the raw [`boolean::Error`](crate::config::boolean::Error) under a strict open —
/// the caller ([`prepare_push`](crate::remote::Connection::prepare_push)) lifts it into
/// [`prepare::Error::AtomicConfig`](super::prepare::Error::AtomicConfig).
pub fn atomic(repo: &Repository) -> Result<Atomicity, crate::config::boolean::Error> {
    let enabled = Push::ATOMIC
        .enrich_error(
            repo.config
                .resolved
                .boolean_filter(Push::ATOMIC, &mut repo.filter_config_section()),
        )
        .with_leniency(repo.options.lenient_config)?
        .unwrap_or(false);
    Ok(if enabled {
        Atomicity::Required
    } else {
        Atomicity::Disabled
    })
}

#[cfg(test)]
mod tests {
    use gix_protocol::push::Atomicity;

    use super::{atomic, index_threads, push_default, push_options, thin};
    use crate as gix;

    /// Open an empty, isolated repo whose only non-default config is `overrides` (git `key=value`
    /// strings, applied at the highest-trust `Api` tier so they pass `filter_config_section`).
    fn repo_with(overrides: &[&str]) -> (gix::Repository, gix_testtools::tempfile::TempDir) {
        let dir = gix_testtools::tempfile::tempdir().expect("tempdir");
        gix::init(dir.path()).expect("init empty repo");
        let mut opts = gix::open::Options::isolated();
        if !overrides.is_empty() {
            opts = opts.config_overrides(overrides.iter().map(|s| s.to_string()));
        }
        let repo = gix::open_opts(dir.path(), opts).expect("reopen with overrides");
        (repo, dir)
    }

    #[test]
    fn index_threads_reads_zero_values_and_unset() {
        let (repo, _t) = repo_with(&["pack.threads=0"]);
        assert_eq!(index_threads(&repo).unwrap(), Some(0), "0 means 'all cores', preserved");
        let (repo, _t) = repo_with(&["pack.threads=3"]);
        assert_eq!(index_threads(&repo).unwrap(), Some(3));
        let (repo, _t) = repo_with(&[]);
        assert_eq!(
            index_threads(&repo).unwrap(),
            None,
            "unset leaves the choice to the engine"
        );
    }

    #[test]
    fn index_threads_lenient_swallows_malformed() {
        let (repo, _t) = repo_with(&["pack.threads=not-a-number"]);
        assert_eq!(
            index_threads(&repo).unwrap(),
            None,
            "lenient (default) config turns a malformed pack.threads into None"
        );
    }

    #[test]
    fn thin_defaults_false_and_reads_config() {
        let (repo, _t) = repo_with(&[]);
        assert!(
            !thin(&repo).unwrap(),
            "unset → false (documented deviation from git's true)"
        );
        let (repo, _t) = repo_with(&["push.thin=true"]);
        assert!(
            thin(&repo).unwrap(),
            "explicit true is read back (validated, even if v1 ignores it)"
        );
        let (repo, _t) = repo_with(&["push.thin=false"]);
        assert!(!thin(&repo).unwrap());
        // Malformed under lenient config (the default) → false, never an error.
        let (repo, _t) = repo_with(&["push.thin=maybe"]);
        assert!(!thin(&repo).unwrap(), "lenient → false");
    }

    #[test]
    fn push_default_defaults_simple_and_parses_modes() {
        let (repo, _t) = repo_with(&[]);
        assert_eq!(
            push_default(&repo).unwrap(),
            gix::push::Default::Simple,
            "unset → Simple"
        );
        for (value, expected) in [
            ("nothing", gix::push::Default::Nothing),
            ("current", gix::push::Default::Current),
            ("upstream", gix::push::Default::Upstream),
            ("tracking", gix::push::Default::Upstream), // documented alias for upstream
            ("simple", gix::push::Default::Simple),
            ("matching", gix::push::Default::Matching),
        ] {
            let (repo, _t) = repo_with(&[&format!("push.default={value}")]);
            assert_eq!(push_default(&repo).unwrap(), expected, "push.default={value}");
        }
        // Malformed under lenient config → Simple, never an error.
        let (repo, _t) = repo_with(&["push.default=bogus"]);
        assert_eq!(
            push_default(&repo).unwrap(),
            gix::push::Default::Simple,
            "lenient → Simple"
        );
    }

    #[test]
    fn push_options_defaults_empty_and_reads_all_values_in_order() {
        let (repo, _t) = repo_with(&[]);
        assert!(
            push_options(&repo).is_empty(),
            "unset push.pushOption → no default options (byte-identical to a plain push)"
        );
        // A multi-valued key: every value is collected, in configuration order, verbatim.
        let (repo, _t) = repo_with(&["push.pushOption=alpha", "push.pushOption=key=val"]);
        assert_eq!(
            push_options(&repo),
            vec![gix::bstr::BString::from("alpha"), gix::bstr::BString::from("key=val")],
            "each push.pushOption value becomes a default option, in order"
        );
    }

    #[test]
    fn push_options_empty_value_resets_the_inherited_list() {
        // C-git reset semantics: an empty value clears everything accumulated before it, then later
        // values re-accumulate. `config_overrides` are applied in order at a single trust tier, so
        // this exercises the reset directly.
        let (repo, _t) = repo_with(&[
            "push.pushOption=stale-one",
            "push.pushOption=stale-two",
            "push.pushOption=",
            "push.pushOption=fresh",
        ]);
        assert_eq!(
            push_options(&repo),
            vec![gix::bstr::BString::from("fresh")],
            "an empty push.pushOption value wipes the inherited list, keeping only what follows"
        );
    }

    #[test]
    fn atomic_defaults_disabled_and_true_requires() {
        let (repo, _t) = repo_with(&[]);
        assert_eq!(
            atomic(&repo).unwrap(),
            Atomicity::Disabled,
            "unset push.atomic → Disabled (the rolfdb default)"
        );
        let (repo, _t) = repo_with(&["push.atomic=true"]);
        assert_eq!(
            atomic(&repo).unwrap(),
            Atomicity::Required,
            "push.atomic=true → Required (git's --atomic is a hard requirement)"
        );
        let (repo, _t) = repo_with(&["push.atomic=false"]);
        assert_eq!(atomic(&repo).unwrap(), Atomicity::Disabled);
        // Malformed under lenient config (the default) → Disabled, never an error.
        let (repo, _t) = repo_with(&["push.atomic=maybe"]);
        assert_eq!(atomic(&repo).unwrap(), Atomicity::Disabled, "lenient → Disabled");
    }

    /// Strict opens surface the parse errors as the terminal push error variants (the whole point of
    /// `gpx02` pre-provisioning `PackThreads`/`ThinConfig`/`PushDefaultConfig`). One isolated,
    /// non-lenient repo drives all three keys.
    #[test]
    fn strict_config_surfaces_typed_errors() {
        let dir = gix_testtools::tempfile::tempdir().expect("tempdir");
        gix::init(dir.path()).expect("init");
        let strict = |kv: &str| {
            gix::open_opts(
                dir.path(),
                gix::open::Options::isolated()
                    .config_overrides([kv.to_string()])
                    .strict_config(true),
            )
            .expect("reopen strict")
        };

        let repo = strict("pack.threads=not-a-number");
        assert!(
            matches!(index_threads(&repo), Err(super::Error::PackThreads(_))),
            "strict pack.threads parse failure is a typed PackThreads error"
        );

        let repo = strict("push.thin=maybe");
        assert!(
            matches!(thin(&repo), Err(super::Error::ThinConfig(_))),
            "strict push.thin parse failure is a typed ThinConfig error"
        );

        let repo = strict("push.default=bogus");
        match push_default(&repo) {
            Err(super::Error::PushDefaultConfig(err)) => {
                assert!(
                    err.to_string().contains("bogus"),
                    "the error names the offending value, got: {err}"
                );
            }
            other => panic!("expected a typed PushDefaultConfig error naming the value, got {other:?}"),
        }

        // push.atomic is a boolean; a strict malformed value surfaces the raw boolean parse error
        // (prepare_push lifts it into prepare::Error::AtomicConfig).
        let repo = strict("push.atomic=maybe");
        assert!(
            atomic(&repo).is_err(),
            "strict push.atomic parse failure is a typed boolean error"
        );
    }
}
