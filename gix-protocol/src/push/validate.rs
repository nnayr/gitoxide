//! Client-side lease pre-check → the advertisement-derived push plan (plan §3.7).
//!
//! [`plan_from_advertisement`] does two things (so callers avoid duplicate work): it runs the
//! force-with-lease pre-check (§2.1 layer a — an obviously stale lease becomes an error **before**
//! any bytes are sent) and it derives the two **distinct** sets the pack builder needs (F1):
//! the `boundary` (our ref's advertised oid, always locally present when non-zero) and the
//! `thin_bases` (the full advertised oid set, server-known but not necessarily local).

use bstr::{BStr, ByteSlice};
use gix_hash::ObjectId;
use gix_ref::FullName;

use crate::push::RefUpdate;

/// The advertisement-derived push plan (F1). The lease pre-check has already passed.
///
/// INVARIANT: when `boundary` is `Some`, it is also an element of `thin_bases` (our advertised ref
/// is itself server-known).
#[derive(Debug, Clone)]
pub struct Advertised {
    /// The advertised oid of **our** ref — the pack-build BOUNDARY (the last state we synced).
    /// Locally present when `Some` (a manifest object the caller holds: a commit, or the tag oid
    /// for an annotated-tag ref — the walk peels it). `None` means create / empty remote, and the
    /// pack walk runs to genesis.
    ///
    /// M1 is single-ref: this reflects the one boundary-bearing (`Update`/`Delete`) command. With a
    /// multi-ref `updates` slice it would reflect only the last such command — multi-ref pack
    /// planning is upstream-generality only (Q5 / `dec-gixpush-ratify` item 3: rolfdb rides a single
    /// `refs/rolfdb/data`, so it is not on rolfdb's milestone track), not a scheduled M3 deliverable.
    pub boundary: Option<ObjectId>,
    /// The **full** advertised oid set — the server-known `DeltaOid` bases for thin packs (§3.6).
    /// May include host-repo refs that are not in the local ODB; never resolved locally, never a
    /// walk boundary.
    pub thin_bases: Vec<ObjectId>,
}

/// The error returned by [`plan_from_advertisement`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("stale lease for {name}: expected the server to advertise {expected:?}, but it advertised {actual:?}")]
    StaleLease {
        name: FullName,
        expected: Option<ObjectId>,
        actual: Option<ObjectId>,
    },
}

impl crate::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        false
    }
}

/// Plan a push from the advertisement: pre-check the leases (§2.1 layer a) and derive the advertised
/// sets the pack builder needs (F1).
///
/// A stale lease — for an `Update`/`Delete` the advertised oid differs from `expected_old`, or for a
/// `Create` the ref already exists — is [`Error::StaleLease`], surfaced before any bytes are sent.
/// A **hidden** ref (absent from the advertisement though it exists on a `hideRefs` host) reads as
/// "does not exist": an `Update` then surfaces as `StaleLease { actual: None }` rather than a blind
/// overwrite (F11).
pub fn plan_from_advertisement(updates: &[RefUpdate], handshake: &crate::Handshake) -> Result<Advertised, Error> {
    let refs = handshake.refs.as_deref().unwrap_or(&[]);

    // The full advertised oid set (server-known thin-delta bases). Includes every commit/tag oid a
    // real advertisement carries — our ref, plus, on a host repo, refs/heads/* and tags.
    let mut thin_bases = Vec::new();
    for r in refs {
        for oid in advertised_oids(r) {
            if !thin_bases.contains(&oid) {
                thin_bases.push(oid);
            }
        }
    }

    let mut boundary = None;
    for update in updates {
        let advertised = advertised_oid_of(refs, update.name().as_bstr());
        match update {
            RefUpdate::Create { name, .. } => {
                if advertised.is_some() {
                    return Err(Error::StaleLease {
                        name: name.clone(),
                        expected: None,
                        actual: advertised,
                    });
                }
            }
            RefUpdate::Update { name, expected_old, .. } => {
                if advertised != Some(*expected_old) {
                    return Err(Error::StaleLease {
                        name: name.clone(),
                        expected: Some(*expected_old),
                        actual: advertised,
                    });
                }
                boundary = Some(*expected_old);
            }
            RefUpdate::Delete { name, expected_old, .. } => {
                if advertised != Some(*expected_old) {
                    return Err(Error::StaleLease {
                        name: name.clone(),
                        expected: Some(*expected_old),
                        actual: advertised,
                    });
                }
            }
        }
    }

    Ok(Advertised { boundary, thin_bases })
}

/// The oid(s) a single advertised ref contributes to the server-known set. An unborn ref
/// contributes none (it has no object).
fn advertised_oids(r: &crate::handshake::Ref) -> Vec<ObjectId> {
    use crate::handshake::Ref::*;
    match r {
        // A `Peeled` (annotated tag) contributes BOTH oids: `tag` is the ref's stored value and
        // `object` is the commit it dereferences to — the server holds both, so both are valid
        // thin-delta bases. (This is the FULL set; `advertised_oid_of` below returns the single
        // *lease* oid, which is `tag` alone — the value the ref points AT.)
        Peeled { tag, object, .. } => vec![*tag, *object],
        // A `Symbolic` resolving through an annotated tag (`tag: Some`, e.g. `HEAD` → an annotated
        // `refs/tags/*`) is the same shape as `Peeled`: `tag` is what the ref refers to and
        // `object` is the peeled commit — the server holds both (`Ref::unpack` returns
        // `tag.unwrap_or(object)` / `object` as peeled). A `tag: None` symref (lightweight tag or a
        // plain branch target) contributes just its `object`, like `Direct` (rolfdb-gpx00b).
        Symbolic {
            tag: Some(tag), object, ..
        } => vec![*tag, *object],
        Direct { object, .. } | Symbolic { object, .. } => vec![*object],
        Unborn { .. } => Vec::new(),
    }
}

/// The advertised object id of `name`, or `None` when the ref is absent or unborn.
fn advertised_oid_of(refs: &[crate::handshake::Ref], name: &BStr) -> Option<ObjectId> {
    use crate::handshake::Ref::*;
    for r in refs {
        let (full, object) = match r {
            // For an annotated tag, `tag` is the ref's STORED value (what the ref points AT) and
            // `object` is the peeled commit. A force-with-lease compares `expected_old` to the
            // ref's stored value, so we must return `tag`, not the peeled `object` (rolfdb-gpx00).
            Peeled { full_ref_name, tag, .. } => (full_ref_name, Some(*tag)),
            Direct { full_ref_name, object } => (full_ref_name, Some(*object)),
            // A `Symbolic` resolving through an annotated tag (`tag: Some`) has the tag oid as its
            // STORED value — the same law as `Peeled`. `Ref::unpack` returns `tag.unwrap_or(object)`
            // as the oid the ref directly refers to, so the lease must compare against `tag` when
            // present and the peeled `object` otherwise (a `tag: None` symref) (rolfdb-gpx00b).
            Symbolic {
                full_ref_name,
                tag,
                object,
                ..
            } => (full_ref_name, Some(tag.unwrap_or(*object))),
            Unborn { full_ref_name, .. } => (full_ref_name, None),
        };
        // Matching is by `full_ref_name` ONLY — `Symbolic.target` is never consulted, so a caller
        // that expanded a symref to its TARGET name resolves through the target's own advertisement
        // line (`Peeled`/`Direct`), not this arm (rolfdb-gpx00b review note).
        if full.as_bstr() == name {
            return object;
        }
    }
    None
}
