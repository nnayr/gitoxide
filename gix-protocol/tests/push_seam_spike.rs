//! M0 write-seam spike (`gp01-u01`) — a checked-in **THROWAWAY** go/no-go integration test.
//!
//! It hand-rolls (M0's `push` module is empty — there is no real API yet) the exact §3.3/§3.4
//! send-pack recipe against the *real* `git-receive-pack` over `file://`:
//!
//!   handshake(ReceivePack) → drain V1 advertisement → request(Binary, Flush)
//!     → write ONE `create` command pkt-line (no trailing LF) → explicit flush-pkt
//!     → into_parts() → write the raw pack → **drop the writer before reading** (R2 deadlock)
//!     → read report-status → assert `unpack ok` + `ok refs/rolfdb/data`, and the ref now exists.
//!
//! It also captures `GIT_TRACE_PACKET=1 git push` against a second bare repo as a REAL oracle
//! and byte-diffs our command triple against git's own trace — empirically settling the
//! trailing-LF question of §1.3/§6.1 (git writes `<old> <new> <name>\0<caps>`, no LF).
//!
//! TEST-ENV DIVERGENCE (deliberate — plan §6 infra note): this fork-side suite invokes the
//! real `git` binary. `file://` runs `git-receive-pack`; `GIT_TRACE_PACKET=1` is the byte-diff
//! oracle. `git` is a dev/test dependency of the FORK suite ONLY — never rolfdb production,
//! whose `git+file` path stays on direct `gix-ref` CAS (§3.8) and whose network path is
//! pure-Rust gitoxide. This does NOT reintroduce a git-binary production dependency.
//!
//! Determinism: no RNG, no sleeps, no wall-clock in the test *logic*. The commit oid is pinned by
//! fixed identity + `GIT_*_DATE` env. The temp dir is keyed on the process id — that is
//! unique-per-process, NOT deterministic across runs; nothing in the assertions depends on it, and
//! it is reclaimed on every exit path (success or panic) by an RAII guard.
//!
//! Unix-only: the spike uses `file://` + real `git-receive-pack` and `/dev/null` config paths
//! (see the `#![cfg(unix)]` gate below); it is not meant to run on Windows.

// Gate on the two features the spike needs. Under any other feature set (e.g. the async build)
// this file compiles to an empty test binary — keeping the fork diff additive (no `[[test]]`
// entry in Cargo.toml, cargo auto-discovers `tests/*.rs`).
#![cfg(all(unix, feature = "push", feature = "blocking-client"))]

// RED marker: references the `push` module by path. Before the empty gated module exists this
// is an unresolved import (compile error = RED for the RIGHT reason, not a broken harness).
// Once the module is added it resolves (GREEN). Imported for its resolution side effect only.
#[allow(unused_imports)]
use gix_protocol::push;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gix_protocol::transport::Service;
use gix_protocol::transport::client::blocking_io::{ReadlineBufRead, Transport, connect};
use gix_protocol::transport::client::{MessageKind, WriteMode};

const REF: &str = "refs/rolfdb/data";

/// Fixed git identity + dates so the empty commit's oid is deterministic (no wall-clock).
fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_AUTHOR_NAME", "spike")
        .env("GIT_AUTHOR_EMAIL", "spike@example.com")
        .env("GIT_COMMITTER_NAME", "spike")
        .env("GIT_COMMITTER_EMAIL", "spike@example.com")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00 +0000")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00 +0000")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    c
}

fn run(mut c: Command) -> (Vec<u8>, Vec<u8>) {
    let out = c.output().expect("spawn git");
    assert!(
        out.status.success(),
        "git failed: {:?}\nstdout={}\nstderr={}",
        c,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.stdout, out.stderr)
}

/// A unique-per-process scratch dir (pid keyed — unique, not deterministic) that is removed on
/// EVERY exit path, including a panicking assertion, via its `Drop`. Deref lets it be used as a
/// `&Path` (`base.join(..)`).
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("gix-push-m0-spike-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        Scratch(dir)
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn m0_write_seam_create_over_file() {
    let base = Scratch::new();
    let remote = base.join("remote.git"); // target of OUR hand-rolled push
    let oracle = base.join("oracle.git"); // target of git's own push (the trace oracle)
    let src = base.join("src"); // source repo holding the commit + pack

    run({
        let mut c = git(&base);
        c.args(["init", "-q", "--bare", remote.to_str().unwrap()]);
        c
    });
    run({
        let mut c = git(&base);
        c.args(["init", "-q", "--bare", oracle.to_str().unwrap()]);
        c
    });
    run({
        let mut c = git(&base);
        c.args(["init", "-q", src.to_str().unwrap()]);
        c
    });
    run({
        let mut c = git(&src);
        c.args(["commit", "-q", "--allow-empty", "-m", "spike"]);
        c
    });

    let (out, _) = run({
        let mut c = git(&src);
        c.args(["rev-parse", "HEAD"]);
        c
    });
    let new_oid = String::from_utf8(out).unwrap().trim().to_owned();
    let zero = "0".repeat(new_oid.len()); // width from the oid = negotiated object-format (sha1 here)

    // Build the pack git-receive-pack must accept: the commit + its (empty) tree, self-contained.
    let pack = {
        let mut c = git(&src);
        c.args(["pack-objects", "--stdout", "--revs"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().expect("spawn pack-objects");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{new_oid}\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "pack-objects failed");
        out.stdout
    };
    assert_eq!(&pack[..4], b"PACK", "captured bytes are a real packfile");

    // --- the hand-rolled command line we will send (create): "<zero> <new> <ref>\0<caps>" ---
    let triple = format!("{zero} {new_oid} {REF}");
    let mut line: Vec<u8> = triple.clone().into_bytes();
    line.push(0); // NUL, then caps on the first (only) command line
    line.extend_from_slice(b"report-status");
    // Byte-level self-check: the command triple carries NO trailing LF; the byte right after the
    // ref name is the NUL (0x00), never 0x0A. This is the client half of the trailing-LF question.
    assert_eq!(
        line[triple.len()],
        0x00,
        "NUL directly follows the ref name (no trailing LF)"
    );
    assert!(!line[..triple.len()].contains(&0x0A), "command triple contains no LF");

    // --- drive the real transport: request(Binary) → command → flush → into_parts → pack → drop → read ---
    let url = format!("file://{}", remote.to_str().unwrap());
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: gix_protocol::transport::Protocol::V1, // keep the receive-pack advertisement inline (§1.6)
            ..Default::default()
        },
    )
    .expect("connect file://");

    // Low-level handshake (no auth / no progress needed for file://). Drain the V1 ref
    // advertisement before issuing the request, per the Transport contract.
    {
        let mut resp = transport
            .handshake(Service::ReceivePack, &[])
            .expect("receive-pack handshake");
        if let Some(refs) = resp.refs.as_mut() {
            let mut s = String::new();
            while refs.readline_str(&mut s).expect("read advertisement") > 0 {
                s.clear();
            }
        }
    } // drop resp → releases the &mut transport borrow

    let mut w = transport
        .request(WriteMode::Binary, MessageKind::Flush, true)
        .expect("open request");
    w.write_all(&line).expect("write command line"); // binary mode → one pkt-line, no LF appended
    w.write_message(MessageKind::Flush).expect("terminate command list"); // explicit flush before the pack

    let (mut raw, mut reader) = w.into_parts(); // raw = the verbatim pack channel (request.rs:101-113)
    raw.write_all(&pack).expect("write raw pack");
    raw.flush().expect("flush pack");
    drop(raw); // MUST drop before reading — the R2 deadlock warning (request.rs:106-110)

    let mut report = String::new();
    let mut l = String::new();
    while reader.readline_str(&mut l).expect("read report") > 0 {
        report.push_str(&l);
        l.clear();
    }
    assert!(
        report.contains("unpack ok"),
        "server accepted the pack; report:\n{report}"
    );
    assert!(
        report.contains(&format!("ok {REF}")),
        "server reported the ref updated; report:\n{report}"
    );
    drop(reader);
    drop(transport);

    // The ref now points at our commit, and no host refs were touched.
    let (out, _) = run({
        let mut c = git(&remote);
        c.args(["rev-parse", REF]);
        c
    });
    assert_eq!(
        String::from_utf8(out).unwrap().trim(),
        new_oid,
        "ref created at pushed oid"
    );
    let (heads, _) = run({
        let mut c = git(&remote);
        c.args(["for-each-ref", "--format=%(refname)", "refs/heads/"]);
        c
    });
    assert!(heads.is_empty(), "no refs/heads/* created by the push");

    // --- byte-diff oracle: capture git's OWN command line and compare our triple against it ---
    let (_, trace) = run({
        let mut c = git(&src);
        c.env("GIT_TRACE_PACKET", "1")
            .args(["push", oracle.to_str().unwrap(), &format!("HEAD:{REF}")]);
        c
    });
    let trace = String::from_utf8_lossy(&trace);
    // git logs the SAME update-command pkt-line from both ends (an outbound "push>" and the
    // receive-pack "<" read) — identical bytes, logged twice. Rather than guess the (git-version-
    // specific) direction label or count copies, collect EVERY line carrying our ref name AND the
    // NUL-escaped caps separator "\0", extract each triple (payload up to "\0", after the pkt
    // direction label, which is "> " or "< "), and require the whole set to be exactly our triple.
    // Label-agnostic, duplicate-tolerant, and never a bare `.unwrap()` that could red the primary
    // proof above on a trace-format drift.
    let git_triples: std::collections::BTreeSet<String> = trace
        .lines()
        .filter(|ln| ln.contains(REF) && ln.contains("\\0"))
        .map(|ln| {
            let payload = ln
                .rsplit_once("> ")
                .or_else(|| ln.rsplit_once("< "))
                .map_or(ln, |(_, r)| r);
            payload.split("\\0").next().unwrap().trim().to_owned()
        })
        .collect();
    assert_eq!(
        git_triples,
        std::iter::once(triple.clone()).collect::<std::collections::BTreeSet<_>>(),
        "git's captured command triple(s) byte-match ours and nothing else; trace:\n{trace}"
    );
    // git renders the ref name immediately followed by the NUL separator — NO literal LF between
    // the name and the caps. (Our own outbound bytes are checked directly at the `0x00` assert above.)
    assert!(
        trace.contains(&format!("{REF}\\0")),
        "git renders <ref>\\0<caps> with the NUL directly after the ref name — no trailing LF; trace:\n{trace}"
    );
    // `base` (Scratch) drops here — its temp tree is removed on this success path AND on any
    // earlier panic, so failing runs no longer accumulate leaked dirs under $TMPDIR.
}
