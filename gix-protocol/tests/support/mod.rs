//! Shared test-support for the M1 push suites: real-git helpers, the pkt-line report builders, the
//! in-memory mock transport, and the wire-byte scanner. Lives in a subdirectory so cargo does not
//! treat it as its own test binary.

#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;

use bstr::{BStr, ByteSlice};
use gix_features::progress::{Discard, DynNestedProgress};
use gix_hash::ObjectId;
use gix_protocol::Handshake;
use gix_protocol::handshake::Ref;
use gix_protocol::push::{self, Context, Error, Options, Outcome, RefUpdate};
use gix_protocol::transport::client::Capabilities;
use gix_protocol::transport::client::blocking_io::{RequestWriter, SetServiceResponse, Transport};
use gix_protocol::transport::client::{
    Error as TransportError, MessageKind, TransportWithoutIO, WriteMode,
};
use gix_protocol::transport::packetline::PacketLineRef;
use gix_protocol::transport::packetline::blocking_io::StreamingPeekableIter;
use gix_protocol::transport::{Protocol, Service};

pub const REF: &str = "refs/rolfdb/data";

// ---------------------------------------------------------------------------------------------
// Value constructors
// ---------------------------------------------------------------------------------------------

pub fn oid_sha1(hex: &str) -> ObjectId {
    ObjectId::from_hex(hex.as_bytes()).expect("valid 40-hex sha1")
}

/// A SHA-256 object id built from a two-hex `pattern` repeated to 64 chars, or `None` when the
/// `gix-hash/sha256` feature is off (so callers self-skip the sha256 laws).
pub fn sha256_oid(pattern: &str) -> Option<ObjectId> {
    let hex = pattern.repeat(64 / pattern.len());
    ObjectId::from_hex(hex.as_bytes()).ok()
}

pub fn zeros(n: usize) -> String {
    "0".repeat(n)
}

pub fn full_name(name: &str) -> gix_ref::FullName {
    gix_ref::FullName::try_from(name).expect("valid full ref name")
}

pub fn create(name: &str, new: &ObjectId) -> RefUpdate {
    RefUpdate::Create {
        name: full_name(name),
        new: *new,
    }
}

pub fn update(name: &str, expected_old: &ObjectId, new: &ObjectId) -> RefUpdate {
    RefUpdate::Update {
        name: full_name(name),
        expected_old: *expected_old,
        new: *new,
    }
}

pub fn delete(name: &str, expected_old: &ObjectId) -> RefUpdate {
    RefUpdate::Delete {
        name: full_name(name),
        expected_old: *expected_old,
    }
}

pub fn once(triple: String) -> BTreeSet<String> {
    std::iter::once(triple).collect()
}

// ---------------------------------------------------------------------------------------------
// Handshake / advertisement builders
// ---------------------------------------------------------------------------------------------

/// Build a [`Capabilities`] set from a space-separated capability string (as advertised after the
/// NUL of the first ref line).
pub fn caps(list: &str) -> Capabilities {
    let bytes = format!("\0{list}");
    Capabilities::from_bytes(bytes.as_bytes())
        .expect("valid capabilities")
        .0
}

/// Build an advertised ref list (each a `Direct` ref).
pub fn advertise(refs: &[(&str, &ObjectId)]) -> Vec<Ref> {
    refs.iter()
        .map(|(name, oid)| Ref::Direct {
            full_ref_name: name.as_bytes().into(),
            object: **oid,
        })
        .collect()
}

pub fn handshake(capabilities: Capabilities, refs: Vec<Ref>) -> Handshake {
    Handshake {
        server_protocol_version: Protocol::V1,
        refs: Some(refs),
        v1_shallow_updates: None,
        capabilities,
    }
}

// ---------------------------------------------------------------------------------------------
// pkt-line report builders (server → client)
// ---------------------------------------------------------------------------------------------

fn pkt(payload: &str) -> Vec<u8> {
    let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
    v.extend_from_slice(payload.as_bytes());
    v
}

/// Frame the given report lines as pkt-lines (each with a trailing LF) terminated by a flush-pkt.
pub fn report_lines(lines: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend(pkt(&format!("{line}\n")));
    }
    out.extend_from_slice(b"0000");
    out
}

pub fn ok_report(refname: &str) -> Vec<u8> {
    report_lines(&["unpack ok", &format!("ok {refname}")])
}

pub fn multi_ok_report(refnames: &[&str]) -> Vec<u8> {
    let mut lines = vec!["unpack ok".to_string()];
    for r in refnames {
        lines.push(format!("ok {r}"));
    }
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    report_lines(&refs)
}

/// A canned report for pushes that are refused before any read happens.
pub fn no_report() -> Vec<u8> {
    Vec::new()
}

/// A minimal raw pack payload (its content is irrelevant to the mock — only the `PACK` magic and the
/// fact that bytes follow the single flush matter to the framing laws).
pub fn dummy_pack() -> Option<Vec<u8>> {
    Some(b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec())
}

// ---------------------------------------------------------------------------------------------
// The in-memory mock transport
// ---------------------------------------------------------------------------------------------

/// A `Transport` that captures every byte the client writes and replays a canned report. `push()`
/// never calls `handshake` (it takes an already-performed [`Handshake`] in its [`Context`]), so only
/// `request` and the `TransportWithoutIO` stubs are needed.
pub struct MockTransport {
    pub sent: Vec<u8>,
    report: StreamingPeekableIter<std::io::Cursor<Vec<u8>>>,
}

impl MockTransport {
    pub fn new(report: Vec<u8>) -> Self {
        MockTransport {
            sent: Vec::new(),
            report: StreamingPeekableIter::new(
                std::io::Cursor::new(report),
                &[PacketLineRef::Flush],
                false,
            ),
        }
    }
}

impl TransportWithoutIO for MockTransport {
    fn to_url(&self) -> Cow<'_, BStr> {
        Cow::Borrowed(b"mock://".as_bstr())
    }
    fn connection_persists_across_multiple_requests(&self) -> bool {
        false
    }
    fn configure(
        &mut self,
        _config: &dyn std::any::Any,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }
}

impl Transport for MockTransport {
    fn handshake<'a>(
        &mut self,
        _service: Service,
        _extra_parameters: &'a [(&'a str, Option<&'a str>)],
    ) -> Result<SetServiceResponse<'_>, TransportError> {
        unreachable!("push() does not call transport.handshake — it takes a Handshake in its Context")
    }

    fn request(
        &mut self,
        write_mode: WriteMode,
        on_into_read: MessageKind,
        trace: bool,
    ) -> Result<RequestWriter<'_>, TransportError> {
        Ok(RequestWriter::new_from_bufread(
            &mut self.sent,
            Box::new(self.report.as_read_without_sidebands()),
            write_mode,
            on_into_read,
            trace,
        ))
    }
}

// ---------------------------------------------------------------------------------------------
// push() drivers over the mock transport
// ---------------------------------------------------------------------------------------------

fn drive_mock(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> (Result<Outcome, Error>, Vec<u8>) {
    let mut hs = handshake(capabilities, refs);
    let mut transport = MockTransport::new(report);
    let user_agent = ("agent", Some(Cow::Borrowed("git/oxide-rolfdb-test")));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack = move |w: &mut dyn Write,
                           _p: &mut dyn DynNestedProgress,
                           _s: &AtomicBool|
          -> Result<(), std::io::Error> {
        if let Some(ref bytes) = pack {
            w.write_all(bytes)?;
        }
        Ok(())
    };
    let interrupt = AtomicBool::new(false);
    let result = push::push(updates, write_pack, Discard, &interrupt, ctx, opts);
    (result, transport.sent)
}

pub fn run_push_capture(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Vec<u8> {
    let (result, sent) = drive_mock(capabilities, refs, updates, pack, report, Options::default());
    result.expect("push succeeds");
    sent
}

pub fn run_push_ok(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Outcome {
    drive_mock(capabilities, refs, updates, pack, report, Options::default())
        .0
        .expect("push succeeds")
}

pub fn run_push_err(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    report: Vec<u8>,
) -> (Error, Vec<u8>) {
    let (result, sent) = drive_mock(capabilities, refs, updates, None, report, Options::default());
    (result.expect_err("push is refused"), sent)
}

pub fn run_push_err_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    report: Vec<u8>,
    opts: Options,
) -> (Error, Vec<u8>) {
    let (result, sent) = drive_mock(capabilities, refs, updates, None, report, opts);
    (result.expect_err("push is refused"), sent)
}

pub fn try_push(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Result<Outcome, Error> {
    drive_mock(capabilities, refs, updates, pack, report, Options::default()).0
}

// ---------------------------------------------------------------------------------------------
// Wire-byte scanner (parses the captured command list; stops at the raw pack)
// ---------------------------------------------------------------------------------------------

pub struct CommandScan {
    pub lines: Vec<Vec<u8>>,
    pub flushes: usize,
    pub pack: Option<Vec<u8>>,
}

impl CommandScan {
    /// The `<old> <new> <name>` triples (the payload before the NUL, trimmed).
    pub fn triples(&self) -> BTreeSet<String> {
        self.lines
            .iter()
            .map(|line| {
                let before = line.split(|b| *b == 0).next().unwrap_or(line);
                String::from_utf8_lossy(before).trim().to_string()
            })
            .collect()
    }

    /// How many command lines carry the NUL-separated capability list.
    pub fn lines_with_caps(&self) -> usize {
        self.lines.iter().filter(|line| line.contains(&0u8)).count()
    }
}

fn hex4(bytes: &[u8]) -> Option<usize> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
}

/// Parse the pkt-line command list out of the captured client bytes, counting flush-pkts and
/// capturing any raw pack that follows the first flush.
pub fn scan_command_list(buf: &[u8]) -> CommandScan {
    let mut pos = 0usize;
    let mut lines = Vec::new();
    let mut flushes = 0usize;
    let mut first_flush: Option<usize> = None;
    while pos + 4 <= buf.len() {
        let len = match hex4(&buf[pos..pos + 4]) {
            Some(n) => n,
            None => break, // reached the raw (non-pkt-framed) pack
        };
        if len == 0 {
            flushes += 1;
            if first_flush.is_none() {
                first_flush = Some(pos);
            }
            pos += 4;
            continue;
        }
        if len < 4 {
            pos += 4; // delimiter / response-end special pkt
            continue;
        }
        if pos + len > buf.len() {
            break;
        }
        lines.push(buf[pos + 4..pos + len].to_vec());
        pos += len;
    }
    let pack = first_flush.and_then(|f| {
        let start = f + 4;
        (start < buf.len()).then(|| buf[start..].to_vec())
    });
    CommandScan {
        lines,
        flushes,
        pack,
    }
}

// ---------------------------------------------------------------------------------------------
// Real-git helpers (dev-dependency of the FORK suite only — never rolfdb production)
// ---------------------------------------------------------------------------------------------

/// A unique-per-process scratch dir removed on every exit path (including a panicking assertion).
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "gix-push-m1-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
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

/// A `git` command in `dir` with a fixed identity + dates so commit oids are deterministic.
pub fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_AUTHOR_NAME", "m1")
        .env("GIT_AUTHOR_EMAIL", "m1@example.com")
        .env("GIT_COMMITTER_NAME", "m1")
        .env("GIT_COMMITTER_EMAIL", "m1@example.com")
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00 +0000")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00 +0000")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null");
    c
}

pub fn run(mut c: Command) -> (Vec<u8>, Vec<u8>) {
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

pub fn init_bare(base: &Path, path: &Path) {
    run({
        let mut c = git(base);
        c.args(["init", "-q", "--bare", path.to_str().unwrap()]);
        c
    });
}

pub fn init_work(base: &Path, path: &Path) {
    run({
        let mut c = git(base);
        c.args(["init", "-q", "-b", "main", path.to_str().unwrap()]);
        c
    });
}

/// Write `content` to `name`, commit it, and return the new HEAD oid (hex).
pub fn commit_file(dir: &Path, name: &str, content: &str) -> String {
    std::fs::write(dir.join(name), content).expect("write file");
    run({
        let mut c = git(dir);
        c.args(["add", name]);
        c
    });
    run({
        let mut c = git(dir);
        c.args(["commit", "-q", "-m", &format!("add {name}={content}")]);
        c
    });
    let (out, _) = run({
        let mut c = git(dir);
        c.args(["rev-parse", "HEAD"]);
        c
    });
    String::from_utf8(out).unwrap().trim().to_owned()
}

/// `git push -q <dir> <target> <spec>` (setup helper for the integration + oracle tests).
pub fn push_git(dir: &Path, target: &Path, spec: &str) {
    run({
        let mut c = git(dir);
        c.args(["push", "-q", target.to_str().unwrap(), spec]);
        c
    });
}

pub fn remote_ref(remote: &Path, refname: &str) -> String {
    let (out, _) = run({
        let mut c = git(remote);
        c.args(["rev-parse", refname]);
        c
    });
    String::from_utf8(out).unwrap().trim().to_owned()
}

/// The command triple(s) git's own `send-pack` writes for `spec`, extracted from a
/// `GIT_TRACE_PACKET=1 git push` capture (the empirical oracle).
pub fn git_push_triples(src: &Path, oracle: &Path, spec: &str) -> BTreeSet<String> {
    let (_out, trace) = run({
        let mut c = git(src);
        c.env("GIT_TRACE_PACKET", "1")
            .args(["push", "-q", oracle.to_str().unwrap(), spec]);
        c
    });
    let trace = String::from_utf8_lossy(&trace);
    let mut set = BTreeSet::new();
    for line in trace.lines() {
        if !line.contains(REF) {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        for w in toks.windows(3) {
            let third = w[2].split("\\0").next().unwrap_or(w[2]);
            if third == REF && is_oidish(w[0]) && is_oidish(w[1]) {
                set.insert(format!("{} {} {REF}", w[0], w[1]));
            }
        }
    }
    set
}

fn is_oidish(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Build a packfile via `git pack-objects --revs` from `includes` (positive tips) and `excludes`
/// (boundary tips, prefixed `^`). Mirrors the caller's §3.6 boundary walk.
pub fn git_pack(dir: &Path, includes: &[&str], excludes: &[&str]) -> Vec<u8> {
    let mut input = String::new();
    for i in includes {
        input.push_str(i);
        input.push('\n');
    }
    for e in excludes {
        input.push_str(&format!("^{e}\n"));
    }
    let mut child = git(dir)
        .args(["pack-objects", "--stdout", "--revs"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pack-objects");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "pack-objects failed");
    assert_eq!(&out.stdout[..4], b"PACK", "captured bytes are a real packfile");
    out.stdout
}

pub fn pack_object_count(pack: &[u8]) -> u32 {
    u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]])
}

fn file_url(path: &Path) -> String {
    format!("file://{}", path.to_str().unwrap())
}

/// Handshake `git-receive-pack` over `file://`, pinning Protocol::V1, and return the parsed
/// [`Handshake`] (its advertisement).
pub fn handshake_over_file(remote: &Path) -> Handshake {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        file_url(remote),
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .expect("connect file://");
    let mut progress = Discard;
    gix_protocol::handshake(
        &mut transport,
        Service::ReceivePack,
        |_action| unreachable!("file:// needs no auth"),
        Vec::new(),
        &mut progress,
    )
    .expect("receive-pack handshake")
}

/// Drive a real push over `file://` against `git-receive-pack`, streaming `pack` (if any) via the
/// `write_pack` closure.
pub fn push_over_file(remote: &Path, updates: &[RefUpdate], pack: Option<Vec<u8>>) -> Outcome {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        file_url(remote),
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .expect("connect file://");
    let mut hs = {
        let mut progress = Discard;
        gix_protocol::handshake(
            &mut transport,
            Service::ReceivePack,
            |_action| unreachable!("file:// needs no auth"),
            Vec::new(),
            &mut progress,
        )
        .expect("receive-pack handshake")
    };
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent: ("agent", Some(Cow::Borrowed("git/oxide-rolfdb-test"))),
        trace_packetlines: false,
    };
    let write_pack = move |w: &mut dyn Write,
                           _p: &mut dyn DynNestedProgress,
                           _s: &AtomicBool|
          -> Result<(), std::io::Error> {
        if let Some(ref bytes) = pack {
            w.write_all(bytes)?;
        }
        Ok(())
    };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, Options::default()).expect("push over file")
}
