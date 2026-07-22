//! Shared test-support for the M1 push suites: real-git helpers, the pkt-line report builders, the
//! in-memory mock transport, and the wire-byte scanner. Lives in a subdirectory so cargo does not
//! treat it as its own test binary.

#![allow(dead_code)]
#![allow(unexpected_cfgs)] // `push_https_test` / `push_tls_test` / `push_async_daemon_test` are set via RUSTFLAGS by the `m2-https` / `m2-tls` / `m3-daemon` sync targets

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::{Read, Write};
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
#[cfg(feature = "blocking-client")]
use gix_protocol::transport::client::blocking_io::{RequestWriter, SetServiceResponse, Transport};
use gix_protocol::transport::client::{Error as TransportError, MessageKind, TransportWithoutIO, WriteMode};
use gix_protocol::transport::packetline::PacketLineRef;
#[cfg(feature = "blocking-client")]
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

/// An advertised annotated-tag ref (`Ref::Peeled`), the `<tag> refs/tags/x` + `<object>
/// refs/tags/x^{}` advertisement pair. `tag` is the ref's STORED value (the annotated-tag oid a
/// force-with-lease must match); `object` is the peeled commit it dereferences to (server-known,
/// but never the lease target). See `rolfdb-gpx00`.
pub fn peeled(name: &str, tag: &ObjectId, object: &ObjectId) -> Ref {
    Ref::Peeled {
        full_ref_name: name.as_bytes().into(),
        tag: *tag,
        object: *object,
    }
}

/// An advertised symbolic ref that resolves through an annotated tag (`Ref::Symbolic { tag:
/// Some(..) }`), e.g. `HEAD` → `refs/tags/v1` where `v1` is annotated. Like [`peeled`], its STORED
/// value — the oid it directly refers to — is the `tag` oid, not the peeled `object`
/// (`Ref::unpack` returns `tag.unwrap_or(object)`); `object` is the commit the tag dereferences to
/// (server-known, but never the lease target). See `rolfdb-gpx00b` (the `Symbolic` sibling of the
/// `Peeled` bug `rolfdb-gpx00`).
pub fn symref_tag(name: &str, target: &str, tag: &ObjectId, object: &ObjectId) -> Ref {
    Ref::Symbolic {
        full_ref_name: name.as_bytes().into(),
        target: target.as_bytes().into(),
        tag: Some(*tag),
        object: *object,
    }
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

/// One side-band pkt-line: `<4-hex-len><band-byte><payload>` (band 1 = data, 2 = progress, 3 = error).
pub fn band(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = format!("{:04x}", payload.len() + 1 + 4).into_bytes();
    v.push(channel);
    v.extend_from_slice(payload);
    v
}

/// Wrap an ordinary (already pkt-line-framed) report inside a single band-1 packet, then append the
/// OUTER flush-pkt that ends the side-band stream — the exact framing a real `git-receive-pack`
/// produces when `side-band-64k` is negotiated (verified against `GIT_TRACE_PACKET`). The inner
/// report keeps its own trailing flush-pkt as literal band-1 payload bytes.
pub fn sideband_report(report: &[u8]) -> Vec<u8> {
    let mut out = band(1, report);
    out.extend_from_slice(b"0000"); // outer flush
    out
}

/// Like [`sideband_report`] but splits the report across the given band-1 payload chunks (proving the
/// demux is robust to however the server fragments band 1). Interleaves the extra `progress`/`error`
/// band packets (channel, payload) at the front so band-2/3 routing is exercised too.
pub fn sideband_report_chunked(report_chunks: &[&[u8]], extra_bands: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (channel, payload) in extra_bands {
        out.extend_from_slice(&band(*channel, payload));
    }
    for chunk in report_chunks {
        out.extend_from_slice(&band(1, chunk));
    }
    out.extend_from_slice(b"0000"); // outer flush
    out
}

// ---------------------------------------------------------------------------------------------
// The in-memory mock transport
// ---------------------------------------------------------------------------------------------

/// A `Transport` that captures every byte the client writes and replays a canned report. `push()`
/// never calls `handshake` (it takes an already-performed [`Handshake`] in its [`Context`]), so only
/// `request` and the `TransportWithoutIO` stubs are needed.
#[cfg(feature = "blocking-client")]
pub struct MockTransport {
    pub sent: Vec<u8>,
    report: StreamingPeekableIter<std::io::Cursor<Vec<u8>>>,
}

#[cfg(feature = "blocking-client")]
impl MockTransport {
    pub fn new(report: Vec<u8>) -> Self {
        MockTransport {
            sent: Vec::new(),
            report: StreamingPeekableIter::new(std::io::Cursor::new(report), &[PacketLineRef::Flush], false),
        }
    }
}

#[cfg(feature = "blocking-client")]
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

#[cfg(feature = "blocking-client")]
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
// push() drivers over the mock transport (blocking)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "blocking-client")]
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
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    let result = push::push(updates, write_pack, Discard, &interrupt, ctx, opts);
    (result, transport.sent)
}

#[cfg(feature = "blocking-client")]
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

#[cfg(feature = "blocking-client")]
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

#[cfg(feature = "blocking-client")]
pub fn run_push_err(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    report: Vec<u8>,
) -> (Error, Vec<u8>) {
    let (result, sent) = drive_mock(capabilities, refs, updates, None, report, Options::default());
    (result.expect_err("push is refused"), sent)
}

#[cfg(feature = "blocking-client")]
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

/// [`run_push_capture`] with explicit [`Options`] (the M3 feature suites drive push-options /
/// side-band through the mock): returns the captured client wire bytes on success.
#[cfg(feature = "blocking-client")]
pub fn run_push_capture_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> Vec<u8> {
    let (result, sent) = drive_mock(capabilities, refs, updates, pack, report, opts);
    result.expect("push succeeds");
    sent
}

/// [`run_push_ok`] with explicit [`Options`]: returns the parsed [`Outcome`] on success.
#[cfg(feature = "blocking-client")]
pub fn run_push_ok_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> Outcome {
    drive_mock(capabilities, refs, updates, pack, report, opts)
        .0
        .expect("push succeeds")
}

/// A [`NestedProgress`] that RECORDS what reaches it — the positive proof that sideband band-2
/// (`set_name`/`init` via `translate_to_progress`) and band-3 (`fail` → `message(Failure)`) payloads
/// are actually ROUTED to the caller's progress, not merely tolerated (m3feat review F3).
#[cfg(feature = "blocking-client")]
#[derive(Clone, Default)]
pub struct CaptureProgress {
    /// `(kind, text)` — kind is `"name"` (set_name), `"msg:<level>"` (message), or `"init"`.
    pub events: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

#[cfg(feature = "blocking-client")]
impl CaptureProgress {
    fn record(&self, kind: &str, text: String) {
        self.events.lock().unwrap().push((kind.to_string(), text));
    }
    /// All recorded texts for `kind`.
    pub fn texts(&self, kind: &str) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(kind))
            .map(|(_, t)| t.clone())
            .collect()
    }
}

#[cfg(feature = "blocking-client")]
impl gix_features::progress::Count for CaptureProgress {
    fn set(&self, _step: usize) {}
    fn step(&self) -> usize {
        0
    }
    fn inc_by(&self, _step: usize) {}
    fn counter(&self) -> gix_features::progress::StepShared {
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::default())
    }
}

#[cfg(feature = "blocking-client")]
impl gix_features::progress::Progress for CaptureProgress {
    fn init(&mut self, _max: Option<usize>, _unit: Option<gix_features::progress::Unit>) {
        self.record("init", String::new());
    }
    fn set_max(&mut self, _max: Option<usize>) -> Option<usize> {
        None
    }
    fn set_name(&mut self, name: String) {
        self.record("name", name);
    }
    fn name(&self) -> Option<String> {
        None
    }
    fn id(&self) -> gix_features::progress::Id {
        gix_features::progress::UNKNOWN
    }
    fn message(&self, level: gix_features::progress::MessageLevel, message: String) {
        self.record(&format!("msg:{level:?}"), message);
    }
}

#[cfg(feature = "blocking-client")]
impl gix_features::progress::NestedProgress for CaptureProgress {
    type SubProgress = Self;
    fn add_child(&mut self, _name: impl Into<String>) -> Self {
        self.clone()
    }
    fn add_child_with_id(&mut self, _name: impl Into<String>, _id: gix_features::progress::Id) -> Self {
        self.clone()
    }
}

/// [`run_push_ok_opts`] with a caller-supplied progress — the sideband routing proof drives a
/// [`CaptureProgress`] through here.
#[cfg(feature = "blocking-client")]
pub fn run_push_ok_opts_with_progress<P>(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
    progress: P,
) -> Outcome
where
    P: gix_features::progress::NestedProgress,
    P::SubProgress: 'static,
{
    let mut hs = handshake(capabilities, refs);
    let mut transport = MockTransport::new(report);
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, progress, &interrupt, ctx, opts).expect("push succeeds")
}

#[cfg(feature = "blocking-client")]
pub fn try_push(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Result<Outcome, Error> {
    drive_mock(capabilities, refs, updates, pack, report, Options::default()).0
}

/// Drive `push()` with a caller-supplied, already-performed [`Handshake`] over the capturing
/// [`MockTransport`], returning push()'s result and the bytes it wrote. The report is never read on
/// a preflight refusal, so pass an empty one. Used to prove a refusal computed from a **real** server
/// advertisement (e.g. an `object-format=sha256` remote handshaked over `file://`) emits ZERO wire
/// bytes: the mock captures the writes, and preflight fails before `transport.request` is ever
/// called (F3), so the captured buffer stays empty.
#[cfg(feature = "blocking-client")]
pub fn run_push_err_with_handshake(mut hs: Handshake, updates: &[RefUpdate]) -> (Error, Vec<u8>) {
    let mut transport = MockTransport::new(no_report());
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    // Never invoked: preflight refuses before the pack path is reached.
    let write_pack =
        |_w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> { Ok(()) };
    let interrupt = AtomicBool::new(false);
    let result = push::push(updates, write_pack, Discard, &interrupt, ctx, Options::default());
    (
        result.expect_err("push is refused before any wire bytes"),
        transport.sent,
    )
}

/// The message the interrupt-lane `write_pack` closures bail with — asserted verbatim through the
/// `Error::WritePack` source chain so a test can prove the typed error is OUR interrupt, not some
/// unrelated I/O failure.
pub const INTERRUPT_MARKER: &str = "pack streaming interrupted by should_interrupt";

/// The `Interrupted` io error every interrupt-lane closure bails with after observing the flag.
pub fn interrupt_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Interrupted, INTERRUPT_MARKER)
}

/// The pkt-line-invalid report both interrupt suites hand the mock: parsing it errors, so a
/// `WritePack` result proves the response parser never ran (the no-report-read tripwire).
pub fn tripwire_report() -> Vec<u8> {
    b"NOT-A-PKT-LINE-REPORT".to_vec()
}

/// Assert `err` is `Error::WritePack` carrying the interrupt-lane closure's `Interrupted` io error
/// verbatim through the source chain — the typed-error law shared by the blocking and async suites.
pub fn assert_writepack_interrupt(err: &Error) {
    match err {
        Error::WritePack(source) => {
            let io = source
                .downcast_ref::<std::io::Error>()
                .expect("the closure's io::Error is preserved, not stringified");
            assert_eq!(io.kind(), std::io::ErrorKind::Interrupted, "kind survives verbatim");
            assert_eq!(io.to_string(), INTERRUPT_MARKER, "message survives verbatim");
        }
        other => panic!("expected Error::WritePack, got {other:?}"),
    }
}

/// Drive `push()` with a `write_pack` that emulates the CALLER's pack machinery observing
/// `should_interrupt` mid-stream (§6.3-11): it writes the first `cut` bytes of `pack`, flips the
/// flag (as `gix-pack`'s writer does when it notices the abort request), and bails with
/// [`interrupt_error`]. Returns push()'s error and the captured wire bytes; panics if push()
/// swallows the abort or the flag was not left flipped.
#[cfg(feature = "blocking-client")]
pub fn run_push_interrupt(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Vec<u8>,
    cut: usize,
    report: Vec<u8>,
) -> (Error, Vec<u8>) {
    use std::sync::atomic::Ordering;
    let mut hs = handshake(capabilities, refs);
    let mut transport = MockTransport::new(report);
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, s: &AtomicBool| -> Result<(), std::io::Error> {
            w.write_all(&pack[..cut])?;
            s.store(true, Ordering::SeqCst);
            Err(interrupt_error())
        };
    let interrupt = AtomicBool::new(false);
    let result = push::push(updates, write_pack, Discard, &interrupt, ctx, Options::default());
    assert!(
        interrupt.load(Ordering::SeqCst),
        "push() hands the CALLER's should_interrupt through to write_pack (the flip is visible after return)"
    );
    (
        result.expect_err("an interrupted pack stream must fail the push"),
        transport.sent,
    )
}

// ---------------------------------------------------------------------------------------------
// push() driver over the mock transport (async, milestone M3) — the async twin of the blocking
// MockTransport + drive_mock above. Behind `async-client` so the shared support still compiles for
// the blocking suites (which never see these items).
// ---------------------------------------------------------------------------------------------

/// The async twin of [`MockTransport`]: captures every byte the client writes (into an async
/// `Cursor` so `&mut self.sent` is a `futures_io::AsyncWrite`) and replays a canned report through
/// the async packetline reader. Only `request` + the `TransportWithoutIO` stubs are exercised by
/// `push()`.
#[cfg(feature = "async-client")]
pub struct AsyncMockTransport {
    sent: gix_protocol::futures_lite::io::Cursor<Vec<u8>>,
    report: gix_protocol::transport::packetline::async_io::StreamingPeekableIter<
        gix_protocol::futures_lite::io::Cursor<Vec<u8>>,
    >,
}

#[cfg(feature = "async-client")]
impl AsyncMockTransport {
    pub fn new(report: Vec<u8>) -> Self {
        use gix_protocol::futures_lite::io::Cursor;
        use gix_protocol::transport::packetline::async_io::StreamingPeekableIter;
        AsyncMockTransport {
            sent: Cursor::new(Vec::new()),
            report: StreamingPeekableIter::new(Cursor::new(report), &[PacketLineRef::Flush], false),
        }
    }

    /// The bytes captured so far (the pkt-line command list, flushes, and any raw pack).
    pub fn sent(&self) -> &[u8] {
        self.sent.get_ref()
    }
}

#[cfg(feature = "async-client")]
impl TransportWithoutIO for AsyncMockTransport {
    fn to_url(&self) -> Cow<'_, BStr> {
        Cow::Borrowed(b"mock-async://".as_bstr())
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

#[cfg(feature = "async-client")]
#[gix_protocol::async_trait::async_trait(?Send)]
impl gix_protocol::transport::client::async_io::Transport for AsyncMockTransport {
    async fn handshake<'a>(
        &mut self,
        _service: Service,
        _extra_parameters: &'a [(&'a str, Option<&'a str>)],
    ) -> Result<gix_protocol::transport::client::async_io::SetServiceResponse<'_>, TransportError> {
        unreachable!("push() does not call transport.handshake — it takes a Handshake in its Context")
    }

    fn request(
        &mut self,
        write_mode: WriteMode,
        on_into_read: MessageKind,
        trace: bool,
    ) -> Result<gix_protocol::transport::client::async_io::RequestWriter<'_>, TransportError> {
        Ok(
            gix_protocol::transport::client::async_io::RequestWriter::new_from_bufread(
                &mut self.sent,
                Box::new(self.report.as_read_without_sidebands()),
                write_mode,
                on_into_read,
                trace,
            ),
        )
    }
}

/// Drive `push()` (async) over an [`AsyncMockTransport`] under `block_on`, returning the outcome and
/// the captured client bytes. Mirrors the blocking [`drive_mock`]; the pack (if any) is streamed by
/// an async `write_pack` closure — the exact `AsyncFnOnce` seam the M0 spike proved.
#[cfg(feature = "async-client")]
pub fn drive_mock_async(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> (Result<Outcome, Error>, Vec<u8>) {
    use gix_protocol::futures_lite::AsyncWriteExt;
    let mut hs = handshake(capabilities, refs);
    let mut transport = AsyncMockTransport::new(report);
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack = async move |w: &mut (dyn gix_protocol::futures_io::AsyncWrite + Unpin),
                                 _p: &mut dyn DynNestedProgress,
                                 _s: &AtomicBool|
                -> Result<(), std::io::Error> {
        if let Some(ref bytes) = pack {
            w.write_all(bytes).await?;
        }
        Ok(())
    };
    let interrupt = AtomicBool::new(false);
    let result =
        gix_protocol::futures_lite::future::block_on(push::push(updates, write_pack, Discard, &interrupt, ctx, opts));
    let sent = transport.sent().to_vec();
    (result, sent)
}

/// Convenience: async push expected to succeed, returning the [`Outcome`].
#[cfg(feature = "async-client")]
pub fn run_push_ok_async(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Outcome {
    drive_mock_async(capabilities, refs, updates, pack, report, Options::default())
        .0
        .expect("push succeeds")
}

/// Convenience: async push expected to succeed, returning the captured client bytes.
#[cfg(feature = "async-client")]
pub fn run_push_capture_async(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
) -> Vec<u8> {
    let (result, sent) = drive_mock_async(capabilities, refs, updates, pack, report, Options::default());
    result.expect("push succeeds");
    sent
}

/// Convenience: async push expected to be refused, returning the [`Error`] and the captured client
/// bytes. Mirrors the blocking [`run_push_err`] — no pack is streamed on the refusal paths, and the
/// captured bytes let a test assert a preflight refusal (F3/F5) emitted ZERO wire bytes.
#[cfg(feature = "async-client")]
pub fn run_push_err_async(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    report: Vec<u8>,
) -> (Error, Vec<u8>) {
    let (result, sent) = drive_mock_async(capabilities, refs, updates, None, report, Options::default());
    (result.expect_err("push is refused"), sent)
}

/// Async twin of [`run_push_capture_opts`]: the captured client bytes on success.
#[cfg(feature = "async-client")]
pub fn run_push_capture_async_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> Vec<u8> {
    let (result, sent) = drive_mock_async(capabilities, refs, updates, pack, report, opts);
    result.expect("push succeeds");
    sent
}

/// Async twin of [`run_push_ok_opts`]: the parsed [`Outcome`] on success.
#[cfg(feature = "async-client")]
pub fn run_push_ok_async_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    report: Vec<u8>,
    opts: Options,
) -> Outcome {
    drive_mock_async(capabilities, refs, updates, pack, report, opts)
        .0
        .expect("push succeeds")
}

/// Async twin of [`run_push_err_opts`]: the [`Error`] and captured bytes on a refusal.
#[cfg(feature = "async-client")]
pub fn run_push_err_async_opts(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    report: Vec<u8>,
    opts: Options,
) -> (Error, Vec<u8>) {
    let (result, sent) = drive_mock_async(capabilities, refs, updates, None, report, opts);
    (result.expect_err("push is refused"), sent)
}

/// The async twin of [`run_push_interrupt`]: the `AsyncFnOnce` `write_pack` streams the first `cut`
/// bytes, flips `should_interrupt`, and bails with [`interrupt_error`]. Returns push()'s error and
/// the captured wire bytes.
#[cfg(feature = "async-client")]
pub fn run_push_interrupt_async(
    capabilities: Capabilities,
    refs: Vec<Ref>,
    updates: &[RefUpdate],
    pack: Vec<u8>,
    cut: usize,
    report: Vec<u8>,
) -> (Error, Vec<u8>) {
    use std::sync::atomic::Ordering;

    use gix_protocol::futures_lite::AsyncWriteExt;
    let mut hs = handshake(capabilities, refs);
    let mut transport = AsyncMockTransport::new(report);
    let user_agent = ("agent", Some("git/oxide-rolfdb-test".to_owned()));
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent,
        trace_packetlines: false,
    };
    let write_pack = async move |w: &mut (dyn gix_protocol::futures_io::AsyncWrite + Unpin),
                                 _p: &mut dyn DynNestedProgress,
                                 s: &AtomicBool|
                -> Result<(), std::io::Error> {
        w.write_all(&pack[..cut]).await?;
        s.store(true, Ordering::SeqCst);
        Err(interrupt_error())
    };
    let interrupt = AtomicBool::new(false);
    let result = gix_protocol::futures_lite::future::block_on(push::push(
        updates,
        write_pack,
        Discard,
        &interrupt,
        ctx,
        Options::default(),
    ));
    assert!(
        interrupt.load(Ordering::SeqCst),
        "push() hands the CALLER's should_interrupt through to the async write_pack"
    );
    let sent = transport.sent().to_vec();
    (result.expect_err("an interrupted pack stream must fail the push"), sent)
}

// ---------------------------------------------------------------------------------------------
// Real async transport driver — git:// (git-daemon) over the async-std TCP connector.
//
// Gated on `push_async_daemon_test` (set only by the `m3-daemon` sync target) because the async
// `connect()` compiles ONLY under `gix-transport/async-std`, which the default M3 build
// (`async-client` alone) does not enable. `git://` is the ONE real-binary transport the async
// client supports: `client::async_io::connect` handles only `Scheme::Git` and returns
// `UnsupportedScheme` for everything else — there is NO async connector for `file://`, http/https,
// or ssh upstream (the blocking `client::blocking_io` has `file.rs`/`http/`/`ssh/`; `async_io` has
// none). See docs/process/gix-push-impl-workflow.md §5 for the full scope note.
// ---------------------------------------------------------------------------------------------

/// Drive a real async `push()` over a `git://` URL against a live `git-receive-pack` (spawned by
/// [`GitDaemon`]), streaming `pack` (if any) via the `AsyncFnOnce` `write_pack` seam. The async twin
/// of the blocking [`push_over_url`]; connects with the async-std TCP connector under
/// `futures_lite::block_on` (async-std drives its own I/O reactor on a background thread, so any
/// executor may poll the top future). `git://` never authenticates, so the auth closure is a
/// `unreachable!`.
#[cfg(push_async_daemon_test)]
pub fn push_over_url_async(
    url: &str,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    opts: Options,
) -> Result<Outcome, Error> {
    use gix_protocol::futures_lite::AsyncWriteExt;
    use gix_protocol::transport::client::async_io::connect;
    gix_protocol::futures_lite::future::block_on(async move {
        let mut transport = connect::connect(
            url,
            connect::Options {
                version: Protocol::V1,
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("async connect {url}: {e}"));
        let mut hs = {
            let mut progress = Discard;
            gix_protocol::handshake(
                &mut transport,
                Service::ReceivePack,
                |_action| unreachable!("git:// needs no auth"),
                Vec::new(),
                &mut progress,
            )
            .await
            .unwrap_or_else(|e| panic!("async receive-pack handshake over {url}: {e}"))
        };
        let ctx = Context {
            handshake: &mut hs,
            transport: &mut transport,
            user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
            trace_packetlines: false,
        };
        let write_pack = async move |w: &mut (dyn gix_protocol::futures_io::AsyncWrite + Unpin),
                                     _p: &mut dyn DynNestedProgress,
                                     _s: &AtomicBool|
                    -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes).await?;
            }
            Ok(())
        };
        let interrupt = AtomicBool::new(false);
        push::push(updates, write_pack, Discard, &interrupt, ctx, opts).await
    })
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

    /// The space-separated capability tokens carried after the NUL of the first command line that
    /// has one (empty when no line carries caps). Lets a test assert an opt-in capability was echoed
    /// (e.g. `quiet`, `atomic`) without matching a bare substring of another token.
    pub fn first_line_caps(&self) -> BTreeSet<String> {
        self.lines
            .iter()
            .find(|line| line.contains(&0u8))
            .and_then(|line| line.splitn(2, |b| *b == 0).nth(1))
            .map(|caps| {
                String::from_utf8_lossy(caps)
                    .split_whitespace()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
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
    CommandScan { lines, flushes, pack }
}

/// A structural view of a push wire request that MAY carry a push-options block (§1.3): the command
/// list, then (optionally) the push-options block, then (optionally) the raw pack. Distinguishes the
/// option block from the pack by the fact that the pack begins with the non-pkt-line `PACK` magic.
pub struct PushWire {
    pub command_lines: Vec<Vec<u8>>,
    pub push_options: Vec<Vec<u8>>,
    pub flushes: usize,
    pub pack: Option<Vec<u8>>,
}

impl PushWire {
    pub fn command_triples(&self) -> BTreeSet<String> {
        self.command_lines
            .iter()
            .map(|line| {
                let before = line.split(|b| *b == 0).next().unwrap_or(line);
                String::from_utf8_lossy(before).trim().to_string()
            })
            .collect()
    }

    /// The push-option payloads as UTF-8 strings, in wire order.
    pub fn option_strings(&self) -> Vec<String> {
        self.push_options
            .iter()
            .map(|o| String::from_utf8_lossy(o).to_string())
            .collect()
    }
}

/// Parse a captured push request into its command list, push-options block, and pack (§1.3). Walks
/// pkt-lines: the first flush ends the command list; if what follows is another pkt-line (not the
/// `PACK` magic) it is the push-options block, ended by a second flush; anything non-pkt-line is the
/// raw pack.
pub fn scan_push_wire(buf: &[u8]) -> PushWire {
    let mut pos = 0usize;
    let mut command_lines = Vec::new();
    let mut push_options = Vec::new();
    let mut flushes = 0usize;
    let mut phase = 0u8; // 0 = commands, 1 = push-options
    let mut pack_start: Option<usize> = None;
    while pos + 4 <= buf.len() {
        let len = match hex4(&buf[pos..pos + 4]) {
            Some(n) => n,
            None => {
                pack_start = Some(pos); // reached the raw (non-pkt-framed) pack
                break;
            }
        };
        if len == 0 {
            flushes += 1;
            pos += 4;
            if phase == 0 {
                phase = 1; // command-list flush → next block is push-options or the pack
            } else {
                // second flush terminates the push-options block; the pack (if any) follows raw
                if pos < buf.len() {
                    pack_start = Some(pos);
                }
                break;
            }
            continue;
        }
        if len < 4 {
            pos += 4; // delimiter / response-end special pkt
            continue;
        }
        if pos + len > buf.len() {
            break;
        }
        let payload = buf[pos + 4..pos + len].to_vec();
        if phase == 0 {
            command_lines.push(payload);
        } else {
            push_options.push(payload);
        }
        pos += len;
    }
    let pack = pack_start.and_then(|s| (s < buf.len()).then(|| buf[s..].to_vec()));
    PushWire {
        command_lines,
        push_options,
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
            "gix-push-{}-{:?}",
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

/// Create an ANNOTATED tag `tag_name` at `HEAD` in the work repo `dir` (a real tag OBJECT, not a
/// lightweight ref), returning its tag-object oid (hex). The fixed identity/date env (see [`git`])
/// keeps the tag oid deterministic. `git rev-parse <tag_name>` then yields the tag object; its
/// `^{}` peel is the commit — the annotated-tag lease law (rolfdb-gpx00) turns on that distinction.
pub fn tag_annotated(dir: &Path, tag_name: &str) -> String {
    run({
        let mut c = git(dir);
        c.args(["tag", "-a", tag_name, "-m", &format!("annotated {tag_name}")]);
        c
    });
    let (out, _) = run({
        let mut c = git(dir);
        c.args(["rev-parse", tag_name]);
        c
    });
    String::from_utf8(out).unwrap().trim().to_owned()
}

/// Set a git config key on `dir` (e.g. `receive.unpackLimit`, `http.receivepack`).
pub fn git_config(dir: &Path, key: &str, value: &str) {
    run({
        let mut c = git(dir);
        c.args(["config", key, value]);
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

/// The `git rev-list`-style stdin for `pack-objects --revs`: positive `includes` then `^`-prefixed
/// `excludes` (the §3.6 boundary tips).
fn revs_stdin(includes: &[&str], excludes: &[&str]) -> String {
    let mut input = String::new();
    for i in includes {
        input.push_str(i);
        input.push('\n');
    }
    for e in excludes {
        input.push('^');
        input.push_str(e);
        input.push('\n');
    }
    input
}

/// Run `git pack-objects --stdout --revs <extra_args>` over the `includes`/`excludes` rev walk and
/// return the raw packfile bytes.
fn pack_objects(dir: &Path, extra_args: &[&str], includes: &[&str], excludes: &[&str]) -> Vec<u8> {
    let mut args = vec!["pack-objects", "--stdout", "--revs"];
    args.extend_from_slice(extra_args);
    let mut child = git(dir)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pack-objects");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(revs_stdin(includes, excludes).as_bytes())
        .expect("write revs to pack-objects");
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "pack-objects {extra_args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(&out.stdout[..4], b"PACK", "captured bytes are a real packfile");
    out.stdout
}

/// Build a packfile via `git pack-objects --revs` from `includes` (positive tips) and `excludes`
/// (boundary tips, prefixed `^`). Mirrors the caller's §3.6 boundary walk.
pub fn git_pack(dir: &Path, includes: &[&str], excludes: &[&str]) -> Vec<u8> {
    pack_objects(dir, &[], includes, excludes)
}

/// Like [`git_pack`] but emits a **thin** pack (`--thin`): delta entries may reference bases the
/// server is assumed to already have (the excluded boundary tips). The server must run
/// `index-pack --fix-thin` to complete it — the M2 gate proves it does (§6.3-4, R1).
pub fn git_pack_thin(dir: &Path, includes: &[&str], excludes: &[&str]) -> Vec<u8> {
    pack_objects(dir, &["--thin", "--delta-base-offset"], includes, excludes)
}

/// Build a **valid 0-object** packfile the way git does — an empty rev walk (no positive tips)
/// produces the canonical 32-byte pack: the 12-byte v2 header (`PACK`, version 2, count 0) followed
/// by its real 20-byte SHA-1 trailer. Unlike [`dummy_pack`] (a trailer-less mock fixture that only
/// exercises framing), a real `git-receive-pack` accepts THIS pack when the server already holds
/// every referenced object (§6.3-5).
pub fn git_empty_pack(dir: &Path) -> Vec<u8> {
    let pack = git_pack(dir, &[], &[]);
    assert_eq!(pack_object_count(&pack), 0, "an empty rev walk yields a 0-object pack");
    pack
}

/// Whether the host `git` can create a SHA-256 repository — probed by an actual
/// `git init --bare --object-format=sha256` in a throwaway dir (removed before returning). Lets the
/// sha256 laws self-skip on a git built without SHA-256 support instead of failing spuriously.
pub fn sha256_supported(base: &Path) -> bool {
    let probe = base.join("sha256-probe.git");
    let ok = git(base)
        .args([
            "init",
            "-q",
            "--bare",
            "--object-format=sha256",
            probe.to_str().unwrap(),
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    let _ = std::fs::remove_dir_all(&probe);
    ok
}

/// `git init --bare --object-format=<fmt>` at `path` (the sha256-remote refusal law, §6.3-10).
pub fn init_bare_object_format(base: &Path, path: &Path, object_format: &str) {
    run({
        let mut c = git(base);
        c.args([
            "init",
            "-q",
            "--bare",
            &format!("--object-format={object_format}"),
            path.to_str().unwrap(),
        ]);
        c
    });
}

/// Point the bare repo's `HEAD` at `target` (e.g. `refs/heads/main`) so `HEAD` resolves
/// deterministically regardless of the host git's `init.defaultBranch`.
pub fn set_head(remote: &Path, target: &str) {
    run({
        let mut c = git(remote);
        c.args(["symbolic-ref", "HEAD", target]);
        c
    });
}

pub fn pack_object_count(pack: &[u8]) -> u32 {
    u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]])
}

fn file_url(path: &Path) -> String {
    format!("file://{}", path.to_str().unwrap())
}

/// Handshake `git-receive-pack` over `file://`, pinning Protocol::V1, and return the parsed
/// [`Handshake`] (its advertisement).
#[cfg(feature = "blocking-client")]
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
#[cfg(feature = "blocking-client")]
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
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, Options::default()).expect("push over file")
}

/// [`push_over_file`] with explicit [`Options`] — the real-`git-receive-pack` driver the M3 feature
/// suites use to prove push-options and side-band-64k end-to-end over `file://` (git's own
/// `receive-pack` frames the sideband report and surfaces the push-options to its hooks).
#[cfg(feature = "blocking-client")]
pub fn push_over_file_opts(remote: &Path, updates: &[RefUpdate], pack: Option<Vec<u8>>, opts: Options) -> Outcome {
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
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, opts).expect("push over file with opts")
}

/// Whether the handshake advertisement for `git-receive-pack` over `file://` at `remote` contains the
/// given capability (e.g. `push-options`, `side-band-64k`). Lets a real-server test self-verify the
/// precondition (and skip loudly if the host git is too old to advertise it).
#[cfg(feature = "blocking-client")]
pub fn advertises_capability(remote: &Path, capability: &str) -> bool {
    handshake_over_file(remote).capabilities.contains(capability)
}

/// The interrupted twin of [`push_over_file`]: streams only the first `cut` bytes of `pack` to the
/// real `git-receive-pack`, flips `should_interrupt`, and bails with [`interrupt_error`] — the
/// §6.3-11 fault lane against a real server. Returns push()'s error (the caller asserts the remote
/// ref never moved).
#[cfg(feature = "blocking-client")]
pub fn push_over_file_interrupted(remote: &Path, updates: &[RefUpdate], pack: Vec<u8>, cut: usize) -> Error {
    use std::sync::atomic::Ordering;

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
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, s: &AtomicBool| -> Result<(), std::io::Error> {
            w.write_all(&pack[..cut])?;
            w.flush()?; // the truncated prefix actually reaches receive-pack before the abort
            s.store(true, Ordering::SeqCst);
            Err(interrupt_error())
        };
    let interrupt = AtomicBool::new(false);
    let result = push::push(updates, write_pack, Discard, &interrupt, ctx, Options::default());
    assert!(
        interrupt.load(Ordering::SeqCst),
        "push() hands the CALLER's should_interrupt through to write_pack over file://"
    );
    result.expect_err("an interrupted pack stream must fail the push")
}

/// Whether `refname` resolves on the remote — the non-asserting probe the interrupt lane uses to
/// prove a ref was NEVER created (where [`remote_ref`] would abort the test).
pub fn remote_has_ref(remote: &Path, refname: &str) -> bool {
    git(remote)
        .args(["rev-parse", "--verify", "--quiet", refname])
        .output()
        .expect("spawn git rev-parse")
        .status
        .success()
}

// ---------------------------------------------------------------------------------------------
// M2 (gp01-u03): generic transport drivers — git:// (daemon) and git+https (http-backend)
// ---------------------------------------------------------------------------------------------

/// Handshake `git-receive-pack` over any `url`, pinning Protocol::V1 (§1.6), and return the parsed
/// [`Handshake`]. `auth` supplies credentials for transports that request them (git:// / file://
/// never do — pass a panicking closure there).
#[cfg(feature = "blocking-client")]
pub fn handshake_over_url(
    url: &str,
    auth: impl FnMut(gix_protocol::credentials::helper::Action) -> gix_protocol::credentials::protocol::Result,
) -> Handshake {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    let mut progress = Discard;
    gix_protocol::handshake(&mut transport, Service::ReceivePack, auth, Vec::new(), &mut progress)
        .unwrap_or_else(|e| panic!("receive-pack handshake over {url}: {e}"))
}

/// Drive a real push over any `url` against `git-receive-pack`, streaming `pack` (if any). `opts`
/// selects capabilities (e.g. `report_status_v2`); `auth` supplies credentials on demand.
#[cfg(feature = "blocking-client")]
pub fn push_over_url(
    url: &str,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    opts: Options,
    mut auth: impl FnMut(gix_protocol::credentials::helper::Action) -> gix_protocol::credentials::protocol::Result,
) -> Result<Outcome, Error> {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    let mut hs = {
        let mut progress = Discard;
        gix_protocol::handshake(
            &mut transport,
            Service::ReceivePack,
            &mut auth,
            Vec::new(),
            &mut progress,
        )
        .unwrap_or_else(|e| panic!("receive-pack handshake over {url}: {e}"))
    };
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, opts)
}

/// The panicking auth closure for transports that must never request credentials (git://, file://).
#[cfg(feature = "blocking-client")]
pub fn no_auth(_action: gix_protocol::credentials::helper::Action) -> gix_protocol::credentials::protocol::Result {
    unreachable!("this transport must not request credentials")
}

/// Pick a free localhost TCP port by binding to :0 and releasing it. There is a TOCTOU window before
/// the caller re-binds, and cargo runs tests on parallel threads in one process — so callers that
/// CAN hold the socket should ([`HttpBackend`] binds once); [`GitDaemon`] must hand the port to an
/// external process, relies on `--reuseaddr`, and asserts its daemon actually won the port.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

/// Block until `127.0.0.1:port` accepts a TCP connection, or panic after ~15s (generous for a cold
/// CI runner spawning `git daemon`). Replaces a fixed sleep so the harness stays deterministic.
pub fn wait_for_port(port: u16) {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(15);
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("server on {addr} did not come up within 5s");
}

/// A `git daemon` serving `base_path` over git:// on a random port with receive-pack enabled.
/// Killed on drop. The served repo URL is `git://127.0.0.1:<port>/<name>`.
pub struct GitDaemon {
    child: std::process::Child,
    pub port: u16,
}

impl GitDaemon {
    /// Spawn a receive-pack-enabled daemon rooted at `base_path` (an already-created dir holding the
    /// bare repos). `--informative-errors` surfaces real messages instead of the generic refusal.
    pub fn serve(base_path: &Path) -> Self {
        let port = free_port();
        let mut child = git(base_path)
            .args([
                "daemon",
                "--reuseaddr",
                "--listen=127.0.0.1",
                &format!("--port={port}"),
                &format!("--base-path={}", base_path.to_str().unwrap()),
                "--export-all",
                "--enable=receive-pack",
                "--informative-errors",
                // Trailing positional = the allowlisted directory tree; with --base-path above, both
                // point at the same root (the whitelist git daemon serves).
                base_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn git daemon");
        wait_for_port(port);
        // Guard the (tiny) free_port TOCTOU window: if our daemon lost the port race and exited, the
        // socket now answering belongs to someone else — fail loudly instead of pushing to the wrong
        // repo. (`--reuseaddr` already covers the common TIME_WAIT case.)
        if let Ok(Some(status)) = child.try_wait() {
            panic!("git daemon on port {port} exited early ({status}); the ephemeral port was likely taken");
        }
        GitDaemon { child, port }
    }

    /// The git:// URL for the bare repo `name` (e.g. `remote.git`) under the base path.
    pub fn url(&self, name: &str) -> String {
        format!("git://127.0.0.1:{}/{name}", self.port)
    }
}

impl Drop for GitDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------------------------
// M2 (gp01-u03-fu1, gap G8): a test-local `sshd` fixture for the `git+ssh://` transport. ssh is a
// §5-M2 deliverable and a rolfdb production transport (F15). Unlike git:///http://, gix drives ssh
// by spawning the `ssh` BINARY (`gix-transport::client::blocking_io::ssh`), so this fixture stands
// up a throwaway OpenSSH server we own end-to-end — generated host + client keys, a pinned
// `known_hosts`, a minimal `sshd -f` config, a random high port — and hands the caller an `ssh`
// command string that points the client at exactly those keys/port (never the developer's real
// `~/.ssh`). Killed on drop. The suite that uses it is `#[ignore]`-gated (needs a real `sshd`),
// so this support only compiles into the normal M2 build; it never runs there.
// ---------------------------------------------------------------------------------------------

/// A non-root OpenSSH `sshd` serving the current user over `ssh://` on a random loopback port,
/// authenticating a generated client key only. Killed on drop. Pair with [`Self::url`] +
/// [`push_over_ssh`], which pins the client at this server's identity/`known_hosts`.
///
/// Environment it needs (documented on the `#[ignore]`-gated suite): `/usr/sbin/sshd`, `ssh`, and
/// `ssh-keygen` on `PATH`, and a `git-receive-pack` reachable from the login shell of the current
/// user (the remote command `sshd` runs). Everything else — keys, config, host verification — is
/// self-contained in a scratch dir.
pub struct SshServer {
    child: std::process::Child,
    dir: PathBuf,
    user: String,
    key: PathBuf,
    known_hosts: PathBuf,
    pub port: u16,
}

impl SshServer {
    /// Generate keys + a minimal `sshd_config` under `base_path/ssh`, then spawn `sshd` in the
    /// foreground on a random loopback port. Panics with an actionable message if `sshd`/`ssh-keygen`
    /// are missing or `sshd` refuses the config (e.g. an over-permissive host key).
    pub fn serve(base_path: &Path) -> Self {
        let dir = base_path.join("ssh");
        std::fs::create_dir_all(&dir).expect("mkdir ssh fixture dir");
        let host_key = dir.join("host_ed25519");
        let client_key = dir.join("client_ed25519");
        let authorized_keys = dir.join("authorized_keys");
        let known_hosts = dir.join("known_hosts");
        let config = dir.join("sshd_config");
        let log = dir.join("sshd.log");
        let user = std::env::var("USER")
            .ok()
            .filter(|u| !u.is_empty())
            .or_else(|| {
                Command::new("id")
                    .arg("-un")
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            })
            .expect("determine the current user for the ssh login");

        // Generate the server host key and the client identity (ed25519, no passphrase). ssh-keygen
        // writes the private keys 0600, which sshd requires for the host key regardless of StrictModes.
        keygen(&host_key);
        keygen(&client_key);
        // Only our generated client key may log in.
        let client_pub = std::fs::read(client_key.with_extension("pub")).expect("read client pubkey");
        write_600(&authorized_keys, &client_pub);
        // Pin the server host key in a private known_hosts so StrictHostKeyChecking=yes verifies it
        // without any prompt or trust-on-first-use: `[127.0.0.1]:<port> <type> <base64>`.
        let host_pub = String::from_utf8(std::fs::read(host_key.with_extension("pub")).expect("read host pubkey"))
            .expect("host pubkey utf8");
        let mut host_fields = host_pub.split_whitespace();
        let (host_type, host_b64) = (
            host_fields.next().expect("host key type"),
            host_fields.next().expect("host key base64"),
        );

        let port = free_port();
        std::fs::write(&known_hosts, format!("[127.0.0.1]:{port} {host_type} {host_b64}\n"))
            .expect("write known_hosts");

        // Minimal, non-root sshd config: loopback only, pubkey-only, no PAM. UsePrivilegeSeparation is
        // obsolete/removed in modern OpenSSH; nothing to set. StrictModes off so the scratch dir's
        // perms don't trip the auth check (the host key itself is still 0600 from ssh-keygen).
        let cfg = format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {authorized_keys}\n\
             PidFile {pid}\n\
             AllowUsers {user}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             UsePAM no\n\
             PermitUserEnvironment no\n\
             StrictModes no\n\
             PrintMotd no\n\
             X11Forwarding no\n\
             AllowTcpForwarding no\n\
             LogLevel ERROR\n",
            host_key = host_key.display(),
            authorized_keys = authorized_keys.display(),
            pid = dir.join("sshd.pid").display(),
            user = user,
        );
        std::fs::write(&config, cfg).expect("write sshd_config");

        // `-D` keeps sshd in the foreground so the child handle owns its lifetime; `-e` routes logs to
        // stderr, which we capture to a file for post-mortem on failure. Absolute config path required.
        let log_file = std::fs::File::create(&log).expect("create sshd log");
        let child = Command::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn /usr/sbin/sshd (is OpenSSH sshd installed?): {e}"));
        let mut server = SshServer {
            child,
            dir,
            user,
            key: client_key,
            known_hosts,
            port,
        };
        // sshd binds the port then accepts; wait for it, and fail loudly (with its log) if it exited
        // early — a bad config or a lost free_port race, not a repo we should silently push nowhere.
        if !port_comes_up(port) {
            let log = std::fs::read_to_string(server.dir.join("sshd.log")).unwrap_or_default();
            let status = server.child.try_wait().ok().flatten();
            panic!("sshd on port {port} did not come up (exit {status:?}); sshd.log:\n{log}");
        }
        if let Ok(Some(status)) = server.child.try_wait() {
            let log = std::fs::read_to_string(server.dir.join("sshd.log")).unwrap_or_default();
            panic!("sshd on port {port} exited early ({status}); sshd.log:\n{log}");
        }
        server
    }

    /// The `git+ssh://` URL for the bare repo at absolute path `remote` (e.g. `base.join("remote.git")`).
    /// The path is absolute so the remote `git-receive-pack '<path>'` resolves regardless of the login
    /// shell's working directory.
    pub fn url(&self, remote: &Path) -> String {
        assert!(
            remote.is_absolute(),
            "ssh remote path must be absolute: {}",
            remote.display()
        );
        format!("ssh://{}@127.0.0.1:{}{}", self.user, self.port, remote.display())
    }

    /// The `ssh` command string handed to gix's ssh transport: our client identity + pinned
    /// `known_hosts` only, the user's real `~/.ssh` config bypassed (`-F none`), and no interactive
    /// prompts (`BatchMode=yes`, `StrictHostKeyChecking=yes`). gix appends `-p<port>` and `user@host`.
    ///
    /// gix runs this string through `sh -c '<command> "$@"'`, so the embedded paths MUST be
    /// single-quoted: the [`Scratch`] dir contains `ThreadId(N)` and sh chokes on the bare parens
    /// (any space would break word-splitting too).
    pub fn ssh_command(&self) -> std::ffi::OsString {
        std::ffi::OsString::from(format!(
            "ssh -F none -o IdentitiesOnly=yes -i '{key}' \
             -o UserKnownHostsFile='{known_hosts}' -o GlobalKnownHostsFile=/dev/null \
             -o StrictHostKeyChecking=yes -o BatchMode=yes -o PasswordAuthentication=no",
            key = self.key.display(),
            known_hosts = self.known_hosts.display(),
        ))
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `ssh-keygen -t ed25519 -N "" -f <path>` — an unencrypted key pair (`<path>` + `<path>.pub`).
fn keygen(path: &Path) {
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("spawn ssh-keygen (is OpenSSH installed?): {e}"));
    assert!(
        out.status.success(),
        "ssh-keygen for {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Write `bytes` to `path` with 0600 perms (authorized_keys must not be group/world writable).
fn write_600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).expect("write file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}

/// Like [`wait_for_port`] but returns `false` instead of panicking, so [`SshServer::serve`] can attach
/// the captured sshd log to its own failure message.
fn port_comes_up(port: u16) -> bool {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(15);
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Drive a real push over `git+ssh://` against `git-receive-pack`, pinning the client at `server`'s
/// generated identity + `known_hosts` (via `ssh.command`) and forcing `ProgramKind::Ssh` so gix adds
/// the `-p<port>` flag (a multi-word ssh command would otherwise be misclassified as the port-less
/// `Simple` kind). Mirrors [`push_over_url`] otherwise. ssh never asks us for credentials — the key
/// is on the command line — so the auth closure is [`no_auth`].
#[cfg(feature = "blocking-client")]
pub fn push_over_ssh(
    server: &SshServer,
    url: &str,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    opts: Options,
) -> Result<Outcome, Error> {
    use gix_protocol::transport::client::blocking_io::connect;
    use gix_protocol::transport::client::blocking_io::ssh::ProgramKind;
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: Protocol::V1,
            ssh: gix_protocol::transport::client::blocking_io::ssh::connect::Options {
                command: Some(server.ssh_command()),
                kind: Some(ProgramKind::Ssh),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    let mut hs = {
        let mut progress = Discard;
        gix_protocol::handshake(&mut transport, Service::ReceivePack, no_auth, Vec::new(), &mut progress)
            .unwrap_or_else(|e| panic!("receive-pack handshake over {url}: {e}"))
    };
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, opts)
}

/// Run `git fsck --strict` on a bare repo and assert it exits clean (no dangling/broken objects).
/// The arbiter of the M2 thin-pack "server can apply it" gate (§6.3-4).
pub fn fsck_clean(remote: &Path) {
    let out = git(remote)
        .args(["fsck", "--strict", "--no-progress"])
        .output()
        .expect("spawn git fsck");
    assert!(
        out.status.success(),
        "git fsck on {} was not clean:\nstdout={}\nstderr={}",
        remote.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------------------------
// M2 git+https: a minimal std-only HTTP/1.1 server that runs `git-http-backend` as a CGI. Enough
// of the smart-http contract for gix's client: GET info/refs?service=git-receive-pack + the
// POST git-receive-pack body. Optional Basic-auth gate exercises the credential-retry path (§6.4).
// Pure std (no hyper) to keep the fork's dev-deps minimal.
// ---------------------------------------------------------------------------------------------

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Auth policy for [`HttpBackend`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HttpAuth {
    /// No `Authorization` required.
    None,
    /// Reject any request without an `Authorization: Basic …` header with 401 (+ `WWW-Authenticate`)
    /// so the client runs its credential helper and retries. Any non-empty credential is accepted.
    Basic,
}

/// A background `git-http-backend` CGI server over HTTP on a random port. Killed on drop.
pub struct HttpBackend {
    pub port: u16,
    shutdown: Arc<AtomicBool>,
    /// The chunk count of the most recent chunked POST body (0 if the last POST used Content-Length).
    /// Lets a test prove the `WriteMode::Binary → Unbounded` pack body genuinely streamed as multiple
    /// `Transfer-Encoding: chunked` chunks rather than a single buffered body.
    last_post_chunks: Arc<AtomicUsize>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HttpBackend {
    /// Serve the bare repos under `project_root` (already created) with `auth` policy.
    pub fn serve(project_root: &Path, auth: HttpAuth) -> Self {
        // Bind ONCE to an ephemeral port and keep the listener — no bind/release/re-bind, which would
        // race another test under cargo's parallel threads (an `AddrInUse` flake).
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind http backend");
        let port = listener.local_addr().expect("local_addr").port();
        listener.set_nonblocking(true).expect("nonblocking listener");
        let shutdown = Arc::new(AtomicBool::new(false));
        let last_post_chunks = Arc::new(AtomicUsize::new(0));
        let root = project_root.to_path_buf();
        let exec_path = git_exec_path();
        let flag = shutdown.clone();
        let chunks = last_post_chunks.clone();
        let handle = std::thread::spawn(move || {
            // One worker thread per accepted connection so a second concurrent connection is not
            // blocked behind the first (which could stall on its read timeout). All workers are
            // joined before this accept thread returns, so Drop reaps everything.
            let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let (root, exec_path, chunks, stop) =
                            (root.clone(), exec_path.clone(), chunks.clone(), flag.clone());
                        workers.push(std::thread::spawn(move || {
                            // Ignore per-connection errors so one bad client cannot wedge the harness.
                            let _ = handle_connection(stream, &root, &exec_path, auth, &chunks, &stop);
                        }));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });
        wait_for_port(port);
        HttpBackend {
            port,
            shutdown,
            last_post_chunks,
            handle: Some(handle),
        }
    }

    /// The http:// URL for the bare repo `name` (e.g. `remote.git`).
    pub fn url(&self, name: &str) -> String {
        format!("http://127.0.0.1:{}/{name}", self.port)
    }

    /// The number of chunks in the most recent chunked POST body (0 if it used Content-Length).
    pub fn last_post_chunks(&self) -> usize {
        self.last_post_chunks.load(Ordering::Relaxed)
    }
}

impl Drop for HttpBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Nudge the accept loop out of its sleep with a throwaway connection.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn git_exec_path() -> PathBuf {
    let out = Command::new("git")
        .arg("--exec-path")
        .output()
        .expect("git --exec-path");
    PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// A minimal buffered reader over a `TcpStream`: keeps leftover bytes between requests (keep-alive)
/// and supports the two request-body framings gix's http client emits — `Content-Length` (small,
/// buffered bodies) and `Transfer-Encoding: chunked` (the streaming `WriteMode::Binary → Unbounded`
/// pack body).
struct ConnReader<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: Read + Write> ConnReader<S> {
    fn new(stream: S) -> Self {
        ConnReader {
            stream,
            buf: Vec::new(),
        }
    }

    /// Pull more bytes from the socket into `buf`. `Ok(false)` == a **clean** EOF (peer closed with
    /// no bytes pending); a read-timeout (`WouldBlock` on the blocking, `SO_RCVTIMEO`-armed socket)
    /// is a real error — NOT EOF — so a stalled client surfaces loudly instead of silently truncating
    /// the request body (M2-2). The accepted socket is set blocking before any wrapping — in
    /// `handle_connection` on the plaintext path, in `handle_tls_connection` on the TLS path
    /// (M2-1) — so `WouldBlock` here can only mean the timeout fired.
    fn fill(&mut self) -> std::io::Result<bool> {
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk) {
            Ok(0) => Ok(false),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timed out waiting for request bytes",
            )),
            Err(e) => Err(e),
        }
    }

    /// Read one header block (through CRLFCRLF) and return it, or `None` at connection end (a clean
    /// EOF between requests is normal keep-alive shutdown, not an error).
    fn read_headers(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = find_subslice(&self.buf, b"\r\n\r\n") {
                let end = pos + 4;
                let headers = self.buf[..end].to_vec();
                self.buf.drain(..end);
                return Ok(Some(headers));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    /// Read exactly `n` body bytes (Content-Length framing). A clean EOF before `n` bytes is a
    /// truncated request — an error, not a short read (M2-2).
    fn read_exact_body(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        while self.buf.len() < n {
            if !self.fill()? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before the declared Content-Length",
                ));
            }
        }
        let body = self.buf[..n].to_vec();
        self.buf.drain(..n);
        Ok(body)
    }

    /// Decode a `Transfer-Encoding: chunked` body into its raw bytes and the number of data chunks.
    /// A clean EOF before the terminating 0-chunk is a truncated body — an error (M2-2).
    fn read_chunked_body(&mut self) -> std::io::Result<(Vec<u8>, usize)> {
        let mut body = Vec::new();
        let mut chunk_count = 0usize;
        loop {
            // A chunk-size line, then CRLF, then that many data bytes, then CRLF.
            let size_line = loop {
                if let Some(pos) = find_subslice(&self.buf, b"\r\n") {
                    let line = self.buf[..pos].to_vec();
                    self.buf.drain(..pos + 2);
                    break line;
                }
                if !self.fill()? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed mid chunk-size line",
                    ));
                }
            };
            let size_str = String::from_utf8_lossy(&size_line);
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
            if size == 0 {
                // Terminating chunk: consume the trailing CRLF (and any trailers up to the blank line).
                loop {
                    if let Some(pos) = find_subslice(&self.buf, b"\r\n") {
                        self.buf.drain(..pos + 2);
                        break;
                    }
                    if !self.fill()? {
                        break; // EOF right after the 0 chunk; the body is already complete.
                    }
                }
                return Ok((body, chunk_count));
            }
            while self.buf.len() < size + 2 {
                if !self.fill()? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed mid chunk data",
                    ));
                }
            }
            body.extend_from_slice(&self.buf[..size]);
            self.buf.drain(..size + 2); // data + its trailing CRLF
            chunk_count += 1;
        }
    }
}

/// Handle every keep-alive request on one connection until the client closes it.
fn handle_connection(
    stream: TcpStream,
    root: &Path,
    exec_path: &Path,
    auth: HttpAuth,
    last_post_chunks: &AtomicUsize,
    shutdown: &AtomicBool,
) -> std::io::Result<()> {
    // The accepted socket can inherit the listener's O_NONBLOCK (it does on macOS/BSD, this repo's
    // test platform), and set_read_timeout does NOT clear that — an immediate `WouldBlock` would then
    // read as EOF and silently truncate the request. Force blocking so the read timeout governs (M2-1).
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    serve_requests(
        ConnReader::new(stream),
        root,
        exec_path,
        auth,
        last_post_chunks,
        shutdown,
    )
}

/// Drive every keep-alive request on one already-established connection until the client closes it.
/// Generic over the byte stream (`S: Read + Write`) so the identical CGI bridge serves both the
/// plaintext `http://` harness ([`HttpBackend`], a raw `TcpStream`) and the `https://` harness
/// ([`TlsBackend`], a rustls TLS stream). Socket-level setup (blocking mode, read timeout) is done by
/// the caller on the raw `TcpStream` before any TLS wrapping, so it governs identically either way.
fn serve_requests<S: Read + Write>(
    mut conn: ConnReader<S>,
    root: &Path,
    exec_path: &Path,
    auth: HttpAuth,
    last_post_chunks: &AtomicUsize,
    shutdown: &AtomicBool,
) -> std::io::Result<()> {
    loop {
        // Return promptly on server shutdown rather than blocking a keep-alive read until the timeout,
        // so HttpBackend::drop (which joins this worker) does not stall (C2).
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        let header_bytes = match conn.read_headers()? {
            Some(h) => h,
            None => return Ok(()), // client closed between requests
        };
        let headers = String::from_utf8_lossy(&header_bytes).to_string();
        let mut lines = headers.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        let mut content_length = 0usize;
        let mut content_type = String::new();
        let mut has_auth = false;
        let mut chunked = false;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = lower.strip_prefix("content-type:") {
                content_type = v.trim().to_string();
            } else if lower.starts_with("authorization:") {
                has_auth = true;
            } else if let Some(v) = lower.strip_prefix("transfer-encoding:") {
                chunked = v.contains("chunked");
            }
        }

        // Consume the request body under whichever framing the client used, and record the chunk
        // count so a test can prove the streaming (chunked) path was taken (M2-3).
        let body = if chunked {
            let (body, chunk_count) = conn.read_chunked_body()?;
            last_post_chunks.store(chunk_count, Ordering::Relaxed);
            body
        } else {
            if method == "POST" {
                last_post_chunks.store(0, Ordering::Relaxed);
            }
            conn.read_exact_body(content_length)?
        };

        let stream = &mut conn.stream;

        // Basic-auth gate: challenge an unauthenticated request so the client retries.
        if auth == HttpAuth::Basic && !has_auth {
            let resp =
                b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(resp)?;
            stream.flush()?;
            continue;
        }

        // Split "/repo.git/service" into PATH_INFO and QUERY_STRING.
        let (path, query) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };

        let cgi = Command::new(exec_path.join("git-http-backend"))
            .env("GIT_PROJECT_ROOT", root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", &method)
            .env("PATH_INFO", &path)
            .env("QUERY_STRING", &query)
            .env("CONTENT_TYPE", &content_type)
            .env("CONTENT_LENGTH", body.len().to_string())
            .env("REMOTE_USER", "tester")
            .env("REMOTE_ADDR", "127.0.0.1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut cgi = match cgi {
            Ok(c) => c,
            Err(_) => {
                let resp = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                stream.write_all(resp)?;
                continue;
            }
        };
        cgi.stdin.take().unwrap().write_all(&body)?;
        let out = cgi.wait_with_output()?;

        // The CGI output is a header block, a blank line, then the body. Translate to HTTP.
        let cgi_out = out.stdout;
        let sep = find_subslice(&cgi_out, b"\r\n\r\n")
            .map(|p| (p, p + 4))
            .or_else(|| find_subslice(&cgi_out, b"\n\n").map(|p| (p, p + 2)));
        let (cgi_headers, cgi_body) = match sep {
            Some((h, b)) => (String::from_utf8_lossy(&cgi_out[..h]).to_string(), &cgi_out[b..]),
            None => (String::new(), &cgi_out[..]),
        };

        let mut status = "200 OK".to_string();
        let mut passthrough = String::new();
        for line in cgi_headers.split('\n').map(|l| l.trim_end_matches('\r')) {
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("status:") {
                status = v.trim().to_string();
            } else if lower.starts_with("content-length:") {
                // We synthesize our own Content-Length below; forwarding the CGI's too would emit a
                // duplicate header that reqwest rejects (M2-5). git-http-backend omits it on smart
                // responses today, but guard the latent double-header.
            } else {
                passthrough.push_str(line);
                passthrough.push_str("\r\n");
            }
        }
        // Surface CGI stderr on a non-2xx status so a misconfigured backend is a legible failure
        // under `--nocapture`, not an opaque transport error (M7).
        if !status.starts_with('2') && !out.stderr.is_empty() {
            eprintln!(
                "git-http-backend {status} for {method} {target}:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let mut resp = format!(
            "HTTP/1.1 {status}\r\n{passthrough}Content-Length: {}\r\n\r\n",
            cgi_body.len()
        )
        .into_bytes();
        resp.extend_from_slice(cgi_body);
        stream.write_all(&resp)?;
        stream.flush()?;
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A fixed-credential auth closure for the git+https Basic-auth test — returns `user:pass` on the
/// `Get` action and no-ops the store/erase actions (matching a real credential helper's contract).
///
/// Gated on `push_https_test` (set only by the `m2-https` sync target) because building an
/// [`Account`](gix_sec::identity::Account) needs `gix-sec`, a dev-dep that only that target pulls in.
#[cfg(push_https_test)]
pub fn static_credentials(
    action: gix_protocol::credentials::helper::Action,
) -> gix_protocol::credentials::protocol::Result {
    use gix_protocol::credentials::helper::Action;
    match action {
        Action::Get(ctx) => Ok(Some(gix_protocol::credentials::protocol::Outcome {
            identity: gix_sec::identity::Account {
                username: "tester".into(),
                password: "secret".into(),
                oauth_refresh_token: None,
            },
            next: ctx.into(),
        })),
        Action::Store(_) | Action::Erase(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------------------------
// M2 git+https-over-TLS (gp01-u03-fu3, testplan G8): a rustls TLS listener wrapping the SAME
// git-http-backend CGI bridge (`serve_requests`), presenting a freshly generated self-signed rcgen
// cert. It proves two things about the production reqwest/rustls transport and the TLS seam:
//
//   * NEGATIVE (the production path): a push handshake over `https://` via the reqwest/rustls client
//     performs a real TLS handshake (the server records the ClientHello) and is REJECTED because the
//     self-signed cert is untrusted — i.e. certificate verification is genuinely enforced, not a
//     no-op. This is the leg the m2-https harness never exercised (it connected over plain http://).
//   * POSITIVE (the trust differential): a rustls client that ADDS the same rcgen cert as a root
//     completes the full smart-http advertisement over that identical TLS endpoint. Same server,
//     same cert — so the only variable between success and the reqwest rejection is trust, pinning
//     the reqwest failure to certificate verification rather than a malformed cert or broken CGI.
//
// fu4 (rolfdb fork): a *trusted* reqwest push IS now reachable. Upstream's reqwest backend built its
// `reqwest::blocking::Client` once with an empty-root config and plumbed NONE of `http::Options`' TLS
// fields (`ssl_ca_info`/`ssl_verify`/`ssl_version` — honored only by the curl backend). The fork
// patches the backend (gix-transport/.../reqwest/remote.rs, via scripts/gix-push-sync.sh's
// `sync_transport`) to build the client LAZILY per request and honor those fields — TLS-trust parity
// with the curl backend, closing the gap at https://github.com/GitoxideLabs/gitoxide/issues/1109
// (curl side: PR #1142; connect_timeout/http_version stay unwired, out of fu4 scope). So a
// client that points `ssl_ca_info` at this server's self-signed cert completes a REAL green push over
// the production reqwest/rustls transport — see `reqwest_rustls_trusted_ca_completes_green_push`,
// driven by `push_over_url_trusting_ca`. Without that trust root, verification is still enforced and
// the push is rejected (the negative leg), so the trust differential holds end-to-end. (fu3+fu4.)
//
// TLS-only: everything here is gated on `push_tls_test` (set by the `m2-tls` sync target) so the
// rustls + rcgen dev-deps are pulled for this lane alone, exactly as `push_https_test` gates gix-sec.
// ---------------------------------------------------------------------------------------------

#[cfg(push_tls_test)]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// A background HTTPS `git-http-backend` CGI server on a random port, presenting a self-signed rcgen
/// cert for `localhost`. Reuses the plaintext harness's [`serve_requests`] CGI bridge over a rustls
/// TLS stream. No auth — the TLS layer is what is under test. Killed on drop.
#[cfg(push_tls_test)]
pub struct TlsBackend {
    pub port: u16,
    shutdown: Arc<AtomicBool>,
    /// Set when the server observed a TLS ClientHello (first record byte `0x16`) on any connection —
    /// positive proof the client spoke TLS, surviving a later cert-verification abort.
    saw_tls: Arc<AtomicBool>,
    /// Set when the server DROVE a TLS handshake to completion on any connection. A client that
    /// distrusts the self-signed cert sends a fatal alert instead of finishing, so this stays false
    /// while `saw_tls` is true — the precise signature of a client-side certificate rejection.
    handshake_completed: Arc<AtomicBool>,
    /// The server's self-signed cert (DER); a trusting client adds it as a root.
    cert_der: CertificateDer<'static>,
    /// The same self-signed cert as PEM (fu4): written out as a `ca.pem` the reqwest backend can load
    /// via `http.sslCAInfo` so the PRODUCTION transport can trust it — not only a hand-rolled client.
    cert_pem: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(push_tls_test)]
impl TlsBackend {
    /// Serve the bare repos under `project_root` over HTTPS with a freshly generated self-signed
    /// cert (SAN `localhost`, so `https://localhost:<port>/…` passes hostname verification for a
    /// client that trusts the cert).
    pub fn serve(project_root: &Path) -> Self {
        // 1. Generate a self-signed cert for `localhost` — pure Rust, no `openssl` binary dependency.
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate self-signed cert");
        let cert_der: CertificateDer<'static> = cert.der().clone();
        // fu4: keep the PEM form too, so `write_ca_pem` can hand the reqwest backend a CA bundle.
        let cert_pem = cert.pem();
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

        // 2. rustls server config with an EXPLICIT crypto provider: reqwest does not install a
        //    process-default `CryptoProvider`, so `ServerConfig::builder()` (which requires one) would
        //    panic. `builder_with_provider` sidesteps that and matches reqwest's aws-lc-rs provider.
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("rustls default protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], PrivateKeyDer::Pkcs8(key_der))
                .expect("valid cert + key"),
        );

        // 3. Accept loop — mirrors `HttpBackend` (bind once, nonblocking listener, one worker per
        //    connection, all joined on drop) but wraps each accepted socket in TLS before the bridge.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls backend");
        let port = listener.local_addr().expect("local_addr").port();
        listener.set_nonblocking(true).expect("nonblocking listener");
        let shutdown = Arc::new(AtomicBool::new(false));
        let saw_tls = Arc::new(AtomicBool::new(false));
        let handshake_completed = Arc::new(AtomicBool::new(false));
        let root = project_root.to_path_buf();
        let exec_path = git_exec_path();
        let flag = shutdown.clone();
        let saw = saw_tls.clone();
        let completed = handshake_completed.clone();
        let handle = std::thread::spawn(move || {
            let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let (root, exec_path, cfg, saw, completed, stop) = (
                            root.clone(),
                            exec_path.clone(),
                            server_config.clone(),
                            saw.clone(),
                            completed.clone(),
                            flag.clone(),
                        );
                        workers.push(std::thread::spawn(move || {
                            let _ = handle_tls_connection(stream, &root, &exec_path, cfg, &saw, &completed, &stop);
                        }));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });
        wait_for_port(port);
        TlsBackend {
            port,
            shutdown,
            saw_tls,
            handshake_completed,
            cert_der,
            cert_pem,
            handle: Some(handle),
        }
    }

    /// The `https://` URL for the bare repo `name`. Host is `localhost` to match the cert's SAN.
    /// PLATFORM ASSUMPTION: the listener binds `127.0.0.1` while clients dial `localhost`, so
    /// `localhost` must resolve to include `127.0.0.1` (true on the supported macOS/Linux test
    /// hosts; an IPv6-only `localhost` would surface as a connect failure, not a false pass).
    pub fn url(&self, name: &str) -> String {
        format!("https://localhost:{}/{name}", self.port)
    }

    /// The server's self-signed cert (DER) — a trusting rustls client adds it as a root.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// Whether the server ever observed a TLS ClientHello — proof a client actually spoke TLS
    /// (rather than plaintext or never connecting), even when the handshake later fails verification.
    pub fn saw_tls_client_hello(&self) -> bool {
        self.saw_tls.load(Ordering::Relaxed)
    }

    /// Whether the server ever drove a TLS handshake to completion. False after a client rejects the
    /// self-signed cert (it aborts with a fatal alert before finishing); true for a trusting client.
    pub fn completed_tls_handshake(&self) -> bool {
        self.handshake_completed.load(Ordering::Relaxed)
    }

    /// fu4: write the server's self-signed cert as `ca.pem` under `dir` and return the path, so it can
    /// be handed to the reqwest backend as `http.sslCAInfo` (a CA bundle it trusts). Makes the SAME
    /// cert trustable through the PRODUCTION reqwest/rustls transport, not only a hand-rolled client.
    pub fn write_ca_pem(&self, dir: &Path) -> PathBuf {
        let path = dir.join("ca.pem");
        std::fs::write(&path, &self.cert_pem).expect("write ca.pem");
        path
    }
}

#[cfg(push_tls_test)]
impl Drop for TlsBackend {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Nudge the accept loop out of its sleep with a throwaway connection.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Wrap one accepted socket in TLS and drive its requests through the shared CGI bridge.
#[cfg(push_tls_test)]
fn handle_tls_connection(
    mut stream: TcpStream,
    root: &Path,
    exec_path: &Path,
    server_config: Arc<rustls::ServerConfig>,
    saw_tls: &AtomicBool,
    handshake_completed: &AtomicBool,
    shutdown: &AtomicBool,
) -> std::io::Result<()> {
    // Force blocking + a read timeout on the RAW socket BEFORE TLS wrapping (M2-1), so the timeout
    // governs the rustls handshake and body reads exactly as it does on the plaintext path.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;

    // Record that the client opened with a TLS ClientHello (handshake record type 0x16) — a positive
    // proof it spoke TLS, not plaintext, that survives a subsequent cert-verification abort. `peek`
    // does not consume the byte, so the rustls handshake below still sees the full ClientHello.
    let mut first = [0u8; 1];
    if let Ok(1) = stream.peek(&mut first) {
        if first[0] == 0x16 {
            saw_tls.store(true, Ordering::Relaxed);
        }
    }

    let mut conn = rustls::ServerConnection::new(server_config).map_err(std::io::Error::other)?;
    // Drive the TLS handshake to completion (or failure) EXPLICITLY. A client that distrusts our
    // self-signed cert verifies it mid-handshake, sends a fatal alert, and never finishes — so
    // `complete_io` errors here and `handshake_completed` stays unset (the cert-rejection signature).
    // A trusting client finishes, and we record it and serve the request over the established TLS.
    conn.complete_io(&mut stream)?;
    handshake_completed.store(true, Ordering::Relaxed);
    let tls = rustls::StreamOwned::new(conn, stream);
    // No auth on the TLS harness; chunk-count tracking is irrelevant here (a throwaway sink).
    let chunks = AtomicUsize::new(0);
    serve_requests(ConnReader::new(tls), root, exec_path, HttpAuth::None, &chunks, shutdown)
}

/// Attempt a receive-pack handshake over `url` with the production reqwest/rustls transport,
/// returning the parsed [`Handshake`] or the FLATTENED error chain (top message + every `source()`)
/// as a string. Unlike [`handshake_over_url`] this returns the error instead of panicking, so the
/// TLS law can assert on a rejected connection. `no_auth` is safe here: a TLS-verification failure
/// aborts before any auth challenge, so the closure is never invoked.
#[cfg(push_tls_test)]
pub fn try_handshake_over_url(url: &str) -> Result<Handshake, String> {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .map_err(|e| chain_error(&e))?;
    let mut progress = Discard;
    gix_protocol::handshake(&mut transport, Service::ReceivePack, no_auth, Vec::new(), &mut progress)
        .map_err(|e| chain_error(&e))
}

/// fu4: like [`push_over_url`], but first configures the production reqwest transport to TRUST the CA
/// bundle at `ca` (as `http.sslCAInfo`), so a self-signed server cert can complete a REAL green push
/// over reqwest/rustls — exercising the fork's TLS-trust patch end-to-end. Auth is [`no_auth`]: the
/// trust test presents no credentials. See https://github.com/GitoxideLabs/gitoxide/issues/1109.
#[cfg(push_tls_test)]
pub fn push_over_url_trusting_ca(
    url: &str,
    ca: &Path,
    updates: &[RefUpdate],
    pack: Option<Vec<u8>>,
    opts: Options,
) -> Result<Outcome, Error> {
    use gix_protocol::transport::client::blocking_io::connect;
    let mut transport = connect::connect(
        url,
        connect::Options {
            version: Protocol::V1,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("connect {url}: {e}"));
    // Trust the server's self-signed cert through the production transport (TLS-trust parity, fu4).
    let http_opts = gix_protocol::transport::client::blocking_io::http::Options {
        ssl_ca_info: Some(ca.to_owned()),
        ..Default::default()
    };
    transport.configure(&http_opts).expect("configure TLS trust roots");
    let mut hs = {
        let mut progress = Discard;
        gix_protocol::handshake(&mut transport, Service::ReceivePack, no_auth, Vec::new(), &mut progress)
            .unwrap_or_else(|e| panic!("receive-pack handshake over {url}: {e}"))
    };
    let ctx = Context {
        handshake: &mut hs,
        transport: &mut transport,
        user_agent: ("agent", Some("git/oxide-rolfdb-test".to_owned())),
        trace_packetlines: false,
    };
    let write_pack =
        move |w: &mut dyn Write, _p: &mut dyn DynNestedProgress, _s: &AtomicBool| -> Result<(), std::io::Error> {
            if let Some(ref bytes) = pack {
                w.write_all(bytes)?;
            }
            Ok(())
        };
    let interrupt = AtomicBool::new(false);
    push::push(updates, write_pack, Discard, &interrupt, ctx, opts)
}

/// Flatten an error's `Display` plus its whole `source()` chain into one `" | "`-joined string, so a
/// test can assert on wording that lives in a nested cause.
#[cfg(push_tls_test)]
pub fn chain_error(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(cause) = src {
        out.push_str(" | ");
        out.push_str(&cause.to_string());
        src = cause.source();
    }
    out
}

/// Fetch the smart-http `git-receive-pack` advertisement from `backend` over TLS with a rustls client
/// that TRUSTS the server's self-signed cert (adds it as the sole root, SAN `localhost`). Returns the
/// full raw HTTP response (status line + headers + body). Proves the CGI serves over real TLS when
/// trust is established — the positive half of the trust differential.
#[cfg(push_tls_test)]
pub fn tls_get_advertisement(backend: &TlsBackend, repo: &str) -> String {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(backend.cert_der()).expect("add self-signed root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").expect("valid server name").to_owned();
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name).expect("client connection");
    let sock = TcpStream::connect(("localhost", backend.port)).expect("tcp connect to tls backend");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("client read timeout");
    let mut tls = rustls::StreamOwned::new(conn, sock);

    let request = format!(
        "GET /{repo}/info/refs?service=git-receive-pack HTTP/1.1\r\n\
         Host: localhost\r\nUser-Agent: git/oxide-rolfdb-test\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes()).expect("write GET over TLS");
    tls.flush().expect("flush GET over TLS");

    // Read the header block, then exactly Content-Length body bytes (the CGI bridge always emits a
    // Content-Length), so we neither hang on keep-alive nor block until the server's read timeout.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let headers_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        match tls.read(&mut tmp) {
            Ok(0) => break buf.len(),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) => panic!("read TLS response headers: {e}"),
        }
    };
    let mut content_length = 0usize;
    for line in String::from_utf8_lossy(&buf[..headers_end]).lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    assert!(
        content_length > 0,
        "the CGI bridge must emit Content-Length — a missing header would silently truncate the body; \
         response headers:\n{}",
        String::from_utf8_lossy(&buf[..headers_end])
    );
    while buf.len() < headers_end + content_length {
        match tls.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}
