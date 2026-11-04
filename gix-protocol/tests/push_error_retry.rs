//! Retryability of `gix_protocol::push::Error`, the replacement for the former `IsSpuriousError`.
//!
//! Failures before the pack was sent (the transport `Client` error) keep exposing a retryable cause.
//! Failures that can occur once the server may already have applied the update (`Response`, `Io`,
//! `WritePack`) must never classify as retryable, as `is_spurious()` was `false` for them: re-pushing
//! is not idempotent. Their `Display` still names the cause.

#![cfg(feature = "push")]

use std::io::ErrorKind::{ConnectionReset, TimedOut};

use gix_protocol::push::{Error, response};

fn io(kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::from(kind)
}

#[test]
fn transport_failures_before_the_pack_is_sent_stay_retryable() {
    let reset = Error::Client(io(ConnectionReset).into());
    assert!(
        gix_error::classify(&reset).can_retry_lenient(),
        "a reset while talking to the server is a transport hiccup"
    );
    let timeout = Error::Client(io(TimedOut).into());
    assert!(
        gix_error::classify(&timeout).can_retry(),
        "a timeout is retryable under the strict policy"
    );
}

#[test]
fn client_errors_display_transparently() {
    let client: gix_protocol::transport::client::Error = io(ConnectionReset).into();
    let expected = client.to_string();
    assert_eq!(
        Error::Client(client).to_string(),
        expected,
        "the plumbing error adds no message of its own around a transport error"
    );
}

#[test]
fn failures_that_can_follow_a_server_side_apply_are_never_retryable() {
    for kind in [ConnectionReset, TimedOut] {
        for (what, err) in [
            ("Response(Io)", Error::Response(response::Error::Io(io(kind)))),
            ("Io", Error::Io(io(kind))),
            ("WritePack", Error::WritePack(Box::new(io(kind)))),
        ] {
            assert!(!gix_error::classify(&err).can_retry(), "{what}/{kind:?}: strict policy");
            assert!(
                !gix_error::classify(&err).can_retry_lenient(),
                "{what}/{kind:?}: lenient policy"
            );
        }
    }
}

#[test]
fn non_retryable_failures_still_name_their_cause() {
    for err in [
        Error::Response(response::Error::Io(io(ConnectionReset))),
        Error::Io(io(ConnectionReset)),
        Error::WritePack(Box::new(io(ConnectionReset))),
    ] {
        assert!(
            err.to_string().ends_with(": connection reset"),
            "the I/O cause is part of the message, got: {err}"
        );
    }
}
