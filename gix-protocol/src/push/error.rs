//! The error returned by [`push()`](crate::push::push).

use bstr::BString;
use gix_error::ClassificationMarker;

/// The error returned by [`push()`](crate::push::push).
///
/// Mirrors the fetch/handshake errors' classification approach: `MissingServerFeature` is the same
/// `{ feature, description }` struct variant fetch used to have, and retry decisions are driven by
/// the [`gix_error::Class`] found in the [source chain](std::error::Error::source).
///
/// Only [`Client`](Error::Client) failures, which happen before the pack is sent, expose their cause for
/// that purpose, so a transport failure stays retryable. [`Response`](Error::Response), [`Io`](Error::Io)
/// and [`WritePack`](Error::WritePack) can occur once the server may already have applied the update, where
/// re-pushing is not idempotent: they classify as [`Conflict`](gix_error::Class::Conflict) and hide their cause
/// from classification, while their `Display` still names it.
#[derive(Debug)]
#[expect(missing_docs)]
pub enum Error {
    NoCommands,
    MissingServerFeature {
        feature: &'static str,
        description: &'static str,
    },
    HashKindMismatch {
        local: gix_hash::Kind,
        server: BString,
    },
    Response(crate::push::response::Error),
    Client(crate::transport::client::Error),
    WritePack(Box<dyn std::error::Error + Send + Sync + 'static>),
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoCommands => f.write_str("No ref update commands were provided"),
            Error::MissingServerFeature { feature, description } => {
                write!(f, "The server lacks the {feature:?} capability: {description}")
            }
            Error::HashKindMismatch { local, server } => write!(
                f,
                "The server's object-format {server:?} does not match the local object hash kind {local}; \
                 refusing before any bytes are sent"
            ),
            Error::Response(err) => std::fmt::Display::fmt(err, f),
            Error::Client(err) => std::fmt::Display::fmt(err, f),
            Error::WritePack(err) => {
                f.write_str("Failed to write the packfile to the transport")?;
                write_causes(f, &**err)
            }
            Error::Io(err) => {
                f.write_str("An I/O error occurred while sending the update request")?;
                write_causes(f, err)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::NoCommands => Some(const { &ClassificationMarker::VALIDATION }),
            Error::MissingServerFeature { .. } | Error::HashKindMismatch { .. } => {
                Some(const { &ClassificationMarker::UNSUPPORTED })
            }
            // Transparent: the response error is the message, only its own cause is the source.
            Error::Response(err) => std::error::Error::source(err),
            // Transparent: only the transport error's own cause is the source.
            Error::Client(err) => std::error::Error::source(err),
            Error::WritePack(_) | Error::Io(_) => Some(const { &ClassificationMarker::CONFLICT }),
        }
    }
}

impl From<crate::push::response::Error> for Error {
    fn from(err: crate::push::response::Error) -> Self {
        Error::Response(err)
    }
}

impl From<crate::transport::client::Error> for Error {
    fn from(err: crate::transport::client::Error) -> Self {
        Error::Client(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// Append `err` and its causes to `f` as `: <err>: <cause>…`, the way an alternate-formatted error chain reads.
///
/// Used where a variant must not expose its cause through [`source()`](std::error::Error::source)
/// (so classification cannot see it) but its message should still name it.
pub(crate) fn write_causes(
    f: &mut std::fmt::Formatter<'_>,
    err: &(dyn std::error::Error + 'static),
) -> std::fmt::Result {
    write!(f, ": {err}")?;
    let mut source = err.source();
    while let Some(cause) = source {
        if !cause.is::<ClassificationMarker>() {
            write!(f, ": {cause}")?;
        }
        source = cause.source();
    }
    Ok(())
}
