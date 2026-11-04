//! The error returned by [`push()`](crate::push::push).

use bstr::BString;
use gix_error::ClassificationMarker;

/// The error returned by [`push()`](crate::push::push).
///
/// Mirrors the fetch/handshake errors' classification approach: `MissingServerFeature` is the same
/// `{ feature, description }` struct variant fetch used to have, and retry decisions are driven by
/// the [`gix_error::Class`] found in the [source chain](std::error::Error::source), so transport
/// failures that are retryable stay retryable once wrapped here (everything else is not).
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
            Error::Client(_) => f.write_str("The transport failed while pushing"),
            Error::WritePack(_) => f.write_str("Failed to write the packfile to the transport"),
            Error::Io(_) => f.write_str("An I/O error occurred while sending the update request"),
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
            Error::Client(err) => Some(err),
            Error::WritePack(err) => Some(&**err),
            Error::Io(err) => Some(err),
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
