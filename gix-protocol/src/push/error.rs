//! The error returned by [`push()`](crate::push::push).

use bstr::BString;

/// The error returned by [`push()`](crate::push::push).
///
/// Mirrors `fetch::Error`: `MissingServerFeature` is the same `{ feature, description }` struct
/// variant (`fetch/error.rs`), and the type implements
/// [`IsSpuriousError`](crate::transport::IsSpuriousError) by forwarding transport/response
/// spuriousness (everything else is non-spurious).
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("No ref update commands were provided")]
    NoCommands,
    #[error("The server lacks the {feature:?} capability: {description}")]
    MissingServerFeature {
        feature: &'static str,
        description: &'static str,
    },
    #[error(
        "The server's object-format {server:?} does not match the local object hash kind {local}; \
         refusing before any bytes are sent"
    )]
    HashKindMismatch {
        local: gix_hash::Kind,
        server: BString,
    },
    #[error(transparent)]
    Response(#[from] crate::push::response::Error),
    #[error(transparent)]
    Client(#[from] crate::transport::client::Error),
    #[error("Failed to write the packfile to the transport")]
    WritePack(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("An I/O error occurred while sending the update request")]
    Io(#[from] std::io::Error),
}

impl crate::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Client(err) => err.is_spurious(),
            Error::Response(err) => err.is_spurious(),
            _ => false,
        }
    }
}
