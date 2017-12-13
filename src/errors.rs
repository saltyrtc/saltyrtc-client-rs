//! Error types used in saltyrtc-client.
//!
//! The implementation is done using the
//! [`failure`](https://crates.io/crates/failure) crate.

use std::convert::From;

use rmp_serde::decode::Error as SerdeDecodeError;


/// Errors that are exposed to the user of the library.
#[derive(Fail, Debug, PartialEq)]
pub enum SaltyError {
    /// A problem with Libsodium or with encrypting or decrypting data.
    #[fail(display = "Crypto error: {}", _0)]
    Crypto(String),

    /// A problem when parsing or decoding data.
    #[fail(display = "Decoding error: {}", _0)]
    Decode(String),

    /// A network related problem.
    #[fail(display = "Network error: {}", _0)]
    Network(String),

    /// A protocol related error.
    #[fail(display = "Protocol error: {}", _0)]
    Protocol(String),

    /// An unexpected error. This should never happen and indicates a bug in
    /// the implementation.
    #[fail(display = "An unexpected error occurred: {}. This indicates a bug and should be reported!", _0)]
    Crash(String),
}

/// A result with [`SaltyError`](enum.SaltyError.html) as error type.
pub type SaltyResult<T> = ::std::result::Result<T, SaltyError>;


/// Internal errors that occur during signaling and that will probably result
/// in the connection being closed.
///
/// TODO: Should the messages be represented as context instead?
#[derive(Fail, Debug, PartialEq)]
pub enum SignalingError {
    /// A problem with decoding data.
    #[fail(display = "Decoding error: {}", _0)]
    Decode(String),

    /// Nonce validation fails.
    #[fail(display = "Invalid nonce: {}", _0)]
    InvalidNonce(String),

    /// A problem with Libsodium or with encrypting or decrypting data.
    #[fail(display = "Crypto error: {}", _0)]
    Crypto(String),

    /// A CSN overflowed.
    /// This is extremely unlikely and must always be treated as a protocol error.
    #[fail(display = "CSN overflow")]
    CsnOverflow,

    /// An invalid state transition was attempted.
    #[fail(display = "Invalid state transition: {}", _0)]
    InvalidStateTransition(String),

    /// A message is not valid.
    #[fail(display = "Invalid message: {}", _0)]
    InvalidMessage(String),

    /// Something happened that violates the protocol.
    /// This error should mainly be used if the event that happened is outside
    /// of our control (e.g. if the peer sends a message we didn't expect).
    /// If the error is an implementation bug, use
    /// [`SignalingError::Crash`](enum.SignalingError.html#crash) instead!
    #[fail(display = "A protocol error occurred: {}", _0)]
    Protocol(String),

    /// The server returned a `SendError` message. This means that a
    /// client-to-client message could not be relayed (the connection between
    /// server and the receiver has been severed).
    #[fail(display = "Server could not relay message")]
    SendError,

    /// An unexpected error. This should never happen and indicates a bug in
    /// the implementation.
    #[fail(display = "An unexpected error occurred: {}. This indicates a bug and should be reported!", _0)]
    Crash(String),
}

/// A result with [`SignalingError`](enum.SignalingError.html) as error type.
pub type SignalingResult<T> = ::std::result::Result<T, SignalingError>;

impl From<SerdeDecodeError> for SignalingError {
    fn from(e: SerdeDecodeError) -> Self {
        SignalingError::Decode(format!("Could not decode msgpack data: {}", e))
    }
}

#[derive(Fail, Debug, PartialEq)]
pub enum BuilderError {
    /// No task has been added.
    #[fail(display = "No task specified")]
    MissingTask,
}
