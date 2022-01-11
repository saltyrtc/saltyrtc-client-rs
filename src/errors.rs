//! Error types used in saltyrtc-client.
//!
//! The implementation is done using the
//! [`failure`](https://crates.io/crates/failure) crate.

use std::convert::From;
use std::sync::TryLockError;

use failure::Fail;
use rmp_serde::decode::Error as SerdeDecodeError;
use tokio_timer::TimeoutError;

/// Re-exported [`Error`](../../failure/struct.Error.html) type from the
/// [failure crate](https://crates.io/crates/failure).
pub type Error = ::failure::Error;

/// Errors that are exposed to the user of the library.
#[derive(Fail, Debug, PartialEq)]
pub enum SaltyError {
    /// A problem with encrypting or decrypting data.
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

    /// No shared task was found.
    #[fail(display = "No shared task found")]
    NoSharedTask,

    /// Peer has not (yet) been determined.
    #[fail(display = "Peer has not (yet) been determined")]
    NoPeer,

    /// A problem occured related to a task.
    #[fail(display = "Task error: {}", _0)]
    Task(String),

    /// An unexpected error. This should never happen and indicates a bug in
    /// the implementation.
    #[fail(
        display = "An unexpected error occurred: {}. This indicates a bug and should be reported!",
        _0
    )]
    Crash(String),

    /// A future timed out.
    #[fail(display = "Future timed out")]
    Timeout,
}

impl From<SignalingError> for SaltyError {
    fn from(e: SignalingError) -> Self {
        match e {
            SignalingError::Crash(msg) => SaltyError::Crash(format!("Signaling error: {}", msg)),
            SignalingError::Crypto(msg) => SaltyError::Crypto(msg),
            SignalingError::CsnOverflow => SaltyError::Crypto(e.to_string()),
            SignalingError::Decode(msg) => SaltyError::Decode(msg),
            SignalingError::InitiatorCouldNotDecrypt => SaltyError::Crypto(e.to_string()),
            SignalingError::InvalidMessage(_) => SaltyError::Protocol(e.to_string()),
            SignalingError::InvalidNonce(_) => SaltyError::Protocol(e.to_string()),
            SignalingError::InvalidStateTransition(_) => SaltyError::Crash(e.to_string()),
            SignalingError::NoSharedTask => SaltyError::NoSharedTask,
            SignalingError::NoPeer => SaltyError::NoPeer,
            SignalingError::Protocol(msg) => SaltyError::Protocol(msg),
            SignalingError::SendError => SaltyError::Network(e.to_string()),
            SignalingError::TaskInitialization(_) => SaltyError::Task(e.to_string()),
        }
    }
}

impl<F> From<TimeoutError<F>> for SaltyError {
    fn from(_: TimeoutError<F>) -> Self {
        SaltyError::Timeout
    }
}

impl<T> From<TryLockError<T>> for SaltyError {
    fn from(e: TryLockError<T>) -> Self {
        SaltyError::Crash(format!("Could not acquire lock: {}", e))
    }
}

/// A result with [`SaltyError`](enum.SaltyError.html) as error type.
pub type SaltyResult<T> = ::std::result::Result<T, SaltyError>;

/// Internal errors that occur during signaling and that will probably result
/// in the connection being closed.
#[derive(Fail, Debug, PartialEq)]
pub(crate) enum SignalingError {
    /// A problem with decoding data.
    #[fail(display = "Decoding error: {}", _0)]
    Decode(String),

    /// Nonce validation fails.
    #[fail(display = "Invalid nonce: {}", _0)]
    InvalidNonce(String),

    /// A problem with encrypting or decrypting data.
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

    /// No shared task was found during the handshake.
    #[fail(display = "No shared task found")]
    NoSharedTask,

    /// Peer has not (yet) been determined.
    #[fail(display = "Peer has not (yet) been determined")]
    NoPeer,

    /// Task initialization failed.
    #[fail(display = "Task initialization failed: {}", _0)]
    TaskInitialization(String),

    /// Initiator could not decrypt key message.
    #[fail(display = "Initiator could not decrypt key message")]
    InitiatorCouldNotDecrypt,

    /// An unexpected error. This should never happen and indicates a bug in
    /// the implementation.
    #[fail(
        display = "An unexpected error occurred: {}. This indicates a bug and should be reported!",
        _0
    )]
    Crash(String),
}

/// A result with [`SignalingError`](enum.SignalingError.html) as error type.
pub(crate) type SignalingResult<T> = ::std::result::Result<T, SignalingError>;

impl From<SerdeDecodeError> for SignalingError {
    fn from(e: SerdeDecodeError) -> Self {
        SignalingError::Decode(format!("Could not decode msgpack data: {}", e))
    }
}

impl<T> From<TryLockError<T>> for SignalingError {
    fn from(e: TryLockError<T>) -> Self {
        SignalingError::Crash(format!("Could not acquire lock: {}", e))
    }
}

/// Errors that may be returned by the [`SaltyClientBuilder`](../struct.SaltyClientBuilder.html).
#[derive(Fail, Debug, PartialEq)]
pub enum BuilderError {
    /// No task has been added.
    #[fail(display = "No task specified")]
    MissingTask,
}

/// Result of the nonce validation.
pub(crate) enum ValidationError {
    /// Ignore message
    DropMsg(String),
    /// Validation failed
    Fail(String),
    /// A critical error occurred
    Crash(String),
}

impl<T> From<TryLockError<T>> for ValidationError {
    fn from(e: TryLockError<T>) -> Self {
        ValidationError::Crash(format!("Could not acquire lock: {}", e))
    }
}
