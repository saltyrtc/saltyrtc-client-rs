//! Error types used in saltyrtc-client.
//!
//! The implementation is done using the
//! [`failure`](https://crates.io/crates/failure) crate.

use rmp_serde::decode::Error as DecodeError;

/// Errors that are exposed to the user of the library.
#[derive(Fail, Debug)]
pub enum SaltyError {
    /// A problem with Libsodium or with encrypting or decrypting data.
    #[fail(display = "Crypto error: {}", _0)]
    Crypto(String),

    /// A problem when parsing data.
    #[fail(display = "Parsing error: {}", _0)]
    Parsing(String),

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

/// A result with [`SaltyError](enum.SaltyError.html) as error type.
pub type SaltyResult<T> = ::std::result::Result<T, SaltyError>;


/// Internal errors that occur during signaling and that will probably result
/// in the connection being closed.
///
/// TODO: Should the messages be represented as context instead?
#[derive(Fail, Debug)]
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
}

/// A result with [`SignalingError](enum.SignalingError.html) as error type.
pub type SignalingResult<T> = ::std::result::Result<T, SignalingError>;

error_chain!{
    // The type defined for this error.
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    // Automatic conversions between this error chain
    // and other error chains.
    links {
    }

    // Automatic conversions between this error chain and other
    // error types not defined by the `error_chain!`.
    // These will be wrapped in a new error.
    foreign_links {
        Io(::std::io::Error) #[cfg(unix)] #[doc = "An I/O error occurred."];
        MsgpackDecode(DecodeError) #[doc = "Decoding msgpack bytes failed."];
    }

    errors {
        /// A problem with decoding data.
        Decode(msg: String) {
            description("decoding error"),
            display("decoding error: {}", msg),
        }
        /// Nonce validation fails.
        InvalidNonce(msg: String) {
            description("invalid nonce"),
            display("invalid nonce: {}", msg),
        }
        /// A problem with Libsodium or with encrypting or decrypting data.
        Crypto(msg: String) {
            description("crypto error"),
            display("crypto error: {}", msg),
        }
        /// A CSN overflowed.
        /// This is extremely unlikely and must be treated as a protocol error.
        CsnOverflow {
            description("csn overflow"),
            display("csn overflow"),
        }
        /// A message has an invalid state.
        InvalidMessageState(msg: String) {
            description("invalid message state"),
            display("invalid message state: {}", msg),
        }
        /// An invalid state transition was attempted.
        InvalidStateTransition(msg: String) {
            description("invalid state transition"),
            display("invalid state transition: {}", msg),
        }
    }
}
