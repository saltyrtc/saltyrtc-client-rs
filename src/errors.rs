//! Error types used in saltyrtc-client.
//!
//! The implementation is done using the
//! [`error-chain`](https://github.com/rust-lang-nursery/error-chain/)
//! crate.

use rmp_serde::decode::Error as DecodeError;

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
    }
}
