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
        Io(::std::io::Error) #[cfg(unix)];
        MsgpackDecode(DecodeError);
    }
}
