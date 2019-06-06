use crate::errors::{SaltyResult, SaltyError};

/// Initialize libsodium. Return an error if initialization failed.
///
/// It is safe to call this function multiple times.
///
/// See [`rust_sodium::init` docs](https://docs.rs/rust_sodium/0.9.0/rust_sodium/fn.init.html)
/// for more information.
pub fn libsodium_init() -> SaltyResult<()> {
    ::rust_sodium::init().map_err(
        |()| SaltyError::Crypto("Could not initialize libsodium".into())
    )
}

/// Initialize libsodium. Panic if initialization fails.
///
/// It is safe to call this function multiple times.
///
/// See [`rust_sodium::init` docs](https://docs.rs/rust_sodium/0.9.0/rust_sodium/fn.init.html)
/// for more information.
pub fn libsodium_init_or_panic() {
    ::rust_sodium::init().expect("Could not initialize libsodium")
}
