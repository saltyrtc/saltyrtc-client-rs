use errors::{SaltyResult, SaltyError};

/// Initialize libsodium. Return an error if initialization failed.
///
/// It is safe to call this function multiple times.
///
/// See [`rust_sodium::init` docs](https://docs.rs/rust_sodium/0.5.0/rust_sodium/fn.init.html)
/// for more information.
pub fn libsodium_init() -> SaltyResult<()> {
    let success = ::rust_sodium::init();
    if !success {
        return Err(SaltyError::Crypto("Could not initialize libsodium".into()));
    } else {
        Ok(())
    }
}

/// Initialize libsodium. Panic if initialization fails.
///
/// It is safe to call this function multiple times.
///
/// See [`rust_sodium::init` docs](https://docs.rs/rust_sodium/0.5.0/rust_sodium/fn.init.html)
/// for more information.
pub fn libsodium_init_or_panic() {
    let success = ::rust_sodium::init();
    if !success {
        panic!("Could not initialize libsodium");
    }
}

/// A test-only trait that allows the user to create random instances of
/// certain types (e.g. a public key).
#[cfg(test)]
pub trait TestRandom {
    fn random() -> Self;
}
