use errors::{Result, ErrorKind};

/// Initialize libsodium. Return an error if initialization failed.
///
/// It is safe to call this function multiple times.
///
/// See [`rust_sodium::init` docs](https://docs.rs/rust_sodium/0.5.0/rust_sodium/fn.init.html)
/// for more information.
pub fn libsodium_init() -> Result<()> {
    let success = ::rust_sodium::init();
    if !success {
        bail!(ErrorKind::Crypto("could not initialize libsodium".into()));
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
        panic!("could not initialize libsodium");
    }
}
