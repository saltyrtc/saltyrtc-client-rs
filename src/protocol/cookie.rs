//! Cookies.

use rust_sodium::randombytes::randombytes_into;

use errors::{Result, ErrorKind};
use helpers::libsodium_init_or_panic;


const COOKIE_BYTES: usize = 16;

/// Newtype wrapper for the cookie bytes.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Cookie([u8; COOKIE_BYTES]);

impl Cookie {

    /// Create a new `Cookie` from a byte array.
    pub fn new(bytes: [u8; COOKIE_BYTES]) -> Self {
        Cookie(bytes)
    }

    /// Create a new `Cookie` from a byte slice.
    ///
    /// This will fail if the byte slice does not contain exactly 16 bytes of
    /// data.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == COOKIE_BYTES,
            ErrorKind::Crypto(format!("byte slice must be exactly {} bytes, not {}", COOKIE_BYTES, bytes.len()))
        );
        let mut array = [0; COOKIE_BYTES];
        for i in 0..COOKIE_BYTES {
            array[i] = bytes[i];
        }
        Ok(Cookie(array))
    }

    /// Create a new random `Cookie`.
    pub fn random() -> Self {
        // Make sure that libsodium is initialized
        libsodium_init_or_panic();

        // Create 16 bytes of cryptographically secure random data
        let mut rand = [0; 16];
        randombytes_into(&mut rand);

        // Make sure that random data was actually generated
        assert!(!rand.iter().all(|&x| x == 0));

        Cookie(rand)
    }

    /// Return the cookie bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}


/// A pair of two [`Cookie`](struct.Cookie.html)s
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookiePair {
    pub ours: Cookie,
    pub theirs: Option<Cookie>,
}

impl CookiePair {
    /// Create a new [`CookiePair`](struct.CookiePair.html).
    pub fn new() -> Self {
        CookiePair {
            ours: Cookie::random(),
            theirs: None,
        }
    }
}


#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// 100 generated random cookies should be different
    #[test]
    fn random_distinct() {
        let mut cookies = HashSet::new();
        for _ in 0..100 {
            let cookie = Cookie::random();
            cookies.insert(cookie);
        }
        assert_eq!(cookies.len(), 100);
    }

}
