//! Cookies.

use std::fmt;
use std::result::Result as StdResult;

use rust_sodium::randombytes::randombytes_into;
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor, Error as SerdeError};

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

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl Serialize for Cookie {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
            where S: Serializer {
        serializer.serialize_bytes(&self.0)
    }
}

struct CookieVisitor;

impl<'de> Visitor<'de> for CookieVisitor {
    type Value = Cookie;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("16 bytes of binary data")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> StdResult<Self::Value, E> where E: SerdeError {
        if v.len() != 16 {
            return Err(SerdeError::invalid_length(v.len(), &self));
        }
        Ok(Cookie::new([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                        v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]]))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> StdResult<Self::Value, E> where E: SerdeError {
        self.visit_bytes(&v)
    }
}

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl<'de> Deserialize<'de> for Cookie {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
            where D: Deserializer<'de> {
        deserializer.deserialize_bytes(CookieVisitor)
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

    use rmp_serde as rmps;

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

    /// The cookie serializes to the contained raw bytes.
    #[test]
    fn cookie_serialize() {
        let cookie = Cookie::new([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);

        let serialized = rmps::to_vec_named(&cookie).expect("Serialization failed");

        assert_eq!(serialized, [
            0xc4, // bin 8
            16, // 16 elements
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, // bytes
        ]);
    }

    /// The cookie deserializes from raw bytes.
    #[test]
    fn cookie_deserialize() {
        let cookie = Cookie::new([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);

        let deserialized: Cookie = rmps::from_slice(&[
            0xc4, // bin 8
            16, // 16 elements
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, // bytes
        ]).unwrap();

        assert_eq!(cookie, deserialized);
    }
}
