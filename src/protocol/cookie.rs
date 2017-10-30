//! Cookies.

use std::fmt;
use std::result::Result as StdResult;

use rust_sodium::randombytes::randombytes_into;
use serde::ser::{Serialize, Serializer, SerializeSeq};
use serde::de::{Deserialize, Deserializer, Visitor, SeqAccess, Error as SerdeError};

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
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for byte in self.0.iter() {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

struct CookieVisitor;

impl<'de> Visitor<'de> for CookieVisitor {
    type Value = Cookie;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of 16 bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> StdResult<Self::Value, A::Error> where A: SeqAccess<'de> {
        Ok(Cookie::new([
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
            seq.next_element()?.ok_or(SerdeError::custom("could not deserialize cookie"))?,
        ]))
    }
}

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl<'de> Deserialize<'de> for Cookie {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
            where D: Deserializer<'de> {
        deserializer.deserialize_seq(CookieVisitor)
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
        let a = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let b = Cookie::new(a.clone());

        let a_ser = rmps::to_vec_named(&a).expect("Serialization failed");
        let b_ser = rmps::to_vec_named(&b).expect("Serialization failed");

        assert_eq!(a_ser, b_ser);
    }

    /// The cookie deserializes from raw bytes.
    #[test]
    fn cookie_deserialize() {
        let bytes = [
            220, // array 16
            0, 16, // 16 elements
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, // array bytes
        ];

        let a_de: [u8; 16] = rmps::from_slice(&bytes).unwrap();
        let b_de: Cookie = rmps::from_slice(&bytes).unwrap();

        assert_eq!(a_de, b_de.bytes());
    }
}
