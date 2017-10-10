//! Nonce related functionality.
//!
//! This includes serialization and deserialization.

use std::convert::Into;
use std::io::Write;

use byteorder::{BigEndian, ByteOrder};
use rust_sodium::crypto::box_;

use errors::Error;

/// Newtype for the sender address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Sender(u8);

impl Sender {
    pub fn new(id: u8) -> Self {
        Sender(id)
    }
}

/// Newtype for the receiver address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Receiver(u8);

impl Receiver {
    pub fn new(id: u8) -> Self {
        Receiver(id)
    }
}

/// The SaltyRTC nonce.
///
/// The type is intentionally non-cloneable, to prevent accidental re-use. All
/// transformations into other formats consume the instance. This is also known
/// as an affine type.
#[derive(Debug, PartialEq, Eq)]
pub struct Nonce {
    cookie: [u8; 16],
    source: Sender,
    destination: Receiver,
    overflow: u16,
    sequence: u32,
}

impl Nonce {
    pub fn new(cookie: [u8; 16], source: Sender, destination: Receiver, overflow: u16, sequence: u32) -> Self {
        Nonce {
            cookie: cookie,
            source: source,
            destination: destination,
            overflow: overflow,
            sequence: sequence,
        }
    }

    /// Parse bytes, return a Nonce.
    ///
    /// This will fail if the byte slice does not contain exactly 24 bytes of
    /// data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ensure!(bytes.len() == 24, "Nonce must be exactly 24 bytes long");
        Ok(Self {
            cookie: [
                bytes[0], bytes[1], bytes[2],  bytes[3],  bytes[4],  bytes[5],  bytes[6],  bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ],
            source: Sender(bytes[16]),
            destination: Receiver(bytes[17]),
            overflow: BigEndian::read_u16(&bytes[18..20]),
            sequence: BigEndian::read_u32(&bytes[20..24]),
        })
    }

    /// Convert the nonce into byte representation.
    ///
    /// This conversion consumes the nonce, so that it cannot be accidentally
    /// reused.
    pub fn into_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        (&mut bytes[0..16]).write_all(&self.cookie).expect("Writing cookie to nonce failed");
        bytes[16] = self.source.0;
        bytes[17] = self.destination.0;
        BigEndian::write_u16(&mut bytes[18..20], self.overflow);
        BigEndian::write_u32(&mut bytes[20..24], self.sequence);
        bytes
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub fn random() -> Self {
        ::helpers::libsodium_init().unwrap();
        let mut bytes = [0u8; 24];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self::from_bytes(&bytes).unwrap()
    }
}

impl Into<box_::Nonce> for Nonce {
    fn into(self) -> box_::Nonce {
        let bytes = self.into_bytes();
        box_::Nonce(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_nonce() -> Nonce {
        Nonce {
            cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            source: Sender(17),
            destination: Receiver(18),
            overflow: 258,
            sequence: 50_595_078,
        }
    }

    fn create_test_nonce_bytes() -> [u8; 24] {
        [
            // Cookie
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            // Source: 17
            17,
            // Destination: 18
            18,
            // Overflow: 258 big endian
            1, 2,
            // Sequence number: 50595078 big endian
            3, 4, 5, 6,
        ]
    }

    #[test]
    fn parse_nonce() {
        let bytes = create_test_nonce_bytes();
        assert_eq!(Nonce::from_bytes(&bytes).unwrap(), create_test_nonce());
    }

    #[test]
    fn serialize_nonce() {
        let nonce = create_test_nonce();
        assert_eq!(nonce.into_bytes(), create_test_nonce_bytes());
    }

    /// Test conversion from a saltyrtc `Nonce` to a rust sodium `Nonce`.
    #[test]
    fn nonce_into_nonce() {
        let nonce: Nonce = create_test_nonce();
        let nonce_bytes: [u8; 24] = create_test_nonce_bytes();
        let rust_sodium_nonce: box_::Nonce = nonce.into();
        assert_eq!(rust_sodium_nonce.0, nonce_bytes);
    }
}
