//! Nonce related functionality.
//!
//! This includes serialization and deserialization.

use std::convert::Into;
use std::io::Write;

use byteorder::{BigEndian, ByteOrder};
use rust_sodium::crypto::{box_, secretbox};

use errors::{SignalingError, SignalingResult};

use super::cookie::Cookie;
use super::csn::CombinedSequenceSnapshot;
use super::types::{Address, Identity};


/// The SaltyRTC nonce.
///
/// The type is intentionally non-cloneable, to prevent accidental re-use. All
/// non-unsafe transformations into other formats consume the instance. This is
/// also known as an affine type.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Nonce {
    cookie: Cookie,
    source: Address,
    destination: Address,
    csn: CombinedSequenceSnapshot,
}

impl Nonce {
    pub(crate) fn new(cookie: Cookie, source: Address, destination: Address, csn: CombinedSequenceSnapshot) -> Self {
        Nonce {
            cookie,
            source,
            destination,
            csn,
        }
    }

    /// Parse bytes, return a Nonce.
    ///
    /// This will fail if the byte slice does not contain exactly 24 bytes of
    /// data.
    pub(crate) fn from_bytes(bytes: &[u8]) -> SignalingResult<Self> {
        if bytes.len() != 24 {
            return Err(SignalingError::Decode(
                format!("Byte slice must be exactly 24 bytes, not {}", bytes.len())
            ));
        }
        let overflow = BigEndian::read_u16(&bytes[18..20]);
        let sequence = BigEndian::read_u32(&bytes[20..24]);
        let csn = CombinedSequenceSnapshot::new(overflow, sequence);
        Ok(Self {
            cookie: Cookie::new([
                bytes[0], bytes[1], bytes[2],  bytes[3],  bytes[4],  bytes[5],  bytes[6],  bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            source: Address(bytes[16]),
            destination: Address(bytes[17]),
            csn,
        })
    }

    /// Convert the nonce into byte representation.
    ///
    /// This conversion consumes the nonce, so that it cannot be accidentally
    /// reused.
    pub(crate) fn into_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        (&mut bytes[0..16]).write_all(self.cookie.as_bytes()).expect("Writing cookie to nonce failed");
        bytes[16] = self.source.0;
        bytes[17] = self.destination.0;
        BigEndian::write_u16(&mut bytes[18..20], self.csn.overflow_number());
        BigEndian::write_u32(&mut bytes[20..24], self.csn.sequence_number());
        bytes
    }

    /// Return a reference to the cookie bytes.
    pub(crate) fn cookie(&self) -> &Cookie {
        &self.cookie
    }

    /// Return the source.
    pub(crate) fn source(&self) -> Address {
        self.source
    }

    /// Return the source identity.
    pub(crate) fn source_identity(&self) -> Identity {
        Identity::from(self.source)
    }

    /// Return the destination.
    pub(crate) fn destination(&self) -> Address {
        self.destination
    }

    /// Return the combined sequence number.
    pub(crate) fn csn(&self) -> &CombinedSequenceSnapshot {
        &self.csn
    }

    /// Clone the nonce.
    ///
    /// This is unsafe because a `Nonce` must never be reused for two messages.
    /// Only clone a `Nonce` if it's absolutely required and if you are sure
    /// that it isn't reused improperly.
    #[cfg_attr(feature="cargo-clippy", allow(should_implement_trait))]
    pub(crate) unsafe fn clone(&self) -> Nonce {
        Nonce {
            cookie: self.cookie.clone(),
            source: self.source,
            destination: self.destination,
            csn: self.csn.clone(),
        }
    }
}

impl Into<box_::Nonce> for Nonce {
    fn into(self) -> box_::Nonce {
        let bytes = self.into_bytes();
        box_::Nonce(bytes)
    }
}

impl Into<secretbox::Nonce> for Nonce {
    fn into(self) -> secretbox::Nonce {
        let bytes = self.into_bytes();
        secretbox::Nonce(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_nonce() -> Nonce {
        Nonce {
            cookie: Cookie::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            source: Address(17),
            destination: Address(18),
            csn: CombinedSequenceSnapshot::new(258, 50_595_078),
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
    fn nonce_methods() {
        let nonce = create_test_nonce();
        assert_eq!(nonce.cookie(), &Cookie::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
        assert_eq!(nonce.source(), Address(17));
        assert_eq!(nonce.destination(), Address(18));
        assert_eq!(nonce.csn().overflow_number(), 258);
        assert_eq!(nonce.csn().sequence_number(), 50_595_078);
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
