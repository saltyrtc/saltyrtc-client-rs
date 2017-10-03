//! Nonce related functionality.
//!
//! This includes serialization and deserialization.

use byteorder::{BigEndian, ByteOrder};

use errors::Error;

/// Newtype for the sender address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct Sender(u8);

/// Newtype for the receiver address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct Receiver(u8);

/// The SaltyRTC nonce.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nonce {
    cookie: [u8; 16],
    source: Sender,
    destination: Receiver,
    overflow: u16,
    sequence: u32,
}

impl Nonce {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nonce() {
        let bytes = vec![
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
        ];
        assert_eq!(Nonce::from_bytes(&bytes).unwrap(), Nonce {
            cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            source: Sender(17),
            destination: Receiver(18),
            overflow: 258,
            sequence: 50595078,
        });
    }
}
