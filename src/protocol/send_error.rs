//! Wrapper type for the `id` field of the `send-error` message.

use std::fmt;

use byteorder::{BigEndian, ByteOrder};
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor, Unexpected, Error as SerdeError};

use errors::{SignalingError, SignalingResult};
use super::Address;
use super::csn::CombinedSequenceSnapshot;

const SEND_ERROR_ID_BYTES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SendErrorId {
    pub(crate) source: Address,
    pub(crate) destination: Address,
    pub(crate) csn: CombinedSequenceSnapshot,
}

impl SendErrorId {
    /// Convert the `SendErrorId` into byte representation.
    pub(crate) fn as_bytes(&self) -> [u8; SEND_ERROR_ID_BYTES] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.source.0;
        bytes[1] = self.destination.0;
        BigEndian::write_u16(&mut bytes[2..4], self.csn.overflow_number());
        BigEndian::write_u32(&mut bytes[4..8], self.csn.sequence_number());
        bytes
    }

    /// Create a new `SendErrorId` from a byte slice.
    ///
    /// This will fail if the byte slice does not contain exactly 8 bytes of
    /// data.
    pub(crate) fn from_slice(bytes: &[u8]) -> SignalingResult<Self> {
        if bytes.len() != SEND_ERROR_ID_BYTES {
            return Err(SignalingError::Decode(
                format!("byte slice must be exactly {} bytes, not {}", SEND_ERROR_ID_BYTES, bytes.len())
            ));
        };
        let source = Address(bytes[0]);
        let destination = Address(bytes[1]);
        let overflow = BigEndian::read_u16(&bytes[2..4]);
        let sequence = BigEndian::read_u32(&bytes[4..8]);
        let csn = CombinedSequenceSnapshot::new(overflow, sequence);
        Ok(SendErrorId { source, destination, csn })
    }
}

impl Serialize for SendErrorId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
        serializer.serialize_bytes(&self.as_bytes())
    }
}

struct SendErrorIdVisitor;

impl<'de> Visitor<'de> for SendErrorIdVisitor {
    type Value = SendErrorId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("8 bytes of binary data")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: SerdeError {
        if v.len() != 8 {
            return Err(SerdeError::invalid_length(v.len(), &self));
        }
        SendErrorId::from_slice(v)
            .map_err(|e| SerdeError::invalid_value(Unexpected::Other(&e.to_string()), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: SerdeError {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for SendErrorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
        deserializer.deserialize_bytes(SendErrorIdVisitor)
    }
}
