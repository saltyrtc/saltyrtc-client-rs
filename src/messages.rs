//! Message types used in the SaltyRTC protocol.

use rmp_serde as rmps;
use serde::{Serialize, Deserialize};

use errors::{Result};
use keystore::PublicKey;

/// A trait to convert types from/to msgpack representation.
pub trait MsgPacked<'de>: Sized + Serialize + Deserialize<'de> {
    const TYPE: &'static str;
    fn from_msgpack(bytes: &[u8]) -> Result<Self>;
    fn to_msgpack(&self) -> Vec<u8>;
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientHello {
    #[serde(rename = "type")]
    pub type_: String,
    pub key: PublicKey,
}

impl ClientHello {
    pub fn new(key: PublicKey) -> Self {
        Self {
            type_: "client-hello".into(),
            key: key,
        }
    }
}

impl<'de> MsgPacked<'de> for ClientHello {
    const TYPE: &'static str = "client-hello";

    fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let decoded: Self = rmps::from_slice::<Self>(&bytes)?;
        if decoded.type_ != Self::TYPE {
            bail!(format!("Invalid type for ClientHello message: {}", decoded.type_));
        }
        Ok(decoded)
    }

    fn to_msgpack(&self) -> Vec<u8> {
        rmps::to_vec_named(&self).expect("Serialization failed")
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ServerHello {
    #[serde(rename = "type")]
    pub type_: String,
    pub key: PublicKey,
}

impl ServerHello {
    pub fn new(key: PublicKey) -> Self {
        Self {
            type_: "server-hello".into(),
            key: key,
        }
    }
}

impl<'de> MsgPacked<'de> for ServerHello {
    const TYPE: &'static str = "server-hello";

    fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        let decoded: Self = rmps::from_slice::<Self>(&bytes)?;
        if decoded.type_ != Self::TYPE {
            bail!(format!("Invalid type for ServerHello message: {}", decoded.type_));
        }
        Ok(decoded)
    }

    fn to_msgpack(&self) -> Vec<u8> {
        rmps::to_vec_named(&self).expect("Serialization failed")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Round-trip msgpack serialization for ServerHello message.
    fn test_server_hello_roundtrip() {
        let hello = ServerHello::new(PublicKey::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2]).unwrap());
        let bytes = hello.to_msgpack();
        let decoded = ServerHello::from_msgpack(&bytes).unwrap();
        assert_eq!(hello, decoded);
    }

    #[test]
    /// Verify the bytes of a serialized ServerHello message.
    fn test_server_hello_msgpack_bytes() {
        let hello = ServerHello::new(PublicKey::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             99, 255]).unwrap());
        let bytes = hello.to_msgpack();
        assert_eq!(bytes, vec![
            // Fixmap with two entries
            0x82,
            // Key: type
            0xa4, 0x74, 0x79, 0x70, 0x65,
            // Val: server-hello
            0xac, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Key: key
            0xa3, 0x6b, 0x65, 0x79,
            // Val: Binary 32 bytes
            0xc4, 0x20,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
            0x63, 0xff,
        ]);
    }
}
