//! Functionality related to libsodium crypto boxes.
//!
//! An open box consists of an unencrypted message and a nonce.
//!
//! A sealed box consists of the encrypted message bytes and a nonce.

use rust_sodium::crypto::box_::NONCEBYTES;

use errors::{Result, ResultExt, ErrorKind};
use keystore::{PublicKey, PrivateKey};
use messages::Message;
use protocol::Nonce;

/// An open box (unencrypted message + nonce).
#[derive(Debug, PartialEq)]
pub struct OpenBox {
    pub message: Message,
    pub nonce: Nonce,
}

impl OpenBox {
    pub fn new(message: Message, nonce: Nonce) -> Self {
        OpenBox { message, nonce }
    }
}


impl OpenBox {
    /// Encode without encryption into a [`ByteBox`](struct.ByteBox.html).
    ///
    /// This should only be necessary for the server-hello message. All other
    /// messages are encrypted.
    pub fn encode(self) -> ByteBox {
        let bytes = self.message.to_msgpack();
        ByteBox::new(bytes, self.nonce)
    }

    //pub fn encrypt(self, public_key: PublicKey, private_key: PrivateKey,
}


/// A byte box (message bytes + nonce). The bytes may or may not be encrypted.
#[derive(Debug, PartialEq)]
pub struct ByteBox {
    pub bytes: Vec<u8>,
    pub nonce: Nonce,
}

impl ByteBox {
    pub fn new(bytes: Vec<u8>, nonce: Nonce) -> Self {
        ByteBox { bytes, nonce }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() > NONCEBYTES, ErrorKind::Decode("message is too short".into()));
        let nonce = Nonce::from_bytes(&bytes[..24])
            .chain_err(|| ErrorKind::Decode("cannot decode nonce".into()))?;
        let bytes = bytes[24..].to_vec();
        Ok(Self::new(bytes, nonce))
    }

    /// Decode an unencrypted message into an [`OpenBox`](struct.OpenBox.html).
    ///
    /// This should only be necessary for the server-hello message. All other
    /// messages are encrypted.
    pub fn decode(self) -> Result<OpenBox> {
        let message = Message::from_msgpack(&self.bytes)
            .chain_err(|| ErrorKind::Decode("cannot decode message payload".into()))?;
        Ok(OpenBox::new(message, self.nonce))
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCEBYTES + self.bytes.len());
        bytes.extend(self.nonce.into_bytes().iter());
        bytes.extend(self.bytes.iter());
        bytes
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_box_from_slice() {
        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8,
            8, 7, 6, 5, 4, 3, 2, 1,
            1, 2, 3, 4, 5, 6, 7, 8,
            9, 10,
        ];
        let bbox = ByteBox::from_slice(&bytes).unwrap();
        assert_eq!(bbox.nonce.csn().overflow_number(), (3 << 8) + 4);
        assert_eq!(bbox.nonce.csn().sequence_number(), (5 << 24) + (6 << 16) + (7 << 8) + 8);
        assert_eq!(bbox.bytes, vec![9, 10]);
    }

    #[test]
    fn byte_box_from_slice_too_short() {
        let bytes_only_nonce = [1, 2, 3, 4, 5, 6, 7, 8,
                                8, 7, 6, 5, 4, 3, 2, 1,
                                1, 2, 3, 4, 5, 6, 7, 8];
        let bytes_not_even_nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        let err1 = ByteBox::from_slice(&bytes_only_nonce).unwrap_err();
        let err2 = ByteBox::from_slice(&bytes_not_even_nonce).unwrap_err();
        assert_eq!(format!("{}", err1), "decoding error: message is too short");
        assert_eq!(format!("{}", err2), "decoding error: message is too short");
    }
}
