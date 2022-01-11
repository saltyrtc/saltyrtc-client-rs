//! Functionality related to nacl crypto boxes.
//!
//! An open box consists of an unencrypted message and a nonce.
//!
//! A sealed box consists of the encrypted message bytes and a nonce.

use rmp_serde as rmps;
use rmpv::Value;
use rust_sodium::crypto::box_::NONCEBYTES;

use crate::{
    crypto::{AuthToken, KeyPair, PublicKey},
    errors::{SignalingError, SignalingResult},
    protocol::{messages::Message, Nonce},
};

/// An open box (unencrypted message + nonce).
#[derive(Debug, PartialEq)]
pub(crate) struct OpenBox<T> {
    pub(crate) message: T,
    pub(crate) nonce: Nonce,
}

impl OpenBox<Message> {
    pub(crate) fn new(message: Message, nonce: Nonce) -> Self {
        OpenBox { message, nonce }
    }

    /// Encode without encryption into a [`ByteBox`](struct.ByteBox.html).
    ///
    /// This should only be necessary for the server-hello message. All other
    /// messages are encrypted.
    pub(crate) fn encode(self) -> ByteBox {
        let bytes = self.message.to_msgpack();
        ByteBox::new(bytes, self.nonce)
    }

    /// Encrypt message for the `other_key` using public key cryptography.
    pub(crate) fn encrypt(
        self,
        keypair: &KeyPair,
        other_key: &PublicKey,
    ) -> SignalingResult<ByteBox> {
        let encrypted = keypair.encrypt(
            // The message bytes to be encrypted
            &self.message.to_msgpack(),
            // The nonce. The unsafe call to `clone()` is required because the
            // nonce needs to be used both for encrypting, as well as being
            // sent along with the message bytes.
            unsafe { self.nonce.clone() },
            // The public key of the recipient
            other_key,
        )?;
        Ok(ByteBox::new(encrypted, self.nonce))
    }

    /// Encrypt token message using the `auth_token` using secret key cryptography.
    pub(crate) fn encrypt_token(self, auth_token: &AuthToken) -> SignalingResult<ByteBox> {
        let encrypted = auth_token.encrypt(
            // The message bytes to be encrypted
            &self.message.to_msgpack(),
            // The nonce. The unsafe call to `clone()` is required because the
            // nonce needs to be used both for encrypting, as well as being
            // sent along with the message bytes.
            unsafe { self.nonce.clone() },
        )?;
        Ok(ByteBox::new(encrypted, self.nonce))
    }

    /// Decode an unencrypted message into an [`OpenBox`](struct.OpenBox.html).
    ///
    /// This should only be necessary for the server-hello message. All other
    /// messages are encrypted.
    pub(crate) fn decode(bbox: ByteBox) -> SignalingResult<Self> {
        let message = Message::from_msgpack(&bbox.bytes)
            .map_err(|e| SignalingError::Decode(format!("Cannot decode message payload: {}", e)))?;
        Ok(Self::new(message, bbox.nonce))
    }

    /// Decrypt an encrypted message into an [`OpenBox`](struct.OpenBox.html).
    pub(crate) fn decrypt(
        bbox: ByteBox,
        keypair: &KeyPair,
        other_key: &PublicKey,
    ) -> SignalingResult<Self> {
        let decrypted: Vec<u8> = keypair
            .decrypt(
                // The message bytes to be decrypted
                &bbox.bytes,
                // The nonce. The unsafe call to `clone()` is required because the
                // nonce needs to be used both for decrypting, as well as being
                // passed along with the message bytes.
                unsafe { bbox.nonce.clone() },
                // The public key of the recipient
                other_key,
            )
            .map_err(|e| {
                SignalingError::Decode(format!("Cannot decrypt message payload: {}", e))
            })?;

        log_decrypted_bytes(&decrypted);

        let message = Message::from_msgpack(&decrypted)
            .map_err(|e| SignalingError::Decode(format!("Cannot decode message payload: {}", e)))?;

        Ok(Self::new(message, bbox.nonce))
    }

    /// Decrypt token message using the `auth_token` using secret key cryptography.
    pub(crate) fn decrypt_token(bbox: ByteBox, auth_token: &AuthToken) -> SignalingResult<Self> {
        let decrypted = auth_token
            .decrypt(&bbox.bytes, unsafe { bbox.nonce.clone() })
            .map_err(|e| SignalingError::Decode(format!("Cannot decode message payload: {}", e)))?;

        log_decrypted_bytes(&decrypted);

        let message = Message::from_msgpack(&decrypted)
            .map_err(|e| SignalingError::Decode(format!("Cannot decode message payload: {}", e)))?;

        Ok(Self::new(message, bbox.nonce))
    }
}

impl OpenBox<Value> {
    pub(crate) fn new(message: Value, nonce: Nonce) -> Self {
        OpenBox { message, nonce }
    }

    /// Encrypt message for the `other_key` using public key cryptography.
    pub(crate) fn encrypt(
        self,
        keypair: &KeyPair,
        other_key: &PublicKey,
    ) -> SignalingResult<ByteBox> {
        let encrypted = keypair.encrypt(
            // The message bytes to be encrypted
            &rmps::to_vec_named(&self.message).expect("Failed to serialize value"),
            // The nonce. The unsafe call to `clone()` is required because the
            // nonce needs to be used both for encrypting, as well as being
            // sent along with the message bytes.
            unsafe { self.nonce.clone() },
            // The public key of the recipient
            other_key,
        )?;
        Ok(ByteBox::new(encrypted, self.nonce))
    }

    /// Decrypt a task message into a dynamically typed msgpack `Value`.
    ///
    /// This should be used after the handshake has finished.
    pub(crate) fn decrypt(
        bbox: ByteBox,
        keypair: &KeyPair,
        other_key: &PublicKey,
    ) -> SignalingResult<OpenBox<Value>> {
        let decrypted: Vec<u8> = keypair
            .decrypt(
                // The message bytes to be decrypted
                &bbox.bytes,
                // The nonce. The unsafe call to `clone()` is required because the
                // nonce needs to be used both for decrypting, as well as being
                // passed along with the message bytes.
                unsafe { bbox.nonce.clone() },
                // The public key of the recipient
                other_key,
            )
            .map_err(|e| {
                SignalingError::Decode(format!("Cannot decrypt message payload: {}", e))
            })?;

        log_decrypted_bytes(&decrypted);

        let message: Value = rmps::from_slice(&decrypted)
            .map_err(|e| SignalingError::Decode(format!("Cannot decode message payload: {}", e)))?;

        Ok(Self::new(message, bbox.nonce))
    }
}

/// A byte box (message bytes + nonce). The bytes may or may not be encrypted.
#[derive(Debug, PartialEq)]
pub(crate) struct ByteBox {
    pub(crate) bytes: Vec<u8>,
    pub(crate) nonce: Nonce,
}

impl ByteBox {
    pub(crate) fn new(bytes: Vec<u8>, nonce: Nonce) -> Self {
        ByteBox { bytes, nonce }
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> SignalingResult<Self> {
        if bytes.len() <= NONCEBYTES {
            return Err(SignalingError::Decode("Message is too short".into()));
        }
        let nonce = Nonce::from_bytes(&bytes[..24])
            .map_err(|e| SignalingError::Decode(format!("Cannot decode nonce: {}", e)))?;
        let bytes = bytes[24..].to_vec();
        Ok(Self::new(bytes, nonce))
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCEBYTES + self.bytes.len());
        bytes.extend(self.nonce.into_bytes().iter());
        bytes.extend(self.bytes.iter());
        bytes
    }
}

#[cfg(feature = "msgpack-debugging")]
fn log_decrypted_bytes(decrypted: &[u8]) {
    use data_encoding::BASE64;
    let encoded = || {
        BASE64
            .encode(&decrypted)
            .replace("+", "%2B")
            .replace("=", "%3D")
            .replace("/", "%2F")
    };
    match option_env!("MSGPACK_DEBUG_URL") {
        Some(url) => trace!("Decrypted bytes: {}{}", url, encoded()),
        None => trace!(
            "Decrypted bytes: {}{}",
            crate::DEFAULT_MSGPACK_DEBUG_URL,
            encoded()
        ),
    }
}

#[cfg(not(feature = "msgpack-debugging"))]
fn log_decrypted_bytes(decrypted: &[u8]) {
    trace!("Decrypted bytes: {:?}", &decrypted);
}

#[cfg(test)]
mod tests {
    use crate::protocol::cookie::Cookie;
    use crate::protocol::csn::CombinedSequenceSnapshot;
    use crate::protocol::types::Address;

    use super::*;

    /// Return a test nonce.
    fn create_test_nonce() -> Nonce {
        Nonce::new(
            Cookie::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            Address(17),
            Address(18),
            CombinedSequenceSnapshot::new(258, 50_595_078),
        )
    }

    /// Return bytes of a server-hello message.
    fn create_test_msg_bytes() -> Vec<u8> {
        vec![
            // Fixmap with two entries
            0x82, // Key: type
            0xa4, 0x74, 0x79, 0x70, 0x65, // Val: server-hello
            0xac, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
            // Key: key
            0xa3, 0x6b, 0x65, 0x79, // Val: Binary 32 bytes
            0xc4, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x00, 0x63, 0xff,
        ]
    }

    #[test]
    fn byte_box_from_slice() {
        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ];
        let bbox = ByteBox::from_slice(&bytes).unwrap();
        assert_eq!(bbox.nonce.csn().overflow_number(), (3 << 8) + 4);
        assert_eq!(
            bbox.nonce.csn().sequence_number(),
            (5 << 24) + (6 << 16) + (7 << 8) + 8
        );
        assert_eq!(bbox.bytes, vec![9, 10]);
    }

    #[test]
    fn byte_box_from_slice_too_short() {
        let bytes_only_nonce = [
            1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let bytes_not_even_nonce = [1, 2, 3, 4, 5, 6, 7, 8];

        let err1 = ByteBox::from_slice(&bytes_only_nonce).unwrap_err();
        let err2 = ByteBox::from_slice(&bytes_not_even_nonce).unwrap_err();
        assert_eq!(format!("{}", err1), "Decoding error: Message is too short");
        assert_eq!(format!("{}", err2), "Decoding error: Message is too short");
    }

    #[test]
    fn byte_box_decode_message() {
        let nonce = create_test_nonce();
        let bbox = ByteBox::new(create_test_msg_bytes(), nonce);
        let obox = OpenBox::<Message>::decode(bbox).unwrap();
        assert_eq!(obox.message.get_type(), "server-hello");
    }

    #[test]
    fn byte_box_decrypt_message() {
        let nonce = create_test_nonce();
        let bytes = create_test_msg_bytes();
        let keypair_tx = KeyPair::new();
        let keypair_rx = KeyPair::new();
        let encrypted = keypair_tx
            .encrypt(&bytes, unsafe { nonce.clone() }, keypair_rx.public_key())
            .unwrap();
        let bbox = ByteBox::new(encrypted, nonce);
        let obox = OpenBox::<Message>::decrypt(bbox, &keypair_rx, keypair_tx.public_key()).unwrap();
        assert_eq!(obox.message.get_type(), "server-hello");
    }

    #[test]
    fn byte_box_decrypt_token_message() {
        // Create test nonce and message
        let nonce = create_test_nonce();
        let bytes = create_test_msg_bytes();

        // New auth token
        let auth_token = AuthToken::new();

        // Encrypt message with that auth token directly
        let encrypted = auth_token
            .encrypt(&bytes, unsafe { nonce.clone() })
            .unwrap();

        // Construct byte box
        let bbox = ByteBox::new(encrypted, nonce);

        // Decrypt byte box
        let obox = OpenBox::decrypt_token(bbox, &auth_token).unwrap();
        assert_eq!(obox.message.get_type(), "server-hello");
    }

    #[test]
    fn byte_box_decrypt_value() {
        let nonce = create_test_nonce();
        let value = Value::Map(vec![
            (
                Value::String("type".into()),
                Value::String("taskmsg".into()),
            ),
            (Value::String("number".into()), Value::Integer(42.into())),
        ]);
        let bytes = rmps::to_vec_named(&value).unwrap();
        let keypair_tx = KeyPair::new();
        let keypair_rx = KeyPair::new();
        let encrypted = keypair_tx
            .encrypt(&bytes, unsafe { nonce.clone() }, keypair_rx.public_key())
            .unwrap();

        // First, make sure that decrypting this as message fails.
        let bbox = ByteBox::new(encrypted.clone(), unsafe { nonce.clone() });
        let decrypt_as_message =
            OpenBox::<Message>::decrypt(bbox, &keypair_rx, keypair_tx.public_key());
        assert!(decrypt_as_message.is_err());

        // Then decrypt as value.
        let bbox = ByteBox::new(encrypted, nonce);
        let obox = OpenBox::<Value>::decrypt(bbox, &keypair_rx, keypair_tx.public_key()).unwrap();
        match obox.message {
            Value::Map(values) => {
                assert_eq!(values.len(), 2);
                assert_eq!(values[0].0, Value::String("type".into()));
                assert_eq!(values[0].1, Value::String("taskmsg".into()));
                assert_eq!(values[1].0, Value::String("number".into()));
                assert_eq!(values[1].1, Value::Integer(42.into()));
            }
            other => panic!("Expected map, got {:?}", other),
        }
    }
}
