//! Message types used in the SaltyRTC protocol.
//!
//! ## Implementation notes
//!
//! All message types own their values. This choice was made to simplify the
//! use and implementation of the library. Some values may be optimized to take
//! references in a future version.

use std::convert::From;

use rmp_serde as rmps;

use errors::{Result};
use keystore::{PublicKey, SignedKeys};

use super::{Address, Cookie};


/// The `Message` enum contains all possible message types that may be used in
/// the SaltyRTC protocol.
///
/// When converting a `Message` to msgpack bytes, it is serialized as
/// internally tagged enum. This is why the inner structs don't actually need
/// to contain a `type` field.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Message {
    #[serde(rename = "client-hello")]
    ClientHello(ClientHello),
    #[serde(rename = "server-hello")]
    ServerHello(ServerHello),
    #[serde(rename = "client-auth")]
    ClientAuth(ClientAuth),
    #[serde(rename = "server-auth")]
    ServerAuth(ServerAuth),
    #[serde(rename = "new-initiator")]
    NewInitiator(NewInitiator),
    #[serde(rename = "new-responder")]
    NewResponder(NewResponder),
    #[serde(rename = "drop-responder")]
    DropResponder(DropResponder),
}

impl Message {
    /// Decode a message from msgpack bytes.
    pub fn from_msgpack(bytes: &[u8]) -> Result<Self> {
        Ok(rmps::from_slice(bytes)?)
    }

    /// Convert this message to msgpack bytes.
    pub fn to_msgpack(&self) -> Vec<u8> {
        rmps::to_vec_named(&self).expect("Serialization failed")
    }

    /// Return the type of the contained message.
    pub fn get_type(&self) -> &'static str {
        match *self {
            Message::ClientHello(_) => "client-hello",
            Message::ServerHello(_) => "server-hello",
            Message::ClientAuth(_) => "client-auth",
            Message::ServerAuth(_) => "server-auth",
            Message::NewInitiator(_) => "new-initiator",
            Message::NewResponder(_) => "new-responder",
            Message::DropResponder(_) => "drop-responder",
        }
    }
}

/// Implement conversion traits to wrap a type in a `Message`.
macro_rules! impl_message_wrapping {
    ($type:ty, $variant:expr) => {
        impl From<$type> for Message {
            fn from(val: $type) -> Self {
                $variant(val)
            }
        }

        impl $type {
            pub fn into_message(self) -> Message {
                self.into()
            }
        }
    }
}

impl_message_wrapping!(ClientHello, Message::ClientHello);
impl_message_wrapping!(ServerHello, Message::ServerHello);
impl_message_wrapping!(ClientAuth, Message::ClientAuth);
impl_message_wrapping!(ServerAuth, Message::ServerAuth);
impl_message_wrapping!(NewInitiator, Message::NewInitiator);
impl_message_wrapping!(NewResponder, Message::NewResponder);
impl_message_wrapping!(DropResponder, Message::DropResponder);


/// The client-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClientHello {
    pub key: PublicKey,
}

impl ClientHello {
    pub fn new(key: PublicKey) -> Self {
        Self { key: key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self {
            key: PublicKey::from_slice(&bytes).unwrap(),
        }
    }
}

/// The server-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ServerHello {
    pub key: PublicKey,
}

impl ServerHello {
    pub fn new(key: PublicKey) -> Self {
        Self { key: key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self {
            key: PublicKey::from_slice(&bytes).unwrap(),
        }
    }
}


/// The client-auth message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClientAuth {
    pub your_cookie: Cookie,
    pub subprotocols: Vec<String>,
    pub ping_interval: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub your_key: Option<PublicKey>,
}


/// The server-auth message received by the initiator.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ServerAuth {
    pub your_cookie: Cookie,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_keys: Option<SignedKeys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responders: Option<Vec<Address>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_connected: Option<bool>,
}

impl ServerAuth {
    /// Create a new ServerAuth message targeted at an initiator.
    pub fn for_initiator(your_cookie: Cookie, signed_keys: Option<SignedKeys>, responders: Vec<Address>) -> Self {
        Self {
            your_cookie,
            signed_keys,
            responders: Some(responders),
            initiator_connected: None,
        }
    }

    /// Create a new ServerAuth message targeted at a responder.
    pub fn for_responder(your_cookie: Cookie, signed_keys: Option<SignedKeys>, initiator_connected: bool) -> Self {
        Self {
            your_cookie,
            signed_keys,
            responders: None,
            initiator_connected: Some(initiator_connected),
        }
    }
}


/// Sent by the server to all responders when a new initiator joins.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct NewInitiator;

impl NewInitiator {
    /// Create a new `NewInitiator` message.
    pub fn new() -> Self {
        Self { }
    }
}


/// Sent by the server to the initiator when a new responder joins.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct NewResponder {
    pub id: Address,
}

impl NewResponder {
    /// Create a new `NewResponder` message.
    pub fn new(id: Address) -> Self {
        Self { id }
    }
}


/// Sent by the initiator to the server when requesting to drop a responder.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DropResponder {
    pub id: Address,
    pub reason: Option<u16>,
}

impl DropResponder {
    /// Create a new `DropResponder` message.
    pub fn new(id: Address) -> Self {
        Self { id, reason: None }
    }

    pub fn with_reason(id: Address, reason: u16) -> Self {
        Self { id, reason: Some(reason) }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify that a message is correctly serialized, internally tagged.
    fn test_encode_message() {
        let key = PublicKey::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          99, 255]).unwrap();
        let msg = Message::ServerHello(ServerHello { key: key });
        let bytes: Vec<u8> = rmps::to_vec_named(&msg).expect("Serialization failed");
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

    #[test]
    /// Verify that a message is correctly deserialized, depending on the type.
    fn test_decode_message() {
        // Create the ServerHello message we'll compare against
        let key = PublicKey::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                          99, 255]).unwrap();
        let server_hello = ServerHello { key: key };

        // The bytes to deserialize
        let bytes = vec![
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
        ];

        // Deserialize and compare
        let msg: Message = rmps::from_slice(&bytes).unwrap();
        if let Message::ServerHello(sh) = msg {
            assert_eq!(sh, server_hello);
        } else {
            panic!("Wrong message type: Should be ServerHello, but is {:?}", msg);
        }
    }

    #[test]
    /// Round-trip msgpack serialization for `ClientHello` message.
    fn test_client_hello_roundtrip() {
        let hello = ClientHello::new(PublicKey::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                             1, 2]).unwrap());
        let msg: Message = hello.into();
        let bytes = msg.to_msgpack();
        let decoded = Message::from_msgpack(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

}
