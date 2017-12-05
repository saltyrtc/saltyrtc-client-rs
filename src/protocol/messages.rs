//! Message types used in the SaltyRTC protocol.
//!
//! ## Implementation notes
//!
//! All message types own their values. This choice was made to simplify the
//! use and implementation of the library. Some values may be optimized to take
//! references in a future version.

use std::collections::{HashMap, HashSet};
use std::convert::From;

use rmp_serde as rmps;
use rmpv::Value;

use crypto::{PublicKey, SignedKeys};
use errors::{SignalingError, SignalingResult};

use super::{Address, Cookie};
use super::csn::{CombinedSequenceSnapshot};
use super::send_error::{SendErrorId};


/// The `Message` enum contains all possible message types that may be used in
/// the SaltyRTC protocol.
///
/// When converting a `Message` to msgpack bytes, it is serialized as
/// internally tagged enum. This is why the inner structs don't actually need
/// to contain a `type` field.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type")]
pub(crate) enum Message {
    // Server to client messages
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
    #[serde(rename = "send-error")]
    SendError(SendError),

    // Client to client messages
    #[serde(rename = "token")]
    Token(Token),
    #[serde(rename = "key")]
    Key(Key),
    #[serde(rename = "auth")]
    Auth(Auth),
}

impl Message {
    /// Decode a message from msgpack bytes.
    pub(crate) fn from_msgpack(bytes: &[u8]) -> SignalingResult<Self> {
        Ok(rmps::from_slice(bytes)?)
    }

    /// Convert this message to msgpack bytes.
    pub(crate) fn to_msgpack(&self) -> Vec<u8> {
        rmps::to_vec_named(&self).expect("Serialization failed")
    }

    /// Return the type of the contained message.
    pub(crate) fn get_type(&self) -> &'static str {
        match *self {
            // Server to client messages
            Message::ClientHello(_) => "client-hello",
            Message::ServerHello(_) => "server-hello",
            Message::ClientAuth(_) => "client-auth",
            Message::ServerAuth(_) => "server-auth",
            Message::NewInitiator(_) => "new-initiator",
            Message::NewResponder(_) => "new-responder",
            Message::DropResponder(_) => "drop-responder",
            Message::SendError(_) => "send-error",

            // Client to client messages
            Message::Token(_) => "token",
            Message::Key(_) => "key",
            Message::Auth(_) => "auth",
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
            pub(crate) fn into_message(self) -> Message {
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
impl_message_wrapping!(SendError, Message::SendError);
impl_message_wrapping!(Token, Message::Token);
impl_message_wrapping!(Key, Message::Key);
impl_message_wrapping!(Auth, Message::Auth);


/// The client-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct ClientHello {
    pub(crate) key: PublicKey,
}

impl ClientHello {
    pub(crate) fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self { key: PublicKey::from_slice(&bytes).unwrap() }
    }
}

/// The server-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct ServerHello {
    pub(crate) key: PublicKey,
}

impl ServerHello {
    pub(crate) fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self { key: PublicKey::from_slice(&bytes).unwrap() }
    }
}


/// The client-auth message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct ClientAuth {
    pub(crate) your_cookie: Cookie,
    pub(crate) subprotocols: Vec<String>,
    pub(crate) ping_interval: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) your_key: Option<PublicKey>,
}


/// The server-auth message received by the initiator.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct ServerAuth {
    pub(crate) your_cookie: Cookie,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) signed_keys: Option<SignedKeys>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) responders: Option<Vec<Address>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) initiator_connected: Option<bool>,
}

impl ServerAuth {
    /// Create a new ServerAuth message targeted at an initiator.
    pub(crate) fn for_initiator(your_cookie: Cookie, signed_keys: Option<SignedKeys>, responders: Vec<Address>) -> Self {
        Self {
            your_cookie,
            signed_keys,
            responders: Some(responders),
            initiator_connected: None,
        }
    }

    /// Create a new ServerAuth message targeted at a responder.
    pub(crate) fn for_responder(your_cookie: Cookie, signed_keys: Option<SignedKeys>, initiator_connected: bool) -> Self {
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
pub(crate) struct NewInitiator;

impl NewInitiator {
    /// Create a new `NewInitiator` message.
    pub(crate) fn new() -> Self {
        Self { }
    }
}


/// Sent by the server to the initiator when a new responder joins.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct NewResponder {
    pub(crate) id: Address,
}

impl NewResponder {
    /// Create a new `NewResponder` message.
    pub(crate) fn new(id: Address) -> Self {
        Self { id }
    }
}


/// Sent by the initiator to the server when requesting to drop a responder.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct DropResponder {
    pub(crate) id: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<u16>,
}

impl DropResponder {
    /// Create a new `DropResponder` message without a reason code.
    pub(crate) fn new(id: Address) -> Self {
        Self { id, reason: None }
    }

    /// Create a new `DropResponder` message with a reason code.
    pub(crate) fn with_reason(id: Address, reason: u16) -> Self {
        Self { id, reason: Some(reason) }
    }
}


/// Sent by the server if relaying a client-to-client message fails.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct SendError {
    pub(crate) id: SendErrorId,
}

impl SendError {
    /// Create a new `SendError` message.
    pub(crate) fn new(id: SendErrorId) -> Self {
        Self { id }
    }
}


/// The token message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Token {
    pub(crate) key: PublicKey,
}

impl Token {
    /// Create a new `Token` message.
    pub(crate) fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self { key: PublicKey::from_slice(&bytes).unwrap() }
    }
}


/// The key message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Key {
    pub(crate) key: PublicKey,
}

impl Key {
    /// Create a new `Key` message.
    pub(crate) fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        ::helpers::libsodium_init_or_panic();
        let mut bytes = [0u8; 32];
        ::rust_sodium::randombytes::randombytes_into(&mut bytes);
        Self { key: PublicKey::from_slice(&bytes).unwrap() }
    }
}


/// The auth message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Auth {
    pub(crate) your_cookie: Cookie,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tasks: Option<HashSet<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) task: Option<String>,
    pub(crate) data: HashMap<String, Option<HashMap<String, Value>>>,
}

pub(crate) struct InitiatorAuthBuilder {
    auth: Auth,
}

pub(crate) struct ResponderAuthBuilder {
    auth: Auth,
}

impl InitiatorAuthBuilder {

    /// Create a new `Auth` message targeted at an initiator.
    pub(crate) fn new(your_cookie: Cookie) -> Self {
        Self {
            auth: Auth {
                your_cookie,
                tasks: Some(HashSet::new()),
                task: None,
                data: HashMap::new(),
            }
        }
    }

    /// Add a task.
    pub(crate) fn add_task<S: Into<String>>(mut self, name: S, data: Option<HashMap<String, Value>>) -> Self {
        let name: String = name.into();
        match self.auth.tasks {
            Some(ref mut tasks) => tasks.insert(name.clone()),
            None => panic!("tasks list not initialized!"),
        };
        self.auth.data.insert(name, data);
        self
    }

    /// Return the resulting `Auth` message.
    pub(crate) fn build(self) -> SignalingResult<Auth> {
        if self.auth.task.is_some() {
            panic!("task may not be set");
        }
        match self.auth.tasks {
            Some(ref tasks) if tasks.len() == 0 => Err(
                SignalingError::InvalidMessage("An `Auth` message must contain at least one task".to_string())
            ),
            Some(_) => Ok(self.auth),
            None => panic!("tasks list not initialized!"),
        }
    }

}

impl ResponderAuthBuilder {

    /// Create a new `Auth` message targeted at a responder.
    pub(crate) fn new(your_cookie: Cookie) -> Self {
        Self {
            auth: Auth {
                your_cookie,
                tasks: None,
                task: None,
                data: HashMap::new(),
            }
        }
    }

    /// Set the task.
    pub(crate) fn set_task<S: Into<String>>(mut self, name: S, data: Option<HashMap<String, Value>>) -> Self {
        let name: String = name.into();
        self.auth.task = Some(name.clone());
        self.auth.data.clear();
        self.auth.data.insert(name, data);
        self
    }

    /// Return the resulting `Auth` message.
    pub(crate) fn build(self) -> SignalingResult<Auth> {
        if self.auth.tasks.is_some() {
            panic!("tasks may not be set");
        }
        if self.auth.task.is_some() {
            Ok(self.auth)
        } else {
            Err(SignalingError::InvalidMessage("An `Auth` message must have a task set".into()))
        }
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

    mod roundtrip {
        use super::*;

        macro_rules! roundtrip {
            ($name:ident, $msg_inner:expr) => {
                #[test]
                fn $name() {
                    let msg: Message = $msg_inner.into();
                    let bytes = msg.to_msgpack();
                    let decoded = Message::from_msgpack(&bytes).unwrap();
                    assert_eq!(msg, decoded);
                }
            }
        }

        roundtrip!(client_hello, ClientHello::random());
        roundtrip!(server_hello, ServerHello::random());
        roundtrip!(drop_responder_no_reason, DropResponder::new(4.into()));
        roundtrip!(drop_responder_with_reason, DropResponder::with_reason(4.into(), 3004));
        roundtrip!(token, Token::random());
        roundtrip!(key, Key::random());
        roundtrip!(auth_initiator, InitiatorAuthBuilder::new(Cookie::random())
                   .add_task("foo.bar.baz", None)
                   .build().unwrap());
        roundtrip!(auth_responder, ResponderAuthBuilder::new(Cookie::random())
                   .set_task("foo.bar.baz", None)
                   .build().unwrap());
    }

    mod auth {
        use super::*;

        #[test]
        fn initiator_auth_builder_incomplete() {
            let builder = InitiatorAuthBuilder::new(Cookie::random());
            let result = builder.build();
            assert!(result.is_err());
        }

        #[test]
        fn initiator_auth_builder() {
            let mut data = HashMap::new();
            data.insert("foo".to_string(), Value::Boolean(true));
            let cookie = Cookie::random();
            let builder = InitiatorAuthBuilder::new(cookie.clone())
                .add_task("data.none", None)
                .add_task("data.none", None)
                .add_task("data.some", Some(data.clone()));
            let result = builder.build();
            let auth = result.unwrap();
            assert_eq!(auth.your_cookie, cookie);
            assert!(auth.task.is_none());
            assert!(auth.tasks.is_some());
            assert_eq!(auth.tasks.unwrap().len(), 2);
            assert_eq!(auth.data.len(), 2);
        }

        #[test]
        fn responder_auth_builder_incomplete() {
            let builder = ResponderAuthBuilder::new(Cookie::random());
            let result = builder.build();
            assert!(result.is_err());
        }

        #[test]
        fn responder_auth_builder() {
            let cookie = Cookie::random();
            let builder = ResponderAuthBuilder::new(cookie.clone())
                .set_task("data.none", None);
            let result = builder.build();
            let auth = result.unwrap();
            assert_eq!(auth.your_cookie, cookie);
            assert!(auth.tasks.is_none());
            assert!(auth.task.is_some());
            assert_eq!(auth.task.unwrap(), "data.none");
            assert_eq!(auth.data.len(), 1);
            assert!(auth.data.contains_key("data.none"));
        }
    }

    mod send_error {
        use super::*;

        #[test]
        fn send_error_decode() {
            let bytes = [
                // Fixmap with two entries
                0x82,
                // Key: type
                0xa4, 0x74, 0x79, 0x70, 0x65,
                // Val: send-error
                0xaa, 0x73, 0x65, 0x6e, 0x64, 0x2d, 0x65, 0x72, 0x72, 0x6f, 0x72,
                // Key: id
                0xa2, 0x69, 0x64,
                // Val: binary data
                0xc4, 0x08,
                    // Source address
                    0x02,
                    // Destination address
                    0x01,
                    // Overflow number
                    0x00, 0x00,
                    // Sequence number
                    0x8a, 0xe3, 0xbe, 0xb5,
            ];

            let msg: Message = rmps::from_slice(&bytes).unwrap();
            if let Message::SendError(se) = msg {
                assert_eq!(se.id.source, Address(2));
                assert_eq!(se.id.destination, Address(1));
                assert_eq!(se.id.csn.overflow_number(), 0);
                assert_eq!(se.id.csn.sequence_number(), (0x8a << 24) + (0xe3 << 16) + (0xbe << 8) + 0xb5);
            } else {
                panic!("Wrong message type: Should be SendError, but is {:?}", msg);
            }
        }
    }
}
