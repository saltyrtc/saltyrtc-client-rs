//! Message types used in the SaltyRTC protocol.
//!
//! ## Implementation notes
//!
//! All message types own their values. This choice was made to simplify the
//! use and implementation of the library. Some values may be optimized to take
//! references in a future version.

use std::collections::HashMap;
use std::convert::From;

use rmp_serde as rmps;
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::crypto_types::{PublicKey, SignedKeys};
use crate::errors::{SignalingError, SignalingResult};
use crate::tasks::Tasks;
use crate::CloseCode;

use super::send_error::SendErrorId;
use super::{Address, Cookie};

/// The `Message` enum contains all possible message types that may be used
/// during the handshake in the SaltyRTC protocol.
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
    #[serde(rename = "disconnected")]
    Disconnected(Disconnected),

    // Client to client messages
    #[serde(rename = "token")]
    Token(Token),
    #[serde(rename = "key")]
    Key(Key),
    #[serde(rename = "auth")]
    Auth(Auth),
    #[serde(rename = "close")]
    Close(Close),
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
            Message::Disconnected(_) => "disconnected",

            // Client to client messages
            Message::Token(_) => "token",
            Message::Key(_) => "key",
            Message::Auth(_) => "auth",
            Message::Close(_) => "close",
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

        #[allow(dead_code)]
        impl $type {
            pub(crate) fn into_message(self) -> Message {
                self.into()
            }
        }
    };
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
impl_message_wrapping!(Close, Message::Close);

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
        use crypto_box::aead::{OsRng, rand_core::RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            key: PublicKey::from(bytes),
        }
    }
}

/// The server-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct ServerHello {
    pub(crate) key: PublicKey,
}

impl ServerHello {
    #[cfg(test)]
    pub(crate) fn new(key: PublicKey) -> Self {
        Self { key }
    }

    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        use crypto_box::aead::{OsRng, rand_core::RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            key: PublicKey::from(bytes),
        }
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
    #[cfg(test)]
    pub(crate) fn for_initiator(
        your_cookie: Cookie,
        signed_keys: Option<SignedKeys>,
        responders: Vec<Address>,
    ) -> Self {
        Self {
            your_cookie,
            signed_keys,
            responders: Some(responders),
            initiator_connected: None,
        }
    }

    /// Create a new ServerAuth message targeted at a responder.
    #[cfg(test)]
    pub(crate) fn for_responder(
        your_cookie: Cookie,
        signed_keys: Option<SignedKeys>,
        initiator_connected: bool,
    ) -> Self {
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

/// Sent by the server to the initiator when a new responder joins.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct NewResponder {
    pub(crate) id: Address,
}

#[allow(dead_code)]
pub(crate) enum DropReason {
    ProtocolError,
    InternalError,
    DroppedByInitiator,
    InitiatorCouldNotDecrypt,
}

impl Into<u16> for DropReason {
    fn into(self) -> u16 {
        use self::DropReason::*;
        match self {
            ProtocolError => 3001,
            InternalError => 3002,
            DroppedByInitiator => 3004,
            InitiatorCouldNotDecrypt => 3005,
        }
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
    /// Create a new `DropResponder` message with a reason code.
    pub(crate) fn with_reason(id: Address, reason: DropReason) -> Self {
        Self {
            id,
            reason: Some(reason.into()),
        }
    }
}

/// Sent by the server if relaying a client-to-client message fails.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct SendError {
    pub(crate) id: SendErrorId,
}

/// Sent by the server if an authenticated peer disconnects.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Disconnected {
    pub(crate) id: Address,
}

impl Disconnected {
    #[allow(dead_code)]
    pub(crate) fn new(id: Address) -> Self {
        Self { id }
    }
}

/// The token message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Token {
    pub(crate) key: PublicKey,
}

impl Token {
    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        use crypto_box::aead::{OsRng, rand_core::RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            key: PublicKey::from(bytes),
        }
    }
}

/// The key message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Key {
    // TODO (#9): Do we want to differentiate between permanent key and session key
    // in the type system?
    pub(crate) key: PublicKey,
}

impl Key {
    /// Create a new instance with dummy data. Used in testing.
    #[cfg(test)]
    pub(crate) fn random() -> Self {
        use crypto_box::aead::{OsRng, rand_core::RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self {
            key: PublicKey::from(bytes),
        }
    }
}

/// The auth message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Auth {
    pub(crate) your_cookie: Cookie,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tasks: Option<Vec<String>>,
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
    /// Create a new `Auth` message targeted at a responder.
    pub(crate) fn new(your_cookie: Cookie) -> Self {
        Self {
            auth: Auth {
                your_cookie,
                tasks: None,
                task: None,
                data: HashMap::new(),
            },
        }
    }

    /// Set the task.
    pub(crate) fn set_task<S: Into<String>>(
        mut self,
        name: S,
        data: Option<HashMap<String, Value>>,
    ) -> Self {
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
            Err(SignalingError::InvalidMessage(
                "An `Auth` message must have a task set".into(),
            ))
        }
    }
}

impl ResponderAuthBuilder {
    /// Create a new `Auth` message targeted at an initiator.
    pub(crate) fn new(your_cookie: Cookie) -> Self {
        Self {
            auth: Auth {
                your_cookie,
                tasks: Some(vec![]),
                task: None,
                data: HashMap::new(),
            },
        }
    }

    /// Add a task.
    #[cfg(test)]
    pub(crate) fn add_task<S: Into<String>>(
        mut self,
        name: S,
        data: Option<HashMap<String, Value>>,
    ) -> Self {
        let name: String = name.into();
        match self.auth.tasks {
            Some(ref mut tasks) => tasks.push(name.clone()),
            None => panic!("tasks list not initialized!"),
        };
        self.auth.data.insert(name, data);
        self
    }

    /// Add a `Tasks` instance.
    pub(crate) fn add_tasks(mut self, tasks: &Tasks) -> Self {
        for task in &tasks.0 {
            let name: String = task.name().into();
            match self.auth.tasks {
                Some(ref mut tasks) => tasks.push(name.clone()),
                None => panic!("tasks list not initialized!"),
            };
            self.auth.data.insert(name, task.data());
        }
        self
    }

    /// Return the resulting `Auth` message.
    pub(crate) fn build(self) -> SignalingResult<Auth> {
        if self.auth.task.is_some() {
            panic!("task may not be set");
        }

        {
            // Validate tasks
            let tasks = self
                .auth
                .tasks
                .as_ref()
                .expect("tasks list not initialized!");

            // Ensure that tasks list is not empty
            if tasks.is_empty() {
                return Err(SignalingError::InvalidMessage(
                    "An `Auth` message must contain at least one task".to_string(),
                ));
            }

            // Ensure that tasks list does not contain duplicates
            let mut cloned = tasks.clone();
            cloned.sort_unstable();
            cloned.dedup();
            if cloned.len() != tasks.len() {
                return Err(SignalingError::InvalidMessage(
                    "An `Auth` message may not contain duplicate tasks".to_string(),
                ));
            }
        } // Waiting for NLL

        Ok(self.auth)
    }
}

/// The client-hello message.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub(crate) struct Close {
    pub(crate) reason: u16,
}

impl Close {
    #[cfg(test)]
    pub(crate) fn new(reason: u16) -> Self {
        Self { reason }
    }

    pub(crate) fn from_close_code(close_code: CloseCode) -> Self {
        Self {
            reason: close_code.as_number(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Verify that a message is correctly serialized, internally tagged.
    fn test_encode_message() {
        let key = PublicKey::from([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 99, 255,
        ]);
        let msg = Message::ServerHello(ServerHello { key });
        let bytes: Vec<u8> = rmps::to_vec_named(&msg).expect("Serialization failed");
        #[rustfmt::skip]
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
        let key = PublicKey::from([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            0, 99, 255,
        ]);
        let server_hello = ServerHello { key };

        // The bytes to deserialize
        #[rustfmt::skip]
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
            panic!(
                "Wrong message type: Should be ServerHello, but is {:?}",
                msg
            );
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
            };
        }

        roundtrip!(client_hello, ClientHello::random());
        roundtrip!(server_hello, ServerHello::random());
        roundtrip!(
            drop_responder,
            DropResponder::with_reason(4.into(), DropReason::DroppedByInitiator)
        );
        roundtrip!(token, Token::random());
        roundtrip!(key, Key::random());
        roundtrip!(
            auth_responder,
            InitiatorAuthBuilder::new(Cookie::random())
                .set_task("foo.bar.baz", None)
                .build()
                .unwrap()
        );
        roundtrip!(
            auth_initiator,
            ResponderAuthBuilder::new(Cookie::random())
                .add_task("foo.bar.baz", None)
                .build()
                .unwrap()
        );
        roundtrip!(close, Close::new(3003));
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
            let cookie = Cookie::random();
            let builder = InitiatorAuthBuilder::new(cookie.clone()).set_task("data.none", None);
            let result = builder.build();
            let auth = result.unwrap();
            assert_eq!(auth.your_cookie, cookie);
            assert!(auth.tasks.is_none());
            assert!(auth.task.is_some());
            assert_eq!(auth.task.unwrap(), "data.none");
            assert_eq!(auth.data.len(), 1);
            assert!(auth.data.contains_key("data.none"));
        }

        #[test]
        fn responder_auth_builder_incomplete() {
            let builder = ResponderAuthBuilder::new(Cookie::random());
            let result = builder.build();
            assert!(result.is_err());
        }

        #[test]
        fn responder_auth_builder() {
            let mut data = HashMap::new();
            data.insert("foo".to_string(), Value::Boolean(true));
            let cookie = Cookie::random();
            let builder = ResponderAuthBuilder::new(cookie.clone())
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
    }

    mod send_error {
        use super::*;

        #[test]
        fn send_error_decode() {
            #[rustfmt::skip]
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
                assert_eq!(
                    se.id.csn.sequence_number(),
                    (0x8a << 24) + (0xe3 << 16) + (0xbe << 8) + 0xb5
                );
            } else {
                panic!("Wrong message type: Should be SendError, but is {:?}", msg);
            }
        }
    }
}
