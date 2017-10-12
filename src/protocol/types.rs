use boxes::{ByteBox};
use keystore::{PublicKey};

/// The role of a peer.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Role {
    /// A SaltyRTC compliant client who wants to establish a WebRTC or ORTC
    /// peer-to-peer connection to a responder.
    Initiator,
    /// A SaltyRTC compliant client who wants to establish a WebRTC or ORTC
    /// peer-to-peer connection to an initiator.
    Responder,
}

impl Role {
    pub fn is_initiator(&self) -> bool {
        *self == Role::Initiator
    }

    pub fn is_responder(&self) -> bool {
        *self == Role::Responder
    }
}


/// An enum returned when an incoming message is handled.
///
/// It can contain different actions that should be done to finish handling the
/// message.
///
/// TODO: This could be split up into actions for the signaling state and
/// actions for the network part.
#[derive(Debug, PartialEq)]
pub enum HandleAction {
    /// Send the specified message through the websocket.
    Reply(ByteBox),
    /// Update the server key.
    SetServerKey(PublicKey),
}
