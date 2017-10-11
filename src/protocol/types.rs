use boxes::{ByteBox};

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


/// An enum returned when an incoming message is handled.
///
/// It can contain different actions that should be done to finish handling the
/// message.
#[derive(Debug, PartialEq)]
pub(crate) enum HandleAction {
    /// Send the specified message through the websocket.
    Reply(ByteBox),
    /// No further action required.
    None,
}
