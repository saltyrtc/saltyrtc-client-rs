/// The state of the entire signaling instance.
///
/// When establishing a connection with a SaltyRTC peer, the connection buildup
/// can be in one of three stages: Server handshake, peer handshake or task.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SignalingState {
    /// The server handshake is in progress.
    ServerHandshake,
    /// The server handshake is finished, the peer handshake is in progress.
    PeerHandshake,
    /// The peer handshake is finished, control has been handed over to a task.
    Task,
}

/// The states when doing a handshake with the server.
///
/// The `ClientHello` state is only valid for the responder role, otherwise the
/// state will transition from `ServerHello` to `ClientAuth` directly.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ServerHandshakeState {
    /// Initial state.
    New,
    /// The client-hello (only responder) and client-auth messages have been sent.
    ClientInfoSent,
    /// The server-auth message has been received and processed.
    Done,
}

/// The states when doing a handshake with the initiator.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum InitiatorHandshakeState {
    /// Initial state.
    New,
    /// A [`Key`](../messages/struct.Key.html) message and maybe a
    /// [`Token`](../messages/struct.Token.html) message have been sent.
    KeySent,
    /// A [`Key`](../messages/struct.Key.html) message has been received.
    KeyReceived,
    AuthSent,
    AuthReceived,
}

/// The states when doing a handshake with the responder.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ResponderHandshakeState {
    /// Initial state.
    New,
    TokenReceived,
    /// A [`Key`](../messages/struct.Key.html) message has been received.
    KeyReceived,
    /// A [`Key`](../messages/struct.Key.html) message has been sent.
    KeySent,
    AuthReceived,
    AuthSent,
}
