/// The error message to be used inside the `Failure` state.
///
/// This is mostly used as an error type when returning results with a list of
/// handle actions.
pub type FailureMsg = String;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SignalingState {
    ServerHandshake,
    PeerHandshake,
    Task,
}

/// The states when doing a handshake with the server.
///
/// The `ClientHello` state is only valid for the responder role, otherwise the
/// state will transition from `ServerHello` to `ClientAuth` directly.
///
/// If any invalid transition happens, the state will change to the terminal
/// `Failure` state.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServerHandshakeState {
    /// Initial state.
    New,
    /// The client-hello (only responder) and client-auth messages have been sent.
    ClientInfoSent,
    /// The server-auth message has been received and processed.
    Done,
    /// Something went wrong. This is a terminal state.
    Failure(String),
}

/// The states when doing a handshake with the initiator.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InitiatorHandshakeState {
    /// Initial state.
    New,
    /// A `key` message and maybe a `token` message have been sent.
    KeySent,
    /// A `key` message has been received.
    KeyReceived,
    AuthSent,
    AuthReceived,
    Failure(String),
}

/// The states when doing a handshake with the responder.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ResponderHandshakeState {
    /// Initial state.
    New,
    TokenReceived,
    KeyReceived,
    KeySent,
    AuthReceived,
    AuthSent,
    Failure(String),
}
