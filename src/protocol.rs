//! Protocol state machine.

use messages::Message;

#[derive(Debug, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, PartialEq, Eq)]
enum ServerHandshakeState {
    /// Initial state
    New,
    /// The server-hello message has been received and processed.
    ServerHello,
    /// The client-hello message has been received and processed.
    /// Only valid if we are a responder.
    ClientHello,
    /// The client-auth message has been received and processed.
    ClientAuth,
    /// The server-auth message has been received and processed.
    ServerAuth,
    /// Something went wrong. This is a terminal state.
    Failure(String),
}

impl ServerHandshakeState {
    pub fn new() -> Self {
        ServerHandshakeState::New
    }
}

impl ServerHandshakeState {
    fn next(self, event: Message, role: Role) -> ServerHandshakeState {
        match (self, event, role) {
            // Valid state transitions
            (ServerHandshakeState::New, Message::ServerHello(_msg), _) => ServerHandshakeState::ServerHello,

            // A failure transition is terminal and does not change
            (f @ ServerHandshakeState::Failure(_), _, _) => f,

            // Any undefined state transition changes to Failure
            (s, msg, _) => {
                ServerHandshakeState::Failure(format!("Invalid event transition: {:?} <- {}", s, msg.get_type()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ::messages::{ServerHello, ClientHello};
    use super::*;

    #[test]
    fn transition_server_hello() {
        // Create a new initial state.
        let state = ServerHandshakeState::new();
        assert_eq!(state, ServerHandshakeState::New);

        // Transition to server-hello state.
        let msg = Message::ServerHello(ServerHello::random());
        let state = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::ServerHello);
    }

    #[test]
    fn transition_failure() {
        // Create a new initial state.
        let state = ServerHandshakeState::new();
        assert_eq!(state, ServerHandshakeState::New);

        // Invalid transition to client-hello state.
        let msg = Message::ClientHello(ClientHello::random());
        let state = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));

        // Another invalid transition won't change the message
        let msg = Message::ServerHello(ServerHello::random());
        let state = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));
    }
}
