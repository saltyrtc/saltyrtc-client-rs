//! Protocol state machine.

use messages::Message;

#[derive(Debug, PartialEq, Eq)]
enum InitiatorState {
    /// Initial state
    New,
    /// The server-hello message has been received and processed.
    ServerHello,
    /// The client-auth message has been received and processed.
    ClientAuth,
    /// The server-auth message has been received and processed.
    ServerAuth,
    /// A final error state.
    Failure(String),
}

impl InitiatorState {
    pub fn new() -> Self {
        InitiatorState::New
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ResponderState {
    /// Initial state
    New,
    /// The server-hello message has been received and processed.
    ServerHello,
    /// The client-hello message has been received and processed.
    ClientHello,
    /// The client-auth message has been received and processed.
    ClientAuth,
    /// The server-auth message has been received and processed.
    ServerAuth,
}

impl ResponderState {
    pub fn new() -> Self {
        ResponderState::New
    }
}

impl InitiatorState {
    fn next(self, event: Message) -> InitiatorState {
        match (self, event) {
            // Valid state transitions
            (InitiatorState::New, Message::ServerHello(_msg)) => InitiatorState::ServerHello,

            // A failure transition is terminal and does not change
            (f @ InitiatorState::Failure(_), _) => f,

            // Any undefined state transition changes to Failure
            (s, msg) => {
                InitiatorState::Failure(format!("Invalid event transition: {:?} <- {}", s, msg.get_type()))
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
        let state = InitiatorState::new();
        assert_eq!(state, InitiatorState::New);

        // Transition to server-hello state.
        let msg = Message::ServerHello(ServerHello::random());
        let state = state.next(msg);
        assert_eq!(state, InitiatorState::ServerHello);
    }

    #[test]
    fn transition_failure() {
        // Create a new initial state.
        let state = InitiatorState::new();
        assert_eq!(state, InitiatorState::New);

        // Invalid transition to client-hello state.
        let msg = Message::ClientHello(ClientHello::random());
        let state = state.next(msg);
        assert_eq!(state, InitiatorState::Failure("Invalid event transition: New <- client-hello".into()));

        // Another invalid transition won't change the message
        let msg = Message::ServerHello(ServerHello::random());
        let state = state.next(msg);
        assert_eq!(state, InitiatorState::Failure("Invalid event transition: New <- client-hello".into()));
    }
}
