//! Protocol state machine.
//!
//! This handles all state transitions independently of the connection.

use std::convert::From;

use messages::Message;
use nonce::Nonce;

#[derive(Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// An enum returned when an incoming message is handled.
///
/// It can contain different actions that should be done to finish handling the
/// message.
#[derive(Debug, PartialEq)]
pub enum HandleAction {
    /// Send the specified message through the websocket.
    Reply(Message, Nonce),
    /// No further action required.
    None,
}

#[derive(Debug, PartialEq)]
pub struct StateTransition<T> {
    /// The state resulting from the state transition.
    state: T,
    /// Any actions that need to be taken as a result of this state transition.
    action: HandleAction,
}

impl<T> StateTransition<T> {
    fn new(state: T, action: HandleAction) -> Self {
        Self {
            state: state,
            action: action,
        }
    }
}

impl<T> From<(T, HandleAction)> for StateTransition<T> {
    fn from(val: (T, HandleAction)) -> Self {
        StateTransition::new(val.0, val.1)
    }
}

impl<T> From<T> for StateTransition<T> {
    /// States can be converted to a `StateTransition` with a `HandleAction::None`.
    fn from(val: T) -> Self {
        StateTransition::new(val, HandleAction::None)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
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
    fn next(self, event: Message, role: Role) -> StateTransition<ServerHandshakeState> {
        match (self, event, role) {
            // Valid state transitions
            (ServerHandshakeState::New, Message::ServerHello(_msg), _) => ServerHandshakeState::ServerHello.into(),

            // A failure transition is terminal and does not change
            (f @ ServerHandshakeState::Failure(_), _, _) => f.into(),

            // Any undefined state transition changes to Failure
            (s, msg, _) => {
                ServerHandshakeState::Failure(
                    format!("Invalid event transition: {:?} <- {}", s, msg.get_type())
                ).into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ::messages::{ServerHello, ClientHello};
    use super::*;

    /// Test that states and tuples implement Into<ServerHandshakeState>.
    #[test]
    fn server_handshake_state_from() {
        let t1: StateTransition<_> = StateTransition::new(ServerHandshakeState::New, HandleAction::None);
        let t2: StateTransition<_> = StateTransition::new(ServerHandshakeState::New, HandleAction::None).into();
        let t3: StateTransition<_> = (ServerHandshakeState::New, HandleAction::None).into();
        let t4: StateTransition<_> = ServerHandshakeState::New.into();
        assert_eq!(t1, t2);
        assert_eq!(t1, t3);
        assert_eq!(t1, t4);
    }

    #[test]
    fn transition_server_hello() {
        // Create a new initial state.
        let state = ServerHandshakeState::new();
        assert_eq!(state, ServerHandshakeState::New);

        // Transition to server-hello state.
        let msg = Message::ServerHello(ServerHello::random());
        let StateTransition { state, action } = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::ServerHello);
        assert_eq!(action, HandleAction::None);
    }

    #[test]
    fn transition_failure() {
        // Create a new initial state.
        let state = ServerHandshakeState::new();
        assert_eq!(state, ServerHandshakeState::New);

        // Invalid transition to client-hello state.
        let msg = Message::ClientHello(ClientHello::random());
        let StateTransition { state, action } = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));
        assert_eq!(action, HandleAction::None);

        // Another invalid transition won't change the message
        let msg = Message::ServerHello(ServerHello::random());
        let StateTransition { state, action } = state.next(msg, Role::Initiator);
        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));
        assert_eq!(action, HandleAction::None);
    }
}
