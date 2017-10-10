//! Protocol state machine.

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
    fn next(self, event: Message, role: Role) -> StateTransition<ServerHandshakeState> {
        match (self, event, role) {
            // Valid state transitions
            (ServerHandshakeState::New, Message::ServerHello(_msg), _) => StateTransition::new(
                ServerHandshakeState::ServerHello.into(), HandleAction::None
            ),

            // A failure transition is terminal and does not change
            (f @ ServerHandshakeState::Failure(_), _, _) => StateTransition::new(f, HandleAction::None),

            // Any undefined state transition changes to Failure
            (s, msg, _) => {
                StateTransition::new(
                    ServerHandshakeState::Failure(
                        format!("Invalid event transition: {:?} <- {}", s, msg.get_type())
                    ),
                    HandleAction::None
                )
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
