use std::convert::From;

use super::types::HandleAction;


/// A state transition contains the new target state as well as a
/// `HandleAction` with resulting side effects (like response messages).
#[derive(Debug, PartialEq)]
pub struct StateTransition<T> {
    /// The state resulting from the state transition.
    pub state: T,
    /// Any actions that need to be taken as a result of this state transition.
    pub actions: Vec<HandleAction>,
}

impl<T> StateTransition<T> {
    pub fn new(state: T, actions: Vec<HandleAction>) -> Self {
        Self {
            state: state,
            actions: actions,
        }
    }
}

impl<T> From<(T, HandleAction)> for StateTransition<T> {
    fn from(val: (T, HandleAction)) -> Self {
        StateTransition::new(val.0, vec![val.1])
    }
}

impl<T> From<(T, Vec<HandleAction>)> for StateTransition<T> {
    fn from(val: (T, Vec<HandleAction>)) -> Self {
        StateTransition::new(val.0, val.1)
    }
}

impl<T> From<T> for StateTransition<T> {
    /// States can be converted to a `StateTransition` with no actions.
    fn from(val: T) -> Self {
        StateTransition::new(val, vec![])
    }
}

/// The server handshake states.
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
