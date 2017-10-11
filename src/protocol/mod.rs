//! Protocol state machines.
//!
//! These state machines handle all state transitions independently of the
//! connection. Instead of executing side effects (like sending a response
//! message to the peer through the websocket), a `HandleAction` is returned.
//!
//! This allows for better decoupling between protocol logic and network code,
//! and makes it possible to easily add tests.

use boxes::{ByteBox, OpenBox};
use messages::{Message, ClientHello};
use nonce::{Nonce, Sender, Receiver};
use keystore::{KeyStore, PublicKey};

mod types;
mod state;

pub use self::types::{Role, HandleAction};
use self::state::{ServerHandshakeState, StateTransition};


/// All signaling related data.
pub struct Signaling {
    pub role: Role,
    pub server: ServerContext,
}

impl Signaling {
    pub fn new(role: Role) -> Self {
        Signaling {
            role: role,
            server: ServerContext::new(),
        }
    }

    /// Handle an incoming message.
    pub fn handle_message(&mut self, bbox: ByteBox) -> HandleAction {
        // Do the state transition
        // TODO: The clone is unelegant! Using mem::replace would be better but won't work here.
        let transition = self.server.handshake_state.clone().next(bbox, self.role);
        trace!("Server handshake state transition: {:?} -> {:?}", self.server.handshake_state, transition.state);
        self.server.handshake_state = transition.state;

        // Return the action
        transition.action
    }
}


trait PeerContext {
    fn address(&self) -> Receiver;
    fn permanent_key(&self) -> Option<&PublicKey>;
    fn session_key(&self) -> Option<&PublicKey>;
}

pub struct ServerContext {
    handshake_state: ServerHandshakeState,
    permanent_key: Option<PublicKey>,
    session_key: Option<PublicKey>,
}

impl ServerContext {
    pub fn new() -> Self {
        ServerContext {
            handshake_state: ServerHandshakeState::New,
            permanent_key: None,
            session_key: None,
        }
    }
}

impl PeerContext for ServerContext {
    fn address(&self) -> Receiver {
        Receiver::server()
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        self.permanent_key.as_ref()
    }

    fn session_key(&self) -> Option<&PublicKey> {
        self.session_key.as_ref()
    }
}


/// Implementation of the server handshake state transitions.
impl ServerHandshakeState {
    pub fn next(self, bbox: ByteBox, role: Role) -> StateTransition<ServerHandshakeState> {
        // Decode message
        let obox: OpenBox = if self == ServerHandshakeState::New {
            match bbox.decode() {
                Ok(obox) => obox,
                Err(e) => return ServerHandshakeState::Failure(format!("{}", e)).into(),
            }
        } else {
            return ServerHandshakeState::Failure("Not yet implemented".into()).into();
        };

        match (self, obox.message, role) {
            // Valid state transitions
            (ServerHandshakeState::New, Message::ServerHello(msg), _) => {
                info!("Hello from server");

                trace!("Server key is {:?}", msg.key);

                // Generate keypair
                let keystore = match KeyStore::new() {
                    Ok(ks) => ks,
                    Err(e) => return ServerHandshakeState::Failure(format!("{}", e)).into(),
                };

                // Reply with client-hello message
                let client_hello = ClientHello::new(keystore.public_key().clone()).into_message();
                let client_nonce = Nonce::new(
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    Sender::new(0),
                    Receiver::new(0),
                    0,
                    123,
                );
                let obox = OpenBox::new(client_hello, client_nonce);

                // TODO: Can we prevent confusing an incoming and an outgoing nonce?
                StateTransition {
                    state: ServerHandshakeState::ClientInfoSent,
                    action: HandleAction::Reply(obox.encode()),
                }
            },

            // A failure transition is terminal and does not change
            (f @ ServerHandshakeState::Failure(_), _, _) => f.into(),

            // Any undefined state transition changes to Failure
            (s, message, _) => {
                ServerHandshakeState::Failure(
                    format!("Invalid event transition: {:?} <- {}", s, message.get_type())
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
        let state = ServerHandshakeState::New;
        assert_eq!(state, ServerHandshakeState::New);

        // Transition to `ClientInfoSent` state.
        let msg = Message::ServerHello(ServerHello::random());
        let obox = OpenBox::new(msg, Nonce::random());
        let StateTransition { state, action } = state.next(obox.encode(), Role::Initiator);
        assert_eq!(state, ServerHandshakeState::ClientInfoSent);
        match action {
            HandleAction::Reply(..) => (),
            a @ _ => panic!("Invalid action: {:?}", a)
        };
    }

//    #[test]
//    fn transition_failure() {
//        // Create a new initial state.
//        let state = ServerHandshakeState::New;
//        assert_eq!(state, ServerHandshakeState::New);
//
//        // Invalid transition to client-hello state.
//        let msg = Message::ClientHello(ClientHello::random());
//        let obox = OpenBox::new(msg, Nonce::random());
//        let StateTransition { state, action } = state.next(obox.encode(), Role::Initiator);
//        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));
//        assert_eq!(action, HandleAction::None);
//
//        // Another invalid transition won't change the message
//        let msg = Message::ServerHello(ServerHello::random());
//        let obox = OpenBox::new(msg, Nonce::random());
//        let StateTransition { state, action } = state.next(obox.encode(), Role::Initiator);
//        assert_eq!(state, ServerHandshakeState::Failure("Invalid event transition: New <- client-hello".into()));
//        assert_eq!(action, HandleAction::None);
//    }

    #[test]
    fn server_context_new() {
        let ctx = ServerContext::new();
        assert_eq!(ctx.address(), Receiver::new(0));
        assert_eq!(ctx.permanent_key(), None);
        assert_eq!(ctx.session_key(), None);
    }
}
