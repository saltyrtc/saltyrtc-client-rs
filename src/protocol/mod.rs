//! Protocol state machines.
//!
//! These state machines handle all state transitions independently of the
//! connection. Instead of executing side effects (like sending a response
//! message to the peer through the websocket), a `HandleAction` is returned.
//!
//! This allows for better decoupling between protocol logic and network code,
//! and makes it possible to easily add tests.

use boxes::{ByteBox, OpenBox};
use messages::{Message, ClientHello, ClientAuth};
use keystore::{KeyStore, PublicKey};

mod csn;
mod nonce;
mod state;
mod types;

use errors::{Result, ErrorKind};

use self::csn::{CombinedSequence};
pub use self::nonce::{Nonce};
pub use self::types::{Role, HandleAction};
use self::types::{Identity, ClientIdentity, Address};
use self::state::{ServerHandshakeState, StateTransition};


/// All signaling related data.
pub struct Signaling {
    pub role: Role, // TODO: Redundant?
    pub identity: ClientIdentity,
    pub server: ServerContext,
    pub permanent_key: KeyStore,
}

/// Result of the nonce validation.
enum ValidationResult {
    Ok,
    DropMsg(String),
    Fail(String),
}

impl Signaling {
    pub fn new(role: Role, permanent_key: KeyStore) -> Self {
        Signaling {
            role: role,
            identity: ClientIdentity::Unknown,
            server: ServerContext::new(),
            permanent_key: permanent_key,
        }
    }

    /// Handle an incoming message.
    pub fn handle_message(&mut self, bbox: ByteBox) -> Vec<HandleAction> {
        // Do the state transition
        let transition = self.next_state(bbox);
        trace!("Server handshake state transition: {:?} -> {:?}", self.server.handshake_state, transition.state);
        self.server.handshake_state = transition.state;

        // Return the action
        transition.actions
    }

    fn validate_nonce(&self, nonce: &Nonce) -> ValidationResult {
		// A client MUST check that the destination address targets its
		// assigned identity (or `0x00` during authentication).
        if nonce.destination() != self.identity.into() {
            let msg = format!("bad destination: {} (our identity is {})", nonce.destination(), self.identity);
            return ValidationResult::Fail(msg);
        }

        // An initiator SHALL ONLY process messages from the server (0x00). As
        // soon as the initiator has been assigned an identity, it MAY ALSO accept
        // messages from other responders (0x02..0xff). Other messages SHALL be
        // discarded and SHOULD trigger a warning.
        //
        // A responder SHALL ONLY process messages from the server (0x00). As soon
        // as the responder has been assigned an identity, it MAY ALSO accept
        // messages from the initiator (0x01). Other messages SHALL be discarded
        // and SHOULD trigger a warning.
        match nonce.source() {
            // From server
            Address(0x00) => {},

            // From initiator
            Address(0x01) => {
                match self.identity {
                    // We're the responder: OK
                    ClientIdentity::Responder(_) => {},
                    // Otherwise: Not OK
                    _ => {
                        let msg = format!("bad source: {} (our identity is {})", nonce.source(), self.identity);
                        return ValidationResult::DropMsg(msg);
                    },
                }
            },

            // From responder
            Address(0x02...0xff) => {
                match self.identity {
                    // We're the initiator: OK
                    ClientIdentity::Initiator => {},
                    // Otherwise: Not OK
                    _ => {
                        let msg = format!("bad source: {} (our identity is {})", nonce.source(), self.identity);
                        return ValidationResult::DropMsg(msg);
                    },
                }
            },

            // Required due to https://github.com/rust-lang/rfcs/issues/1550
            Address(_) => { unreachable!() },
        };

        ValidationResult::Ok
    }

    /// Determine the next state based on the incoming message bytes and the
    /// current (read-only) state.
    fn next_state(&self, bbox: ByteBox) -> StateTransition<ServerHandshakeState> {
        // Validate the nonce
        match self.validate_nonce(&bbox.nonce) {
            // It's valid! Carry on.
            ValidationResult::Ok => {},

            // Drop and ignore some of the messages
            ValidationResult::DropMsg(warning) => {
                warn!("invalid nonce: {}", warning);
                return self.server.handshake_state.clone().into();
            },

            // Nonce is invalid, fail the signaling
            ValidationResult::Fail(reason) => {
                return ServerHandshakeState::Failure(format!("invalid nonce: {}", reason)).into();
            },
        }

        // Decode message
        let obox: OpenBox = match self.server.handshake_state {

            // If we're in state `New`, message must be unencrypted.
            ServerHandshakeState::New => {
                match bbox.decode() {
                    Ok(obox) => obox,
                    Err(e) => return ServerHandshakeState::Failure(format!("{}", e)).into(),
                }
            },

            // If we're already in `Failure` state, stay there.
            ServerHandshakeState::Failure(ref msg) => return ServerHandshakeState::Failure(msg.clone()).into(),

            // Otherwise, not yet implemented!
            _ => return ServerHandshakeState::Failure("Not yet implemented".into()).into(),

        };

        match (&self.server.handshake_state, obox.message) {

            // Valid state transitions
            (&ServerHandshakeState::New, Message::ServerHello(msg)) => {
                info!("Hello from server");

                let mut actions = Vec::with_capacity(3);

                trace!("Server key is {:?}", msg.key);
                actions.push(HandleAction::SetServerKey(msg.key.clone()));

                // Reply with client-hello message
                let key = self.permanent_key.public_key().clone();
                let client_hello = ClientHello::new(key).into_message();
                let client_hello_nonce = Nonce::new(
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    Address(0),
                    Address(0),
                    CombinedSequence::random().unwrap(),
                );
                let reply = OpenBox::new(client_hello, client_hello_nonce);
                actions.push(HandleAction::Reply(reply.encode()));

                // Send with client-auth message
                let client_auth = ClientAuth {
                    your_cookie: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], // TODO
                    subprotocols: vec!["vX.saltyrtc.org".into()], // TODO
                    ping_interval: 0, // TODO
                    your_key: None, // TODO
                }.into_message();
                let client_auth_nonce = Nonce::new(
                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                    Address(0),
                    Address(0),
                    CombinedSequence::random().unwrap(),
                );
                let reply = OpenBox::new(client_auth, client_auth_nonce);
                actions.push(HandleAction::Reply(reply.encode()));

                // TODO: Can we prevent confusing an incoming and an outgoing nonce?
                StateTransition {
                    state: ServerHandshakeState::ClientInfoSent,
                    actions: actions,
                }
            },

            // A failure transition is terminal and does not change
            (&ServerHandshakeState::Failure(ref msg), _) => ServerHandshakeState::Failure(msg.clone()).into(),

            // Any undefined state transition changes to Failure
            (s, message) => {
                ServerHandshakeState::Failure(
                    format!("Invalid event transition: {:?} <- {}", s, message.get_type())
                ).into()
            }

        }
    }
}


trait PeerContext {
    fn identity(&self) -> Identity;
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
    fn identity(&self) -> Identity {
        Identity::Server
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        self.permanent_key.as_ref()
    }

    fn session_key(&self) -> Option<&PublicKey> {
        self.session_key.as_ref()
    }
}


#[cfg(test)]
mod tests {
    use ::messages::{ServerHello, ClientHello};
    use super::*;

    fn create_test_nonce() -> Nonce {
        Nonce::new(
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Address(17),
            Address(18),
            CombinedSequence::new(258, 50_595_078),
        )
    }

    fn create_test_bbox() -> ByteBox {
        ByteBox::new(vec![1, 2, 3], create_test_nonce())
    }

    /// Test that states and tuples implement Into<ServerHandshakeState>.
    #[test]
    fn server_handshake_state_from() {
        let t1: StateTransition<_> = StateTransition::new(ServerHandshakeState::New, vec![HandleAction::Reply(create_test_bbox())]);
        let t2: StateTransition<_> = StateTransition::new(ServerHandshakeState::New, vec![HandleAction::Reply(create_test_bbox())]).into();
        let t3: StateTransition<_> = (ServerHandshakeState::New, HandleAction::Reply(create_test_bbox())).into();
        let t4: StateTransition<_> = (ServerHandshakeState::New, vec![HandleAction::Reply(create_test_bbox())]).into();
        assert_eq!(t1, t2);
        assert_eq!(t1, t3);
        assert_eq!(t1, t4);

        let t4: StateTransition<_> = ServerHandshakeState::New.into();
        let t5: StateTransition<_> = StateTransition::new(ServerHandshakeState::New, vec![]);
        assert_eq!(t4, t5);
    }

    /// A client MUST check that the destination address targets its assigned
    /// identity (or 0x00 during authentication).
    #[test]
    fn first_message_wrong_destination() {
        let ks = KeyStore::new().unwrap();
        let mut s = Signaling::new(Role::Initiator, ks);

        let msg = ServerHello::random().into_message();
        let cs = CombinedSequence::random().unwrap();
        let nonce = Nonce::new([0; 16], Address(0), Address(1), cs);
        let obox = OpenBox::new(msg, nonce);
        let bbox = obox.encode();

        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(bbox);
        assert_eq!(
            s.server.handshake_state,
            ServerHandshakeState::Failure("invalid nonce: bad destination: Address(0x01) (our identity is Unknown)".into())
        );
        // TODO: Check actions for closing
    }

    /// An initiator SHALL ONLY process messages from the server (0x00). As
    /// soon as the initiator has been assigned an identity, it MAY ALSO accept
    /// messages from other responders (0x02..0xff). Other messages SHALL be
    /// discarded and SHOULD trigger a warning.
    #[test]
    fn wrong_source_initiator() {
        let ks = KeyStore::new().unwrap();
        let mut s = Signaling::new(Role::Initiator, ks);

        let make_msg = |src: u8, dest: u8| {
            let msg = ServerHello::random().into_message();
            let cs = CombinedSequence::random().unwrap();
            let nonce = Nonce::new([0; 16], Address(src), Address(dest), cs);
            let obox = OpenBox::new(msg, nonce);
            let bbox = obox.encode();
            bbox
        };

        // Handling messages from initiator is always invalid
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0x01, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        assert_eq!(actions, vec![]);

        // Handling messages from responder is invalid as long as identity
        // hasn't been assigned.
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0xff, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        assert_eq!(actions, vec![]);

        // Handling messages from the server is always valid
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0x00, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::ClientInfoSent);

        // Handling messages from responder is valid as soon as the identity
        // has been assigned.
        // TODO once state transition has been implemented
//        s.server.handshake_state = ServerHandshakeState::Done;
//        s.identity = ClientIdentity::Initiator;
//        assert_eq!(s.server.handshake_state, ServerHandshakeState::Done);
//        let actions = s.handle_message(make_msg(0xff, 0x01));
//        assert_eq!(s.server.handshake_state, ServerHandshakeState::Done);
//        assert_eq!(actions, vec![]);
    }

    /// A responder SHALL ONLY process messages from the server (0x00). As soon
    /// as the responder has been assigned an identity, it MAY ALSO accept
    /// messages from the initiator (0x01). Other messages SHALL be discarded
    /// and SHOULD trigger a warning.
    #[test]
    fn wrong_source_responder() {
        let ks = KeyStore::new().unwrap();
        let mut s = Signaling::new(Role::Responder, ks);

        let make_msg = |src: u8, dest: u8| {
            let msg = ServerHello::random().into_message();
            let cs = CombinedSequence::random().unwrap();
            let nonce = Nonce::new([0; 16], Address(src), Address(dest), cs);
            let obox = OpenBox::new(msg, nonce);
            let bbox = obox.encode();
            bbox
        };

        // Handling messages from a responder is always invalid
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0x03, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        assert_eq!(actions, vec![]);

        // Handling messages from initiator is invalid as long as identity
        // hasn't been assigned.
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0x01, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        assert_eq!(actions, vec![]);

        // Handling messages from the server is always valid
        assert_eq!(s.server.handshake_state, ServerHandshakeState::New);
        let actions = s.handle_message(make_msg(0x00, 0x00));
        assert_eq!(s.server.handshake_state, ServerHandshakeState::ClientInfoSent);

        // Handling messages from initiator is valid as soon as the identity
        // has been assigned.
        // TODO once state transition has been implemented
//        s.server.handshake_state = ServerHandshakeState::Done;
//        s.identity = ClientIdentity::Initiator;
//        assert_eq!(s.server.handshake_state, ServerHandshakeState::Done);
//        let actions = s.handle_message(make_msg(0x01, 0x03));
//        assert_eq!(s.server.handshake_state, ServerHandshakeState::Done);
//        assert_eq!(actions, vec![]);
    }


//    #[test]
//    fn transition_server_hello() {
//        // Create a new initial state.
//        let state = ServerHandshakeState::New;
//        assert_eq!(state, ServerHandshakeState::New);
//
//        // Transition to `ClientInfoSent` state.
//        let msg = Message::ServerHello(ServerHello::random());
//        let obox = OpenBox::new(msg, Nonce::random());
//        let StateTransition { state, action } = state.next(obox.encode(), Role::Initiator);
//        assert_eq!(state, ServerHandshakeState::ClientInfoSent);
//        match action {
//            HandleAction::Reply(..) => (),
//            a @ _ => panic!("Invalid action: {:?}", a)
//        };
//    }

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
        assert_eq!(ctx.identity(), Identity::Server);
        assert_eq!(ctx.permanent_key(), None);
        assert_eq!(ctx.session_key(), None);
    }
}
