//! Protocol implementation.
//!
//! Incoming messages can be passed to a [`Signaling`](trait.Signaling.html)
//! implementation where they will be processed. Instead of sending responses
//! through the network directly, a [`HandleAction`](types/enum.HandleAction.html)
//! is returned.
//!
//! All peer related state is contained in the [context
//! structs](context/index.html), depending on the role.

use std::collections::{HashMap, HashSet};

use boxes::{ByteBox, OpenBox};
use crypto::{KeyStore, AuthToken, PublicKey};
use errors::{SignalingError, SignalingResult};

pub(crate) mod context;
pub(crate) mod cookie;
pub(crate) mod csn;
pub(crate) mod messages;
pub(crate) mod nonce;
pub(crate) mod send_error;
pub(crate) mod state;
pub(crate) mod types;

#[cfg(test)] mod tests;

use self::context::{PeerContext, ServerContext, InitiatorContext, ResponderContext};
pub(crate) use self::cookie::{Cookie};
use self::messages::{Message, ServerHello, ServerAuth, ClientHello, ClientAuth, NewResponder};
use self::messages::{SendError, Token, Key, InitiatorAuthBuilder};
pub(crate) use self::nonce::{Nonce};
pub use self::types::{Role};
pub(crate) use self::types::{HandleAction};
use self::types::{Identity, ClientIdentity, Address};
use self::state::{SignalingState, ServerHandshakeState};
use self::state::{InitiatorHandshakeState, ResponderHandshakeState};


/// The main signaling trait.
///
/// This is implemented by both the initiator and responder signaling structs.
/// It handles all signaling state and processes incoming messages.
pub(crate) trait Signaling {
    /// Return reference to the common data.
    fn common(&self) -> &Common;

    /// Return mutable reference to the common data.
    fn common_mut(&mut self) -> &mut Common;

    /// Return reference to the server context.
    fn server(&self) -> &ServerContext {
        &self.common().server
    }

    /// Return mutable reference to the server context.
    fn server_mut(&mut self) -> &mut ServerContext {
        &mut self.common_mut().server
    }

    /// Return the identity.
    fn identity(&self) -> ClientIdentity {
        self.common().identity
    }

    /// Return the role.
    fn role(&self) -> Role {
        self.common().role
    }

    /// Return the auth token.
    fn auth_token(&self) -> Option<&AuthToken> {
        self.common().auth_token.as_ref()
    }

    /// Return the server handshake state
    fn server_handshake_state(&self) -> ServerHandshakeState {
        self.server().handshake_state()
    }

    fn validate_nonce<'a>(&'a mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        self.validate_nonce_destination(nonce)?;
        self.validate_nonce_source(nonce)?;
        self.validate_nonce_csn(nonce)?;
        self.validate_nonce_cookie(nonce)?;
        Ok(())
    }

    /// Return the peer context.
    ///
    /// May return `None` if the peer is not yet set.
    fn get_peer(&self) -> Option<&PeerContext>;

    /// Return the peer context with the specified address.
    fn get_peer_with_address_mut(&mut self, addr: Address) -> Option<&mut PeerContext>;

    /// Validate the nonce destination.
    fn validate_nonce_destination(&mut self, nonce: &Nonce) -> Result<(), ValidationError>;

    /// Validate the nonce source.
    fn validate_nonce_source(&mut self, nonce: &Nonce) -> Result<(), ValidationError>;

    /// Validate the nonce CSN.
    fn validate_nonce_csn(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        // Validate CSN
        //
        // In case this is the first message received from the sender, the peer:
        //
        // * MUST check that the overflow number of the source peer is 0 and,
        // * if the peer has already sent a message to the sender, MUST check
        //   that the sender's cookie is different than its own cookie, and
        // * MUST store the combined sequence number for checks on further messages.
        // * The above number(s) SHALL be stored and updated separately for
        //   each other peer by its identity (source address in this case).
        //
        // Otherwise, the peer:
        //
        // * MUST check that the combined sequence number of the source peer
        //   has been increased by 1 and has not reset to 0.
        let role = self.role();
        let peer: &mut PeerContext = self.get_peer_with_address_mut(nonce.source()).ok_or_else(|| {
            if role == Role::Initiator && nonce.source().is_responder() {
                ValidationError::Fail(format!("Could not find responder with address {}", nonce.source()))
            } else {
                ValidationError::Crash("Got message from invalid sender that wasn't dropped".into())
            }
        })?;

        let peer_identity = peer.identity();
        let mut csn_pair = peer.csn_pair().borrow_mut();

        // If we already have the CSN of the peer,
        // ensure that it has been increased properly.
        if let Some(ref mut csn) = csn_pair.theirs {
            let previous = csn;
            let current = nonce.csn();
            if current < previous {
                let msg = format!("{} CSN is lower than last time", peer_identity);
                return Err(ValidationError::Fail(msg));
            } else if current == previous {
                let msg = format!("{} CSN hasn't been incremented", peer_identity);
                return Err(ValidationError::Fail(msg));
            } else {
                *previous = current.clone();
            }
        }

        // Otherwise, this is the first message from that peer.
        if csn_pair.theirs.is_none() {
            // Validate the overflow number...
            if nonce.csn().overflow_number() != 0 {
                let msg = format!("First message from {} must have set the overflow number to 0", peer.identity());
                return Err(ValidationError::Fail(msg));
            }
            // ...and store the CSN.
            csn_pair.theirs = Some(nonce.csn().clone());
        }

        Ok(())
    }

    /// Validate the nonce cookie.
    fn validate_nonce_cookie(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        // Validate cookie
        //
        // In case this is the first message received from the sender:
        //
        // * If the peer has already sent a message to the sender, it MUST
        //   check that the sender's cookie is different than its own cookie, and
        // * MUST store cookie for checks on further messages
        // * The above number(s) SHALL be stored and updated separately for
        //   each other peer by its identity (source address in this case).
        //
        // Otherwise, the peer:
        //
        // * MUST ensure that the 16 byte cookie of the sender has not changed
        let role = self.role();
        let peer: &mut PeerContext = self.get_peer_with_address_mut(nonce.source()).ok_or_else(|| {
            if role == Role::Initiator && nonce.source().is_responder() {
                ValidationError::Fail(format!("Could not find responder with address {}", nonce.source()))
            } else {
                ValidationError::Crash("Got message from invalid sender that wasn't dropped".into())
            }
        })?;

        let peer_identity = peer.identity();
        let cookie_pair = peer.cookie_pair_mut();

        match cookie_pair.theirs {
            None => {
                // This is the first message from that peer,
                if *nonce.cookie() == cookie_pair.ours {
                    // validate the cookie...
                    Err(ValidationError::Fail(
                        format!("Cookie from {} is identical to our own cookie", peer_identity)
                    ))
                } else  {
                    // ...and store it.
                    cookie_pair.theirs = Some(nonce.cookie().clone());
                    Ok(())
                }
            },
            Some(ref cookie) => {
                // Ensure that the cookie has not changed
                if nonce.cookie() != cookie {
                    Err(ValidationError::Fail(
                        format!("Cookie from {} has changed", peer_identity)
                    ))
                } else {
                    Ok(())
                }
            },
        }
    }

    /// Handle an incoming message.
    fn handle_message(&mut self, bbox: ByteBox) -> SignalingResult<Vec<HandleAction>> {
        // Validate the nonce
        match self.validate_nonce(&bbox.nonce) {
            // It's valid! Carry on.
            Ok(_) => {},

            // Drop and ignore some of the messages
            Err(ValidationError::DropMsg(warning)) => {
                warn!("Invalid nonce: {}", warning);
                return Ok(vec![]);
            },

            // Nonce is invalid, fail the signaling
            Err(ValidationError::Fail(reason)) =>
                return Err(SignalingError::InvalidNonce(reason)),

            // A critical error occurred
            Err(ValidationError::Crash(reason)) =>
                return Err(SignalingError::Crash(reason)),
        };

        // Decode message depending on source
        let obox: OpenBox = if bbox.nonce.source().is_server() {
            self.decode_server_message(bbox)?
        } else {
            self.decode_peer_message(bbox)?
        };

        // Handle message depending on state
        match self.common().signaling_state() {
            SignalingState::ServerHandshake =>
                self.handle_server_message(obox),

            SignalingState::PeerHandshake if obox.nonce.source().is_server() =>
                self.handle_server_message(obox),
            SignalingState::PeerHandshake =>
                self.handle_peer_message(obox),

            SignalingState::Task =>
                unimplemented!("TODO: Handle task messages"),
        }
    }


    // Message decoding

    /// Decode or decrypt a binary message coming from the server.
    fn decode_server_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox> {
        // The very first message from the server is unencrypted
        if self.common().signaling_state() == SignalingState::ServerHandshake
        && self.server_handshake_state() == ServerHandshakeState::New {
            return bbox.decode();
        }

        // Otherwise, decrypt with server key
        match self.server().permanent_key {
            Some(ref pubkey) => bbox.decrypt(&self.common().permanent_key, pubkey),
            None => Err(SignalingError::Crash("Missing server permanent key".into())),
        }
    }

    /// Decrypt a binary message coming from a peer.
    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox>;


    // Message handling: Dispatching

    /// Determine the next server handshake state based on the incoming
    /// server-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_server_message(&mut self, obox: OpenBox) -> SignalingResult<Vec<HandleAction>> {
        let old_state = self.server_handshake_state().clone();
        match (old_state, obox.message) {
            // Valid state transitions
            (ServerHandshakeState::New, Message::ServerHello(msg)) =>
                self.handle_server_hello(msg),
            (ServerHandshakeState::ClientInfoSent, Message::ServerAuth(msg)) =>
                self.handle_server_auth(msg),
            (ServerHandshakeState::Done, Message::NewResponder(msg)) =>
                self.handle_new_responder(msg),
            (ServerHandshakeState::Done, Message::DropResponder(_msg)) =>
                unimplemented!("Handling DropResponder messages not yet implemented"),
            (ServerHandshakeState::Done, Message::SendError(msg)) =>
                self.handle_send_error(msg),

            // Any undefined state transition results in an error
            (s, message) => Err(SignalingError::InvalidStateTransition(
                format!("Got {} message from server in {:?} state", message.get_type(), s)
            )),
        }
    }

    /// Determine the next peer handshake state based on the incoming
    /// client-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_peer_message(&mut self, obox: OpenBox) -> SignalingResult<Vec<HandleAction>>;


    // Message handling: Handling

    /// Handle an incoming [`ServerHello`](messages/struct.ServerHello.html) message.
    fn handle_server_hello(&mut self, msg: ServerHello) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received server-hello");

        let mut actions = Vec::with_capacity(2);

        // Set the server public permanent key
        trace!("Server permanent key is {:?}", msg.key);
        if self.server().permanent_key.is_some() {
            return Err(SignalingError::Protocol(
                "Got a server-hello message, but server permanent key is already set".to_string()
            ));
        }
        self.common_mut().server.permanent_key = Some(msg.key);

        // Reply with client-hello message if we're a responder
        if self.role() == Role::Responder {
            let client_hello = {
                let key = self.common().permanent_key.public_key();
                ClientHello::new(*key).into_message()
            };
            let client_hello_nonce = Nonce::new(
                // Cookie
                self.server().cookie_pair().ours.clone(),
                // Src
                self.common().identity.into(),
                // Dst
                self.server().identity().into(),
                // Csn
                self.server().csn_pair().borrow_mut().ours.increment()?,
            );
            let reply = OpenBox::new(client_hello, client_hello_nonce);
            debug!("<-- Enqueuing client-hello");
            actions.push(HandleAction::Reply(reply.encode()));
        }

        // Send client-auth message
        let client_auth = ClientAuth {
            your_cookie: self.server().cookie_pair().theirs.clone().unwrap(),
            subprotocols: vec![::SUBPROTOCOL.into()],
            ping_interval: 0, // TODO
            your_key: None, // TODO
        }.into_message();
        let client_auth_nonce = Nonce::new(
            self.server().cookie_pair().ours.clone(),
            self.identity().into(),
            self.server().identity().into(),
            self.server().csn_pair().borrow_mut().ours.increment()?,
        );
        let reply = OpenBox::new(client_auth, client_auth_nonce);
        match self.server().permanent_key {
            Some(ref pubkey) => {
                debug!("<-- Enqueuing client-auth");
                actions.push(HandleAction::Reply(reply.encrypt(&self.common().permanent_key, pubkey)));
            },
            None => return Err(SignalingError::Crash("Missing server permanent key".into())),
        };

        // TODO: Can we prevent confusing an incoming and an outgoing nonce?
        self.server_mut().set_handshake_state(ServerHandshakeState::ClientInfoSent);
        Ok(actions)
    }

    /// Handle an incoming [`ServerAuth`](messages/struct.ServerAuth.html) message.
    fn handle_server_auth(&mut self, msg: ServerAuth) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received server-auth");

        // When the client receives a 'server-auth' message, it MUST
        // have accepted and set its identity as described in the
        // Receiving a Signalling Message section.
        if self.identity() == ClientIdentity::Unknown {
            return Err(SignalingError::Crash(
                "No identity assigned when receiving server-auth message".into()
            ));
        }

        // It MUST check that the cookie provided in the your_cookie
        // field contains the cookie the client has used in its
        // previous and messages to the server.
        if msg.your_cookie != self.server().cookie_pair().ours {
            trace!("Our cookie as sent by server: {:?}", msg.your_cookie);
            trace!("Our actual cookie: {:?}", self.server().cookie_pair().ours);
            return Err(SignalingError::InvalidMessage(
                "Cookie sent in server-auth message does not match our cookie".into()
            ));
        }

        // If the client has knowledge of the server's public permanent
        // key, it SHALL decrypt the signed_keys field by using the
        // message's nonce, the client's private permanent key and the
        // server's public permanent key. The decrypted message MUST
        // match the concatenation of the server's public session key
        // and the client's public permanent key (in that order). If
        // the signed_keys is present but the client does not have
        // knowledge of the server's permanent key, it SHALL log a
        // warning.
        // TODO: Implement

        // Moreover, the client MUST do some checks depending on its role
        let actions = self.handle_server_auth_impl(&msg)?;

        info!("Server handshake completed");
        self.server_mut().set_handshake_state(ServerHandshakeState::Done);
        self.common_mut().set_signaling_state(SignalingState::PeerHandshake)?;
        Ok(actions)
    }

    /// Role-specific handling of an incoming [`ServerAuth`](messages/struct.ServerAuth.html) message.
    fn handle_server_auth_impl(&mut self, msg: &ServerAuth) -> SignalingResult<Vec<HandleAction>>;

    /// Handle an incoming [`NewResponder`](messages/struct.NewResponder.html) message.
    fn handle_new_responder(&mut self, msg: NewResponder) -> SignalingResult<Vec<HandleAction>>;

    /// Handle an incoming [`SendError`](messages/struct.ServerAuth.html) message.
    fn handle_send_error(&mut self, msg: SendError) -> SignalingResult<Vec<HandleAction>> {
        warn!("--> Received send-error");
        debug!("Message that could not be relayed: {:#?}", msg.id);
        return Err(SignalingError::SendError);
    }
}


/// Common functionality and state for all signaling types.
pub(crate) struct Common {
    // The signaling state
    signaling_state: SignalingState,

    // Our permanent keypair
    pub(crate) permanent_key: KeyStore,

    // Our session keypair
    pub(crate) session_key: Option<KeyStore>,

    // An optional auth token
    pub(crate) auth_token: Option<AuthToken>,

    // The assigned role
    pub(crate) role: Role,

    // The assigned client identity
    pub(crate) identity: ClientIdentity,

    // The server context
    pub(crate) server: ServerContext,
}

impl Common {
    /// Return the current signaling state.
    fn signaling_state(&self) -> SignalingState {
        self.signaling_state
    }

    /// Set the current signaling state.
    fn set_signaling_state(&mut self, state: SignalingState) -> SignalingResult<()> {
        if self.signaling_state == state {
            trace!("Ignoring signaling state transition: {:?} -> {:?}", self.signaling_state(), state);
            return Ok(())
        }
        if !self.signaling_state.may_transition_to(state) {
            return Err(SignalingError::InvalidStateTransition(
                format!("Signaling state: {:?} -> {:?}", self.signaling_state(), state)
            ));
        }
        trace!("Signaling state transition: {:?} -> {:?}", self.signaling_state(), state);
        self.signaling_state = state;
        Ok(())
    }

    /// Generate a session key.
    fn generate_session_key(&mut self) -> SignalingResult<()> {
        if self.session_key.is_some() {
            return Err(
                SignalingError::Crash("Cannot generate new session key: It has already been generated".into())
            );
        }

        // The client MUST generate a session key pair (a new NaCl key pair for
        // public key authenticated encryption) for further communication with
        // the other client.
        //
        // Note: This *could* cause a panic if libsodium initialization fails, but
        // that's not possible in practice because libsodium should already
        // have been initialized previously.
        let mut session_key = KeyStore::new().expect("Libsodium initialization failed");
        while session_key == self.permanent_key {
            warn!("Session keypair == permanent keypair! This is highly unlikely. Regenerating...");
            session_key = KeyStore::new().expect("Libsodium initialization failed");
        }
        self.session_key = Some(session_key);
        Ok(())
    }
}


/// Signaling data for the initiator.
pub(crate) struct InitiatorSignaling {
    // Common state and functionality
    pub(crate) common: Common,

    // The list of responders
    pub(crate) responders: HashMap<Address, ResponderContext>,

    // The chosen responder
    pub(crate) responder: Option<ResponderContext>,
}

impl Signaling for InitiatorSignaling {
    /// Return a reference to the `Common` struct.
    fn common(&self) -> &Common {
        &self.common
    }

    /// Return a mutable reference to the `Common` struct.
    fn common_mut(&mut self) -> &mut Common {
        &mut self.common
    }

    fn get_peer(&self) -> Option<&PeerContext> {
        self.responder.as_ref().map(|p| p as &PeerContext)
    }

    fn get_peer_with_address_mut(&mut self, addr: Address) -> Option<&mut PeerContext> {
        let identity: Identity = addr.into();
        match identity {
            Identity::Server => Some(&mut self.common.server as &mut PeerContext),
            Identity::Initiator => None,
            Identity::Responder(_) => self.responders.get_mut(&addr).map(|r| r as &mut PeerContext),
            Identity::Unknown => unreachable!(),
        }
    }

    fn validate_nonce_destination(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
		// A client MUST check that the destination address targets its
		// assigned identity (or `0x00` during authentication).
        if self.identity() == ClientIdentity::Unknown
        && !nonce.destination().is_unknown()
        && self.server_handshake_state() != ServerHandshakeState::New {
            // The first message received with a destination address different
            // to `0x00` SHALL be accepted as the client's assigned identity.
            // However, the client MUST validate that the identity fits its
            // role – initiators SHALL ONLY accept `0x01`. The identity MUST
            // be stored as the client's assigned identity.
            if nonce.destination().is_initiator() {
                self.common.identity = ClientIdentity::Initiator;
                debug!("Assigned identity: {}", self.identity());
            } else {
                return Err(ValidationError::Fail(
                    format!("cannot assign address {} to initiator", nonce.destination())
                ));
            };
        }
        if nonce.destination() != self.identity().into() {
            return Err(ValidationError::Fail(
                format!("Bad destination: {} (our identity is {})", nonce.destination(), self.identity())
            ));
        }

        Ok(())
    }

    fn validate_nonce_source(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        // An initiator SHALL ONLY process messages from the server (0x00). As
        // soon as the initiator has been assigned an identity, it MAY ALSO accept
        // messages from other responders (0x02..0xff). Other messages SHALL be
        // discarded and SHOULD trigger a warning.
        match nonce.source() {
            // From server
            Address(0x00) => Ok(()),

            // From initiator
            Address(0x01) => Err(ValidationError::DropMsg(
                format!("Bad source: {} (our identity is {})", nonce.source(), self.identity())
            )),

            // From responder
            Address(0x02...0xff) => {
                if self.identity() == ClientIdentity::Initiator {
                    Ok(())
                } else {
                    Err(ValidationError::DropMsg(
                        format!("Bad source: {} (our identity is {})", nonce.source(), self.identity())
                    ))
                }
            },

            // Required due to https://github.com/rust-lang/rfcs/issues/1550
            Address(_) => unreachable!(),
        }
    }

    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox> {
        // Validate source again
        if !bbox.nonce.source().is_responder() {
            return Err(SignalingError::Crash(format!("Received message from an initiator")));
        }

        // Find responder
        let source = bbox.nonce.source();
        let responder = match self.responders.get(&source) {
            Some(responder) => responder,
            None => return Err(SignalingError::Crash(format!("Did not find responder with address {}", source))),
        };

        // Helper functions
        fn responder_permanent_key(responder: &ResponderContext) -> SignalingResult<&PublicKey> {
            responder.permanent_key.as_ref()
                .ok_or(SignalingError::Crash(
                    format!("Did not find public permanent key for responder {}", responder.address.0)))
        }
        fn responder_session_key(responder: &ResponderContext) -> SignalingResult<&PublicKey> {
            responder.session_key.as_ref()
                .ok_or(SignalingError::Crash(
                    format!("Did not find public session key for responder {}", responder.address.0)))
        }

        // Decrypt depending on state
        match responder.handshake_state() {
            ResponderHandshakeState::New => {
                // Expect token message, encrypted with authentication token.
                match self.common.auth_token {
                    Some(ref token) => bbox.decrypt_token(token),
                    None => Err(SignalingError::Crash("Auth token not set".into())),
                }
            },
            ResponderHandshakeState::TokenReceived => {
                // Expect key message, encrypted with our public permanent key
                // and responder private permanent key
                bbox.decrypt(&self.common.permanent_key, responder_permanent_key(&responder)?)
            },
            ResponderHandshakeState::KeySent => {
                // Expect auth message, encrypted with our public session key
                // and responder private session key
                bbox.decrypt(&responder.keystore, responder_session_key(&responder)?)
            },
            other => {
                // TODO: Maybe remove these states?
                Err(SignalingError::Crash(format!("Invalid responder handshake state: {:?}", other)))
            },
        }
    }

    /// Determine the next peer handshake state based on the incoming
    /// client-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_peer_message(&mut self, obox: OpenBox) -> SignalingResult<Vec<HandleAction>> {
        let source = obox.nonce.source();
        let old_state = {
            let responder = self.responders.get(&source)
                .ok_or(SignalingError::Crash(
                    format!("Did not find responder with address {}", source)
                ))?;
            responder.handshake_state()
        };

        // State transitions
        match (old_state, obox.message) {
            // Valid state transitions
            (ResponderHandshakeState::New, Message::Token(msg)) => self.handle_token(msg, source),
            (ResponderHandshakeState::TokenReceived, Message::Key(msg)) => self.handle_key(msg, source),
            // TODO

            // Any undefined state transition results in an error
            (s, message) => Err(SignalingError::InvalidStateTransition(
                format!("Got {} message from responder {} in {:?} state", message.get_type(), obox.nonce.source().0, s)
            )),
        }
    }

    fn handle_server_auth_impl(&mut self, msg: &ServerAuth) -> SignalingResult<Vec<HandleAction>> {
        // In case the client is the initiator, it SHALL check
        // that the responders field is set and contains an
        // Array of responder identities.
        if msg.initiator_connected.is_some() {
            return Err(SignalingError::InvalidMessage(
                "We're the initiator, but the `initiator_connected` field in the server-auth message is set".into()
            ));
        }
        let responders = match msg.responders {
            Some(ref responders) => responders,
            None => return Err(SignalingError::InvalidMessage(
                "`responders` field in server-auth message not set".into()
            )),
        };

        // The responder identities MUST be validated and SHALL
        // neither contain addresses outside the range
        // 0x02..0xff
        let responders_set: HashSet<Address> = responders.iter().cloned().collect();
        if responders_set.contains(&Address(0x00)) || responders_set.contains(&Address(0x01)) {
            return Err(SignalingError::InvalidMessage(
                "`responders` field in server-auth message may not contain addresses <0x02".into()
            ));
        }

        // ...nor SHALL an address be repeated in the
        // Array.
        if responders.len() != responders_set.len() {
            return Err(SignalingError::InvalidMessage(
                "`responders` field in server-auth message may not contain duplicates".into()
            ));
        }

        // An empty Array SHALL be considered valid. However,
        // Nil SHALL NOT be considered a valid value of that
        // field.
        // -> Already covered by Rust's type system.

        // It SHOULD store the responder's identities in its
        // internal list of responders.
        for address in responders_set {
            self.responders.insert(address, ResponderContext::new(address)?);
        }

        // Additionally, the initiator MUST keep its path clean
        // by following the procedure described in the Path
        // Cleaning section.
        // TODO: Implement

        Ok(vec![])
    }

    fn handle_new_responder(&mut self, msg: NewResponder) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received new-responder");

        // An initiator who receives a 'new-responder' message SHALL validate
        // that the id field contains a valid responder address (0x02..0xff).
        if !msg.id.is_responder() {
            return Err(SignalingError::InvalidMessage(
                "`id` field in new-responder message is not a valid responder address".into()
            ));
        }

        // It SHOULD store the responder's identity in its internal list of responders.
        // If a responder with the same id already exists, all currently cached
        // information about and for the previous responder (such as cookies
        // and the sequence number) MUST be deleted first.
        if self.responders.contains_key(&msg.id) {
            warn!("Overwriting responder context for address {:?}", msg.id);
        } else {
            info!("Registering new responder with address {:?}", msg.id);
        }
        self.responders.insert(msg.id, ResponderContext::new(msg.id)?);

        // Furthermore, the initiator MUST keep its path clean by following the
        // procedure described in the Path Cleaning section.
        // TODO: Implement

        Ok(vec![])
    }

}

impl InitiatorSignaling {
    pub(crate) fn new(permanent_key: KeyStore) -> Self {
        InitiatorSignaling {
            common: Common {
                signaling_state: SignalingState::ServerHandshake,
                role: Role::Initiator,
                identity: ClientIdentity::Unknown,
                permanent_key: permanent_key,
                session_key: None,
                auth_token: Some(AuthToken::new()),
                server: ServerContext::new(),
            },
            responders: HashMap::new(),
            responder: None,
        }
    }

    /// Handle an incoming [`Token`](messages/struct.Token.html) message.
    fn handle_token(&mut self, msg: Token, source: Address) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received token");

        // Find responder instance
        let responder = self.responders.get_mut(&source)
            .ok_or(SignalingError::Crash(
                format!("Did not find responder with address {}", source)
            ))?;

        // Sanity check
        if responder.permanent_key.is_some() {
            return Err(SignalingError::Crash("Responder already has a permanent key set!".into()));
        }

        // Set public permanent key
        responder.permanent_key = Some(msg.key);

        // State transition
        responder.set_handshake_state(ResponderHandshakeState::TokenReceived);

        Ok(vec![])
    }

    /// Handle an incoming [`Key`](messages/struct.Key.html) message.
    fn handle_key(&mut self, msg: Key, source: Address) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received key");

        // Find responder instance
        let responder = self.responders.get_mut(&source)
            .ok_or(SignalingError::Crash(
                format!("Did not find responder with address {}", source)
            ))?;

        // Sanity check
        if responder.session_key.is_some() {
            return Err(SignalingError::Crash("Responder already has a session key set!".into()));
        }

        // Ensure that session key != permanent key
        match responder.permanent_key {
            Some(pk) if pk == msg.key => {
                return Err(SignalingError::Protocol("Responder session key and permanent key are equal".into()));
            },
            Some(_) => {},
            None => {
                return Err(SignalingError::Crash("Responder permanent key not set".into()));
            }
        };

        // Set public session key
        responder.session_key = Some(msg.key);

        // State transition
        responder.set_handshake_state(ResponderHandshakeState::KeyReceived);

        // Reply with our own key msg
        let key: Message = Key {
            key: responder.keystore.public_key().clone(),
        }.into_message();
        let key_nonce = Nonce::new(
            responder.cookie_pair().ours.clone(),
            self.common.identity.into(),
            responder.identity().into(),
            responder.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::new(key, key_nonce);
        let bbox = obox.encrypt(
            &self.common.permanent_key,
            responder.permanent_key.as_ref()
                .ok_or(SignalingError::Crash("Responder permanent key not set".into()))?,
        );

        debug!("<-- Enqueuing key");
        Ok(vec![HandleAction::Reply(bbox)])
    }
}


/// Signaling data for the responder.
pub(crate) struct ResponderSignaling {
    // Common state and functionality
    pub(crate) common: Common,

    // The initiator context
    pub(crate) initiator: InitiatorContext,
}

impl Signaling for ResponderSignaling {
    /// Return a reference to the `Common` struct.
    fn common(&self) -> &Common {
        &self.common
    }

    /// Return a mutable reference to the `Common` struct.
    fn common_mut(&mut self) -> &mut Common {
        &mut self.common
    }

    fn get_peer(&self) -> Option<&PeerContext> {
        Some(&self.initiator as &PeerContext)
    }

    fn get_peer_with_address_mut(&mut self, addr: Address) -> Option<&mut PeerContext> {
        let identity: Identity = addr.into();
        match identity {
            Identity::Server => Some(&mut self.common.server),
            Identity::Initiator => Some(&mut self.initiator),
            Identity::Responder(_) => None,
            Identity::Unknown => unreachable!(),
        }
    }

    fn validate_nonce_destination(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
		// A client MUST check that the destination address targets its
		// assigned identity (or `0x00` during authentication).
        if self.identity() == ClientIdentity::Unknown
        && !nonce.destination().is_unknown()
        && self.server_handshake_state() != ServerHandshakeState::New {
            // The first message received with a destination address different
            // to `0x00` SHALL be accepted as the client's assigned identity.
            // However, the client MUST validate that the identity fits its
            // role – responders SHALL ONLY an identity from the range
            // `0x02..0xff`. The identity MUST be stored as the client's
            // assigned identity.
            if nonce.destination().is_responder() {
                self.common.identity = ClientIdentity::Responder(nonce.destination().0);
                debug!("Assigned identity: {}", self.identity());
            } else {
                return Err(ValidationError::Fail(
                    format!("cannot assign address {} to a responder", nonce.destination())
                ));
            };
        }
        if nonce.destination() != self.identity().into() {
            return Err(ValidationError::Fail(
                format!("Bad destination: {} (our identity is {})", nonce.destination(), self.identity())
            ));
        }

        Ok(())
    }

    fn validate_nonce_source(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        // A responder SHALL ONLY process messages from the server (0x00). As soon
        // as the responder has been assigned an identity, it MAY ALSO accept
        // messages from the initiator (0x01). Other messages SHALL be discarded
        // and SHOULD trigger a warning.
        match nonce.source() {
            // From server
            Address(0x00) => Ok(()),

            // From initiator
            Address(0x01) => {
                if let ClientIdentity::Responder(_) = self.identity() {
                    Ok(())
                } else {
                    Err(ValidationError::DropMsg(
                        format!("Bad source: {} (our identity is {})", nonce.source(), self.identity())
                    ))
                }
            },

            // From responder
            Address(0x02...0xff) => Err(ValidationError::DropMsg(
                format!("Bad source: {} (our identity is {})", nonce.source(), self.identity())
            )),

            // Required due to https://github.com/rust-lang/rfcs/issues/1550
            Address(_) => unreachable!(),
        }
    }

    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox> {
        // Validate source again
        if !bbox.nonce.source().is_initiator() {
            return Err(SignalingError::Crash(format!("Received message from a responder")));
        }

        // Decrypt depending on state
        match self.initiator.handshake_state() {
            InitiatorHandshakeState::KeySent => {
                // Expect key message, encrypted with our public permanent key
                // and initiator private permanent key
                bbox.decrypt(&self.common.permanent_key, &self.initiator.permanent_key)
            },
            InitiatorHandshakeState::AuthSent => {
                // Expect an auth message, encrypted with our public session
                // key and initiator private session key
                match (self.common().session_key.as_ref(), self.initiator.session_key.as_ref()) {
                    (Some(ref our_key), Some(ref initiator_key)) => bbox.decrypt(our_key, initiator_key),
                    (None, _) => return Err(SignalingError::Crash("Our session key not set".into())),
                    (_, None) => return Err(SignalingError::Crash("Initiator session key not set".into())),
                }
            },
            other => {
                // TODO: Maybe remove these states?
                Err(SignalingError::Crash(format!("Invalid initiator handshake state: {:?}", other)))
            },
        }
    }

    /// Determine the next peer handshake state based on the incoming
    /// client-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_peer_message(&mut self, obox: OpenBox) -> SignalingResult<Vec<HandleAction>> {
        let old_state = self.initiator.handshake_state();
        match (old_state, obox.message) {
            // Valid state transitions
            (InitiatorHandshakeState::KeySent, Message::Key(msg)) => self.handle_key(msg, &obox.nonce),

            // Any undefined state transition results in an error
            (s, message) => Err(SignalingError::InvalidStateTransition(
                format!("Got {} message from initiator in {:?} state", message.get_type(), s)
            )),
        }
    }

    fn handle_server_auth_impl(&mut self, msg: &ServerAuth) -> SignalingResult<Vec<HandleAction>> {
        // In case the client is the responder, it SHALL check
        // that the initiator_connected field contains a
        // boolean value.
        if msg.responders.is_some() {
            return Err(SignalingError::InvalidMessage(
                "We're a responder, but the `responders` field in the server-auth message is set".into()
            ));
        }
        let mut actions: Vec<HandleAction> = vec![];
        match msg.initiator_connected {
            Some(true) => {
                if let Some(ref token) = self.common().auth_token {
                    actions.push(self.send_token(&token)?);
                } else {
                    debug!("No auth token set");
                }
                self.common_mut().generate_session_key()?;
                actions.push(self.send_key()?);
                self.initiator.set_handshake_state(InitiatorHandshakeState::KeySent);
            },
            Some(false) => {
                debug!("No initiator connected so far");
            },
            None => return Err(SignalingError::InvalidMessage(
                "We're a responder, but the `initiator_connected` field in the server-auth message is not set".into()
            )),
        }
        Ok(actions)
    }

    fn handle_new_responder(&mut self, _msg: NewResponder) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Protocol("Received 'new-responder' message as responder".into()))
    }
}

impl ResponderSignaling {
    pub(crate) fn new(permanent_key: KeyStore,
                      initiator_pubkey: PublicKey,
                      auth_token: Option<AuthToken>) -> Self {
        ResponderSignaling {
            common: Common {
                signaling_state: SignalingState::ServerHandshake,
                role: Role::Responder,
                identity: ClientIdentity::Unknown,
                permanent_key: permanent_key,
                session_key: None,
                auth_token: auth_token,
                server: ServerContext::new(),
            },
            initiator: InitiatorContext::new(initiator_pubkey),
        }
    }

    /// Build a `Token` message.
    fn send_token(&self, token: &AuthToken) -> SignalingResult<HandleAction> {
        // The responder MUST set the public key (32 bytes) of the permanent
        // key pair in the key field of this message.
        let msg: Message = Token {
            key: self.common().permanent_key.public_key().to_owned(),
        }.into_message();
        let nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.identity().into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::new(msg, nonce);

        // The message SHALL be NaCl secret key encrypted by the token the
        // initiator created and issued to the responder.
        let bbox = obox.encrypt_token(&token);

        // TODO: In case the initiator has successfully decrypted the 'token'
        // message, the secret key MUST be invalidated immediately and SHALL
        // NOT be used for any other message.

        debug!("<-- Enqueuing token");
        Ok(HandleAction::Reply(bbox))
    }

    /// Build a `Key` message.
    fn send_key(&self) -> SignalingResult<HandleAction> {
        // It MUST set the public key (32 bytes) of that key pair in the key field.
        let msg: Message = match self.common().session_key {
            Some(ref session_key) => Key {
                key: session_key.public_key().to_owned(),
            }.into_message(),
            None => return Err(SignalingError::Crash("Missing session keypair".into())),
        };
        let nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.identity().into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::new(msg, nonce);

        // The message SHALL be NaCl public-key encrypted by the client's
        // permanent key pair and the other client's permanent key pair.
        let bbox = obox.encrypt(&self.common().permanent_key, &self.initiator.permanent_key);

        debug!("<-- Enqueuing key");
        Ok(HandleAction::Reply(bbox))
    }

    /// Handle an incoming [`Key`](messages/struct.Key.html) message.
    fn handle_key(&mut self, msg: Key, nonce: &Nonce) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received key");

        // Sanity check
        if self.initiator.session_key.is_some() {
            return Err(SignalingError::Crash("Initiator already has a session key set!".into()));
        }

        // Ensure that session key != permanent key
        if msg.key == self.initiator.permanent_key {
            return Err(SignalingError::Protocol("Responder session key and permanent key are equal".into()));
        }

        // Set public session key
        self.initiator.session_key = Some(msg.key);

        // State transition
        self.initiator.set_handshake_state(InitiatorHandshakeState::KeyReceived);

        // Reply with auth msg
        let auth: Message = InitiatorAuthBuilder::new(nonce.cookie().clone())
            .add_task("dummy", None)
            .build()?
            .into_message();
        let auth_nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.common().identity.into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::new(auth, auth_nonce);
        let bbox = obox.encrypt(
            self.common().session_key.as_ref()
                .ok_or(SignalingError::Crash("Our session key not set".into()))?,
            self.initiator.session_key.as_ref()
                .ok_or(SignalingError::Crash("Initiator session key not set".into()))?,
        );

        debug!("<-- Enqueuing auth");
        Ok(vec![HandleAction::Reply(bbox)])
    }
}


/// Result of the nonce validation.
pub(crate) enum ValidationError {
    /// Ignore message
    DropMsg(String),
    /// Validation failed
    Fail(String),
    /// A critical error occurred
    Crash(String),
}
