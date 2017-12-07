use std::collections::{HashMap, HashSet};

use ::boxes::{OpenBox, ByteBox};
use ::crypto::{KeyStore, AuthToken, PublicKey};
use ::errors::{SignalingError, SignalingResult};
use ::protocol::context::{PeerContext, ServerContext, InitiatorContext, ResponderContext};
use ::protocol::messages::{Message};
use ::protocol::nonce::{Nonce};
use ::protocol::types::{Role, ClientIdentity, Address, HandleAction, Identity};
use ::protocol::state::{SignalingState, ServerHandshakeState};
use ::protocol::state::{InitiatorHandshakeState, ResponderHandshakeState};

/// The main signaling trait.
pub(crate) trait NewSignaling {
    fn common(&self) -> &Common;

    /// Return the identity.
    fn identity(&self) -> ClientIdentity {
        self.common().identity
    }

    /// Return the role.
    fn role(&self) -> Role {
        self.common().role
    }

    /// Return the server handshake state
    fn server_handshake_state(&self) -> ServerHandshakeState {
        self.common().server.handshake_state()
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

    /// Validate the nonce destination
    fn validate_nonce_destination(&mut self, nonce: &Nonce) -> Result<(), ValidationError>;

    /// Validate the nonce source
    fn validate_nonce_source(&mut self, nonce: &Nonce) -> Result<(), ValidationError>;

    /// Validate the nonce CSN
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

    /// Validate the nonce cookie
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

    /// Decode or decrypt a binary message coming from the server
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

    /// Decrypt a binary message coming from a peer
    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox>;

    /// Determine the next server handshake state based on the incoming
    /// server-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_server_message(&mut self, obox: OpenBox) -> SignalingResult<Vec<HandleAction>> {
        let old_state = self.server_handshake_state().clone();
        match (old_state, obox.message) {
//            // Valid state transitions
//            (ServerHandshakeState::New, Message::ServerHello(msg)) =>
//                self.handle_server_hello(msg),
//            (ServerHandshakeState::ClientInfoSent, Message::ServerAuth(msg)) =>
//                self.handle_server_auth(msg),
//            (ServerHandshakeState::Done, Message::NewResponder(msg)) =>
//                on_inner!(self, ref mut s, s.handle_new_responder(msg)),
//            (ServerHandshakeState::Done, Message::DropResponder(_msg)) =>
//                unimplemented!("Handling DropResponder messages not yet implemented"),
//            (ServerHandshakeState::Done, Message::SendError(msg)) =>
//                self.handle_send_error(msg),

            // Any undefined state transition results in an error
            (s, message) => Err(SignalingError::InvalidStateTransition(
                format!("Got {} message from server in {:?} state", message.get_type(), s)
            )),
        }
    }

    fn
}

/// Common functionality / state for all signaling types.
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
}


/// Signaling data for the initiator.
pub(crate) struct NewInitiatorSignaling {
    // Common state and functionality
    pub(crate) common: Common,

    // The list of responders
    pub(crate) responders: HashMap<Address, ResponderContext>,

    // The chosen responder
    pub(crate) responder: Option<ResponderContext>,
}

impl NewSignaling for NewInitiatorSignaling {
    /// Return a reference to the `Common` struct.
    fn common(&self) -> &Common {
        &self.common
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
            Address(0x02...0xff) => Ok(()),

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

}

impl NewInitiatorSignaling {
    pub(crate) fn new(permanent_key: KeyStore) -> Self {
        NewInitiatorSignaling {
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
}


/// Signaling data for the responder.
pub(crate) struct NewResponderSignaling {
    // Common state and functionality
    pub(crate) common: Common,

    // The initiator context
    pub(crate) initiator: InitiatorContext,
}

impl NewSignaling for NewResponderSignaling {
    /// Return a reference to the `Common` struct.
    fn common(&self) -> &Common {
        &self.common
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
            Address(0x01) => Ok(()),

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
                match (self.session_key.as_ref(), self.initiator.session_key.as_ref()) {
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
}

impl NewResponderSignaling {
    pub(crate) fn new(permanent_key: KeyStore,
                      initiator_pubkey: PublicKey,
                      auth_token: Option<AuthToken>) -> Self {
        NewResponderSignaling {
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
