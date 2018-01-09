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
use std::mem;
use std::time::Duration;

use boxes::{ByteBox, OpenBox};
use crypto::{KeyPair, AuthToken, PublicKey};
use errors::{SignalingError, SignalingResult};
use rmpv::{Value};

pub(crate) mod context;
pub(crate) mod cookie;
pub(crate) mod csn;
pub(crate) mod messages;
pub(crate) mod nonce;
pub(crate) mod send_error;
pub(crate) mod state;
pub(crate) mod types;

#[cfg(test)] mod tests;

use ::events::{Event};
use ::task::{Task, Tasks, BoxedTask};
use self::context::{PeerContext, ServerContext, InitiatorContext, ResponderContext};
pub(crate) use self::cookie::{Cookie};
use self::messages::{
    Message, ServerHello, ServerAuth, ClientHello, ClientAuth,
    NewResponder, DropResponder, DropReason,
    SendError, Token, Key, Auth, InitiatorAuthBuilder, ResponderAuthBuilder,
};
pub(crate) use self::nonce::{Nonce};
pub use self::types::{Role};
pub(crate) use self::types::{HandleAction};
use self::types::{Identity, ClientIdentity, Address};
use self::state::{
    SignalingState, ServerHandshakeState,
    InitiatorHandshakeState, ResponderHandshakeState,
};


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

    /// Return the server handshake state.
    fn server_handshake_state(&self) -> ServerHandshakeState {
        self.server().handshake_state()
    }

    /// Validate the nonce.
    fn validate_nonce(&mut self, nonce: &Nonce) -> Result<(), ValidationError> {
        self.validate_nonce_destination(nonce)?;
        self.validate_nonce_source(nonce)?;
        self.validate_nonce_csn(nonce)?;
        self.validate_nonce_cookie(nonce)?;
        Ok(())
    }

    /// Validate the repeated cookie from the `Auth` message.
    fn validate_repeated_cookie(&self, repeated_cookie: &Cookie,
                                our_cookie: &Cookie, identity: Identity)
                                -> Result<(), SignalingError> {
        if repeated_cookie != our_cookie {
            debug!("Our cookie: {:?}", our_cookie);
            debug!("Their cookie: {:?}", repeated_cookie);
            return Err(SignalingError::Protocol(
                format!("Repeated cookie in auth message from {} does not match our cookie", identity)
            ))
        }
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
                let msg = format!("The {} CSN is lower than last time", peer_identity);
                return Err(ValidationError::Fail(msg));
            } else if current == previous {
                let msg = format!("The {} CSN hasn't been incremented", peer_identity);
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

        match self.common().signaling_state() {
            SignalingState::ServerHandshake => self.handle_handshake_message(bbox),
            SignalingState::PeerHandshake => self.handle_handshake_message(bbox),
            SignalingState::Task => self.handle_task_message(bbox),
        }
    }

    /// Handle an incoming handshake message.
    fn handle_handshake_message(&mut self, bbox: ByteBox) -> SignalingResult<Vec<HandleAction>> {
        // Decode message depending on source
        let obox: OpenBox<Message> = if bbox.nonce.source().is_server() {
            self.decode_server_message(bbox)?
        } else {
            self.decode_peer_message(bbox)?
        };

        // Handle message depending on state
        match self.common().signaling_state() {
            // Server handshake
            SignalingState::ServerHandshake =>
                self.handle_server_message(obox),

            // Peer handshake
            SignalingState::PeerHandshake if obox.nonce.source().is_server() =>
                self.handle_server_message(obox),
            SignalingState::PeerHandshake =>
                self.handle_peer_message(obox),

            // Task
            SignalingState::Task =>
                return Err(SignalingError::Crash("Illegal signaling state: Task".into())),
        }
    }

    /// Handle an incoming task message.
    fn handle_task_message(&mut self, bbox: ByteBox) -> SignalingResult<Vec<HandleAction>> {
        // Decode message
        let _obox: OpenBox<Value> = self.decode_task_message(bbox)?;

        // Pass message to task
        unimplemented!("TODO: Finish implementing handle_task_message");
    }


    // Message decoding

    /// Decode or decrypt a binary message coming from the server.
    fn decode_server_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox<Message>> {
        // The very first message from the server is unencrypted
        if self.common().signaling_state() == SignalingState::ServerHandshake
        && self.server_handshake_state() == ServerHandshakeState::New {
            return OpenBox::decode(bbox);
        }

        // Otherwise, decrypt with server key
        match self.server().session_key {
            Some(ref pubkey) => OpenBox::<Message>::decrypt(bbox, &self.common().permanent_keypair, pubkey),
            None => Err(SignalingError::Crash("Missing server session key".into())),
        }
    }

    /// Decrypt a binary message coming from a peer.
    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox<Message>>;

    /// Decrypt a binary message after the handshake has been finished.
    fn decode_task_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox<Value>> {
        let peer = self.get_peer()
            .ok_or(SignalingError::Crash("Peer not set".into()))?;
        let session_key = peer.session_key()
            .ok_or(SignalingError::Crash("Peer session key not set".into()))?;
        OpenBox::<Value>::decrypt(
            bbox,
            peer.keypair().ok_or(SignalingError::Crash("Peer session keypair not available".into()))?,
            session_key,
        )
    }


    // Message handling: Dispatching

    /// Determine the next server handshake state based on the incoming
    /// server-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_server_message(&mut self, obox: OpenBox<Message>) -> SignalingResult<Vec<HandleAction>> {
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
    fn handle_peer_message(&mut self, obox: OpenBox<Message>) -> SignalingResult<Vec<HandleAction>>;


    // Message handling: Handling

    /// Handle an incoming [`ServerHello`](messages/struct.ServerHello.html) message.
    fn handle_server_hello(&mut self, msg: ServerHello) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received server-hello from server");

        let mut actions = Vec::with_capacity(2);

        // Set the server public session key
        trace!("Server session key is {:?}", msg.key);
        if self.server().session_key.is_some() {
            return Err(SignalingError::Protocol(
                "Got a server-hello message, but server session key is already set".to_string()
            ));
        }
        self.common_mut().server.session_key = Some(msg.key);

        // Reply with client-hello message if we're a responder
        if self.role() == Role::Responder {
            let client_hello = {
                let key = self.common().permanent_keypair.public_key();
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
            let reply = OpenBox::<Message>::new(client_hello, client_hello_nonce);
            debug!("<-- Enqueuing client-hello to server");
            actions.push(HandleAction::Reply(reply.encode()));
        }

        // Send client-auth message
        let ping_interval = self.common()
            .ping_interval
            .map(|duration| duration.as_secs())
            .map(|secs| if secs > ::std::u32::MAX as u64 {
                warn!("Ping interval is too large. Truncating it to {} seconds.", ::std::u32::MAX);
                ::std::u32::MAX
            } else {
                secs as u32
            })
            .unwrap_or(0u32);
        match ping_interval {
            0 => debug!("Requesting WebSocket ping messages to be disabled"),
            n => debug!("Requesting WebSocket ping messages every {}s", n),
        };
        let client_auth = ClientAuth {
            your_cookie: self.server().cookie_pair().theirs.clone().unwrap(),
            subprotocols: vec![::SUBPROTOCOL.into()],
            ping_interval,
            your_key: None, // TODO (#12)
        }.into_message();
        let client_auth_nonce = Nonce::new(
            self.server().cookie_pair().ours.clone(),
            self.identity().into(),
            self.server().identity().into(),
            self.server().csn_pair().borrow_mut().ours.increment()?,
        );
        let reply = OpenBox::<Message>::new(client_auth, client_auth_nonce);
        match self.server().session_key {
            Some(ref pubkey) => {
                debug!("<-- Enqueuing client-auth to server");
                actions.push(HandleAction::Reply(reply.encrypt(&self.common().permanent_keypair, pubkey)));
            },
            None => return Err(SignalingError::Crash("Missing server permanent key".into())),
        };

        // TODO (#13): Can we prevent confusing an incoming and an outgoing nonce?
        self.server_mut().set_handshake_state(ServerHandshakeState::ClientInfoSent);
        Ok(actions)
    }

    /// Handle an incoming [`ServerAuth`](messages/struct.ServerAuth.html) message.
    fn handle_server_auth(&mut self, msg: ServerAuth) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received server-auth from server");

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
        self.validate_repeated_cookie(
            &msg.your_cookie,
            &self.server().cookie_pair().ours,
            self.server().identity(),
        )?;

        // If the client has knowledge of the server's public permanent
        // key, it SHALL decrypt the signed_keys field by using the
        // message's nonce, the client's private permanent key and the
        // server's public permanent key. The decrypted message MUST
        // match the concatenation of the server's public session key
        // and the client's public permanent key (in that order). If
        // the signed_keys is present but the client does not have
        // knowledge of the server's permanent key, it SHALL log a
        // warning.
        // TODO (#12): Implement

        // Moreover, the client MUST do some checks depending on its role
        let mut actions = self.handle_server_auth_impl(&msg)?;

        info!("Server handshake completed");
        actions.push(HandleAction::Event(Event::ServerHandshakeDone));

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
        warn!("--> Received send-error from server");
        debug!("Message that could not be relayed: {:#?}", msg.id);
        return Err(SignalingError::SendError);
    }
}


pub(crate) type BoxedSignaling = Box<Signaling + Send>;


/// Common functionality and state for all signaling types.
pub(crate) struct Common {
    /// The signaling state.
    signaling_state: SignalingState,

    /// Our permanent keypair.
    pub(crate) permanent_keypair: KeyPair,

    /// An optional auth token.
    pub(crate) auth_token: Option<AuthToken>,

    /// The assigned role.
    pub(crate) role: Role,

    /// The assigned client identity.
    pub(crate) identity: ClientIdentity,

    /// The server context.
    pub(crate) server: ServerContext,

    /// The list of possible task instances.
    pub(crate) tasks: Option<Tasks>,

    /// The chosen task.
    pub(crate) task: Option<BoxedTask>,

    /// The interval at which the server should send WebSocket ping messages.
    pub(crate) ping_interval: Option<Duration>,
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

    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox<Message>> {
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
                    Some(ref token) => OpenBox::decrypt_token(bbox, token),
                    None => Err(SignalingError::Crash("Auth token not set".into())),
                }
            },
            ResponderHandshakeState::TokenReceived => {
                // Expect key message, encrypted with our public permanent key
                // and responder private permanent key
                OpenBox::<Message>::decrypt(bbox, &self.common.permanent_keypair, responder_permanent_key(&responder)?)
            },
            ResponderHandshakeState::KeySent => {
                // Expect auth message, encrypted with our public session key
                // and responder private session key
                OpenBox::<Message>::decrypt(bbox, &responder.keypair, responder_session_key(&responder)?)
            },
            other => {
                // TODO (#14): Maybe remove these states?
                Err(SignalingError::Crash(format!("Invalid responder handshake state: {:?}", other)))
            },
        }
    }

    /// Determine the next peer handshake state based on the incoming
    /// client-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_peer_message(&mut self, obox: OpenBox<Message>) -> SignalingResult<Vec<HandleAction>> {
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
            (ResponderHandshakeState::KeySent, Message::Auth(msg)) => self.handle_auth(msg, source),

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
            self.responders.insert(address, ResponderContext::new(address));
        }

        // Additionally, the initiator MUST keep its path clean
        // by following the procedure described in the Path
        // Cleaning section.
        // TODO (#15): Implement

        Ok(vec![])
    }

    fn handle_new_responder(&mut self, msg: NewResponder) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received new-responder ({}) from server", msg.id);

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
        self.responders.insert(msg.id, ResponderContext::new(msg.id));

        // Furthermore, the initiator MUST keep its path clean by following the
        // procedure described in the Path Cleaning section.
        // TODO (#15): Implement

        Ok(vec![])
    }

}

impl InitiatorSignaling {
    pub(crate) fn new(permanent_keypair: KeyPair,
                      tasks: Tasks,
                      ping_interval: Option<Duration>) -> Self {
        InitiatorSignaling {
            common: Common {
                signaling_state: SignalingState::ServerHandshake,
                role: Role::Initiator,
                identity: ClientIdentity::Unknown,
                permanent_keypair: permanent_keypair,
                auth_token: Some(AuthToken::new()),
                server: ServerContext::new(),
                tasks: Some(tasks),
                task: None,
                ping_interval: ping_interval,
            },
            responders: HashMap::new(),
            responder: None,
        }
    }

    /// Handle an incoming [`Token`](messages/struct.Token.html) message.
    fn handle_token(&mut self, msg: Token, source: Address) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received token from {}", Identity::from(source));

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
        let source_identity = Identity::from(source);
        debug!("--> Received key from {}", source_identity);

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
            key: responder.keypair.public_key().clone(),
        }.into_message();
        let key_nonce = Nonce::new(
            responder.cookie_pair().ours.clone(),
            self.common.identity.into(),
            responder.identity().into(),
            responder.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::<Message>::new(key, key_nonce);
        let bbox = obox.encrypt(
            &self.common.permanent_keypair,
            responder.permanent_key.as_ref()
                .ok_or(SignalingError::Crash("Responder permanent key not set".into()))?,
        );

        // State transition
        responder.set_handshake_state(ResponderHandshakeState::KeySent);

        debug!("<-- Enqueuing key to {}", source_identity);
        Ok(vec![HandleAction::Reply(bbox)])
    }

    /// Handle an incoming [`Auth`](messages/struct.Auth.html) message.
    fn handle_auth(&mut self, msg: Auth, source: Address) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received auth from {}", Identity::from(source));

        let mut actions = vec![];

        // Find responder instance
        let mut responder = self.responders.remove(&source)
            .ok_or(SignalingError::Crash(
                format!("Did not find responder with address {}", source)
            ))?;

        // The cookie provided in the `your_cookie` field SHALL contain the cookie
        // we have used in our previous messages to the responder.
        self.validate_repeated_cookie(
            &msg.your_cookie,
            &responder.cookie_pair().ours,
            responder.identity(),
        )?;

        // An initiator SHALL validate that the tasks field contains an array with at least one element.
        if msg.task.is_some() {
            return Err(SignalingError::InvalidMessage("We're an initiator, but the `task` field in the auth message is set".into()));
        }
        let proposed_tasks = match msg.tasks {
            None => return Err(SignalingError::InvalidMessage("The `tasks` field in the auth message is not set".into())),
            Some(ref tasks) if tasks.len() == 0 => return Err(SignalingError::InvalidMessage("The `tasks` field in the auth message is empty".into())),
            Some(tasks) => tasks,
        };

        // Each element in the Array SHALL be a string.
        // -> Already covered in deserialization

        // Validate data field
        if msg.data.len() != proposed_tasks.len() {
            return Err(SignalingError::InvalidMessage("The `tasks` and `data` fields in the auth message have a different number of entries".into()));
        };
        for task in proposed_tasks.iter() {
            if !msg.data.contains_key(task) {
                return Err(SignalingError::InvalidMessage(format!("The task \"{}\" in the auth message does not have a corresponding data entry", task)));
            }
        }

        // The initiator SHALL continue by comparing the provided tasks
        // to its own array of supported tasks.
        // It MUST choose the first task in its own list of supported tasks
        // that is also contained in the list of supported tasks provided by the responder.
        // In case no common task could be found, the initiator SHALL send a 'close' message
        // to the responder containing the close code 3006 (No Shared Task Found) as reason
        // and raise an error event indicating that no common signalling task could be found.
        let our_tasks = mem::replace(&mut self.common_mut().tasks, None)
            .ok_or(SignalingError::Crash("No tasks defined".into()))?;
        trace!("Our tasks: {:?}", &our_tasks);
        trace!("Proposed tasks: {:?}", &proposed_tasks);
        let mut chosen_task: BoxedTask = our_tasks
            .choose_shared_task(&proposed_tasks)
            .ok_or_else(|| {
                // TODO (#17)
                SignalingError::NoSharedTask
            })?;

        // Both initiator an responder SHALL verify that the data field contains a Map
        // and SHALL look up the chosen task's data value.
        let task_data = msg.data.get(&*chosen_task.name())
            .ok_or(SignalingError::Crash("Task data not found".into()))?;

        // The value MUST be handed over to the corresponding task
        // after processing this message is complete.
        chosen_task.init(task_data)
            .map_err(|e| SignalingError::TaskInitialization(format!("{}", e)))?;

        // After the above procedure has been followed, the other client has successfully
        // authenticated it towards the client. The other client's public key MAY be stored
        // as trusted for that path if the application desires it.
        info!("Responder {:#04x} authenticated", source.0);

        // The initiator MUST drop all other connected responders with a 'drop-responder'
        // message containing the close code 3004 (Dropped by Initiator) in the reason field.
        if !self.responders.is_empty() {
            info!("Dropping {} other responders", self.responders.len());
            for addr in self.responders.keys() {
                let drop = DropResponder::with_reason(addr.clone(), DropReason::DroppedByInitiator).into_message();
                let drop_nonce = Nonce::new(
                    self.server().cookie_pair.ours.clone(),
                    self.common.identity.into(),
                    self.server().identity().into(),
                    self.server().csn_pair().borrow_mut().ours.increment()?,
                );
                let obox = OpenBox::<Message>::new(drop, drop_nonce);
                let bbox = obox.encrypt(
                    &self.common().permanent_keypair,
                    self.server().session_key()
                        .ok_or(SignalingError::Crash("Server session key not set".into()))?
                );
                debug!("<-- Enqueuing drop-responder to {}", self.server().identity());
                actions.push(HandleAction::Reply(bbox));
            }

            // Remove responders
            self.responders.clear();

            // Free the memory used for tracking responders
            self.responders.shrink_to_fit();
        }

        // State transition
        responder.set_handshake_state(ResponderHandshakeState::AuthReceived);

        // Respond with auth message
        let responder_cookie = responder.cookie_pair.theirs.as_ref().cloned()
            .ok_or(SignalingError::Crash("Responder cookie not set".into()))?;
        let auth: Message = InitiatorAuthBuilder::new(responder_cookie)
            .set_task(chosen_task.name(), chosen_task.data())
            .build()?
            .into_message();
        let auth_nonce = Nonce::new(
            responder.cookie_pair().ours.clone(),
            self.common.identity.into(),
            responder.address,
            responder.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::<Message>::new(auth, auth_nonce);
        let bbox = obox.encrypt(
            &responder.keypair,
            responder.session_key.as_ref()
                .ok_or(SignalingError::Crash("Responder session key not set".into()))?,
        );
        debug!("<-- Enqueuing auth to {}", &responder.identity());
        actions.push(HandleAction::Reply(bbox));

        // Store chosen task
        self.common_mut().task = Some(chosen_task);

        // State transitions
        responder.set_handshake_state(ResponderHandshakeState::AuthSent);
        self.common.set_signaling_state(SignalingState::Task)?;
        info!("Peer handshake completed");
        actions.push(HandleAction::Event(Event::PeerHandshakeDone));

        self.responder = Some(responder);
        Ok(actions)
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

    fn decode_peer_message(&self, bbox: ByteBox) -> SignalingResult<OpenBox<Message>> {
        // Validate source again
        if !bbox.nonce.source().is_initiator() {
            return Err(SignalingError::Crash(format!("Received message from a responder")));
        }

        // Decrypt depending on state
        match self.initiator.handshake_state() {
            InitiatorHandshakeState::KeySent => {
                // Expect key message, encrypted with our public permanent key
                // and initiator private permanent key
                OpenBox::<Message>::decrypt(bbox, &self.common.permanent_keypair, &self.initiator.permanent_key)
            },
            InitiatorHandshakeState::AuthSent => {
                // Expect an auth message, encrypted with our public session
                // key and initiator private session key
                let initiator_session_key = self.initiator.session_key.as_ref()
                    .ok_or(SignalingError::Crash("Initiator session key not set".into()))?;
                OpenBox::<Message>::decrypt(bbox, &self.initiator.keypair, initiator_session_key)
            },
            other => {
                // TODO (#14): Maybe remove these states?
                Err(SignalingError::Crash(format!("Invalid initiator handshake state: {:?}", other)))
            },
        }
    }

    /// Determine the next peer handshake state based on the incoming
    /// client-to-client message and the current state.
    ///
    /// This method call may have some side effects, like updates in the peer
    /// context (cookie, CSN, etc).
    fn handle_peer_message(&mut self, obox: OpenBox<Message>) -> SignalingResult<Vec<HandleAction>> {
        let old_state = self.initiator.handshake_state();
        match (old_state, obox.message) {
            // Valid state transitions
            (InitiatorHandshakeState::KeySent, Message::Key(msg)) => self.handle_key(msg, &obox.nonce),
            (InitiatorHandshakeState::AuthSent, Message::Auth(msg)) => self.handle_auth(msg, obox.nonce.source()),

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
    pub(crate) fn new(permanent_keypair: KeyPair,
                      initiator_pubkey: PublicKey,
                      auth_token: Option<AuthToken>,
                      tasks: Tasks,
                      ping_interval: Option<Duration>) -> Self {
        ResponderSignaling {
            common: Common {
                signaling_state: SignalingState::ServerHandshake,
                role: Role::Responder,
                identity: ClientIdentity::Unknown,
                permanent_keypair: permanent_keypair,
                auth_token: auth_token,
                server: ServerContext::new(),
                tasks: Some(tasks),
                task: None,
                ping_interval: ping_interval,
            },
            initiator: InitiatorContext::new(initiator_pubkey),
        }
    }

    /// Build a `Token` message.
    fn send_token(&self, token: &AuthToken) -> SignalingResult<HandleAction> {
        // The responder MUST set the public key (32 bytes) of the permanent
        // key pair in the key field of this message.
        let msg: Message = Token {
            key: self.common().permanent_keypair.public_key().to_owned(),
        }.into_message();
        let nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.identity().into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::<Message>::new(msg, nonce);

        // The message SHALL be NaCl secret key encrypted by the token the
        // initiator created and issued to the responder.
        let bbox = obox.encrypt_token(&token);

        // TODO (#18): In case the initiator has successfully decrypted the 'token'
        // message, the secret key MUST be invalidated immediately and SHALL
        // NOT be used for any other message.

        debug!("<-- Enqueuing token to {}", self.initiator.identity());
        Ok(HandleAction::Reply(bbox))
    }

    /// Build a `Key` message.
    fn send_key(&self) -> SignalingResult<HandleAction> {
        // It MUST set the public key (32 bytes) of that key pair in the key field.
        let msg: Message = Key {
            key: self.initiator.keypair.public_key().to_owned(),
        }.into_message();
        let nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.identity().into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::<Message>::new(msg, nonce);

        // The message SHALL be NaCl public-key encrypted by the client's
        // permanent key pair and the other client's permanent key pair.
        let bbox = obox.encrypt(&self.common().permanent_keypair, &self.initiator.permanent_key);

        debug!("<-- Enqueuing key to {}", self.initiator.identity());
        Ok(HandleAction::Reply(bbox))
    }

    /// Handle an incoming [`Key`](messages/struct.Key.html) message.
    fn handle_key(&mut self, msg: Key, nonce: &Nonce) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received key from {}", nonce.source_identity());

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
        let auth: Message = ResponderAuthBuilder::new(nonce.cookie().clone())
            .add_tasks(
                self.common()
                    .tasks
                    .as_ref()
                    .ok_or(SignalingError::Crash("Tasks are not set".into()))?
            )
            .build()?
            .into_message();
        let auth_nonce = Nonce::new(
            self.initiator.cookie_pair().ours.clone(),
            self.common().identity.into(),
            self.initiator.identity().into(),
            self.initiator.csn_pair().borrow_mut().ours.increment()?,
        );
        let obox = OpenBox::<Message>::new(auth, auth_nonce);
        let bbox = obox.encrypt(
            &self.initiator.keypair,
            self.initiator.session_key.as_ref()
                .ok_or(SignalingError::Crash("Initiator session key not set".into()))?,
        );

        // State transition
        self.initiator.set_handshake_state(InitiatorHandshakeState::AuthSent);

        debug!("<-- Enqueuing auth to {}", self.initiator.identity());
        Ok(vec![HandleAction::Reply(bbox)])
    }

    /// Handle an incoming [`Auth`](messages/struct.Auth.html) message.
    fn handle_auth(&mut self, msg: Auth, source: Address) -> SignalingResult<Vec<HandleAction>> {
        debug!("--> Received auth from {}", Identity::from(source));

        // The cookie provided in the `your_cookie` field SHALL contain the cookie
        // we have used in our previous messages to the responder.
        self.validate_repeated_cookie(
            &msg.your_cookie,
            &self.initiator.cookie_pair().ours,
            self.initiator.identity(),
        )?;

        // A responder SHALL validate that the task field is present and contains one of the tasks it has previously offered to the initiator.
        if msg.tasks.is_some() {
            return Err(SignalingError::InvalidMessage("We're a responder, but the `tasks` field in the auth message is set".into()));
        }
        let mut chosen_task: BoxedTask = match msg.task {
            Some(task) => {
                let our_tasks = mem::replace(&mut self.common_mut().tasks, None)
                    .ok_or(SignalingError::Crash("No tasks defined".into()))?;
                our_tasks
                    .into_iter()
                    .filter(|t: &BoxedTask| t.name() == task)
                    .next()
                    .ok_or(SignalingError::Protocol("The `task` field in the auth message contains an unknown task".into()))?
            },
            None => return Err(SignalingError::InvalidMessage("The `task` field in the auth message is not set".into())),
        };

        // Make sure that there is only one data entry.
        if msg.data.is_empty() {
            return Err(SignalingError::Protocol("The `data` field in the auth message is empty".into()));
        }
        if msg.data.len() > 1 {
            return Err(SignalingError::Protocol("The `data` field in the auth message contains more than one entry".into()));
        }

        // Both initiator an responder SHALL verify that the data field contains a Map
        // and SHALL look up the chosen task's data value.
        let task_data = msg.data.get(&*chosen_task.name())
            .ok_or(SignalingError::Protocol("The task in the auth message does not have a corresponding data entry".into()))?;

        // The value MUST be handed over to the corresponding task
        // after processing this message is complete.
        chosen_task.init(task_data)
            .map_err(|e| SignalingError::TaskInitialization(format!("{}", e)))?;

        // After the above procedure has been followed, the other client has successfully
        // authenticated it towards the client. The other client's public key MAY be stored
        // as trusted for that path if the application desires it.
        info!("Initiator authenticated");

        // Store chosen task
        self.common_mut().task = Some(chosen_task);

        // State transitions
        self.initiator.set_handshake_state(InitiatorHandshakeState::AuthReceived);
        self.common.set_signaling_state(SignalingState::Task)?;
        info!("Peer handshake completed");

        Ok(vec![HandleAction::Event(Event::PeerHandshakeDone)])
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
