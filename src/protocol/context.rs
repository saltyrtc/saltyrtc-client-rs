//! The context structs hold state used in signaling.

use std::sync::RwLock;

use crypto::{PublicKey, KeyPair};

use super::cookie::{CookiePair};
use super::csn::{CombinedSequencePair};
use super::state::{ServerHandshakeState, InitiatorHandshakeState, ResponderHandshakeState};
use super::types::{Identity, Address};


pub(crate) trait PeerContext {
    /// Return the peer identity.
    fn identity(&self) -> Identity;

    /// Return the peer public permanent key.
    fn permanent_key(&self) -> Option<&PublicKey>;

    /// Return the peer public session key.
    fn session_key(&self) -> Option<&PublicKey>;

    /// Return our session keypair with this peer.
    fn keypair(&self) -> Option<&KeyPair>;

    /// Return our CSN pair with this peer.
    /// The returned reference is inside a RwLock, providing interior mutability.
    fn csn_pair(&self) -> &RwLock<CombinedSequencePair>;

    /// Return our cookie pair with this peer.
    fn cookie_pair(&self) -> &CookiePair;

    /// Return our mutable cookie pair with this peer.
    fn cookie_pair_mut(&mut self) -> &mut CookiePair;
}


#[derive(Debug)]
pub(crate) struct ServerContext {
    /// The server handshake state.
    handshake_state: ServerHandshakeState,

    /// The public permanent key of the server.
    pub(crate) permanent_key: Option<PublicKey>,

    /// The public session key of the server.
    pub(crate) session_key: Option<PublicKey>,

    /// The combined sequence number.
    pub(crate) csn_pair: RwLock<CombinedSequencePair>,

    /// The cookie pair between us and the server.
    pub(crate) cookie_pair: CookiePair,
}

impl ServerContext {
    /// Create a new `ServerContext` instance.
    pub fn new() -> Self {
        ServerContext {
            handshake_state: ServerHandshakeState::New,
            permanent_key: None,
            session_key: None,
            csn_pair: RwLock::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
    }

    /// Return the current server handshake state.
    pub fn handshake_state(&self) -> ServerHandshakeState {
        self.handshake_state
    }

    /// Update the server handshake state.
    pub fn set_handshake_state(&mut self, new_state: ServerHandshakeState) {
        trace!("Server handshake state transition: {:?} -> {:?}", self.handshake_state, new_state);
        // TODO (#22): Validate state transitions
        self.handshake_state = new_state;
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

    fn keypair(&self) -> Option<&KeyPair> {
        None // There is no session keypair between the client and the server
    }

    fn csn_pair(&self) -> &RwLock<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}


#[derive(Debug)]
pub(crate) struct InitiatorContext {
    /// The initiator handshake state.
    handshake_state: InitiatorHandshakeState,

    /// The public permanent key of the initiator.
    pub(crate) permanent_key: PublicKey,

    /// The public session key of the initiator.
    pub(crate) session_key: Option<PublicKey>,

    /// Our session keypair for the initiator.
    pub(crate) keypair: KeyPair,

    /// The combined sequence number.
    pub(crate) csn_pair: RwLock<CombinedSequencePair>,

    /// The cookie pair between us and the initiator.
    pub(crate) cookie_pair: CookiePair,
}

impl InitiatorContext {
    pub fn new(permanent_key: PublicKey) -> Self {
        InitiatorContext {
            handshake_state: InitiatorHandshakeState::New,
            permanent_key,
            session_key: None,
            keypair: KeyPair::new(),
            csn_pair: RwLock::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
    }

    /// Return the current initiator handshake state.
    pub fn handshake_state(&self) -> InitiatorHandshakeState {
        self.handshake_state
    }

    /// Update the initiator handshake state.
    pub fn set_handshake_state(&mut self, new_state: InitiatorHandshakeState) {
        trace!("Initiator handshake state transition: {:?} -> {:?}", self.handshake_state, new_state);
        // TODO (#22): Validate state transitions
        self.handshake_state = new_state;
    }
}

impl PeerContext for InitiatorContext {
    fn identity(&self) -> Identity {
        Identity::Initiator
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        Some(&self.permanent_key)
    }

    fn session_key(&self) -> Option<&PublicKey> {
        self.session_key.as_ref()
    }

    fn keypair(&self) -> Option<&KeyPair> {
        Some(&self.keypair)
    }

    fn csn_pair(&self) -> &RwLock<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}


#[derive(Debug)]
pub(crate) struct ResponderContext {
    /// The responder handshake state.
    handshake_state: ResponderHandshakeState,

    /// A counter used to identify the oldest responders when doing path
    /// cleaning.
    pub(crate) counter: u32,

    /// The receiver address.
    pub(crate) address: Address,

    /// The public permanent key of the responder.
    pub(crate) permanent_key: Option<PublicKey>,

    /// Public session key of the responder
    pub(crate) session_key: Option<PublicKey>,

    /// Our session keypair for this responder
    pub(crate) keypair: KeyPair,

    /// Our combined sequence pair for this responder
    pub(crate) csn_pair: RwLock<CombinedSequencePair>,

    /// The cookie pair between us and the responder.
    pub(crate) cookie_pair: CookiePair,
}

impl ResponderContext {
    pub fn new(address: Address, counter: u32) -> Self {
        ResponderContext {
            handshake_state: ResponderHandshakeState::New,
            counter,
            address,
            permanent_key: None,
            session_key: None,
            keypair: KeyPair::new(),
            csn_pair: RwLock::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
    }

    /// Return the current responder handshake state.
    pub fn handshake_state(&self) -> ResponderHandshakeState {
        self.handshake_state
    }

    /// Update the responder handshake state.
    pub fn set_handshake_state(&mut self, new_state: ResponderHandshakeState) {
        trace!("Responder handshake state transition: {:?} -> {:?}", self.handshake_state, new_state);
        // TODO (#22): Validate state transitions
        self.handshake_state = new_state;
    }
}

impl PeerContext for ResponderContext {
    fn identity(&self) -> Identity {
        Identity::Responder(self.address.0)
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        self.permanent_key.as_ref()
    }

    fn session_key(&self) -> Option<&PublicKey> {
        self.session_key.as_ref()
    }

    fn keypair(&self) -> Option<&KeyPair> {
        Some(&self.keypair)
    }

    fn csn_pair(&self) -> &RwLock<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_context_new() {
        let ctx = ServerContext::new();
        assert_eq!(ctx.identity(), Identity::Server);
        assert_eq!(ctx.permanent_key(), None);
        assert_eq!(ctx.session_key(), None);
    }
}
