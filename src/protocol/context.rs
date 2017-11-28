//! The context structs hold state used in signaling.

use std::cell::RefCell;

use crypto::{PublicKey};

use super::cookie::{CookiePair};
use super::csn::{CombinedSequencePair};
use super::state::{ServerHandshakeState};
use super::types::{Identity, Address};


pub trait PeerContext {
    fn identity(&self) -> Identity;
    fn permanent_key(&self) -> Option<&PublicKey>;
    fn session_key(&self) -> Option<&PublicKey>;
    fn csn_pair(&self) -> &RefCell<CombinedSequencePair>;
    fn cookie_pair(&self) -> &CookiePair;
    fn cookie_pair_mut(&mut self) -> &mut CookiePair;
}


#[derive(Debug, PartialEq, Eq)]
pub struct ServerContext {
    handshake_state: ServerHandshakeState,
    pub(crate) permanent_key: Option<PublicKey>,
    pub(crate) session_key: Option<PublicKey>,
    pub(crate) csn_pair: RefCell<CombinedSequencePair>,
    pub(crate) cookie_pair: CookiePair,
}

impl ServerContext {
    pub fn new() -> Self {
        ServerContext {
            handshake_state: ServerHandshakeState::New,
            permanent_key: None,
            session_key: None,
            csn_pair: RefCell::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
    }

    /// Return the current server handshake state.
    pub fn handshake_state(&self) -> &ServerHandshakeState {
        &self.handshake_state
    }

    /// Update the server handshake state.
    pub fn set_handshake_state(&mut self, new_state: ServerHandshakeState) {
        trace!("Server handshake state transition: {:?} -> {:?}", self.handshake_state, new_state);
        if let ServerHandshakeState::Failure(ref msg) = new_state {
            warn!("Server handshake failure: {}", msg);
        }
        self.handshake_state = new_state;
    }

    /// Set the server handshake state to `Failure` with the specified message.
    pub fn handshake_failed<S: Into<String>>(&mut self, msg: S) {
        self.set_handshake_state(ServerHandshakeState::Failure(msg.into()));
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

    fn csn_pair(&self) -> &RefCell<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}


#[derive(Debug, PartialEq, Eq)]
pub struct InitiatorContext {
    pub(crate) permanent_key: Option<PublicKey>,
    pub(crate) session_key: Option<PublicKey>,
    pub(crate) csn_pair: RefCell<CombinedSequencePair>,
    pub(crate) cookie_pair: CookiePair,
}

impl InitiatorContext {
    pub fn new() -> Self {
        InitiatorContext {
            permanent_key: None,
            session_key: None,
            csn_pair: RefCell::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
    }
}

impl PeerContext for InitiatorContext {
    fn identity(&self) -> Identity {
        Identity::Initiator
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        self.permanent_key.as_ref()
    }

    fn session_key(&self) -> Option<&PublicKey> {
        self.session_key.as_ref()
    }

    fn csn_pair(&self) -> &RefCell<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}


#[derive(Debug, PartialEq, Eq)]
pub struct ResponderContext {
    pub(crate) address: Address,
    pub(crate) permanent_key: Option<PublicKey>,
    pub(crate) session_key: Option<PublicKey>,
    pub(crate) csn_pair: RefCell<CombinedSequencePair>,
    pub(crate) cookie_pair: CookiePair,
}

impl ResponderContext {
    pub fn new(address: Address) -> Self {
        ResponderContext {
            address: address,
            permanent_key: None,
            session_key: None,
            csn_pair: RefCell::new(CombinedSequencePair::new()),
            cookie_pair: CookiePair::new(),
        }
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

    fn csn_pair(&self) -> &RefCell<CombinedSequencePair> {
        &self.csn_pair
    }

    fn cookie_pair(&self) -> &CookiePair {
        &self.cookie_pair
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        &mut self.cookie_pair
    }
}
