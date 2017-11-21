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
    pub(crate) handshake_state: ServerHandshakeState,
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


/// An enum holding all possible peer context instances.
/// Only transitional. Will be removed in the future.
#[derive(Debug, PartialEq, Eq)]
pub enum TmpPeer {
    Initiator(InitiatorContext),
    Responder(ResponderContext),
}

impl PeerContext for TmpPeer {
    fn identity(&self) -> Identity {
        match *self {
            TmpPeer::Initiator(ref p) => Identity::Initiator,
            TmpPeer::Responder(ref p) => Identity::Responder(p.address.0),
        }
    }

    fn permanent_key(&self) -> Option<&PublicKey> {
        match *self {
            TmpPeer::Initiator(ref p) => p.permanent_key.as_ref(),
            TmpPeer::Responder(ref p) => p.permanent_key.as_ref(),
        }
    }

    fn session_key(&self) -> Option<&PublicKey> {
        match *self {
            TmpPeer::Initiator(ref p) => p.session_key.as_ref(),
            TmpPeer::Responder(ref p) => p.session_key.as_ref(),
        }
    }

    fn csn_pair(&self) -> &RefCell<CombinedSequencePair> {
        match *self {
            TmpPeer::Initiator(ref p) => &p.csn_pair,
            TmpPeer::Responder(ref p) => &p.csn_pair,
        }
    }

    fn cookie_pair(&self) -> &CookiePair {
        match *self {
            TmpPeer::Initiator(ref p) => &p.cookie_pair,
            TmpPeer::Responder(ref p) => &p.cookie_pair,
        }
    }

    fn cookie_pair_mut(&mut self) -> &mut CookiePair {
        match *self {
            TmpPeer::Initiator(ref mut p) => &mut p.cookie_pair,
            TmpPeer::Responder(ref mut p) => &mut p.cookie_pair,
        }
    }
}
