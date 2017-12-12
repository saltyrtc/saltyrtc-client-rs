//! The context structs hold state used in signaling.

use std::cell::RefCell;

use crypto::{PublicKey, KeyStore};
use errors::{SignalingError, SignalingResult};

use super::cookie::{CookiePair};
use super::csn::{CombinedSequencePair};
use super::state::{ServerHandshakeState, InitiatorHandshakeState, ResponderHandshakeState};
use super::types::{Identity, Address};


pub(crate) trait PeerContext {
    fn identity(&self) -> Identity;
    fn permanent_key(&self) -> Option<&PublicKey>;
    fn session_key(&self) -> Option<&PublicKey>;
    fn csn_pair(&self) -> &RefCell<CombinedSequencePair>;
    fn cookie_pair(&self) -> &CookiePair;
    fn cookie_pair_mut(&mut self) -> &mut CookiePair;
}


#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServerContext {
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
    pub fn handshake_state(&self) -> ServerHandshakeState {
        self.handshake_state
    }

    /// Update the server handshake state.
    pub fn set_handshake_state(&mut self, new_state: ServerHandshakeState) {
        trace!("Server handshake state transition: {:?} -> {:?}", self.handshake_state, new_state);
        // TODO: Validate state transitions
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
pub(crate) struct InitiatorContext {
    handshake_state: InitiatorHandshakeState,
    pub(crate) permanent_key: PublicKey,
    pub(crate) session_key: Option<PublicKey>,
    /// Our session keystore for this initiator
    pub(crate) keystore: KeyStore,
    pub(crate) csn_pair: RefCell<CombinedSequencePair>,
    pub(crate) cookie_pair: CookiePair,
}

impl InitiatorContext {
    pub fn new(permanent_key: PublicKey) -> Self {
        InitiatorContext {
            handshake_state: InitiatorHandshakeState::New,
            permanent_key: permanent_key,
            session_key: None,
            keystore: KeyStore::new(),
            csn_pair: RefCell::new(CombinedSequencePair::new()),
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
        // TODO: Validate state transitions
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
pub(crate) struct ResponderContext {
    /// The handshake state with this receiver
    handshake_state: ResponderHandshakeState,
    /// The receiver address
    pub(crate) address: Address,
    /// Public permanent key of the responder
    pub(crate) permanent_key: Option<PublicKey>,
    /// Public session key of the responder
    pub(crate) session_key: Option<PublicKey>,
    /// Our session keystore for this responder
    pub(crate) keystore: KeyStore,
    /// Our combined sequence pair for this responder
    pub(crate) csn_pair: RefCell<CombinedSequencePair>,
    /// Our cookie pair for this responder
    pub(crate) cookie_pair: CookiePair,
}

impl ResponderContext {
    pub fn new(address: Address) -> Self {
        ResponderContext {
            handshake_state: ResponderHandshakeState::New,
            address: address,
            permanent_key: None,
            session_key: None,
            keystore: KeyStore::new(),
            csn_pair: RefCell::new(CombinedSequencePair::new()),
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
        // TODO: Validate state transitions
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
