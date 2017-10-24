//! The context structs hold state used in signaling.

use keystore::{PublicKey};

use super::csn::{CombinedSequencePair};
use super::state::{ServerHandshakeState};
use super::types::{Identity, Address};


pub trait PeerContext {
    fn identity(&self) -> Identity;
    fn permanent_key(&self) -> Option<&PublicKey>;
    fn session_key(&self) -> Option<&PublicKey>;
    fn csn_pair(&self) -> &CombinedSequencePair;
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerContext {
    pub(crate) handshake_state: ServerHandshakeState,
    pub(crate) permanent_key: Option<PublicKey>,
    pub(crate) session_key: Option<PublicKey>,
    pub(crate) csn_pair: CombinedSequencePair,
}

impl ServerContext {
    pub fn new() -> Self {
        ServerContext {
            handshake_state: ServerHandshakeState::New,
            permanent_key: None,
            session_key: None,
            csn_pair: CombinedSequencePair::new(),
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

    fn csn_pair(&self) -> &CombinedSequencePair {
        &self.csn_pair
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderContext {
    pub(crate) address: Address,
    pub(crate) permanent_key: Option<PublicKey>,
    pub(crate) session_key: Option<PublicKey>,
    pub(crate) csn_pair: CombinedSequencePair,
}

impl ResponderContext {
    pub fn new(address: Address) -> Self {
        ResponderContext {
            address: address,
            permanent_key: None,
            session_key: None,
            csn_pair: CombinedSequencePair::new(),
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

    fn csn_pair(&self) -> &CombinedSequencePair {
        &self.csn_pair
    }
}
