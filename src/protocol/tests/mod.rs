//! Protocol tests.

use ::test_helpers::{DummyTask, TestRandom};
use super::*;
use super::csn::CombinedSequenceSnapshot;

mod validate_nonce;
mod signaling_messages;

#[test]
fn test_responder_counter() {
    let mut rc = ResponderCounter::new();
    assert_eq!(rc.0, 0);
    assert_eq!(rc.increment(), Ok(0));
    assert_eq!(rc.0, 1);
}

#[test]
fn test_responder_counter_overflow() {
    let mut rc = ResponderCounter(::std::u32::MAX);
    assert_eq!(rc.0, ::std::u32::MAX);
    assert_eq!(
        rc.increment(),
        Err(SignalingError::Crash("Overflow when incrementing responder counter".into())),
    );
    assert_eq!(rc.0, ::std::u32::MAX);
}


struct MockSignaling {
    pub common: Common,
    pub peer: Option<Box<PeerContext>>,
    pub initiator_pubkey: PublicKey,
}

impl MockSignaling {
    pub fn new(
        role: Role,
        identity: ClientIdentity,
        signaling_state: SignalingState,
    ) -> Self {
        Self {
            common: Common {
                signaling_state,
                permanent_keypair: KeyPair::new(),
                auth_provider: None,
                role,
                identity,
                server: ServerContext::new(),
                tasks: None,
                task: None,
                task_supported_types: None,
                ping_interval: None,
            },
            peer: None,
            initiator_pubkey: PublicKey::random(),
        }
    }

    pub fn set_peer<P: PeerContext + 'static>(&mut self, peer: P) {
        self.peer = Some(Box::new(peer));
    }
}

impl Signaling for MockSignaling {
    fn common(&self) -> &Common {
        &self.common
    }

    fn common_mut(&mut self) -> &mut Common {
        &mut self.common
    }

    fn get_peer(&self) -> Option<&PeerContext> {
        self.peer.as_ref().map(AsRef::as_ref)
    }

    fn get_peer_with_address_mut(&mut self, _addr: Address) -> Option<&mut PeerContext> {
        None
    }

    fn initiator_pubkey(&self) -> &PublicKey {
        &self.initiator_pubkey
    }

    fn validate_nonce_destination(&mut self, _nonce: &Nonce) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_nonce_source(&mut self, _nonce: &Nonce) -> Result<(), ValidationError> {
        Ok(())
    }

    fn decode_peer_message(&self, _bbox: ByteBox) -> SignalingResult<OpenBox<Message>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }

    fn handle_peer_message(&mut self, _obox: OpenBox<Message>) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }

    fn handle_server_auth_impl(&mut self, _msg: &ServerAuth) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }

    fn handle_new_initiator(&mut self, _msg: NewInitiator) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }

    fn handle_new_responder(&mut self, _msg: NewResponder) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }

    fn handle_disconnected(&mut self, _msg: Disconnected) -> SignalingResult<Vec<HandleAction>> {
        Err(SignalingError::Crash("Not implemented in mock".into()))
    }
}

/// If there's no peer, there should be no current peer sequence number.
#[test]
fn test_peer_sequence_number_no_peer() {
    let signaling = InitiatorSignaling::new(
        KeyPair::new(),
        Tasks::new(Box::new(DummyTask::new(42))),
        None,
        None,
        None,
    );
    assert_eq!(signaling.current_peer_sequence_numbers(), None);
}

#[test]
fn test_peer_sequence_number_with_peer() {
    // Create a mock signaling instance as responder
    let mut signaling = MockSignaling::new(
        Role::Responder,
        ClientIdentity::Responder(3),
        SignalingState::Task,
    );

    // Create initiator state
    let initiator = InitiatorContext::new(PublicKey::random());
    let our_csn = {
        let mut pair = initiator.csn_pair().write().expect("Could not acquire write lock");
        pair.theirs = Some(CombinedSequenceSnapshot::new(3, 1234));
        pair.ours.combined_sequence_number()
    };
    signaling.set_peer(initiator);

    // Ensure that the sequence numbers returned are correct
    let psns = signaling.current_peer_sequence_numbers();
    assert_eq!(psns, Some(csn::PeerSequenceNumbers {
        incoming: (3 << 32) | 1234,
        outgoing: our_csn,
    }));
}
