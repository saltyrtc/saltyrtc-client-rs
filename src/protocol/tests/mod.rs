//! Protocol tests.
use crypto_box::{aead::rand_core::OsRng, generate_nonce};

use crate::{
    crypto::PrivateKey,
    test_helpers::{DummyTask, TestRandom},
};

use super::csn::CombinedSequenceSnapshot;
use super::*;

mod signaling_messages;
mod validate_nonce;

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
        Err(SignalingError::Crash(
            "Overflow when incrementing responder counter".into()
        )),
    );
    assert_eq!(rc.0, ::std::u32::MAX);
}

struct MockSignaling {
    pub common: Common,
    pub peer: Option<Box<dyn PeerContext>>,
    pub initiator_pubkey: PublicKey,
}

impl MockSignaling {
    pub fn new(role: Role, identity: ClientIdentity, signaling_state: SignalingState) -> Self {
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

    fn get_peer(&self) -> Option<&dyn PeerContext> {
        self.peer.as_ref().map(AsRef::as_ref)
    }

    fn get_peer_with_address_mut(&mut self, _addr: Address) -> Option<&mut dyn PeerContext> {
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

    fn handle_peer_message(
        &mut self,
        _obox: OpenBox<Message>,
    ) -> SignalingResult<Vec<HandleAction>> {
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
        let mut pair = initiator
            .csn_pair()
            .write()
            .expect("Could not acquire write lock");
        pair.theirs = Some(CombinedSequenceSnapshot::new(3, 1234));
        pair.ours.combined_sequence_number()
    };
    signaling.set_peer(initiator);

    // Ensure that the sequence numbers returned are correct
    let psns = signaling.current_peer_sequence_numbers();
    assert_eq!(
        psns,
        Some(csn::PeerSequenceNumbers {
            incoming: (3 << 32) | 1234,
            outgoing: our_csn,
        })
    );
}

/// If there's no peer, raw encrypting and decrypting should fail.
#[test]
fn test_encrypt_decrypt_raw_with_session_keys_no_peer() {
    let signaling = InitiatorSignaling::new(
        KeyPair::new(),
        Tasks::new(Box::new(DummyTask::new(42))),
        None,
        None,
        None,
    );
    let nonce = generate_nonce(&mut OsRng);
    assert_eq!(
        signaling.encrypt_raw_with_session_keys(&[1, 2, 3], &nonce),
        Err(SignalingError::NoPeer)
    );
    assert_eq!(
        signaling.decrypt_raw_with_session_keys(&[1, 2, 3], &nonce),
        Err(SignalingError::NoPeer)
    );
}

/// Test encrypting raw bytes.
#[test]
fn test_encrypt_raw_with_session_keys_with_peer() {
    // Generate keypairs and nonce
    let peer_kp = KeyPair::new();
    let our_kp = KeyPair::new();
    let our_private_key_clone = our_kp.private_key().clone();
    let nonce = generate_nonce(&mut OsRng);

    // Create signaling instance
    let mut signaling = MockSignaling::new(
        Role::Responder,
        ClientIdentity::Responder(3),
        SignalingState::Task,
    );
    let mut initiator = InitiatorContext::new(PublicKey::random());
    initiator.session_key = Some(peer_kp.public_key().clone());
    initiator.keypair = our_kp;
    signaling.set_peer(initiator);

    // Encrypt data
    let data = [2, 3, 4, 5];
    let ciphertext = signaling
        .encrypt_raw_with_session_keys(&data, &nonce)
        .unwrap();
    assert_ne!(&data, ciphertext.as_slice());

    // Verify
    let cbox = crypto_box::Box::new(peer_kp.public_key(), &our_private_key_clone);
    assert_eq!(cbox.decrypt(&nonce, &*ciphertext), Ok(vec![2, 3, 4, 5]));
}

/// Test decrypting raw bytes with a known test vector.
///
/// Encrypting an empty byte sequence with nonce "connectionidconnectionid" results in the
/// ciphertext [253, 142, 84, 143, 118, 139, 224, 253, 252, 98, 240, 45, 22, 73, 234, 94].
#[test]
fn test_encrypt_raw_with_session_keys_with_peer_known_result() {
    // Generate keypairs and nonce
    let peer_kp = KeyPair::from_private_key(PrivateKey::from([
        1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4,
        4, 4,
    ]));
    let our_kp = KeyPair::from_private_key(PrivateKey::from([
        4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
        1, 1,
    ]));

    // Create signaling instance
    let mut signaling = MockSignaling::new(
        Role::Responder,
        ClientIdentity::Responder(3),
        SignalingState::Task,
    );
    let mut initiator = InitiatorContext::new(PublicKey::random());
    initiator.session_key = Some(peer_kp.public_key().clone());
    initiator.keypair = our_kp;
    signaling.set_peer(initiator);

    // Encrypt data
    let data = [];
    let nonce = *b"connectionidconnectionid";
    let ciphertext = signaling
        .encrypt_raw_with_session_keys(&data, &nonce.into())
        .unwrap();

    // Verify
    assert_eq!(
        ciphertext,
        [253, 142, 84, 143, 118, 139, 224, 253, 252, 98, 240, 45, 22, 73, 234, 94],
    );
}

/// Test decrypting raw bytes.
#[test]
fn test_decrypt_raw_with_session_keys_with_peer() {
    // Generate keypairs and nonce
    let peer_kp = KeyPair::new();
    let our_kp = KeyPair::new();
    let nonce = generate_nonce(&mut OsRng);

    // Encrypt data
    let data = [1, 2, 3, 4];

    let cbox = crypto_box::Box::new(peer_kp.public_key(), our_kp.private_key());
    let ciphertext = cbox.encrypt(&nonce, &data[..]).unwrap();

    // Create signaling instance
    let mut signaling = MockSignaling::new(
        Role::Responder,
        ClientIdentity::Responder(3),
        SignalingState::Task,
    );
    let mut initiator = InitiatorContext::new(PublicKey::random());
    initiator.session_key = Some(peer_kp.public_key().clone());
    initiator.keypair = our_kp;
    signaling.set_peer(initiator);

    // Decrypt with wrong nonce
    assert_eq!(
        signaling.decrypt_raw_with_session_keys(&ciphertext, &generate_nonce(&mut OsRng)),
        Err(SignalingError::Crypto("Could not decrypt bytes".into()))
    );

    // Decrypt with correct nonce
    assert_eq!(
        signaling.decrypt_raw_with_session_keys(&ciphertext, &nonce),
        Ok(vec![1, 2, 3, 4])
    );
}
