use ::test_helpers::TestRandom;
use self::cookie::{Cookie};
use self::csn::{CombinedSequenceSnapshot};
use self::messages::*;

use super::*;

/// A client MUST check that the destination address targets its assigned
/// identity (or 0x00 during authentication).
#[test]
fn first_message_wrong_destination() {
    let ks = KeyStore::new();
    let mut s = InitiatorSignaling::new(ks, Tasks(vec![]));

    let msg = ServerHello::random().into_message();
    let cs = CombinedSequenceSnapshot::random();
    let nonce = Nonce::new(Cookie::random(), Address(0), Address(1), cs);
    let obox = OpenBox::<Message>::new(msg, nonce);
    let bbox = obox.encode();

    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(
        s.handle_message(bbox),
        Err(SignalingError::InvalidNonce(
            "Bad destination: 0x01 (our identity is Unknown)".into()
        ))
    );
}

/// An initiator SHALL ONLY process messages from the server (0x00). As
/// soon as the initiator has been assigned an identity, it MAY ALSO accept
/// messages from other responders (0x02..0xff). Other messages SHALL be
/// discarded and SHOULD trigger a warning.
#[test]
fn wrong_source_initiator() {
    let ks = KeyStore::new();
    let mut s = InitiatorSignaling::new(ks, Tasks(vec![]));

    let make_msg = |src: u8, dest: u8| {
        let msg = ServerHello::random().into_message();
        let cs = CombinedSequenceSnapshot::random();
        let nonce = Nonce::new(Cookie::random(), Address(src), Address(dest), cs);
        let obox = OpenBox::<Message>::new(msg, nonce);
        let bbox = obox.encode();
        bbox
    };

    // Handling messages from initiator is always invalid (messages are ignored)
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0x01, 0x00)).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(actions, vec![]);

    // Handling messages from responder is invalid as long as identity
    // hasn't been assigned (messages are ignored)
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0xff, 0x00)).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(actions, vec![]);

    // Handling messages from the server is always valid
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0x00, 0x00)).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    // Send only client-auth
    assert_eq!(actions.len(), 1);

    // Handling messages from responder is valid as soon as the identity
    // has been assigned.
    // TODO once state transition has been implemented
//        s.server_mut().handshake_state = ServerHandshakeState::Done;
//        s.identity = ClientIdentity::Initiator;
//        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
//        let actions = s.handle_message(make_msg(0xff, 0x01)).unwrap();
//        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
//        assert_eq!(actions, vec![]);
}

/// A responder SHALL ONLY process messages from the server (0x00). As soon
/// as the responder has been assigned an identity, it MAY ALSO accept
/// messages from the initiator (0x01). Other messages SHALL be discarded
/// and SHOULD trigger a warning.
#[test]
fn wrong_source_responder() {
    let ks = KeyStore::new();
    let initiator_pubkey = PublicKey::from_slice(&[0u8; 32]).unwrap();
    let mut s = ResponderSignaling::new(ks, initiator_pubkey, None, Tasks(vec![]));

    let make_msg = |src: u8, dest: u8| {
        let msg = ServerHello::random().into_message();
        let cs = CombinedSequenceSnapshot::random();
        let nonce = Nonce::new(Cookie::random(), Address(src), Address(dest), cs);
        let obox = OpenBox::<Message>::new(msg, nonce);
        let bbox = obox.encode();
        bbox
    };

    // Handling messages from a responder is always invalid (messages are ignored)
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0x03, 0x00)).expect("handle_message 1");
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(actions, vec![]);

    // Handling messages from initiator is invalid as long as identity
    // hasn't been assigned (messages are ignored)
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0x01, 0x00)).expect("handle_message 2");
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(actions, vec![]);

    // Handling messages from the server is always valid
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    let actions = s.handle_message(make_msg(0x00, 0x00)).expect("handle_message 3");
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    // Send client-hello and client-auth
    assert_eq!(actions.len(), 2);

    // Handling messages from initiator is valid as soon as the identity
    // has been assigned.
    // TODO once state transition has been implemented
//        s.server_mut().handshake_state = ServerHandshakeState::Done;
//        s.identity = ClientIdentity::Initiator;
//        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
//        let actions = s.handle_message(make_msg(0x01, 0x03)).unwrap();
//        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
//        assert_eq!(actions, vec![]);
}

/// In case this is the first message received from the sender, the peer
/// MUST check that the overflow number of the source peer is 0
#[test]
fn first_message_bad_overflow_number() {
    let ks = KeyStore::new();
    let mut s = InitiatorSignaling::new(ks, Tasks(vec![]));

    let msg = ServerHello::random().into_message();
    let cs = CombinedSequenceSnapshot::new(1, 1234);
    let nonce = Nonce::new(Cookie::random(), Address(0), Address(0), cs);
    let obox = OpenBox::<Message>::new(msg, nonce);
    let bbox = obox.encode();

    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(
        s.handle_message(bbox),
        Err(SignalingError::InvalidNonce(
            "First message from server must have set the overflow number to 0".into()
        ))
    );
}

/// The peer MUST check that the combined sequence number of the source
/// peer has been increased by 1 and has not reset to 0.
#[test]
fn sequence_number_incremented() {
    // TODO: Write once ServerAuth message has been implemented
}

/// In case this is the first message received from the sender, the
/// peer MUST check that the sender's cookie is different than its own
/// cookie.
#[test]
fn cookie_differs_from_own() {
    let ks = KeyStore::new();
    let mut s = InitiatorSignaling::new(ks, Tasks(vec![]));

    let msg = ServerHello::random().into_message();
    let cookie = s.server().cookie_pair.ours.clone();
    let nonce = Nonce::new(cookie, Address(0), Address(0), CombinedSequenceSnapshot::random());
    let obox = OpenBox::<Message>::new(msg, nonce);
    let bbox = obox.encode();

    assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
    assert_eq!(
        s.handle_message(bbox),
        Err(SignalingError::InvalidNonce(
            "Cookie from server is identical to our own cookie".into()
        ))
    );
}

/// The peer MUST check that the cookie of the sender does not change.
#[test]
fn cookie_did_not_change() {
    // TODO: Write once ServerAuth message has been implemented
}
