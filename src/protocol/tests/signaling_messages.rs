use ::helpers::TestRandom;
use self::cookie::{Cookie, CookiePair};
use self::csn::{CombinedSequenceSnapshot};
use self::messages::*;
use self::types::{Identity};

use super::*;

struct TestContext<S: Signaling> {
    pub our_ks: KeyStore,
    pub server_ks: KeyStore,
    pub our_cookie: Cookie,
    pub server_cookie: Cookie,
    pub signaling: S,
}

impl TestContext<InitiatorSignaling> {
    fn initiator(
            identity: ClientIdentity,
            signaling_state: SignalingState,
            server_handshake_state: ServerHandshakeState,
    ) -> TestContext<InitiatorSignaling> {
        let our_ks = KeyStore::new().unwrap();
        let server_ks = KeyStore::new().unwrap();
        let our_cookie = Cookie::random();
        let server_cookie = Cookie::random();
        let mut signaling = InitiatorSignaling::new(KeyStore::from_private_key(our_ks.private_key().clone()));
        signaling.common_mut().identity = identity;
        signaling.server_mut().set_handshake_state(server_handshake_state);
        signaling.server_mut().cookie_pair = CookiePair {
            ours: our_cookie.clone(),
            theirs: Some(server_cookie.clone()),
        };
        signaling.server_mut().permanent_key = Some(server_ks.public_key().clone());
        signaling.common_mut().set_signaling_state(signaling_state).expect("Could not set signaling state");
        TestContext {
            our_ks: our_ks,
            server_ks: server_ks,
            our_cookie: our_cookie,
            server_cookie: server_cookie,
            signaling: signaling,
        }
    }
}
impl TestContext<ResponderSignaling> {
    fn responder(
            identity: ClientIdentity,
            signaling_state: SignalingState,
            server_handshake_state: ServerHandshakeState,
            initiator_pubkey: Option<PublicKey>,
            auth_token: Option<AuthToken>,
    ) -> TestContext<ResponderSignaling> {
        let our_ks = KeyStore::new().unwrap();
        let server_ks = KeyStore::new().unwrap();
        let our_cookie = Cookie::random();
        let server_cookie = Cookie::random();
        let mut signaling = {
            let pk = match initiator_pubkey {
                Some(pk) => pk,
                None => PublicKey::from_slice(&[0u8; 32]).unwrap(),
            };
            ResponderSignaling::new(KeyStore::from_private_key(our_ks.private_key().clone()), pk, auth_token)
        };
        signaling.common_mut().identity = identity;
        signaling.server_mut().set_handshake_state(server_handshake_state);
        signaling.server_mut().cookie_pair = CookiePair {
            ours: our_cookie.clone(),
            theirs: Some(server_cookie.clone()),
        };
        signaling.server_mut().permanent_key = Some(server_ks.public_key().clone());
        signaling.common_mut().set_signaling_state(signaling_state).expect("Could not set signaling state");
        TestContext {
            our_ks: our_ks,
            server_ks: server_ks,
            our_cookie: our_cookie,
            server_cookie: server_cookie,
            signaling: signaling,
        }
    }
}

#[derive(Debug)]
struct TestMsgBuilder {
    msg: Message,
    src: Option<Address>,
    dest: Option<Address>,
}

impl TestMsgBuilder {
    pub fn new(msg: Message) -> Self {
        TestMsgBuilder { msg, src: None, dest: None }
    }

    pub fn from(mut self, addr: u8) -> Self {
        self.src = Some(Address(addr));
        self
    }

    pub fn to(mut self, addr: u8) -> Self {
        self.dest = Some(Address(addr));
        self
    }

    pub fn build(self, cookie: Cookie, ks: &KeyStore, pubkey: &PublicKey) -> ByteBox {
        let nonce = Nonce::new(cookie,
                               self.src.expect("Source not set"),
                               self.dest.expect("Destination not set"),
                               CombinedSequenceSnapshot::random());
        let obox = OpenBox::new(self.msg, nonce);
        obox.encrypt(ks, pubkey)
    }

    /// Helper method to make a message coming from the server,
    /// encrypted with our permanent key.
    pub fn build_from_server<S: Signaling>(self, ctx: &TestContext<S>) -> ByteBox {
        self.build(
            ctx.server_cookie.clone(),
            &ctx.server_ks,
            ctx.our_ks.public_key()
        )
    }
}

/// Assert that handling the specified byte box fails in ClientInfoSent
/// state with the specified error.
fn assert_client_info_sent_fail<S: Signaling>(ctx: &mut TestContext<S>, bbox: ByteBox, error: SignalingError) {
    assert_eq!(ctx.signaling.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    assert_eq!(ctx.signaling.handle_message(bbox), Err(error))
}

// When the client receives a 'server-auth' message, it MUST have
// accepted and set its identity as described in the Receiving a
// Signalling Message section.
#[test]
fn server_auth_no_identity() {
    // Initialize signaling class
    let ctx = TestContext::responder(
        ClientIdentity::Unknown,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        None, None
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_responder(ctx.our_cookie.clone(), None, false).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(13).build_from_server(&ctx);

    // Handle message
    let mut s = ctx.signaling;
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    let actions = s.handle_message(bbox).unwrap();
    assert_eq!(s.identity(), ClientIdentity::Responder(13));
    assert_eq!(actions, vec![]);
}

// The peer MUST check that the cookie provided in the your_cookie
// field contains the cookie the client has used in its
// previous and messages to the server.
#[test]
fn server_auth_your_cookie() {
    // Initialize signaling class
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_initiator(Cookie::random(), None, vec![]).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "Cookie sent in server-auth message does not match our cookie".into()));
}

#[test]
fn server_auth_initiator_wrong_fields() {
    // Initialize signaling class
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_responder(ctx.our_cookie.clone(), None, true).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "We're the initiator, but the `initiator_connected` field in the server-auth message is set".into()));
}

#[test]
fn server_auth_initiator_missing_fields() {
    // Initialize signaling class
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth {
        your_cookie: ctx.our_cookie.clone(),
        signed_keys: None,
        responders: None,
        initiator_connected: None,
    }.into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "`responders` field in server-auth message not set".into()));
}

#[test]
fn server_auth_initiator_duplicate_fields() {
    // Initialize signaling class
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_initiator(ctx.our_cookie.clone(), None, vec![Address(2), Address(3), Address(3)]).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "`responders` field in server-auth message may not contain duplicates".into()));
}

#[test]
fn server_auth_initiator_invalid_fields() {
    // Initialize signaling class
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_initiator(ctx.our_cookie.clone(), None, vec![Address(1), Address(2), Address(3)]).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "`responders` field in server-auth message may not contain addresses <0x02".into()));
}

/// The client SHOULD store the responder's identities in its internal
/// list of responders.
#[test]
fn server_auth_initiator_stored_responder() {
    // Initialize signaling class
    let ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth::for_initiator(ctx.our_cookie.clone(), None, vec![Address(2), Address(3)]).into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

    // Handle message
    let mut s = ctx.signaling;
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    assert_eq!(s.responders.len(), 0);
    let actions = s.handle_message(bbox).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
    assert_eq!(s.responders.len(), 2);
    assert_eq!(actions, vec![]);
}

/// The client SHALL check that the initiator_connected field contains
/// a boolean value.
#[test]
fn server_auth_responder_validate_initiator_connected() {
    // Initialize signaling class
    let mut ctx = TestContext::responder(
        ClientIdentity::Responder(4),
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        None, None,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth {
        your_cookie: ctx.our_cookie.clone(),
        signed_keys: None,
        responders: None,
        initiator_connected: None,
    }.into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(4).build_from_server(&ctx);

    // Handle message
    assert_client_info_sent_fail(&mut ctx, bbox,
                                 SignalingError::InvalidMessage(
                                     "We're a responder, but the `initiator_connected` field in the server-auth message is not set".into()));
}

/// In case the client is the responder, it SHALL check that the
/// initiator_connected field contains a boolean value. In case the
/// field's value is true, the responder MUST proceed with sending a
/// `token` or `key` client-to-client message described in the
/// Client-to-Client Messages section.
fn _server_auth_respond(ctx: TestContext<ResponderSignaling>) -> Vec<HandleAction> {
    // Prepare a ServerAuth message
    let msg = ServerAuth {
        your_cookie: ctx.our_cookie.clone(),
        signed_keys: None,
        responders: None,
        initiator_connected: Some(true),
    }.into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(7).build_from_server(&ctx);

    // Signaling ref
    let mut s = ctx.signaling;

    // Handle message
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    assert_eq!(s.initiator.handshake_state(), InitiatorHandshakeState::New);
    let actions = s.handle_message(bbox).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
    assert_eq!(s.initiator.handshake_state(), InitiatorHandshakeState::KeySent);

    actions
}

#[test]
fn server_auth_respond_initiator_with_token() { // TODO: Add similar test without token
    let ctx = TestContext::responder(
        ClientIdentity::Responder(7),
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        None, Some(AuthToken::new()),
    );
    let actions = _server_auth_respond(ctx);
    assert_eq!(actions.len(), 2);
}

#[test]
fn server_auth_respond_initiator_without_token() { // TODO: Add similar test without token
    let ctx = TestContext::responder(
        ClientIdentity::Responder(7),
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        None, None,
    );
    let actions = _server_auth_respond(ctx);
    assert_eq!(actions.len(), 1);
}

/// If processing the server auth message succeeds, the signaling state
/// should change to `PeerHandshake`.
#[test]
fn server_auth_signaling_state_transition() {
    let ctx = TestContext::responder(
        ClientIdentity::Responder(7),
        SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        None, None,
    );

    // Prepare a ServerAuth message
    let msg = ServerAuth {
        your_cookie: ctx.our_cookie.clone(),
        signed_keys: None,
        responders: None,
        initiator_connected: Some(false),
    }.into_message();
    let bbox = TestMsgBuilder::new(msg).from(0).to(7).build_from_server(&ctx);

    // Signaling ref
    let mut s = ctx.signaling;

    // Handle message
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
    assert_eq!(s.common().signaling_state(), SignalingState::ServerHandshake);
    let _actions = s.handle_message(bbox).unwrap();
    assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
    assert_eq!(s.common().signaling_state(), SignalingState::PeerHandshake);
}

/// A receiving initiator MUST check that the message contains a valid NaCl
/// public key (32 bytes) in the key field.
#[test]
fn token_initiator_validate_public_key() {
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::PeerHandshake, ServerHandshakeState::Done,
    );

    // Create new responder context
    let addr = Address(3);
    let responder = ResponderContext::new(addr).unwrap();
    ctx.signaling.responders.insert(addr, responder);

    // Prepare a token message
    let msg_bytes = [
        // Fixmap with two entries
        0x82,
        // Key: type
        0xa4, 0x74, 0x79, 0x70, 0x65,
        // Val: send-error
        0xa5, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
        // Key: key
        0xa3, 0x6b, 0x65, 0x79,
        // Val: 3 bytes
        0xc4, 0x03, 0x00, 0x01, 0x02,
    ];

    // The token message is encrypted with the auth token,
    // so we can't use the `TestMsgBuilder` here.
    let cookie = Cookie::random();
    let nonce = Nonce::new(cookie, Address(3), Address(1),
    CombinedSequenceSnapshot::random());
    let encrypted = ctx.signaling
        .auth_token().expect("Could not get auth token")
        .encrypt(&msg_bytes, unsafe { nonce.clone() });
    let bbox = ByteBox::new(encrypted, nonce);

    // Handle message. This should result in a decoding error
    let err = ctx.signaling.handle_message(bbox).unwrap_err();
    assert_eq!(err, SignalingError::Decode(
        "Cannot decode message payload: Decoding error: Could not decode msgpack data: error while decoding value".into()
    ));
}

/// In case the initiator expects a 'token' message but could not
/// decrypt the message's content, it SHALL send a 'drop-responder'
/// message containing the id of the responder who sent the message and
/// a close code of 3005 (Initiator Could Not Decrypt) in the reason
/// field.
fn token_initiator_cannot_decrypt() {
    // TODO!
}

/// If a token message is valid, set the responder permanent key.
#[test]
fn token_initiator_set_public_key() {
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::PeerHandshake, ServerHandshakeState::Done,
    );

    // Create new responder context
    let addr = Address(3);
    let responder = ResponderContext::new(addr).unwrap();
    ctx.signaling.responders.insert(addr, responder);

    // Generate a public permanent key for the responder
    let pk = PublicKey::random();

    // Prepare a token message
    let msg: Message = Token { key: pk }.into_message();
    let msg_bytes = msg.to_msgpack();

    // The token message is encrypted with the auth token,
    // so we can't use the `TestMsgBuilder` here.
    let cookie = Cookie::random();
    let nonce = Nonce::new(cookie, Address(3), Address(1),
    CombinedSequenceSnapshot::random());
    let encrypted = ctx.signaling
        .auth_token().expect("Could not get auth token")
        .encrypt(&msg_bytes, unsafe { nonce.clone() });
    let bbox = ByteBox::new(encrypted, nonce);

    { // Waiting for NLL
        let responder = ctx.signaling.responders.get(&addr).unwrap();
        assert_eq!(responder.handshake_state(), ResponderHandshakeState::New);
        assert!(responder.permanent_key.is_none());
    }
    // Handle message. This should result in a state transition.
    let actions = ctx.signaling.handle_message(bbox).unwrap();
    {
        let responder = ctx.signaling.responders.get(&addr).unwrap();
        assert_eq!(responder.handshake_state(), ResponderHandshakeState::TokenReceived);
        assert_eq!(responder.permanent_key, Some(pk));
        assert_eq!(actions, vec![]);
    }
}

/// The client MUST generate a session key pair (a new NaCl key pair
/// for public key authenticated encryption) for further communication
/// with the other client. The client's session key pair SHALL NOT be
/// identical to the client's permanent key pair. It MUST set the
/// public key (32 bytes) of that key pair in the key field.
#[test]
fn key_initiator_success() {
    let mut ctx = TestContext::initiator(
        ClientIdentity::Initiator,
        SignalingState::PeerHandshake, ServerHandshakeState::Done,
    );

    // Peer crypto
    let peer_permanent_pk = PublicKey::random();
    let peer_session_pk = PublicKey::random();
    let cookie = Cookie::random();

    // Create new responder context
    let addr = Address(3);
    let mut responder = ResponderContext::new(addr).unwrap();
    responder.set_handshake_state(ResponderHandshakeState::TokenReceived);
    responder.permanent_key = Some(peer_permanent_pk.clone());

    // Prepare a key message
    let msg: Message = Key {
        key: peer_session_pk.clone(),
    }.into_message();

    // Encrypt message
    let bbox = TestMsgBuilder::new(msg).from(3).to(1).build(cookie, &ctx.our_ks, &peer_permanent_pk);

    // Store responder in signaling instance
    ctx.signaling.responders.insert(addr, responder);

    { // Waiting for NLL
        let responder = ctx.signaling.responders.get(&addr).unwrap();
        assert_eq!(responder.handshake_state(), ResponderHandshakeState::TokenReceived);
        assert!(responder.session_key.is_none());
    }
    // Handle message. This should result in a state transition.
    let actions = ctx.signaling.handle_message(bbox).unwrap();
    {
        let responder = ctx.signaling.responders.get(&addr).unwrap();
        assert_eq!(responder.handshake_state(), ResponderHandshakeState::KeyReceived);
        assert_eq!(responder.session_key, Some(peer_session_pk));
        assert_eq!(actions.len(), 1); // Reply with key msg
    }
}

/// The client MUST generate a session key pair (a new NaCl key pair
/// for public key authenticated encryption) for further communication
/// with the other client. The client's session key pair SHALL NOT be
/// identical to the client's permanent key pair. It MUST set the
/// public key (32 bytes) of that key pair in the key field.
//#[test]
fn key_responder_success() {
    // Peer crypto
    let peer_permanent_pk = PublicKey::random();
    let peer_session_pk = PublicKey::random();
    let cookie = Cookie::random();

    // Context
    let mut ctx = TestContext::responder(
        ClientIdentity::Responder(6),
        SignalingState::PeerHandshake, ServerHandshakeState::Done,
        Some(peer_permanent_pk), None,
    );
    assert_eq!(ctx.signaling.initiator.permanent_key, peer_permanent_pk);
    ctx.signaling.initiator.set_handshake_state(InitiatorHandshakeState::KeySent);

    // Prepare a key message
    let msg: Message = Key {
        key: peer_session_pk.clone(),
    }.into_message();

    // Encrypt message
    let bbox = TestMsgBuilder::new(msg).from(1).to(6).build(cookie, &ctx.our_ks, &peer_permanent_pk);

    assert_eq!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::KeySent);
    assert_eq!(ctx.signaling.initiator.session_key, None);
    let actions = ctx.signaling.handle_message(bbox).unwrap();
    assert_eq!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::KeyReceived);
    assert_eq!(ctx.signaling.initiator.session_key, Some(peer_session_pk));
    assert_eq!(actions.len(), 1); // Reply with auth msg

    // TODO
}
