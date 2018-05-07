use ::test_helpers::{DummyTask, TestRandom};
use self::cookie::{Cookie, CookiePair};
use self::csn::{CombinedSequenceSnapshot};
use self::messages::*;

use super::*;

struct TestContext<S: Signaling> {
    /// Our permanent keypair.
    pub our_ks: KeyPair,
    /// The server session keypair.
    pub server_ks: KeyPair,
    /// Our cookie towards the server.
    pub our_cookie: Cookie,
    /// The server cookie.
    pub server_cookie: Cookie,
    /// The signaling instance.
    pub signaling: S,
}

impl TestContext<InitiatorSignaling> {
    fn initiator(
            identity: ClientIdentity,
            peer_trusted_pubkey: Option<PublicKey>,
            signaling_state: SignalingState,
            server_handshake_state: ServerHandshakeState,
    ) -> TestContext<InitiatorSignaling> {
        let our_ks = KeyPair::new();
        let server_ks = KeyPair::new();
        let our_cookie = Cookie::random();
        let server_cookie = Cookie::random();
        let ks = KeyPair::from_private_key(our_ks.private_key().clone());
        let tasks = Tasks::new(Box::new(DummyTask::new(42)));
        let mut signaling = InitiatorSignaling::new(ks, tasks, peer_trusted_pubkey, None, None);
        signaling.common_mut().identity = identity;
        signaling.server_mut().set_handshake_state(server_handshake_state);
        signaling.server_mut().cookie_pair = CookiePair {
            ours: our_cookie.clone(),
            theirs: Some(server_cookie.clone()),
        };
        signaling.server_mut().session_key = Some(server_ks.public_key().clone());
        signaling.common_mut().set_signaling_state_forced(signaling_state)
            .expect("Could not set test signaling state");
        TestContext {
            our_ks,
            server_ks,
            our_cookie,
            server_cookie,
            signaling,
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
        let our_ks = KeyPair::new();
        let server_ks = KeyPair::new();
        let our_cookie = Cookie::random();
        let server_cookie = Cookie::random();
        let mut signaling = {
            let pk = match initiator_pubkey {
                Some(pk) => pk,
                None => PublicKey::from_slice(&[0u8; 32]).unwrap(),
            };
            let ks = KeyPair::from_private_key(our_ks.private_key().clone());
            let mut tasks = Tasks::new(Box::new(DummyTask::new(23)));
            tasks.add_task(Box::new(DummyTask::new(42))).unwrap();
            ResponderSignaling::new(ks, pk, auth_token, None, tasks, None)
        };
        signaling.common_mut().identity = identity;
        signaling.server_mut().set_handshake_state(server_handshake_state);
        signaling.server_mut().cookie_pair = CookiePair {
            ours: our_cookie.clone(),
            theirs: Some(server_cookie.clone()),
        };
        signaling.server_mut().session_key = Some(server_ks.public_key().clone());
        signaling.common_mut().set_signaling_state_forced(signaling_state)
            .expect("Could not set test signaling state");
        TestContext {
            our_ks,
            server_ks,
            our_cookie,
            server_cookie,
            signaling,
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

    pub fn build(self, cookie: Cookie, ks: &KeyPair, pubkey: &PublicKey) -> ByteBox {
        let nonce = Nonce::new(cookie,
                               self.src.expect("Source not set"),
                               self.dest.expect("Destination not set"),
                               CombinedSequenceSnapshot::random());
        let obox = OpenBox::<Message>::new(self.msg, nonce);
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

mod server_auth {
    use super::*;

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
    fn no_identity() {
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
        let _actions = s.handle_message(bbox).unwrap();
        assert_eq!(s.identity(), ClientIdentity::Responder(13));
    }

    // The peer MUST check that the cookie provided in the your_cookie
    // field contains the cookie the client has used in its
    // previous and messages to the server.
    #[test]
    fn your_cookie() {
        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent
        );

        // Prepare a ServerAuth message
        let msg = ServerAuth::for_initiator(Cookie::random(), None, vec![]).into_message();
        let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

        // Handle message
        assert_client_info_sent_fail(&mut ctx, bbox,
                                     SignalingError::Protocol(
                                         "Repeated cookie in auth message from server does not match our cookie".into()));
    }

    #[test]
    fn initiator_wrong_fields() {
        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
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
    fn initiator_missing_fields() {
        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
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
    fn initiator_duplicate_fields() {
        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
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
    fn initiator_invalid_fields() {
        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
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
    fn initiator_stored_responder() {
        // Initialize signaling class
        let ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        );

        // Prepare a ServerAuth message
        let msg = ServerAuth::for_initiator(ctx.our_cookie.clone(), None, vec![Address(2), Address(3)]).into_message();
        let bbox = TestMsgBuilder::new(msg).from(0).to(1).build_from_server(&ctx);

        // Handle message
        let mut s = ctx.signaling;
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
        assert_eq!(s.responders.len(), 0);
        let _actions = s.handle_message(bbox).unwrap();
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
        assert_eq!(s.responders.len(), 2);
    }

    /// The client SHALL check that the initiator_connected field contains
    /// a boolean value.
    #[test]
    fn responder_validate_initiator_connected() {
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
    fn respond_initiator_with_token() {
        let ctx = TestContext::responder(
            ClientIdentity::Responder(7),
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
            None, Some(AuthToken::new()),
        );
        let actions = _server_auth_respond(ctx);
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[2], HandleAction::Event(Event::ServerHandshakeDone(true)));
    }

    #[test]
    fn respond_initiator_without_token() {
        let ctx = TestContext::responder(
            ClientIdentity::Responder(7),
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
            None, None,
        );
        let actions = _server_auth_respond(ctx);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[1], HandleAction::Event(Event::ServerHandshakeDone(true)));
    }

    /// If processing the server auth message succeeds, the signaling state
    /// should change to `PeerHandshake`.
    #[test]
    fn signaling_state_transition() {
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
        let actions = s.handle_message(bbox).unwrap();
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::Done);
        assert_eq!(s.common().signaling_state(), SignalingState::PeerHandshake);
        assert_eq!(actions, vec![
            HandleAction::Event(Event::ServerHandshakeDone(false)),
        ]);
    }

    #[test]
    fn server_public_permanent_key_validate() {
        // Create server public permanent key
        let server_permanent_ks1 = KeyPair::new();
        let server_permanent_ks2 = KeyPair::new();

        // Initialize signaling class
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        );
        ctx.signaling.server_mut().permanent_key = Some(server_permanent_ks1.public_key().clone());

        // Create nonce for ServerAuth message
        let nonce = Nonce::new(ctx.server_cookie.clone(), Address(0), Address(1), CombinedSequenceSnapshot::random());

        // Prepare signed keys
        let unsigned_keys = UnsignedKeys::new(
            ctx.signaling.server().session_key().unwrap().clone(),
            ctx.our_ks.public_key().clone(),
        );
        let signed_keys = unsigned_keys.sign(&server_permanent_ks1, ctx.our_ks.public_key(), unsafe { nonce.clone() });

        // Prepare a ServerAuth message.
        let msg = ServerAuth::for_initiator(ctx.our_cookie.clone(), Some(signed_keys), vec![]).into_message();
        let msg_bytes = msg.to_msgpack();
        let encrypted = ctx.our_ks.encrypt(&msg_bytes, unsafe { nonce.clone() }, ctx.server_ks.public_key());
        let bbox = ByteBox::new(encrypted, nonce);

        // Change server permanent key (to provoke a validation error)
        ctx.signaling.server_mut().permanent_key = Some(server_permanent_ks2.public_key().clone());

        // Handle message
        let mut s = ctx.signaling;
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
        assert_eq!(
            s.handle_message(bbox),
            Err(SignalingError::Crypto("Could not decrypt signed keys".into()))
        );
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);

        // TODO: Add two additional tests:
        // - Successful validation
        // - Correct encryption but bad keys inside
    }
}

mod client_auth {
    use super::*;

    fn _test_ping_interval(interval: Option<Duration>) -> ClientAuth {
        let kp = KeyPair::new();
        let mut s = InitiatorSignaling::new(
            kp,
            Tasks::new(Box::new(DummyTask::new(123))),
            None,
            None,
            interval,
        );

        // Create and encode ServerHello message
        let server_pubkey = PublicKey::random();
        let server_hello = ServerHello::new(server_pubkey.clone()).into_message();
        let cs = CombinedSequenceSnapshot::random();
        let nonce = Nonce::new(Cookie::random(), Address(0), Address(0), cs);
        let obox = OpenBox::<Message>::new(server_hello, nonce);
        let bbox = obox.encode();

        // Handle message
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::New);
        let mut actions = s.handle_message(bbox).unwrap();
        assert_eq!(s.server().handshake_state(), ServerHandshakeState::ClientInfoSent);
        assert_eq!(actions.len(), 1); // Reply with client-auth

        // Action contains ClientAuth message, encrypted with our permanent key
        // and the server session key. Decrypt it to take a look at its contents.
        let action = actions.remove(0);
        let bytes: ByteBox = match action {
            HandleAction::Reply(bbox) => bbox,
            HandleAction::HandshakeDone => panic!("Unexpected HandshakeDone"),
            HandleAction::TaskMessage(_) => panic!("Unexpected TaskMessage"),
            HandleAction::Event(_) => panic!("Unexpected Event"),
        };

        let decrypted = OpenBox::<Message>::decrypt(
            bytes, &s.common().permanent_keypair, &server_pubkey
        ).unwrap();
        match decrypted.message {
            Message::ClientAuth(client_auth) => client_auth,
            other => panic!("Expected ClientAuth, got {:?}", other)
        }
    }

    /// If ping interval is None, send zero.
    #[test]
    fn ping_interval_none() {
        let client_auth = _test_ping_interval(None);
        assert_eq!(client_auth.ping_interval, 0);
    }

    /// If ping interval is 0s, send zero.
    #[test]
    fn ping_interval_zero() {
        let client_auth = _test_ping_interval(Some(Duration::from_secs(0)));
        assert_eq!(client_auth.ping_interval, 0);
    }

    /// If ping interval is a larger number, send that (as seconds).
    #[test]
    fn ping_interval_12345() {
        let client_auth = _test_ping_interval(Some(Duration::from_secs(12345)));
        assert_eq!(client_auth.ping_interval, 12345);
    }

    /// Ignore sub-second values.
    #[test]
    fn ping_interval_nanos() {
        let client_auth = _test_ping_interval(Some(Duration::new(123, 45)));
        assert_eq!(client_auth.ping_interval, 123);
    }
}

mod token {
    use super::*;

    /// A receiving initiator MUST check that the message contains a valid NaCl
    /// public key (32 bytes) in the key field.
    #[test]
    fn token_initiator_validate_public_key() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Create new responder context
        let addr = Address(3);
        let responder = ResponderContext::new(addr);
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
    #[test]
    fn token_initiator_cannot_decrypt() {
        // TODO (#19)!
    }

    /// If a token message is valid, set the responder permanent key.
    #[test]
    fn token_initiator_set_public_key() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Create new responder context
        let addr = Address(3);
        let responder = ResponderContext::new(addr);
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
}

mod key {
    use super::*;

    /// The client MUST generate a session key pair (a new NaCl key pair
/// for public key authenticated encryption) for further communication
/// with the other client. The client's session key pair SHALL NOT be
/// identical to the client's permanent key pair. It MUST set the
/// public key (32 bytes) of that key pair in the key field.
    #[test]
    fn key_initiator_success() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Peer crypto
        let peer_permanent_pk = PublicKey::random();
        let peer_session_pk = PublicKey::random();
        let cookie = Cookie::random();

        // Create new responder context
        let addr = Address(3);
        let mut responder = ResponderContext::new(addr);
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
            assert_eq!(responder.handshake_state(), ResponderHandshakeState::KeySent);
            assert_eq!(responder.session_key, Some(peer_session_pk));
            assert_eq!(actions.len(), 1); // Reply with key msg
        }
    }

    /// The client MUST generate a session key pair (a new NaCl key pair
    /// for public key authenticated encryption) for further communication
    /// with the other client. The client's session key pair SHALL NOT be
    /// identical to the client's permanent key pair. It MUST set the
    /// public key (32 bytes) of that key pair in the key field.
    #[test]
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
        assert_eq!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::AuthSent);
        assert_eq!(ctx.signaling.initiator.session_key, Some(peer_session_pk));
        assert_eq!(actions.len(), 1); // Reply with auth msg
    }
}

mod auth {
    use super::*;

    /// Prepare context and responder for auth message validation tests.
    fn _auth_msg_prepare_initiator() -> (TestContext<InitiatorSignaling>, ResponderContext) {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Create new main responder context
        let peer_session_pk = PublicKey::random();
        let mut responder = ResponderContext::new(Address(3));
        responder.set_handshake_state(ResponderHandshakeState::KeySent);
        responder.session_key = Some(peer_session_pk.clone());

        fn make_responder(addr: u8, state: ResponderHandshakeState) -> ResponderContext {
            let mut r = ResponderContext::new(Address(addr));
            r.set_handshake_state(state);
            r.session_key = Some(PublicKey::random());
            r
        }

        // Add some additional responders
        ctx.signaling.responders.insert(Address(4), make_responder(4, ResponderHandshakeState::New));
        ctx.signaling.responders.insert(Address(7), make_responder(7, ResponderHandshakeState::KeySent));

        (ctx, responder)
    }

    /// Prepare context and initiator for auth message validation tests.
    fn _auth_msg_prepare_responder() -> TestContext<ResponderSignaling> {
        let mut ctx = TestContext::responder(
            ClientIdentity::Responder(3),
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
            Some(PublicKey::random()),
            Some(AuthToken::new()),
        );

        // Create new initiator context
        ctx.signaling.initiator.set_handshake_state(InitiatorHandshakeState::AuthSent);
        ctx.signaling.initiator.session_key = Some(PublicKey::random());

        ctx
    }

    /// Handle a message for auth message validation tests.
    fn _auth_msg_handle_initiator(msg: Message,
                                  ctx: &mut TestContext<InitiatorSignaling>,
                                  responder: ResponderContext)
                                  -> SignalingResult<Vec<HandleAction>> {
        // Encrypt message
        let bbox = TestMsgBuilder::new(msg).from(3).to(1)
            .build(Cookie::random(), &responder.keypair, responder.session_key.as_ref().unwrap());

        // Store responder in signaling instance
        ctx.signaling.responders.insert(responder.address, responder);

        // Handle message
        ctx.signaling.handle_message(bbox)
    }

    /// Handle a message for auth message validation tests.
    fn _auth_msg_handle_responder(msg: Message,
                                  ctx: &mut TestContext<ResponderSignaling>)
                                  -> SignalingResult<Vec<HandleAction>> {
        // Encrypt message
        let bbox = TestMsgBuilder::new(msg).from(1).to(3)
            .build(Cookie::random(),
                   &ctx.signaling.initiator.keypair,
                   ctx.signaling.initiator.session_key.as_ref().unwrap());

        // Handle message
        ctx.signaling.handle_message(bbox)
    }

    /// The cookie provided in the your_cookie field SHALL contain the cookie it has used in its previous messages to the other client.
    #[test]
    fn initiator_validate_repeated_cookie() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = ResponderAuthBuilder::new(Cookie::random()) // Note: Not our cookie
            .add_task("dummy", None)
            .build()
            .unwrap()
            .into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("Repeated cookie in auth message from responder 0x03 does not match our cookie".into()));
    }

    /// The cookie provided in the your_cookie field SHALL contain the cookie it has used in its previous messages to the other client.
    #[test]
    fn responder_validate_repeated_cookie() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = ResponderAuthBuilder::new(Cookie::random()) // Note: Not our cookie
            .add_task("dummy", None)
            .build()
            .unwrap()
            .into_message();

        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("Repeated cookie in auth message from initiator does not match our cookie".into()));
    }

    /// An initiator SHALL validate that the tasks field contains an array with at least one element.
    #[test]
    fn initiator_task_field() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: Some("foo".into()),
            tasks: None,
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage("We're an initiator, but the `task` field in the auth message is set".into()));
    }

    /// An initiator SHALL validate that the tasks field contains an array with at least one element.
    #[test]
    fn initiator_tasks_field_missing() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: None,
            tasks: None,
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage("The `tasks` field in the auth message is not set".into()));
    }

    /// An initiator SHALL validate that the tasks field contains an array with at least one element.
    #[test]
    fn initiator_tasks_field_empty() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: None,
            tasks: Some(vec![]),
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage("The `tasks` field in the auth message is empty".into()));
    }


    /// A responder SHALL validate that the tasks field contains an array with at least one element.
    #[test]
    fn responder_tasks_field() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: None,
            tasks: Some(vec!["asjk".into()]),
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage("We're a responder, but the `tasks` field in the auth message is set".into()));
    }

    /// Make sure that the `task` field is a known task.
    #[test]
    fn responder_task_field_missing() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: None,
            tasks: None,
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage("The `task` field in the auth message is not set".into()));
    }

    /// Make sure that the `task` field is a known task.
    #[test]
    fn responder_task_field_unknown() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: Some("unknown".into()),
            tasks: None,
            data: HashMap::new(),
        }.into_message();

        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("The `task` field in the auth message contains an unknown task".into()));
    }

    /// Validate that the number of data items matches the number of tasks
    #[test]
    fn initiator_data_field_length_mismatch() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: None,
            tasks: Some(vec!["a".into(), "b".into()]),
            data: { let mut m = HashMap::new(); m.insert("a".into(), None); m },
        }.into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage(
            "The `tasks` and `data` fields in the auth message have a different number of entries".into()));
    }

    /// Validate that there is exactly one data entry
    #[test]
    fn responder_data_field_empty() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: Some("dummy.42".into()),
            tasks: None,
            data: HashMap::new(),
        }.into_message();
        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("The `data` field in the auth message is empty".into()));
    }

    /// Validate that there is exactly one data entry
    #[test]
    fn responder_data_field_multiple() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: Some("dummy.42".into()),
            tasks: None,
            data: { let mut m = HashMap::new(); m.insert("a".into(), None); m.insert("b".into(), None); m },
        }.into_message();
        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("The `data` field in the auth message contains more than one entry".into()));
    }

    /// Validate that all tasks have corresponding data entries.
    #[test]
    fn initiator_data_field_key_mismatch() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: None,
            tasks: Some(vec!["a".into(), "b".into()]),
            data: { let mut m = HashMap::new(); m.insert("a".into(), None); m.insert("c".into(), None); m },
        }.into_message();

        let err = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap_err();
        assert_eq!(err, SignalingError::InvalidMessage(
            "The task \"b\" in the auth message does not have a corresponding data entry".into()));
    }

    /// Validate that the task has a corresponding data entry.
    #[test]
    fn responder_data_key_not_found() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: Some(DummyTask::name_for(42)),
            tasks: None,
            data: { let mut m = HashMap::new(); m.insert("a".into(), None); m },
        }.into_message();
        let err = _auth_msg_handle_responder(msg, &mut ctx).unwrap_err();
        assert_eq!(err, SignalingError::Protocol("The task in the auth message does not have a corresponding data entry".into()));
    }

    #[test]
    fn initiator_choose_task() {
        let (mut ctx, responder) = _auth_msg_prepare_initiator();

        let msg: Message = Auth {
            your_cookie: responder.cookie_pair.ours.clone(),
            task: None,
            tasks: Some(vec!["a".into(), DummyTask::name_for(42)]),
            data: {
                let mut m = HashMap::new();
                m.insert("a".into(), None);
                m.insert(DummyTask::name_for(42), None);
                m
            },
        }.into_message();

        // No task set so far
        assert!(ctx.signaling.common().task.is_none());

        // List of valid tasks contains 1 entry
        assert_eq!(ctx.signaling.common().tasks.as_ref().unwrap().len(), 1);

        // Signaling state is peer handshake
        assert_eq!(ctx.signaling.common().signaling_state(), SignalingState::PeerHandshake);

        let actions = _auth_msg_handle_initiator(msg, &mut ctx, responder).unwrap();

        // Task was set!
        assert!(ctx.signaling.common().task.is_some());
        assert_eq!(ctx.signaling.common().task.as_ref().unwrap().lock().unwrap().name(), DummyTask::name_for(42));

        // Tasks list was removed
        assert!(ctx.signaling.common().tasks.is_none());

        // Responders are being dropped
        assert_eq!(ctx.signaling.responders.len(), 0);

        // Peer was set
        assert!(ctx.signaling.get_peer().is_some());
        assert_eq!(ctx.signaling.get_peer().as_ref().unwrap().identity(), ctx.signaling.responder.as_ref().unwrap().identity());

        // Number of reply messages
        assert_eq!(actions.len(), 4); // auth + drop-responder(5) + drop-responder(7) + HandshakeDone

        // State transitions
        assert_eq!(ctx.signaling.common().signaling_state(), SignalingState::Task);
        assert_eq!(ctx.signaling.responder.unwrap().handshake_state(), ResponderHandshakeState::AuthSent);
    }

    #[test]
    fn responder_choose_task() {
        let mut ctx = _auth_msg_prepare_responder();

        let msg: Message = Auth {
            your_cookie: ctx.signaling.initiator.cookie_pair.ours.clone(),
            task: Some(DummyTask::name_for(42)),
            tasks: None,
            data: {
                let mut m = HashMap::new();
                m.insert(DummyTask::name_for(42), None);
                m
            },
        }.into_message();

        // No task set so far
        assert!(ctx.signaling.common().task.is_none());

        // List of valid tasks contains 2 entries
        assert_eq!(ctx.signaling.common().tasks.as_ref().unwrap().len(), 2);

        // Signaling state is peer handshake
        assert_eq!(ctx.signaling.common().signaling_state(), SignalingState::PeerHandshake);

        let actions = _auth_msg_handle_responder(msg, &mut ctx).unwrap();

        // Task was set!
        assert!(ctx.signaling.common().task.is_some());
        assert_eq!(ctx.signaling.common().task.as_ref().unwrap().lock().unwrap().name(), DummyTask::name_for(42));

        // Tasks list was removed
        assert!(ctx.signaling.common().tasks.is_none());

        // Peer was set
        assert!(ctx.signaling.get_peer().is_some());
        assert_eq!(ctx.signaling.get_peer().as_ref().unwrap().identity(), ctx.signaling.initiator.identity());

        // Number of actionsmessages
        assert_eq!(actions, vec![HandleAction::HandshakeDone]);

        // State transitions
        assert_eq!(ctx.signaling.common().signaling_state(), SignalingState::Task);
        assert_eq!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::AuthReceived);
    }

    /// Ensure that duplicate names are not allowed when constructing a responder `Auth` message.
    #[test]
    fn responder_auth_tasks_no_duplicates_simple() {
        let simple = ResponderAuthBuilder::new(Cookie::random())
            .add_task("dummy1", None)
            .add_task("dummy1", None)
            .build();
        assert_eq!(
            simple,
            Err(SignalingError::InvalidMessage("An `Auth` message may not contain duplicate tasks".into())),
        );

        let nonconsecutive = ResponderAuthBuilder::new(Cookie::random())
            .add_task("dummy1", None)
            .add_task("dummy2", None)
            .add_task("dummy1", None)
            .build();
        assert_eq!(
            nonconsecutive,
            Err(SignalingError::InvalidMessage("An `Auth` message may not contain duplicate tasks".into())),
        );

        let different_data = ResponderAuthBuilder::new(Cookie::random())
            .add_task("dummy1", None)
            .add_task("dummy1", Some({
                let mut data = HashMap::new(); data.insert("a".into(), 1.into()); data
            }))
            .build();
        assert_eq!(
            different_data,
            Err(SignalingError::InvalidMessage("An `Auth` message may not contain duplicate tasks".into())),
        );
    }
}

mod new_initiator {
    use super::*;

    /// An initiator should reject `NewInitiator` messages.
    #[test]
    fn handle_as_initiator() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Encrypt message
        let msg = Message::NewInitiator(NewInitiator);
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let err = ctx.signaling.handle_message(bbox).unwrap_err();
        let msg = "Received \'new-responder\' message as initiator".into();
        assert_eq!(err, SignalingError::Protocol(msg))
    }

    /// A responder should properly handle `NewInitiator` messages.
    #[test]
    fn handle_as_responder() {
        let mut ctx = TestContext::responder(
            ClientIdentity::Responder(7),
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
            None,
            None,
        );

        // Encrypt message
        let msg = Message::NewInitiator(NewInitiator);
        let bbox = TestMsgBuilder::new(msg).from(0).to(7)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Old initiator context
        let old_cookie_pair = ctx.signaling.initiator.cookie_pair().clone();
        assert!(ctx.signaling.initiator.csn_pair.borrow().theirs.is_none());
        ctx.signaling.initiator.csn_pair.borrow_mut().theirs = Some(CombinedSequenceSnapshot::new(0, 0));
        ctx.signaling.initiator.set_handshake_state(InitiatorHandshakeState::AuthSent);

        // Handle message
        let actions = ctx.signaling.handle_message(bbox).unwrap();

        // A responder who receives a 'new-initiator' message MUST proceed by deleting
        // all currently cached information about and for the previous initiator
        // (such as cookies and the sequence numbers)...
        let new_cookie_pair = ctx.signaling.initiator.cookie_pair().clone();
        assert_ne!(old_cookie_pair, new_cookie_pair);
        assert!(ctx.signaling.initiator.csn_pair.borrow().theirs.is_none());
        assert_ne!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::AuthSent);

        // ...and continue by sending a 'token' or 'key' client-to-client message
        // described in the Client-to-Client Messages section.
        assert_eq!(actions.len(), 1);
        assert_eq!(ctx.signaling.initiator.handshake_state(), InitiatorHandshakeState::KeySent);
    }
}

mod new_responder {
    use super::*;

    /// When a trusted key is available, the client should not expect a token
    /// message.
    #[test]
    fn expect_no_token() {
        let peer_trusted_pk = PublicKey::random();
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, Some(peer_trusted_pk.clone()),
            SignalingState::PeerHandshake, ServerHandshakeState::Done
        );

        // Encrypt new-responder message
        let address = Address::from(7);
        let msg = Message::NewResponder(NewResponder { id: address.clone() });
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let _actions = ctx.signaling.handle_message(bbox).unwrap();
        assert!(ctx.signaling.responder.is_none());

        // Encrypt token message
        let bbox = {
            let responder_cookie = Cookie::random();
            let responder: &mut ResponderContext = ctx.signaling.responders.get_mut(&address).unwrap();
            responder.cookie_pair_mut().theirs = Some(responder_cookie.clone());
            let msg = Message::Token(Token { key: peer_trusted_pk });
            TestMsgBuilder::new(msg).from(7).to(1)
                .build(responder_cookie,
                       &responder.keypair().expect("No responder keypair"),
                       ctx.our_ks.public_key())
        }; // Waiting for NLL

        // Handle message
        let actions = ctx.signaling.handle_message(bbox).unwrap();
        assert_eq!(actions.len(), 1); // Drop responder
    }

}

mod disconnected {
    use super::*;

    /// During server auth, 'disconnected' messages are invalid.
    #[test]
    fn disconnected_during_server_auth() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::ServerHandshake, ServerHandshakeState::ClientInfoSent,
        );

        // Encrypt message
        let msg = Message::Disconnected(Disconnected::new(ClientIdentity::Responder(3).into()));
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let err = ctx.signaling.handle_message(bbox).unwrap_err();
        let msg = "Got \'disconnected\' message from server in ClientInfoSent state".into();
        assert_eq!(err, SignalingError::InvalidStateTransition(msg))
    }

    /// An initiator who receives a 'disconnected' message SHALL validate
    /// that the id field contains a valid responder address (0x02..0xff).
    #[test]
    fn disconnected_initiator_invalid_id() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Encrypt message
        let msg = Message::Disconnected(Disconnected::new(ClientIdentity::Initiator.into()));
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let err = ctx.signaling.handle_message(bbox).unwrap_err();
        let msg = "Received \'disconnected\' message with non-responder id".into();
        assert_eq!(err, SignalingError::Protocol(msg))
    }

    /// A responder who receives a 'disconnected' message SHALL validate
    /// that the id field contains a valid initiator address (0x01).
    #[test]
    fn disconnected_responder_invalid_id() {
        let mut ctx = TestContext::responder(
            ClientIdentity::Responder(3),
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
            None, None,
        );

        // Encrypt message
        let msg = Message::Disconnected(Disconnected::new(ClientIdentity::Responder(7).into()));
        let bbox = TestMsgBuilder::new(msg).from(0).to(3)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let err = ctx.signaling.handle_message(bbox).unwrap_err();
        let msg = "Received \'disconnected\' message with non-initiator id".into();
        assert_eq!(err, SignalingError::Protocol(msg))
    }

    /// A receiving client MUST notify the user application about the incoming
    /// 'disconnected' message, along with the id field.
    #[test]
    fn disconnected_notify_user() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::PeerHandshake, ServerHandshakeState::Done,
        );

        // Encrypt message
        let msg = Message::Disconnected(Disconnected::new(ClientIdentity::Responder(7).into()));
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let actions = ctx.signaling.handle_message(bbox).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], HandleAction::Event(Event::Disconnected(7)));
    }

    /// A disconnected message should be processed by the initiator, even in
    /// task signaling state. (Regression test)
    #[test]
    fn disconnected_in_task_signaling_state() {
        let mut ctx = TestContext::initiator(
            ClientIdentity::Initiator, None,
            SignalingState::Task, ServerHandshakeState::Done,
        );

        // Encrypt message
        let msg = Message::Disconnected(Disconnected::new(ClientIdentity::Responder(7).into()));
        let bbox = TestMsgBuilder::new(msg).from(0).to(1)
            .build(ctx.server_cookie.clone(),
                   &ctx.server_ks,
                   ctx.our_ks.public_key());

        // Handle message
        let actions = ctx.signaling.handle_message(bbox).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], HandleAction::Event(Event::Disconnected(7)));
    }
}
