//! SaltyRTC client implementation in Rust.
//!
//! SaltyRTC is an end-to-end encrypted signalling protocol. It offers to
//! freely choose from a range of signalling tasks, such as setting up a WebRTC
//! or ORTC peer-to-peer connection, or using the WebSocket based signaling
//! server as a relay. SaltyRTC is completely open to new and custom signalling
//! tasks for everything feasible.
//!
//! The implementation is asynchronous using [Tokio](https://tokio.rs/) /
//! [Futures](https://docs.rs/futures/0.2.1/futures/).
//!
//! This library requires Rust 1.36.
//!
//! ## Usage
//!
//! To establish a SaltyRTC connection:
//!
//! 1. Create an instance of a type that implements the
//!    [`Task`](tasks/trait.Task.html) interface.
//! 2. Using that task instance, create a [`SaltyClient`](struct.SaltyClient.html)
//!    instance using the [`SaltyClientBuilder`](struct.SaltyClientBuilder.html).
//! 3. Create an instance of the Tokio reactor core.
//! 4. Create a connect future and an event channel using the
//!    [`connect`](fn.connect.html) function.
//! 5. Pass the result of the connect future to the
//!    [`do_handshake`](fn.do_handshake.html) function.
//! 6. Pass the result of the handshake future (the WebSocket client) to the
//!    [`task_loop`](fn.task_loop.html) function.
//! 7. Send and receive data through the event channel returned by the
//!    [`connect`](fn.connect.html) function. Send and receive data through the
//!    task instance.
//!
//! For a real-life example, please take a look at the
//! [chat example](https://github.com/saltyrtc/saltyrtc-client-rs/tree/master/examples/chat).
//!
//! ## Timeouts
//!
//! If you want timeouts (e.g. for connecting, for the handshake, etc) combine
//! the futures with a timeout feature (for example from
//! [tokio-timer](https://github.com/tokio-rs/tokio-timer)).
#![recursion_limit = "1024"]
#![deny(missing_docs)]

#[macro_use]
extern crate log;

/// Re-exports of dependencies that are in the public API.
pub mod dep {
    pub use futures;
    pub use native_tls;
    pub use rmpv;
}

// Modules
mod boxes;
mod close_code;
mod crypto_types;
pub mod errors;
mod helpers;
mod protocol;
mod send_all;
pub mod tasks;
#[cfg(test)]
mod test_helpers;

// Rust imports
use std::error::Error;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

// Third party imports
use data_encoding::HEXLOWER;
use futures::{stream, Future, Stream, Sink};
use futures::future::{self, Loop};
use futures::sync::mpsc;
use futures::sync::oneshot;
use native_tls::TlsConnector;
use rmpv::Value;
use rust_sodium::crypto::box_;
use tokio_core::reactor::Handle;
use tokio_core::net::TcpStream;
use tokio_timer::Timer;
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::client::r#async::{Client, TlsStream};
use websocket::client::builder::Url;
use websocket::ws::dataframe::DataFrame;
use websocket::header::WebSocketProtocol;
use websocket::message::{OwnedMessage, CloseData};

// Re-exports
pub use crate::close_code::CloseCode;
pub use crate::protocol::Role;
pub use crate::protocol::csn::PeerSequenceNumbers;

/// Cryptography-related types like public/private keys.
pub mod crypto {
    pub use crate::crypto_types::{KeyPair, PublicKey, PrivateKey, AuthToken};
    pub use crate::crypto_types::{public_key_from_hex_str, private_key_from_hex_str};
}

// Internal imports
use crate::boxes::{ByteBox};
use crate::crypto_types::{KeyPair, PublicKey, AuthToken};
use crate::errors::{SaltyResult, SaltyError, SignalingResult, SignalingError, BuilderError};
use crate::helpers::libsodium_init;
use crate::protocol::{HandleAction, Signaling, InitiatorSignaling, ResponderSignaling};
use crate::tasks::{Tasks, TaskMessage, BoxedTask};


// Constants
const SUBPROTOCOL: &str = "v1.saltyrtc.org";
#[cfg(feature = "msgpack-debugging")]
const DEFAULT_MSGPACK_DEBUG_URL: &'static str = "https://msgpack.dbrgn.ch/#base64=";


/// A type alias for a boxed future.
pub type BoxedFuture<T, E> = Box<dyn Future<Item = T, Error = E>>;

/// A type alias for the async websocket client type.
pub type WsClient = Client<TlsStream<TcpStream>>;


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


/// The builder instance returned by
/// [`SaltyClient::build`](struct.SaltyClient.html#method.build). Use this
/// builder to construct a [`SaltyClient`](struct.SaltyClient.html) instance.
pub struct SaltyClientBuilder {
    permanent_key: KeyPair,
    tasks: Vec<BoxedTask>,
    ping_interval: Option<Duration>,
    server_public_permanent_key: Option<PublicKey>,
}

impl SaltyClientBuilder {
    /// Instantiate a new builder.
    pub(crate) fn new(permanent_key: KeyPair) -> Self {
        SaltyClientBuilder {
            permanent_key,
            tasks: vec![],
            ping_interval: None,
            server_public_permanent_key: None,
        }
    }

    /// Register a [`Task`](trait.Task.html) that should be accepted by the client.
    ///
    /// When calling this method multiple times, tasks added first
    /// have the highest priority during task negotation.
    pub fn add_task(mut self, task: BoxedTask) -> Self {
        self.tasks.push(task);
        self
    }

    /// Specify the server public permanent key if you want to use server key
    /// pinning.
    pub fn with_server_key(mut self, server_public_permanent_key: PublicKey) -> Self {
        self.server_public_permanent_key = Some(server_public_permanent_key);
        self
    }

    /// Request that the server sends a WebSocket ping message at the specified interval.
    ///
    /// Set the `interval` argument to `None` or to a zero duration to disable intervals.
    ///
    /// Note: Fractions of seconds are ignored, so if you set the duration to 13.37s,
    /// then the ping interval 13s will be requested.
    ///
    /// By default, ping messages are disabled.
    pub fn with_ping_interval(mut self, interval: Option<Duration>) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Create a new SaltyRTC initiator.
    pub fn initiator(self) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = InitiatorSignaling::new(
            self.permanent_key,
            tasks,
            None,
            self.server_public_permanent_key,
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
        })
    }

    /// Create a new SaltyRTC initiator with a trusted peer public key.
    pub fn initiator_trusted(self, responder_trusted_pubkey: PublicKey) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = InitiatorSignaling::new(
            self.permanent_key,
            tasks,
            Some(responder_trusted_pubkey),
            self.server_public_permanent_key,
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
        })
    }

    /// Create a new SaltyRTC responder.
    pub fn responder(self, initiator_pubkey: PublicKey, auth_token: AuthToken) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = ResponderSignaling::new(
            self.permanent_key,
            initiator_pubkey,
            Some(auth_token),
            self.server_public_permanent_key,
            tasks,
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
        })
    }

    /// Create a new SaltyRTC responder with a trusted peer public key.
    pub fn responder_trusted(self, initiator_trusted_pubkey: PublicKey) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = ResponderSignaling::new(
            self.permanent_key,
            initiator_trusted_pubkey,
            None,
            self.server_public_permanent_key,
            tasks,
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
        })
    }
}

/// The SaltyRTC Client instance.
///
/// To create an instance of this struct, use the
/// [`SaltyClientBuilder`](struct.SaltyClientBuilder.html).
pub struct SaltyClient {
    /// The signaling trait object.
    ///
    /// This is either an
    /// [`InitiatorSignaling`](protocol/struct.InitiatorSignaling.html) or a
    /// [`ResponderSignaling`](protocol/struct.ResponderSignaling.html)
    /// instance.
    signaling: Box<dyn Signaling>,
}

impl SaltyClient {

    /// Instantiate a new [`SaltyClientBuilder`](struct.SaltyClientBuilder.html) instance.
    pub fn build(permanent_key: KeyPair) -> SaltyClientBuilder {
        SaltyClientBuilder::new(permanent_key)
    }

    /// Return the assigned role.
    pub fn role(&self) -> Role {
        self.signaling.role()
    }

    /// Return a reference to the auth token.
    pub fn auth_token(&self) -> Option<&AuthToken> {
        self.signaling.auth_token()
    }

    /// Return a reference to the initiator public key.
    pub fn initiator_pubkey(&self) -> &PublicKey {
        self.signaling.initiator_pubkey()
    }

    /// Return a reference to the selected task.
    pub fn task(&self) -> Option<Arc<Mutex<BoxedTask>>> {
        self.signaling
            .common()
            .task
            .clone()
    }

    /// Handle an incoming message.
    fn handle_message(&mut self, bbox: ByteBox) -> SignalingResult<Vec<HandleAction>> {
        self.signaling.handle_message(bbox)
    }

    /// Encrypt a task message.
    pub fn encrypt_task_message(&mut self, val: Value) -> SaltyResult<Vec<u8>> {
        trace!("Encrypting task message");
        self.signaling
            .encode_task_message(val)
            .map(|bbox: ByteBox| bbox.into_bytes())
            .map_err(|e: SignalingError| match e {
                SignalingError::Crypto(msg) => SaltyError::Crypto(msg),
                SignalingError::Decode(msg) => SaltyError::Decode(msg),
                SignalingError::Protocol(msg) => SaltyError::Protocol(msg),
                SignalingError::Crash(msg) => SaltyError::Crash(msg),
                other => SaltyError::Crash(format!("Unexpected signaling error: {}", other)),
            })
    }

    /// Encrypt a close message for the peer.
    pub fn encrypt_close_message(&mut self, reason: CloseCode) -> SaltyResult<Vec<u8>> {
        trace!("Encrypting close message");
        self.signaling
            .encode_close_message(reason, None)
            .map(|bbox: ByteBox| bbox.into_bytes())
            .map_err(|e: SignalingError| match e {
                SignalingError::Crypto(msg) => SaltyError::Crypto(msg),
                SignalingError::Decode(msg) => SaltyError::Decode(msg),
                SignalingError::Protocol(msg) => SaltyError::Protocol(msg),
                SignalingError::Crash(msg) => SaltyError::Crash(msg),
                other => SaltyError::Crash(format!("Unexpected signaling error: {}", other)),
            })
    }

    /// If the peer is already determined, return the current incoming and
    /// outgoing sequence numbers.
    pub fn current_peer_sequence_numbers(&self) -> Option<PeerSequenceNumbers> {
        self.signaling.current_peer_sequence_numbers()
    }

    /// Encrypt raw bytes using the session keys after the handshake has been finished.
    pub fn encrypt_raw_with_session_keys(&self, data: &[u8], nonce: &[u8]) -> SaltyResult<Vec<u8>> {
        let sodium_nonce = box_::Nonce::from_slice(nonce)
            .ok_or(SaltyError::Crypto("Invalid nonce bytes".into()))?;
        Ok(self.signaling.encrypt_raw_with_session_keys(data, &sodium_nonce)?)
    }

    /// Decrypt raw bytes using the session keys after the handshake has been finished.
    pub fn decrypt_raw_with_session_keys(&self, data: &[u8], nonce: &[u8]) -> SaltyResult<Vec<u8>> {
        let sodium_nonce = box_::Nonce::from_slice(nonce)
            .ok_or(SaltyError::Crypto("Invalid nonce bytes".into()))?;
        Ok(self.signaling.decrypt_raw_with_session_keys(data, &sodium_nonce)?)
    }
}


/// Non-message events that may happen during connection.
#[derive(Debug, PartialEq)]
pub enum Event {
    /// Server handshake is done.
    ///
    /// The boolean indicates whether a peer is already
    /// connected + authenticated towards the server.
    ServerHandshakeDone(bool),

    /// Peer handshake is done.
    PeerHandshakeDone,

    /// An authenticated peer disconnected from the server.
    Disconnected(u8),
}


/// Wrapper type for decoded form of WebSocket message types that we want to handle.
#[derive(Debug)]
enum WsMessageDecoded {
    /// We got bytes that we decoded into a ByteBox.
    ByteBox(ByteBox),
    /// We got a ping message.
    Ping(Vec<u8>),
    /// We got a close message.
    Close(Option<CloseCode>),
    /// We got a message type that we want to ignore.
    Ignore,
}


/// An unbounded channel sender/receiver pair.
pub struct UnboundedChannel<T> {
    /// The channel sender.
    pub tx: mpsc::UnboundedSender<T>,
    /// The channel receiver.
    pub rx: mpsc::UnboundedReceiver<T>,
}

impl<T> UnboundedChannel<T> {
    /// Create a new `UnboundedChannel`.
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::unbounded::<T>();
        UnboundedChannel { tx, rx }
    }

    /// Split this channel into sending and receiving half.
    pub fn split(self) -> (mpsc::UnboundedSender<T>, mpsc::UnboundedReceiver<T>) {
        (self.tx, self.rx)
    }

    /// Get a clone of the sending half of the channel.
    pub fn clone_tx(&self) -> mpsc::UnboundedSender<T> {
        self.tx.clone()
    }
}


/// Connect to the specified SaltyRTC server.
///
/// This function returns a future. The future must be run in a Tokio reactor
/// core for something to actually happen.
///
/// The future completes once the server connection is established.
/// It returns the async websocket client instance.
pub fn connect(
    host: &str,
    port: u16,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
    salty: Arc<RwLock<SaltyClient>>,
) -> SaltyResult<(
    impl Future<Item=WsClient, Error=SaltyError>,
    UnboundedChannel<Event>,
)> {
    // Initialize libsodium
    libsodium_init()?;

    // Parse URL
    let path = salty.read()
        .map(|client| HEXLOWER.encode(&client.initiator_pubkey().0))
        .map_err(|_| SaltyError::Crash("connect: Could not read-lock SaltyClient".into()))?;
    let url = format!("wss://{}:{}/{}", host, port, path);
    let ws_url = match Url::parse(&url) {
        Ok(b) => b,
        Err(e) => return Err(SaltyError::Decode(format!("Could not parse URL: {}", e))),
    };

    // Initialize WebSocket client
    let server = format!("{}:{}", host, port);
    let future = ClientBuilder::from_url(&ws_url)
        .add_protocol(SUBPROTOCOL)
        .async_connect_secure(tls_config, handle)
        .map_err(move |e: WebSocketError| SaltyError::Network(match e.cause() {
            Some(cause) => format!("Could not connect to server ({}): {}: {}", server, e, cause),
            None => format!("Could not connect to server ({}): {}", server, e),
        }))
        .and_then(|(client, headers)| {
            // Verify that the correct subprotocol was chosen
            trace!("Websocket server headers: {:?}", headers);
            match headers.get::<WebSocketProtocol>() {
                Some(proto) if proto.len() == 1 && proto[0] == SUBPROTOCOL => {
                    Ok(client)
                },
                Some(proto) => {
                    error!("More than one chosen protocol: {:?}", proto);
                    Err(SaltyError::Protocol("More than one websocket subprotocol chosen by server".into()))
                },
                None => {
                    error!("No protocol chosen by server");
                    Err(SaltyError::Protocol("Websocket subprotocol not accepted by server".into()))
                },
            }
        })
        .map(move |client| {
            let role = salty
                .read()
                .map(|s| s.role().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            info!("Connected to server as {}", role);
            client
        });
    debug!("Created WS connect future");

    // Create event channel
    let event_channel = UnboundedChannel::new();
    debug!("Created event channel");

    Ok((future, event_channel))
}

/// Decode a websocket `OwnedMessage` and wrap it into a `WsMessageDecoded`.
fn decode_ws_message(msg: OwnedMessage) -> SaltyResult<WsMessageDecoded> {
    let decoded = match msg {
        OwnedMessage::Binary(bytes) => {
            debug!("--> Incoming binary message ({} bytes)", bytes.len());

            // Parse into ByteBox
            let bbox = ByteBox::from_slice(&bytes)
                .map_err(|e| SaltyError::Protocol(e.to_string()))?;
            trace!("ByteBox: {:?}", bbox);

            WsMessageDecoded::ByteBox(bbox)
        },
        OwnedMessage::Ping(payload) => {
            debug!("--> Incoming WS ping message");
            WsMessageDecoded::Ping(payload)
        },
        OwnedMessage::Pong(_) => {
            debug!("--> Incoming WS pong message (ignored)");
            WsMessageDecoded::Ignore
        },
        OwnedMessage::Close(close_data) => {
            debug!("--> Incoming WS close message");
            match close_data {
                Some(data) => {
                    let close_code = CloseCode::from_number(data.status_code);
                    if data.reason.is_empty() {
                        info!("Server closed connection with close code {}", close_code);
                    } else {
                        info!("Server closed connection with close code {} ({})", close_code, data.reason);
                    }
                    WsMessageDecoded::Close(Some(close_code))
                }
                None => {
                    info!("Server closed connection without close code");
                    WsMessageDecoded::Close(None)
                }
            }
        },
        OwnedMessage::Text(payload) => {
            warn!("Skipping text message: {:?}", payload);
            WsMessageDecoded::Ignore
        },
    };
    Ok(decoded)
}

/// An action in our pipeline.
///
/// This is used to enable early-return inside the pipeline. If a step returns a `Future`,
/// it should be passed directly to the `loop_fn`.
enum PipelineAction {
    /// We got a ByteBox to handle.
    ByteBox((WsClient, ByteBox)),
    /// Immediately pass on this future in the next step.
    Future(BoxedFuture<Loop<WsClient, WsClient>, SaltyError>),
}

/// Preprocess a `WsMessageDecoded`.
///
/// Here pings and ignored messages are handled.
fn preprocess_ws_message((decoded, client): (WsMessageDecoded, WsClient)) -> SaltyResult<PipelineAction> {
    // Unwrap byte box, handle ping messages
    let bbox = match decoded {
        WsMessageDecoded::ByteBox(bbox) => bbox,
        WsMessageDecoded::Ping(payload) => {
            let pong = OwnedMessage::Pong(payload);
            let outbox = stream::iter_ok::<_, WebSocketError>(vec![pong]);
            let future = send_all::new(client, outbox)
                .map_err(move |e| SaltyError::Network(format!("Could not send pong message: {}", e)))
                .map(|(client, _)| {
                    debug!("Sent pong message");
                    Loop::Continue(client)
                });
            let action = PipelineAction::Future(boxed!(future));
            return Ok(action);
        },
        WsMessageDecoded::Close(_code) => {
            let future = future::ok(Loop::Break(client));
            let action = PipelineAction::Future(boxed!(future));
            return Ok(action);
        },
        WsMessageDecoded::Ignore => {
            debug!("Ignoring message");
            let action = PipelineAction::Future(boxed!(future::ok(Loop::Continue(client))));
            return Ok(action);
        },
    };
    Ok(PipelineAction::ByteBox((client, bbox)))
}

/// Do the server and peer handshake.
///
/// This function returns a future. The future must be run in a Tokio reactor
/// core for something to actually happen.
///
/// The future completes once the peer handshake is done, or if an error occurs.
/// It returns the async websocket client instance.
pub fn do_handshake(
    client: WsClient,
    salty: Arc<RwLock<SaltyClient>>,
    event_tx: mpsc::UnboundedSender<Event>,
    timeout: Option<Duration>,
) -> impl Future<Item=WsClient, Error=SaltyError> {
    // Main loop
    let main_loop = future::loop_fn(client, move |client| {

        let salty = Arc::clone(&salty);

        // Take the next incoming message
        let event_tx = event_tx.clone();
        client.into_future()

            // Map errors to our custom error type
            .map_err(|(e, _)| SaltyError::Network(format!("Could not receive message from server: {}", e)))

            // Process incoming messages and convert them to a `WsMessageDecoded`.
            .and_then(|(msg_option, client)| {
                let decoded = match msg_option {
                    Some(msg) => decode_ws_message(msg),
                    None => return Err(SaltyError::Network("Server message stream ended without close message".into())),
                };
                decoded.map(|decoded| (decoded, client))
            })

            // Preprocess messages, handle things like ping/pong and ignored messages
            .and_then(preprocess_ws_message)

            // Process received signaling message
            .and_then(move |pipeline_action| {
                let (client, bbox) = match pipeline_action {
                    PipelineAction::ByteBox(x) => x,
                    PipelineAction::Future(f) => return f,
                };

                // Handle message bytes
                let handle_actions = match salty.write() {
                    Ok(mut s) => match s.handle_message(bbox) {
                        Ok(actions) => actions,
                        Err(e) => return boxed!(future::err(e.into())),
                    },
                    Err(e) => return boxed!(future::err(SaltyError::Crash(
                        format!("do_handshake: Could not write-lock SaltyClient: {}", e)
                    ))),
                };

                // Extract messages that should be sent back to the server
                let mut messages = vec![];
                let mut handshake_done = false;
                let mut late_error: Option<SaltyError> = None;
                for action in handle_actions {
                    match action {
                        HandleAction::Reply(bbox) => messages.push(OwnedMessage::Binary(bbox.into_bytes())),
                        HandleAction::HandshakeDone => {
                            handshake_done = true;
                            if event_tx.unbounded_send(Event::PeerHandshakeDone).is_err() {
                                return boxed!(future::err(
                                    SaltyError::Crash("Could not send event through channel".into())
                                ));
                            }
                        },
                        HandleAction::TaskMessage(_) => return boxed!(future::err(
                            SaltyError::Crash("Received task message during handshake".into())
                        )),
                        HandleAction::Event(e) => {
                            // Notify the user about event
                            if event_tx.unbounded_send(e).is_err() {
                                return boxed!(future::err(
                                    SaltyError::Crash("Could not send event through channel".into())
                                ));
                            }
                        },
                        HandleAction::HandshakeError(e) => {
                            if late_error.is_some() {
                                error!("Dropping error because another error happened previously: {}", e);
                            } else {
                                late_error = Some(e);
                            }
                        },
                    }
                }

                macro_rules! loop_action {
                    ($client:expr) => {
                        if handshake_done {
                            Loop::Break($client)
                        } else {
                            Loop::Continue($client)
                        }
                    }
                };

                // If there are enqueued messages, send them
                if messages.is_empty() {
                    boxed!(future::ok(loop_action!(client)))
                } else {
                    for message in &messages {
                        debug!("Sending {} bytes", message.size());
                    }
                    let outbox = stream::iter_ok::<_, WebSocketError>(messages);
                    let future = send_all::new(client, outbox)
                        .map_err(move |e| SaltyError::Network(format!("Could not send message: {}", e)))
                        .and_then(move |(client, _)| {
                            trace!("Sent all messages");
                            match late_error {
                                Some(e) => future::err(e),
                                None => future::ok(loop_action!(client)),
                            }
                        });
                    boxed!(future)
                }
            })
    });

    let timeout_duration = match timeout {
        Some(duration) => duration,
        None => return boxed!(main_loop),
    };

    let timer = Timer::default();
    boxed!(timer.timeout(main_loop, timeout_duration))
}

/// Start the task loop.
///
/// Only call this function once you have finished the handshake!
#[cfg_attr(feature="cargo-clippy", allow(needless_pass_by_value))]
pub fn task_loop(
    client: WsClient,
    salty: Arc<RwLock<SaltyClient>>,
    event_tx: mpsc::UnboundedSender<Event>,
) -> Result<(
    Arc<Mutex<BoxedTask>>,
    impl Future<Item=(), Error=SaltyError>,
), SaltyError> {
    let task_name = salty
        .read()
        .ok()
        .and_then(|salty| salty.task())
        .and_then(|task| match task.lock() {
            Ok(t) => Some(t.name()),
            Err(_) => None,
        })
        .unwrap_or_else(|| "Unknown".into());
    info!("Starting task loop for task {}", task_name);

    let salty = Arc::clone(&salty);

    // Split websocket connection into sink/stream
    let (ws_sink, ws_stream) = client.split();

    // Create communication channels
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded::<TaskMessage>();
    let (raw_outgoing_tx, raw_outgoing_rx) = mpsc::unbounded::<OwnedMessage>();
    let (incoming_tx, incoming_rx) = mpsc::unbounded::<TaskMessage>();
    let (disconnect_tx, disconnect_rx) = oneshot::channel::<Option<CloseCode>>();

    // Stream future for processing incoming WebSocket messages
    let reader = ws_stream

        // Map errors to our custom error type
        // TODO: Take a look at `sink_from_err`
        .map_err(|e| SaltyError::Network(format!("Could not receive message from server: {}", e)))

        // Decode messages
        .and_then(decode_ws_message)

        // Wrap errors in a result type
        .map_err(Err)

        // Handle each incoming message.
        //
        // The closure passed to `for_each` must return:
        //
        // * `future::ok(())` to continue processing the stream
        // * `future::err(Ok(()))` to stop the loop without an error
        // * `future::err(Err(_))` to stop the loop with an error
        .for_each({
            let salty = Arc::clone(&salty);
            let raw_outgoing_tx = raw_outgoing_tx.clone();
            move |msg: WsMessageDecoded| {
                let raw_outgoing_tx = raw_outgoing_tx.clone();
                match msg {
                    WsMessageDecoded::ByteBox(bbox) => {
                        // Handle message bytes
                        let handle_actions = match salty.write() {
                            Ok(mut s) => match s.handle_message(bbox) {
                                Ok(actions) => actions,
                                Err(e) => return boxed!(future::err(Err(e.into()))),
                            },
                            Err(e) => return boxed!(future::err(Err(
                                SaltyError::Crash(format!("task_loop/reader: Could not write-lock SaltyClient: {}", e))
                            ))),
                        };

                        // Extract messages that should be sent back to the server
                        let mut out_messages: Vec<OwnedMessage> = vec![];
                        let mut in_messages: Vec<TaskMessage> = vec![];
                        let mut close_stream = false;
                        for action in handle_actions {
                            info!("Action: {:?}", action);
                            match action {
                                HandleAction::Reply(bbox) => out_messages.push(OwnedMessage::Binary(bbox.into_bytes())),
                                HandleAction::TaskMessage(msg) => {
                                    if let TaskMessage::Close(_) = msg {
                                        close_stream = true;
                                    }

                                    // Forward message to user
                                    in_messages.push(msg);
                                },
                                HandleAction::Event(e) => {
                                    // Notify the user about event
                                    match event_tx.unbounded_send(e) {
                                        Ok(_) => {},
                                        Err(_) => return boxed!(future::err(Err(
                                            SaltyError::Crash("Could not send event through channel".into())
                                        ))),
                                    }
                                },
                                HandleAction::HandshakeDone => return boxed!(future::err(Err(
                                    SaltyError::Crash("Got HandleAction::HandshakeDone in task loop".into())
                                ))),
                                HandleAction::HandshakeError(_) => return boxed!(future::err(Err(
                                    SaltyError::Crash("Got HandleAction::HandshakeError in task loop".into())
                                ))),
                            }
                        }

                        // Handle outgoing queued messages
                        let out_future = if out_messages.is_empty() {
                            boxed!(future::ok(()))
                        } else {
                            let msg_count = out_messages.len();
                            let outbox = stream::iter_ok::<_, Result<(), SaltyError>>(out_messages);
                            let future = raw_outgoing_tx
                                .sink_map_err(|e| Err(SaltyError::Network(format!("Sink error: {}", e))))
                                .send_all(outbox)
                                .map(move |_| debug!("Sent {} messages", msg_count));
                            boxed!(future)
                        };

                        // Handle incoming queued messages
                        let in_future = if in_messages.is_empty() {
                            boxed!(future::ok(()))
                        } else {
                            let msg_count = in_messages.len();
                            let inbox = stream::iter_ok::<_, Result<(), SaltyError>>(in_messages);
                            let future = incoming_tx
                                .clone()
                                .sink_map_err(|e| Err(SaltyError::Crash(format!("Channel error: {}", e))))
                                .send_all(inbox)
                                .map(move |_| debug!("Received {} task messages", msg_count));
                            boxed!(future)
                        };

                        boxed!(
                            out_future
                                .join(in_future)
                                .and_then(move |_| if close_stream {
                                    // Stop processing stream
                                    Err(Ok(()))
                                } else {
                                    // Continue processing stream
                                    Ok(())
                                })
                        )
                    },
                    WsMessageDecoded::Ping(payload) => {
                        let pong = OwnedMessage::Pong(payload);
                        let future = raw_outgoing_tx
                            .send(pong)
                            .map(|_| debug!("<-- Enqueuing pong message"))
                            .map_err(|e| Err(SaltyError::Network(format!("Could not enqueue pong message: {}", e))));
                        boxed!(future)
                    },
                    WsMessageDecoded::Close(_) | WsMessageDecoded::Ignore => boxed!(future::ok(())),
                }
            }
        })

        .or_else(|res| match res {
            Ok(_) => boxed!(future::ok(())),
            Err(e) => boxed!(future::err(e))
        })

        .select(
            disconnect_rx
                .and_then({
                    let outgoing_tx = outgoing_tx.clone();
                    move |reason_opt: Option<CloseCode>| {
                        info!("Disconnecting");

                        // Send close message
                        outgoing_tx
                            .send(TaskMessage::Close(reason_opt.unwrap_or(CloseCode::WsGoingAway)))
                            .map(|_| ())
                            .or_else(|e| {
                                warn!("Could not enqueue close message: {}", e);
                                future::ok(())
                            })
                    }
                })
                .or_else(|_| {
                    warn!("Waiting for disconnect_rx failed");
                    future::ok(())
                })
        )

        .map(|_| debug!("† Reader future done"))
        .map_err(|(e, _next)| e);

    // Transform future that sends values from the outgoing channel to the raw outgoing channel
    let transformer = outgoing_rx

        // Wrap errors in result
        .map_err(|_| Err(()))

        // Encode and encrypt values.
        .and_then({
            let salty = Arc::clone(&salty);
            move |msg: TaskMessage| {
                trace!("Transforming outgoing message: {:?}", msg);

                // Get reference to SaltyClient
                // TODO: Can we do something about the errors here?
                let mut salty_mut = salty.write().map_err(|_| Err(()))?;

                // When we receive a `Value` message, simply send it as-is.
                // But when we receive a `Close` message, also insert a WebSocket close message.
                match msg {
                    TaskMessage::Value(map) => {
                        // Create message
                        let val = Value::Map(
                            map
                                .into_iter()
                                .map(|(k, v)| (Value::from(k), v))
                                .collect()
                        );
                        // Encrypt message
                        salty_mut
                            .encrypt_task_message(val)
                            .map(|bytes| {
                                debug!("<-- Enqueuing task message to peer");
                                stream::iter_result::<_, OwnedMessage, Result<(), ()>>(
                                    vec![
                                        Ok(OwnedMessage::Binary(bytes))
                                    ]
                                )
                            })
                            .map_err(|e| {
                                warn!("Could not encrypt task message: {}", e);
                                Err(())
                            })
                    },
                    TaskMessage::Application(data) => {
                        let mut map = vec![];
                        map.push((Value::String("type".into()), Value::String("application".into())));
                        map.push((Value::String("data".into()), data));
                        let val = Value::Map(map);
                        salty_mut
                            .encrypt_task_message(val)
                            .map(|bytes| {
                                debug!("<-- Enqueuing application message to peer");
                                stream::iter_result::<_, OwnedMessage, Result<(), ()>>(
                                    vec![
                                        Ok(OwnedMessage::Binary(bytes))
                                    ]
                                )
                            })
                            .map_err(|e| {
                                warn!("Could not encrypt task message: {}", e);
                                Err(())
                            })
                    },
                    TaskMessage::Close(reason) => {
                        // Create and encrypt SaltyRTC close message,
                        // followed by a WebSocket close message
                        salty_mut
                            .encrypt_close_message(reason)
                            .map(|bytes| {
                                debug!("<-- Enqueuing SaltyRTC close message to peer");
                                debug!("<-- Enqueuing WebSocket close message to peer");
                                stream::iter_result::<_, OwnedMessage, Result<(), ()>>(
                                    vec![
                                        Ok(OwnedMessage::Binary(bytes)),
                                        Ok(OwnedMessage::Close(Some(CloseData {
                                            status_code: reason.as_number(),
                                            reason: reason.to_string(),
                                        }))),
                                        Err(Ok(())), // Terminate transformer future
                                    ]
                                )
                            })
                            .map_err(|e| {
                                warn!("Could not encrypt SaltyRTC close message: {}", e);
                                Err(())
                            })
                    },
                }
            }
        })

        .flatten()

        // Forward to raw queue
        .forward(raw_outgoing_tx.sink_map_err(|_| Err(())))

        // Ignore stream/sink
        .map(|(_, _)| debug!("† Transformer future done"))

        // Flatten errors
        .or_else(|e| e.map_err(|_| SaltyError::Crash("Transformer future error (TODO)".into())));

    // Sink future for sending messages from the raw outgoing channel through the WebSocket
    let writer = raw_outgoing_rx

        .map_err(|_| SaltyError::Crash("TODO receiver error".to_string()))

        // Forward all messages from the channel receiver to the sink
        .forward(
            ws_sink.sink_map_err(|e| SaltyError::Crash(format!("TODO sink error: {:?}", e)))
        )

        // Ignore sink
        .map(|_| debug!("† Writer future done"));

    // The task loop is finished when all futures are resolved.
    let task_loop = boxed!(
        future::ok(())
        .and_then(|_| reader.join(transformer).join(writer).map(|_| ()))
        .and_then(|_| { info!("† Task loop future done"); future::ok(()) })
    );

    // Get reference to task
    let task = match salty.write() {
        Ok(salty) => salty
            .task()
            .ok_or_else(|| SaltyError::Crash("Task not set".into()))?,
        Err(e) => return Err(
            SaltyError::Crash(format!("task_loop/task: Could not write-lock SaltyClient: {}", e))
        ),
    };

    // Notify task that it can now take over
    task.lock()
        .map_err(|e| SaltyError::Crash(format!("Could not lock task mutex: {}", e)))?
        .start(outgoing_tx, incoming_rx, disconnect_tx);

    // Return reference to task and the task loop future
    Ok((task, task_loop))
}
