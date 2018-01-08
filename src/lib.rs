//! SaltyRTC client implementation in Rust.
//!
//! Early prototype. More docs will follow (#26).
#![recursion_limit = "1024"]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate byteorder;
extern crate data_encoding;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate rmp_serde;
extern crate rust_sodium;
extern crate rust_sodium_sys;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate url;
extern crate ws;

// Re-exports
pub extern crate rmpv;

// Modules
mod boxes;
mod crypto_types;
pub mod errors;
mod helpers;
mod protocol;
mod task;
#[cfg(test)]
mod test_helpers;

// Rust imports
use std::cell::RefCell;
use std::borrow::Cow;
use std::fmt;
use std::io::ErrorKind;
use std::mem;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Duration;

// Third party imports
use data_encoding::HEXLOWER;
use openssl::ssl::{SslMethod, SslStream, SslConnectorBuilder, SslVerifyMode};
use rmpv::Value;
use url::Url;
use ws::util::TcpStream;

// Re-exports
pub use protocol::Role;
pub use task::Task;

/// Cryptography-related types like public/private keys.
pub mod crypto {
    pub use crypto_types::{KeyPair, PublicKey, PrivateKey, AuthToken};
    pub use crypto_types::public_key_from_hex_str;
}

// Internal imports
use boxes::ByteBox;
use crypto_types::{KeyPair, PublicKey, AuthToken};
use errors::{SaltyResult, SaltyError, SignalingResult, BuilderError};
use helpers::libsodium_init;
use protocol::{HandleAction, Signaling, InitiatorSignaling, ResponderSignaling};
use task::Tasks;


// Constants
const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";
#[cfg(feature = "msgpack-debugging")]
const DEFAULT_MSGPACK_DEBUG_URL: &'static str = "https://msgpack.dbrgn.ch/#base64=";


// Type aliases
//type WsClient = Client<TlsStream<TcpStream>>;


/// Helper function to create named thread
fn named_thread(name: &str) -> thread::Builder {
    thread::Builder::new().name(name.into())
}


/// The builder used to create a [`SaltyClient`](struct.SaltyClient.html) instance.
pub struct SaltyClientBuilder {
    permanent_key: KeyPair,
    tasks: Vec<Box<Task>>,
    ping_interval: Option<Duration>,
}

impl SaltyClientBuilder {
    /// Instantiate a new builder.
    pub fn new(permanent_key: KeyPair) -> Self {
        SaltyClientBuilder {
            permanent_key,
            tasks: vec![],
            ping_interval: None,
        }
    }

    /// Register a [`Task`](trait.Task.html) that should be accepted by the client.
    ///
    /// When calling this method multiple times, tasks added first
    /// have the highest priority during task negotation.
    pub fn add_task(mut self, task: Box<Task>) -> Self {
        self.tasks.push(task);
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
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
            state: ConnectionState::Disconnected,
        })
    }

    /// Create a new SaltyRTC responder.
    pub fn responder(self, initiator_pubkey: PublicKey, auth_token: Option<AuthToken>) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = ResponderSignaling::new(
            self.permanent_key,
            initiator_pubkey,
            auth_token,
            tasks,
            self.ping_interval,
        );
        Ok(SaltyClient {
            signaling: Box::new(signaling),
            state: ConnectionState::Disconnected,
        })
    }
}

enum ConnectionState {
    Disconnected,
    Connected {
        tx_thread: thread::JoinHandle<()>,
        tx_channel: Sender<ws::Message>,
        rx_thread: thread::JoinHandle<()>,
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
    signaling: Box<Signaling>,

    /// The connection state.
    state: ConnectionState,
}

impl SaltyClient {
    /// Return the assigned role.
    pub fn role(&self) -> Role {
        self.signaling.role()
    }

    /// Return a reference to the auth token.
    pub fn auth_token(&self) -> Option<&AuthToken> {
        self.signaling.auth_token()
    }

    /// Return a reference to the selected task.
    pub fn task(&self) -> Option<&Box<Task>> {
        self.signaling.common().task.as_ref()
    }

    /// Connect to server.
    /// TODO: Combine with handshake?
    pub fn connect(&mut self, hostname: &str, port: u16) -> SaltyResult<&mut Self> {
        // Initialize libsodium
        libsodium_init()?;

        // Determine URL
        let path = {
            match self.signaling.role() {
                Role::Initiator => self.signaling.common().permanent_keypair.public_key_hex(),
                Role::Responder => HEXLOWER.encode(
                    self.signaling
                        .get_peer().expect("Initiator context not set")
                        .permanent_key().expect("Initiator permanent key not set")
                        .as_ref()
                ),
            }
        };
        let url_string = format!("wss://{}:{}/{}", hostname, port, path);
        info!("Connecting to {}", url_string);

        // Parse URL
        let url = Url::parse(&url_string)
            .map_err(|e| SaltyError::Decode(format!("Invalid URL: {}", e)))?;

        // TODO: Get rid of the following unwraps inside the threads

        // Set up a one-time channel used to transfer the WebSocket sender outside the handler.
        let (sender_tx, sender_rx) = channel::<ws::Sender>();

        // Create new WebSocket
        let mut socket = ws::WebSocket::new(move |sender: ws::Sender| {
            // Send cloned sender through channel
            sender_tx.send(sender.clone()).expect("Could not send ws::Sender through channel");

            // Create a new [`Connection`](struct.Connection.html) instance
            Connection { ws: sender }
        }).map_err(|e| SaltyError::Network(format!("Could not create WebSocket: {}", e)))?;

        // Prepare server connection
        socket.connect(url)
            .map_err(|e| SaltyError::Network(format!("Could not connect to WebSocket server: {}", e)))?;

        // Start receiving thread
        let rx_thread = named_thread("saltyrtc-rx").spawn(move || {
            socket.run().expect("WebSocket error");
            info!("RX thread done");
        }).map_err(|e| SaltyError::Io(e.to_string()))?;

        // Get access to a WebSocket `Sender` instance
        let ws_sender = sender_rx.recv().unwrap();
        mem::drop(sender_rx);

        // Start sending thread
        let (tx, rx) = channel::<ws::Message>();
        let tx_thread = named_thread("saltyrtc-tx").spawn(move || {
            for msg in rx.iter() {
                ws_sender.send(msg).expect("Error when sending message");
            }
            info!("TX thread done");
        }).map_err(|e| SaltyError::Io(e.to_string()))?;

        self.state = ConnectionState::Connected {
            tx_thread,
            tx_channel: tx,
            rx_thread,
        };

        Ok(self)
    }

    pub fn wait(self) {
        match self.state {
            ConnectionState::Connected { tx_thread, rx_thread, .. } => rx_thread.join().unwrap(),
            ConnectionState::Disconnected => panic!("Cannot wait on disconnected client"),
        };
    }
}

struct Connection {
    /// The WebSocket sender object.
    ws: ws::Sender,
}

impl ws::Handler for Connection {

    /// A method for creating the initial handshake request for WebSocket clients.
    ///
    /// This is where we add our custom subprotocol header.
    fn build_request(&mut self, url: &Url) -> ws::Result<ws::Request> {
        debug!("Building initial WebSocket request");
        let mut req = ws::Request::from_url(url)?;
        req.add_protocol(SUBPROTOCOL);
        Ok(req)
    }

    /// The WebSocket is now open!
    fn on_open(&mut self, shake: ws::Handshake) -> ws::Result<()> {
        info!("WebSocket is open!");

        let protocols = shake.request.protocols()?;

        fn make_error<I>(msg: I) -> ws::Result<()> where I: Into<Cow<'static, str>> {
            Err(ws::Error::new(ws::ErrorKind::Protocol, msg))
        }

        // Verify that the correct subprotocol was chosen
        match protocols.len() {
            0 => make_error("Websocket subprotocol not accepted by server"),
            1 if protocols[0] == SUBPROTOCOL => {
                trace!("Subprotocol chosen by server was verified");
                Ok(())
            },
            1 => make_error(format!("Wrong subprotocol chosen by server: {}", protocols[0])),
            _ => make_error("More than one websocket subprotocol chosen by server"),
        }
    }

    fn on_message(&mut self, msg: ws::Message) -> ws::Result<()> {
        match msg {
            ws::Message::Text(_) => debug!("Incoming text message, ignoring"),
            ws::Message::Binary(bytes) => debug!("Incoming message ({} bytes)", bytes.len()),
        }
        Ok(())
    }

    fn on_send_message(&mut self, msg: ws::Message) -> ws::Result<Option<ws::Message>> {
        match msg {
            ws::Message::Text(_) => debug!("Outgoing text message"),
            ws::Message::Binary(ref bytes) => debug!("Outgoing message ({} bytes)", bytes.len()),
        }
        Ok(Some(msg))
    }

    fn on_close(&mut self, code: ws::CloseCode, reason: &str) {
        if reason.is_empty() {
            info!("WebSocket connection closed, code: {:?}", code);
        } else {
            info!("WebSocket connection closed, code: {:?}, reason: {}", code, reason);
        }
    }

    fn on_error(&mut self, err: ws::Error) {
        error!("WebSocket error: {:?}", err);
    }

    /// Upgrade the TcpStream to an SslStream.
    fn upgrade_ssl_client(&mut self, stream: TcpStream, url: &Url) -> ws::Result<SslStream<TcpStream>> {
        let domain = url.domain()
            .ok_or(ws::Error::new(
                ws::ErrorKind::Protocol,
                format!("Unable to parse domain from {}. Needed for TLS.", url),
            ))?;

        let mut builder = SslConnectorBuilder::new(SslMethod::tls())
            .map_err(|e| ws::Error::new(ws::ErrorKind::Internal, format!("Failed to upgrade client to SSL: {}", e)))?;

        // TODO: This must not be in the final version!
        builder.builder_mut().set_verify(SslVerifyMode::empty());
        let connector = builder.build();
        connector
            .danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
            .map_err(ws::Error::from)

        //connector.connect(domain, stream).map_err(ws::Error::from)
    }
}



/// Close codes used by SaltyRTC.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CloseCode {
    WsGoingAway,
    WsProtocolError,
    PathFull,
    ProtocolError,
    InternalError,
    Handover,
    DroppedByInitiator,
    InitiatorCouldNotDecrypt,
    NoSharedTask,
    InvalidKey,
}

impl CloseCode {
    fn as_number(&self) -> u16 {
        use CloseCode::*;
        match *self {
            WsGoingAway => 1001,
            WsProtocolError => 1002,
            PathFull => 3000,
            ProtocolError => 3001,
            InternalError => 3002,
            Handover => 3003,
            DroppedByInitiator => 3004,
            InitiatorCouldNotDecrypt => 3005,
            NoSharedTask => 3006,
            InvalidKey => 3007,
        }
    }

    fn from_number(code: u16) -> Option<CloseCode> {
        use CloseCode::*;
        match code {
            1001 => Some(WsGoingAway),
            1002 => Some(WsProtocolError),
            3000 => Some(PathFull),
            3001 => Some(ProtocolError),
            3002 => Some(InternalError),
            3003 => Some(Handover),
            3004 => Some(DroppedByInitiator),
            3005 => Some(InitiatorCouldNotDecrypt),
            3006 => Some(NoSharedTask),
            3007 => Some(InvalidKey),
            _ => None,
        }
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} ({})", self, self.as_number())
    }
}
