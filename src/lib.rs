//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate byteorder;
extern crate data_encoding;
#[macro_use] extern crate failure;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate rmp_serde;
pub extern crate rmpv;
extern crate rust_sodium;
extern crate rust_sodium_sys;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tokio_core;
extern crate websocket;

// Modules
mod boxes;
mod crypto;
mod errors;
mod helpers;
mod protocol;
mod send_all;
mod task;
#[cfg(test)]
mod test_helpers;

// Rust imports
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

// Third party imports
use native_tls::TlsConnector;
use tokio_core::reactor::{Handle};
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::client::builder::Url;
use websocket::ws::dataframe::DataFrame;
use websocket::futures::stream;
use websocket::futures::{Future, Stream};
use websocket::futures::future::{self, Loop};
use websocket::header::WebSocketProtocol;
use websocket::message::OwnedMessage;

// Re-exports
pub use crypto::{KeyStore, PublicKey, PrivateKey, AuthToken};
pub use errors::{SaltyResult, SaltyError, SignalingResult, SignalingError, BuilderError};
pub use protocol::{Role};
pub use task::{Task};

pub mod utils {
    pub use crypto::{public_key_from_hex_str};
}

// Internal imports
use helpers::libsodium_init;
use protocol::{HandleAction, Signaling, InitiatorSignaling, ResponderSignaling};
use task::{Tasks};


// Constants
const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";
#[cfg(feature = "msgpack-debugging")]
const DEFAULT_MSGPACK_DEBUG_URL: &'static str = "https://msgpack.dbrgn.ch/#base64=";


/// A type alias for a boxed future.
pub type BoxedFuture<T, E> = Box<Future<Item = T, Error = E>>;


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


pub struct SaltyClientBuilder {
    permanent_key: KeyStore,
    tasks: Vec<Box<Task>>,
}

impl SaltyClientBuilder {
    pub fn new(permanent_key: KeyStore) -> Self {
        SaltyClientBuilder {
            permanent_key,
            tasks: vec![],
        }
    }

    pub fn add_task(mut self, task: Box<Task>) -> Self {
        self.tasks.push(task);
        self
    }

    /// Create a new SaltyRTC initiator.
    pub fn initiator(self) -> Result<SaltyClient, BuilderError> {
        let tasks = Tasks::from_vec(self.tasks).map_err(|_| BuilderError::MissingTask)?;
        let signaling = InitiatorSignaling::new(self.permanent_key, tasks);
        Ok(SaltyClient {
            signaling: Box::new(signaling),
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
    signaling: Box<Signaling>,
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

    /// Handle an incoming message.
    fn handle_message(&mut self, bbox: boxes::ByteBox) -> SignalingResult<Vec<HandleAction>> {
        self.signaling.handle_message(bbox)
    }
}



/// Connect to the specified SaltyRTC server.
///
/// This function returns a boxed future. The future must be run in a Tokio
/// reactor core for something to actually happen.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
    salty: Rc<RefCell<SaltyClient>>,
) -> SaltyResult<BoxedFuture<(), SaltyError>> {
    // Initialize libsodium
    libsodium_init()?;

    // Parse URL
    let ws_url = match Url::parse(url) {
        Ok(b) => b,
        Err(e) => return Err(SaltyError::Decode(format!("Could not parse URL: {}", e))),
    };

    // Initialize WebSocket client
    let client = ClientBuilder::from_url(&ws_url)
        .add_protocol(SUBPROTOCOL)
        .async_connect_secure(tls_config, handle)
        .map_err(|e: WebSocketError| SaltyError::Network(format!("Could not connect to server: {}", e)))
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
        });

    // Send message to server
    let future = client
        .and_then(move |client| {
            let role = salty
                .deref()
                .try_borrow()
                .map(|s| s.role().to_string())
                .unwrap_or_else(|_| "Unknown".to_string());
            info!("Connected to server as {}", role);

            // We're connected to the SaltyRTC server.
            // Filter the incoming message stream. We're only interested in the binary ones.
            let messages = client
                .filter_map(|msg| {
                    match msg {
                        OwnedMessage::Binary(bytes) => {
                            debug!("Incoming binary message");
                            Some(bytes)
                        },
                        OwnedMessage::Close(close_data) => {
                            match close_data {
                                Some(data) => if data.reason.is_empty() {
                                    info!("Server closed connection with status code {}", data.status_code);
                                } else {
                                    info!("Server closed connection with status code {} ({})", data.status_code, data.reason);
                                },
                                None => info!("Server closed connection without close reason"),
                            };
                            None
                        },
                        m => {
                            // TODO (#4): Handle ping messages
                            warn!("Skipping non-binary message: {:?}", m);
                            None
                        },
                    }
                });

            // Main loop
            let main_loop = future::loop_fn(messages, move |client| {

                let salty = Rc::clone(&salty);

                // Take the next incoming message
                client.into_future()

                    // Map errors to our custom error type
                    .map_err(|(e, _)| SaltyError::Network(format!("Could not receive message from server: {}", e)))

                    // Get nonce and message payload from the incoming bytes
                    .and_then(|(bytes_option, client)| {
                        // Unwrap bytes
                        let bytes = bytes_option.ok_or(SaltyError::Network("Server message stream ended".into()))?;
                        debug!("Received {} bytes", bytes.len());

                        // Parse into ByteBox
                        let bbox = boxes::ByteBox::from_slice(&bytes)
                            .map_err(|e| SaltyError::Protocol(e.to_string()))?;
                        trace!("ByteBox: {:?}", bbox);

                        Ok((bbox, client))
                    })

                    // Process received message
                    .and_then(move |(bbox, client)| {

                        // Handle message bytes
                        let handle_actions = match salty.deref().try_borrow_mut() {
                            Ok(mut s) => match s.handle_message(bbox) {
                                Ok(actions) => actions,
                                Err(e) => match e {
                                    SignalingError::Crash(msg) => {
                                        return boxed!(future::err(SaltyError::Crash(
                                            format!("Signaling error: {}", msg)
                                        )));
                                    },
                                    SignalingError::SendError => {
                                        return boxed!(future::err(SaltyError::Network(e.to_string())));
                                    },
                                    SignalingError::Protocol(msg) => {
                                        return boxed!(future::err(SaltyError::Protocol(msg)));
                                    },
                                    SignalingError::NoSharedTask => {
                                        return boxed!(future::err(SaltyError::Crash("No shared task found (TODO #5)".into())));
                                    }
                                    other => {
                                        return boxed!(future::err(SaltyError::Crash(
                                            format!("Signaling error (TODO #5): {}", other)
                                        )));
                                    },
                                },
                            },
                            Err(e) => return boxed!(
                                future::err(SaltyError::Crash(
                                    format!("Could not get mutable reference to SaltyClient: {}", e)
                                ))
                            ),
                        };

                        // Extract messages that should be sent back to the server
                        let mut messages = vec![];
                        for action in handle_actions {
                            match action {
                                HandleAction::Reply(bbox) => messages.push(OwnedMessage::Binary(bbox.into_bytes())),
                            }
                        }

                        // If there are enqueued messages, send them
                        if messages.is_empty() {
                            boxed!(future::ok(Loop::Continue(client)))
                        } else {
                            for message in &messages {
                                debug!("Sending {} bytes", message.size());
                            }
                            let outbox = stream::iter_ok::<_, WebSocketError>(messages);
                            let future = send_all::new(client, outbox)
                                .map_err(move |e| SaltyError::Network(format!("Could not send message: {}", e)))
                                .map(|(client, _)| {
                                    trace!("Sent all messages");
                                    Loop::Continue(client)
                                });
                            boxed!(future)
                        }
                    })
            });

            boxed!(main_loop)
        });

    Ok(boxed!(future))
}
