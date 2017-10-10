//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate byteorder;
extern crate data_encoding;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate rmp_serde;
extern crate rust_sodium;
extern crate rust_sodium_sys;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tokio_core;
extern crate websocket;

// Modules
pub mod errors;
mod helpers;
mod keystore;
pub mod messages;
pub mod nonce;
mod protocol;

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
use websocket::futures::{Future, Stream, Sink};
use websocket::futures::future::{self, Loop};
use websocket::header::WebSocketProtocol;
use websocket::message::OwnedMessage;

// Re-exports
pub use keystore::{KeyStore, PublicKey, PrivateKey};

// Internal imports
use errors::{Result, Error};
use helpers::libsodium_init;
use messages::{Message};
use nonce::{Nonce};
use protocol::{HandleAction, ServerHandshakeState, Role};


const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";


/// A type alias for a boxed future.
pub type BoxedFuture<T, E> = Box<Future<Item = T, Error = E>>;


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


pub struct SaltyClient {
    role: Role,
    server_handshake_state: ServerHandshakeState,
}

impl SaltyClient {
    pub fn new() -> Self {
        SaltyClient {
            role: Role::Responder, // TODO make this configurable
            server_handshake_state: ServerHandshakeState::New,
        }
    }

    fn handle_message(&mut self, msg: Message, nonce: Nonce) -> HandleAction {
        info!("SaltyClient::handle_message");

        // Do the state transition
        // TODO: The clone is unelegant! Using mem::replace would be better but wont' work here.
        let transition = self.server_handshake_state.clone().next(msg, nonce, self.role);
        trace!("Server handshake state transition: {:?} -> {:?}", self.server_handshake_state, transition.state);
        self.server_handshake_state = transition.state;

        // Return the action with side effects
        transition.action
    }
}


/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
    salty: Rc<RefCell<SaltyClient>>,
) -> Result<BoxedFuture<(), Error>> {
    // Initialize libsodium
    libsodium_init()?;

    // Parse URL
    let ws_url = match Url::parse(url) {
        Ok(b) => b,
        Err(e) => bail!("Could not parse URL: {}", e),
    };

    // Initialize WebSocket client
    let client = ClientBuilder::from_url(&ws_url)
        .add_protocol(SUBPROTOCOL)
        .async_connect_secure(tls_config, handle)
        .map_err(|e: WebSocketError| format!("Could not connect to server: {}", e).into())
        .and_then(|(client, headers)| {
            // Verify that the correct subprotocol was chosen
            trace!("Websocket server headers: {:?}", headers);
            match headers.get::<WebSocketProtocol>() {
                Some(proto) if proto.len() == 1 && proto[0] == SUBPROTOCOL => {
                    Ok(client)
                },
                Some(proto) => {
                    error!("More than one chosen protocol: {:?}", proto);
                    Err("More than one websocket subprotocol chosen by server".into())
                },
                None => {
                    error!("No protocol chosen by server");
                    Err("Websocket subprotocol not accepted by server".into())
                },
            }
        });

    // Send message to server
    let future = client
        .and_then(move |client| {
            info!("Connected to server!");

            // We're connected to the SaltyRTC server.
            // Filter the incoming message stream. We're only interested in the binary ones.
            let messages = client
                .filter_map(|msg| {
                    match msg {
                        OwnedMessage::Binary(bytes) => {
                            debug!("Received binary message");
                            Some(bytes)
                        },
                        m => {
                            // TODO: Handle ping messages
                            warn!("Skipping non-binary message: {:?}", m);
                            None
                        },
                    }
                });

            // Main loop
            boxed!(future::loop_fn(messages, move |stream| {

                let salty = Rc::clone(&salty);

                // Take the next incoming message
                stream.into_future()

                    // Map errors to our custom error type
                    .map_err(|(e, _)| format!("Could not receive message from server: {}", e).into())

                    // Decode nonce and message from the incoming bytes
                    .and_then(|(bytes_option, stream)| {
                        // Unwrap bytes
                        let bytes = bytes_option.ok_or("Server message stream ended")?;

                        // Decode nonce
                        let nonce = match Nonce::from_bytes(&bytes[..24]) {
                            Ok(val) => val,
                            Err(e) => bail!("Could not parse nonce: {}", e),
                        };
                        trace!("Nonce: {:?}", nonce);

                        // Decode message
                        let msg = match Message::from_msgpack(&bytes[24..]) {
                            Ok(msg) => msg,
                            Err(e) => bail!("Could not decode message: {}", e),
                        };
                        trace!("Message: {:?}", msg);

                        Ok((nonce, msg, stream))
                    })

                    // Process received message
                    .and_then(move |(nonce, msg, stream)| {
                        info!("Received {} message", msg.get_type());

                        let handle_action = match salty.deref().try_borrow_mut() {
                            Ok(mut s) => s.handle_message(msg, nonce),
                            Err(e) => return boxed!(
                                future::err(format!("Could not get mutable reference to SaltyClient: {}", e).into())
                            ),
                        };

                        match handle_action {
                            HandleAction::Reply(msg, nonce) => {
                                let mut msg_bytes: Vec<u8> = vec![];
                                msg_bytes.extend(nonce.into_bytes().iter());
                                msg_bytes.extend(msg.to_msgpack().iter());

                                debug!("Sending {} message", msg.get_type());
                                boxed!(stream
                                    .send(OwnedMessage::Binary(msg_bytes))
                                    .map(Loop::Continue)
                                    .map_err(move |e| format!("Could not send {} message: {}", msg.get_type(), e).into()))
                            },
                            HandleAction::None => {
                                boxed!(future::ok(Loop::Continue(stream)))
                            }
                        }
                    })
            }))
        });

    Ok(boxed!(future))
}
