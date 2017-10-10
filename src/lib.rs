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

// Rust imports
use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

// Third party imports
use native_tls::TlsConnector;
use rust_sodium::crypto::box_ as cryptobox;
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
use messages::{Message, ClientHello};
use nonce::{Nonce, Sender, Receiver};


const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";


pub struct SaltyClient { }

impl SaltyClient {
    pub fn new() -> Self {
        SaltyClient { }
    }

    //fn handle_message(msg: Message, nonce: Nonce) {
    fn handle_message(&self) {
        info!("SaltyClient::handle_message");
    }
}


/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
    salty: Rc<RefCell<SaltyClient>>,
) -> Result<Box<Future<Item = (), Error = Error>>> {
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
            future::loop_fn(messages, move |stream| {

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
                    .and_then(move |(_nonce, msg, stream)| {
                        info!("Received {} message", msg.get_type());

                        match salty.deref().try_borrow_mut() {
                            Ok(s) => s.handle_message(),
                            Err(e) => {
                                return Box::new(
                                    future::err(format!("Could not get mutable reference to SaltyClient: {}", e).into())
                                ) as Box<Future<Item = _, Error = _>>;
                            },
                        };

                        // Handle depending on type
                        match msg {

                            Message::ServerHello(server_hello) => {
                                info!("Hello from server");

                                trace!("Server key is {:?}", server_hello.key);

                                // Generate keypair
                                let (ourpk, _oursk) = cryptobox::gen_keypair();

                                // Reply with client-hello message
                                let client_hello = ClientHello::new(ourpk).into_message();
                                let client_nonce = Nonce::new(
                                    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                                    Sender::new(0),
                                    Receiver::new(0),
                                    0,
                                    123,
                                );
                                let mut client_hello_bytes: Vec<u8> = vec![];
                                client_hello_bytes.extend(client_nonce.into_bytes().iter());
                                client_hello_bytes.extend(client_hello.to_msgpack().iter());

                                trace!("Sending {:?}", client_hello);
                                Box::new(stream
                                    .send(OwnedMessage::Binary(client_hello_bytes))
                                    .map(Loop::Continue)
                                    .map_err(|e| format!("Could not send client-hello message: {}", e).into()))
                                    as Box<Future<Item = _, Error = _>>
                            },

                            Message::ClientHello(_) => {
                                error!("Received invalid message: {}", msg.get_type());
                                Box::new(future::ok(Loop::Break("hoo".to_string())))
                            },

                        }
                    })
            })
        })
        .map(|_| ());

    Ok(Box::new(future))
}
