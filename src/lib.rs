//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]

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

// Third party imports
use native_tls::TlsConnector;
use rust_sodium::crypto::box_ as cryptobox;
use tokio_core::reactor::{Handle};
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::client::builder::Url;
use websocket::header::WebSocketProtocol;
use websocket::message::OwnedMessage;
use websocket::futures::{Future, Stream, Sink};

// Re-exports
pub use keystore::{KeyStore, PublicKey, PrivateKey};

// Internal imports
use errors::{Result, Error};
use helpers::libsodium_init;
use messages::MsgPacked;


const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";


/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
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
        .and_then(|client| {
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
                            warn!("Skipping non-binary message: {:?}", m);
                            None
                        },
                    }
                });

            // Process the stream of binary messages
            messages

                // Get the first message from the message stream
                .into_future()

                // Handle errors
                // TODO: What type of errors can happen here?
                .map_err(|(e, _)| format!("Could not receive message from server: {}", e).into())

                // The first message must be the server-hello message
                .and_then(|(bytes_option, messages)| {
                    let bytes = bytes_option.ok_or(format!("Server message stream ended"))?;
                    let nonce = match nonce::Nonce::from_bytes(&bytes[..24]) {
                        Ok(val) => val,
                        Err(e) => bail!("Could not parse nonce: {}", e),
                    };
                    trace!("Nonce: {:?}", nonce);
                    let server_hello = match messages::ServerHello::from_msgpack(&bytes[24..]) {
                        Ok(val) => val,
                        Err(e) => bail!("Could not deserialize server-hello message: {}", e),
                    };
                    info!("Received server-hello");
                    trace!("Server hello: {:?}", server_hello);

                    // Generate keypair
                    let (ourpk, oursk) = cryptobox::gen_keypair();

                    // Reply with client-hello message
                    let client_hello = messages::ClientHello::new(ourpk.clone());
                    let client_nonce = nonce::Nonce::new(
                        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
                        nonce::Sender::new(0),
                        nonce::Receiver::new(0),
                        0,
                        123,
                    );
                    let mut client_hello_bytes: Vec<u8> = vec![];
                    client_hello_bytes.extend(client_nonce.into_bytes().iter());
                    client_hello_bytes.extend(client_hello.to_msgpack().iter());
                    trace!("Sending {:?}", client_hello);

                    Ok(messages.send(OwnedMessage::Binary(client_hello_bytes)))
                })

                // For now, stop processing here.
                .map(|_| ())

        });

    Ok(Box::new(future))
}
