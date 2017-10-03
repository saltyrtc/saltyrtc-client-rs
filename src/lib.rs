//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate rmp_serde;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sodiumoxide;
extern crate tokio_core;
extern crate websocket;

pub mod errors;
pub mod messages;

use native_tls::TlsConnector;
use tokio_core::reactor::{Handle};
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::client::builder::Url;
use websocket::header::WebSocketProtocol;
use websocket::message::OwnedMessage;
use websocket::futures::{Future, Stream};

use errors::{Result, Error};
use messages::MsgPacked;


const SUBPROTOCOL: &'static str = "v1.saltyrtc.org";


/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
) -> Result<Box<Future<Item = (), Error = Error>>> {

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
                    // TODO: Parse nonce
                    match messages::ServerHello::from_msgpack(&bytes[24..]) {
                        Ok(val) => info!("Server hello: {:?}", val),
                        Err(e) => error!("Could not deserialize server-hello message: {}", e),
                    };
                    Ok(messages)
                })

                // For now, stop processing here.
                .map(|_| ())

        });

    Ok(Box::new(future))
}
