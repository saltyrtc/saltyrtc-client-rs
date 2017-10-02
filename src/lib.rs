//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate futures;
#[macro_use]
extern crate log;
extern crate native_tls;
extern crate rmp_serde as rmps;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sodiumoxide;
extern crate tokio_core;
extern crate websocket;

pub mod errors;
pub mod messages;

use futures::future;
use native_tls::TlsConnector;
use tokio_core::reactor::{Handle, Timeout};
use websocket::Message;
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::client::async::{Client, TlsStream, TcpStream};
use websocket::client::builder::Url;
use websocket::header::WebSocketProtocol;
use websocket::message::OwnedMessage;
use websocket::futures::{Future, Stream, Sink};

use errors::{Result, Error};


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
                Some(proto) => Err("More than one websocket subprotocol chosen by server".into()),
                None => Err("Websocket subprotocol not accepted by server".into()),
            }
        });

    // Send message to server
    let future = client
        .and_then(|client| {
            info!("Connected to server!");
            let (sink, stream) = client.split();
            stream
                .filter_map(|msg| {
                    //debug!("Received message: {:?}", msg);
                    debug!("Received message");
                    match msg {
                        OwnedMessage::Binary(bytes) => {
                            debug!("Matched binary");
                            Some(bytes)
                        },
                        _ => {
                            debug!("Matched other");
                            None
                        }
                    }
                })
                .take(1)
                .into_future()
                .map(|x| x.0)
                .map_err(|e| "Could not receive message from server".into())
        })
        .map(|bytes| {
            let bytes = bytes.unwrap();
            trace!("Future resolved. Bytes: {:?}", bytes);
            // TODO: Parse nonce
            match rmps::from_slice::<messages::ServerHello>(&bytes[24..]) {
                Ok(val) => info!("Server hello: {:?}", val),
                Err(e) => error!("Could not deserialize server-hello message: {}", e),
            };
        });

    Ok(Box::new(future))
}
