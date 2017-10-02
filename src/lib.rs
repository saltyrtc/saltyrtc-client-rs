//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate native_tls;
extern crate sodiumoxide;
extern crate tokio_core;
extern crate websocket;

pub mod errors;

use native_tls::TlsConnector;
use tokio_core::reactor::Handle;
use websocket::WebSocketError;
use websocket::client::async::{Client, TlsStream, TcpStream};
use websocket::client::ClientBuilder;
use websocket::futures::Future;

use errors::Result;


/// Connect to the specified SaltyRTC server.
/// 
/// Return a `Client` instance as a future.
fn get_client(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
) -> Result<Box<Future<Item = Client<TlsStream<TcpStream>>, Error = WebSocketError>>> {
    let builder = match ClientBuilder::new(url) {
        Ok(b) => b,
        Err(e) => bail!("Could not parse URL: {}", e),
    };
    let future = builder
        .async_connect_secure(tls_config, handle)
        .map(|(client, _headers)| client);
    Ok(Box::new(future))
}

/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
) -> Result<Box<Future<Item = Client<TlsStream<TcpStream>>, Error = WebSocketError>>> {
    get_client(url, tls_config, handle)
}
