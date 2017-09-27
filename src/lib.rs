//! SaltyRTC client implementation in Rust.
//!
//! Early prototype.

#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate native_tls;
extern crate tokio_core;
extern crate websocket;

pub mod errors;

use native_tls::TlsConnector;
use tokio_core::reactor::Handle;
use websocket::Message;
use websocket::async::TcpStream;
use websocket::client::async::{ClientNew, TlsStream};
use websocket::client::ClientBuilder;
use websocket::futures::{Future, Sink, Stream};

use errors::{Result, Error};


/// Connect to the specified SaltyRTC server.
pub fn connect(
    url: &str,
    tls_config: Option<TlsConnector>,
    handle: &Handle,
) -> Result<Box<Future<Item = (), Error = Error>>> {
    let builder = match ClientBuilder::new(url) {
        Ok(b) => b,
        Err(e) => bail!("Could not parse URL: {}", e),
    };
    let future = builder
        .async_connect_secure(tls_config, handle)
        .and_then(|(s, _)| s.send(Message::text("hallo").into()))
        .and_then(|s| s.into_future().map_err(|e| e.0))
        .map(|(m, _)| {
            println!("Received answer: {:?}", m);
            assert_eq!(m, Some(Message::text("hallo").into()))
        })
        .map_err(|e| format!("Error while processing server answer: {}", e).into());
    Ok(Box::new(future))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
