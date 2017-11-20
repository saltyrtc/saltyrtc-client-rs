extern crate tokio_core;
extern crate websocket;

use std::env;
use std::process;
use tokio_core::reactor::{Core, Handle};
use websocket::WebSocketError;
use websocket::client::ClientBuilder;
use websocket::futures::{Future, Stream, Sink};
use websocket::futures::future::{self, Loop};
use websocket::futures::stream;
use websocket::message::{Message, OwnedMessage};

/// A type alias for a boxed future.
pub type BoxedFuture<T, E> = Box<Future<Item = T, Error = E>>;

/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}

fn send(handle: &Handle) -> BoxedFuture<(), WebSocketError> {
    let future = ClientBuilder::new("ws://demos.kaazing.com/echo").unwrap()
        .async_connect(None, handle)
        .map(|(client, _)| client)

        // Send messages
        .and_then(|client| client.send(Message::text("echo 1").into()))
        .and_then(|client| client.send(Message::text("echo 2").into()))
        .and_then(|client| client.send(Message::text("echo 3").into()))
        .and_then(|client| {
            println!("  3 messages sent");
            future::ok(client)
        })

        // Receive replies
        .and_then(|client| {
            let main_loop: BoxedFuture<(), WebSocketError> = boxed!(
                future::loop_fn(client, move |client| {
                    client.into_future()
                        .map_err(|e| e.0)
                        .and_then(|(msg, framed)| {
                            println!("  Incoming reply: {:?}", msg);
                            future::ok(Loop::Continue(framed))
                        })
                })
            );
            main_loop
        })
        .map(|_| ());

    boxed!(future)
}

fn send_all(handle: &Handle) -> BoxedFuture<(), WebSocketError> {
    let future = ClientBuilder::new("ws://demos.kaazing.com/echo").unwrap()
        .async_connect(None, handle)
        .map(|(client, _)| client)

        // Send initial message
        .and_then(|client| client.send(Message::text("echo 1").into()))
        .and_then(|client| {
            println!("  Sent initial message");
            future::ok(client)
        })

        // Receive replies and send more messages
        .and_then(|client| {
            let main_loop: BoxedFuture<(), WebSocketError> = boxed!(
                future::loop_fn(client, |client| {
                    client.into_future()
                        .map_err(|e| e.0)
                        .and_then(|(msg, client)| {
                            let msgstr = format!("{:?}", msg);
                            println!("  Incoming reply: {}", msgstr);

                            if msgstr.contains("echo 1") {
                                let messages = vec![
                                    OwnedMessage::Text("echo 2".into()),
                                    OwnedMessage::Text("echo 3".into()),
                                ];
                                let outbox = stream::iter_ok::<_, WebSocketError>(messages);
                                let future = client
                                    .send_all(outbox)
                                    .map(|(client, _)| {
                                        println!("  Sent all messages");
                                        client
                                    })
                                    .and_then(|client| {
                                        future::ok(Loop::Continue(client))
                                    });
                                boxed!(future)
                            } else {
                                boxed!(future::ok(Loop::Continue(client)))
                            }
                        })
                })
            );
            main_loop
        })
        .map(|_| ());

    boxed!(future)
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
enum Method {
    Send,
    SendAll,
}

fn main() {
    let method = match env::args().nth(1) {
        Some(ref val) => if val == "send" {
            Method::Send
        } else if val == "send_all" {
            Method::SendAll
        } else {
            println!("Invalid method \"{}\", must be either \"send\" or \"send_all\".", val);
            process::exit(1);
        },
        None => {
            println!("Please specify either \"send\" or \"send_all\" as command line argument");
            process::exit(1);
        }
    };

    let mut core = Core::new().unwrap();

    let future = match method {
        Method::Send => send(&core.handle()),
        Method::SendAll => send_all(&core.handle()),
    };

    println!("Using method {:?}", method);
    match core.run(future) {
        Ok(_) => println!("  => Success"),
        Err(e) => println!("  => Error: {}", e),
    };
}
