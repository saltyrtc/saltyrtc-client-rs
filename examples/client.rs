//! Connect to a server as initiator and print the connection info.

extern crate chrono;
extern crate clap;
extern crate data_encoding;
extern crate dotenv;
extern crate env_logger;
#[macro_use] extern crate failure;
extern crate futures;
#[macro_use] extern crate log;
extern crate native_tls;
extern crate saltyrtc_client;
extern crate tokio_core;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process;
use std::rc::Rc;
use std::time::Duration;

use chrono::Local;
use clap::{Arg, App, SubCommand};
use data_encoding::{HEXLOWER};
use env_logger::{Builder};
use failure::{Error};
use futures::future::{Future};
use native_tls::{TlsConnector, Certificate, Protocol};
use tokio_core::reactor::{Core};

use saltyrtc_client::{SaltyClientBuilder, Role, Task};
use saltyrtc_client::crypto::{KeyPair, AuthToken, public_key_from_hex_str};
use saltyrtc_client::rmpv::{Value};


pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    dotenv::dotenv().ok();
    Builder::new()
        .format(|buf, record| {
            writeln!(buf, "{} [{:<5}] {} ({}:{})",
                     Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                     record.level(),
                     record.args(),
                     record.file().unwrap_or("?"),
                     record.line().map(|num| num.to_string()).unwrap_or("?".to_string()))
        })
        .parse(&env::var("RUST_LOG").unwrap_or_default())
        .init();

    const ARG_PATH: &'static str = "path";
    const ARG_AUTHTOKEN: &'static str = "authtoken";
    const ARG_PING_INTERVAL: &'static str = "ping_interval";

    // Set up CLI arguments
    let arg_ping_interval = Arg::with_name(ARG_PING_INTERVAL)
        .short("i")
        .takes_value(true)
        .value_name("SECONDS")
        .required(false)
        .default_value("30")
        .help("The WebSocket ping interval (set to 0 to disable pings)");
    let app = App::new("SaltyRTC Test Client")
        .version(VERSION)
        .author("Danilo Bargen <mail@dbrgn.ch>")
        .about("Test client for SaltyRTC.")
        .subcommand(SubCommand::with_name("initiator")
            .about("Start client as initiator")
            .arg(arg_ping_interval.clone()))
        .subcommand(SubCommand::with_name("responder")
            .about("Start client as responder")
            .arg(Arg::with_name(ARG_PATH)
                .short("p")
                .takes_value(true)
                .value_name("PATH")
                .required(true)
                .help("The websocket path (hex encoded public key of the initiator)"))
            .arg(Arg::with_name(ARG_AUTHTOKEN)
                .short("a")
                .alias("token")
                .alias("authtoken")
                .takes_value(true)
                .value_name("AUTHTOKEN")
                .required(true)
                .help("The auth token (hex encoded)"))
            .arg(arg_ping_interval));

    // Parse arguments
    let subcommand = app.get_matches().subcommand.unwrap_or_else(|| {
        println!("Missing subcommand.");
        println!("Use -h or --help to see usage.");
        process::exit(1);
    });
    let args = &subcommand.matches;

    // Determine role
    let role = match &*subcommand.name {
        "initiator" => Role::Initiator,
        "responder" => Role::Responder,
        other => {
            println!("Invalid subcommand: {}", other);
            process::exit(1);
        },
    };

    // Tokio reactor core
    let mut core = Core::new().unwrap();

    // Read server certificate bytes
    let mut server_cert_bytes: Vec<u8> = vec![];
    File::open(&Path::new("saltyrtc.der"))
        .expect("Could not open saltyrtc.der")
        .read_to_end(&mut server_cert_bytes)
        .expect("Could not read saltyrtc.der");

    // Parse server certificate
    let server_cert = Certificate::from_der(&server_cert_bytes)
        .unwrap_or_else(|e| {
            panic!("Problem with CA cert: {}", e);
        });

    // Create TLS connector instance
    let mut tls_builder = TlsConnector::builder()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector builder: {}", e));
    tls_builder.supported_protocols(&[Protocol::Tlsv11, Protocol::Tlsv11, Protocol::Tlsv10])
        .unwrap_or_else(|e| panic!("Could not set TLS protocols: {}", e));
    tls_builder.add_root_certificate(server_cert)
        .unwrap_or_else(|e| panic!("Could not add root certificate: {}", e));
    let tls_connector = tls_builder.build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e));

    // Create new public permanent keypair
    let keypair = KeyPair::new();

    // Determine websocket path
    let path: String = match role {
        Role::Initiator => keypair.public_key_hex(),
        Role::Responder => args.value_of(ARG_PATH).expect("Path not supplied").to_lowercase(),
    };

    // Determine ping interval
    let ping_interval = {
        let seconds: u64 = args.value_of(ARG_PING_INTERVAL).expect("Ping interval not supplied")
                               .parse().expect("Could not parse interval seconds to a number");
        Duration::from_secs(seconds)
    };

    // Create new SaltyRTC client instance
    let (salty, auth_token_hex) = match role {
        Role::Initiator => {
            let task = ChatTask::new("initiat0r");
            let salty = SaltyClientBuilder::new(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval))
                .initiator()
                .expect("Could not create SaltyClient instance");
            let auth_token_hex = HEXLOWER.encode(salty.auth_token().unwrap().secret_key_bytes());
            (salty, auth_token_hex)
        },
        Role::Responder => {
            let task = ChatTask::new("r3spond3r");
            let auth_token_hex = args.value_of(ARG_AUTHTOKEN).expect("Auth token not supplied").to_string();
            let auth_token = AuthToken::from_hex_str(&auth_token_hex).expect("Invalid auth token hex string");
            let initiator_pubkey = public_key_from_hex_str(&path).unwrap();
            let salty = SaltyClientBuilder::new(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval))
                .responder(initiator_pubkey, Some(auth_token))
                .expect("Could not create SaltyClient instance");
            (salty, auth_token_hex)
        },
    };

    println!("\n\x1B[32m******************************");
    println!("Connecting as {}", role);
    println!("");
    println!("Signaling path: {}", path);
    println!("Auth token: {}", auth_token_hex);
    println!("");
    println!("To connect with a peer:");
    match role {
        Role::Initiator => println!("cargo run --features 'msgpack-debugging' --example client -- responder \\\n    -p {} \\\n    -a {}", path, auth_token_hex),
        Role::Responder => println!("cargo run --features 'msgpack-debugging' --example client -- initiator"),
    }
    println!("******************************\x1B[0m\n");

    // Wrap SaltyClient in a Rc<RefCell<>>
    let salty_rc = Rc::new(RefCell::new(salty));

    // Connect to server
    let (connect_future, _incoming_rx, _outgoing_tx) = saltyrtc_client::connect(
            &format!("wss://localhost:8765/{}", path),
            Some(tls_connector),
            &core.handle(),
            salty_rc.clone(),
        )
        .unwrap();

    // Do handshake
    let handshake_future = connect_future
        .map(|client| { println!("Connected to server"); client })
        .and_then(|client| saltyrtc_client::do_handshake(client, salty_rc.clone()))
        .map(|client| { println!("Handshake done"); client });

    // Start task loop
    let task_future = handshake_future
        .and_then(|client| saltyrtc_client::task_loop(client, salty_rc.clone()));

    // Run future in reactor
    match core.run(task_future) {
        Ok(_) => {
            println!("Success.");
        },
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        },
    };
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct ChatTask {
    our_name: String,
    peer_name: Option<String>,
}

impl ChatTask {
    pub fn new<S: Into<String>>(our_name: S) -> Self {
        ChatTask {
            our_name: our_name.into(),
            peer_name: None,
        }
    }
}

impl Task for ChatTask {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        let peer_name: String = match *data {
            Some(ref map) => match map.get("nickname") {
                Some(&Value::String(ref nickname)) => nickname.to_string(),
                Some(ref val) => bail!("The \"nickname\" field has the wrong type: {:?}", val),
                None => bail!("No \"nickname\" field in data passed to task initialization"),
            },
            None => bail!("No data passed to task initialization"),
        };
        self.peer_name = Some(peer_name);
        Ok(())
    }

    /// Used by the signaling class to notify task that the peer handshake is over.
    ///
    /// This is the point where the task can take over.
    fn on_peer_handshake_done(&mut self) {
        info!("Peer handshake done");
        // TODO
    }

    /// Return whether the specified message type is supported by this task.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn type_supported(&self, type_: &str) -> bool {
        match type_ {
            "msg" | "nick_change" => true,
            _ => false,
        }
    }

    /// This method is called by SaltyRTC when a task related message
    /// arrives through the WebSocket.
    fn on_task_message(&mut self, message: Value) {
        info!("New message arrived: {:?}", message);
    }

    /// Send bytes through the task signaling channel.
    ///
    /// This method should only be called after the handover.
    ///
    /// Note that the data passed in to this method should *not* already be encrypted. Otherwise,
    /// data will be encrypted twice.
    fn send_signaling_message(&self, _payload: &[u8]) {
        panic!("send_signaling_message called even though task does not implement handover");
    }

    /// Return the task protocol name.
    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("v0.simplechat.tasks.saltyrtc.org")
    }

    /// Return the task data used for negotiation in the `auth` message.
    /// This data will be sent to the peer.
    fn data(&self) -> Option<HashMap<String, Value>> {
        let mut map = HashMap::new();
        map.insert("nickname".to_string(), self.our_name.clone().into());
        Some(map)
    }

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, _reason: u8) {
        // TODO
    }
}
