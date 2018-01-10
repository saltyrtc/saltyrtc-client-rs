//! Connect to a server as initiator and print the connection info.

extern crate chrono;
extern crate clap;
extern crate data_encoding;
extern crate dotenv;
extern crate env_logger;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;
extern crate saltyrtc_client;

use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write, stdin, stdout};
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Local;
use clap::{Arg, App, SubCommand};
use data_encoding::{HEXLOWER};
use env_logger::{Builder};
use failure::{Error};

use saltyrtc_client::{SaltyClientBuilder, Role, Task};
use saltyrtc_client::crypto::{KeyPair, AuthToken, public_key_from_hex_str};
use saltyrtc_client::errors::{SaltyResult};
use saltyrtc_client::events::{Event};
use saltyrtc_client::rmpv::{Value};
use saltyrtc_client::ws;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    dotenv::dotenv().ok();
    Builder::new()
        .format(|buf, record| {
            writeln!(buf, "{} [{:<5}] {} ({}:{}, {})",
                     Local::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
                     record.level(),
                     record.args(),
                     record.file().unwrap_or("?"),
                     record.line().map(|num| num.to_string()).unwrap_or("?".to_string()),
                     thread::current().name().unwrap_or("?"))
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

    // Read server certificate bytes
    let mut server_cert_bytes: Vec<u8> = vec![];
    File::open(&Path::new("saltyrtc.der"))
        .expect("Could not open saltyrtc.der")
        .read_to_end(&mut server_cert_bytes)
        .expect("Could not read saltyrtc.der");

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
    let (mut salty, auth_token_hex) = match role {
        Role::Initiator => {
            let task = ChatTask::new("initiat0r");
            let salty = SaltyClientBuilder::new(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval))
                .initiator()
                .expect("Could not create SaltyClient instance");
            let auth_token_hex = HEXLOWER.encode(salty.auth_token_bytes().unwrap().as_ref());
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
    println!();
    println!("Signaling path: {}", path);
    println!("Auth token: {}", auth_token_hex);
    println!();
    println!("To connect with a peer:");
    match role {
        Role::Initiator => println!("cargo run --features 'msgpack-debugging' --example client -- responder \\\n    -p {} \\\n    -a {}", path, auth_token_hex),
        Role::Responder => println!("cargo run --features 'msgpack-debugging' --example client -- initiator"),
    }
    println!("******************************\x1B[0m\n");

    // Connect to server
    salty.connect("localhost", 8765).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(1);
    });

    let mut events = salty.events();

    // Wait for handshake
    loop {
        match events.recv() {
            Ok(event) => {
                println!("An event happened: {:?}", event);
                if event == Event::PeerHandshakeDone {
                    break;
                }
            },
            Err(_) => {
                println!("Event stream ended");
                process::exit(0);
            }
        }
    }

    // Start chat loop
    thread::sleep(Duration::from_millis(1000));
    println!(r" ___       _ _         ___ _         _");
    println!(r"/ __| __ _| | |_ _  _ / __| |_  __ _| |_");
    println!(r"\__ \/ _` | |  _| || | (__| ' \/ _` |  _|");
    println!(r"|___/\__,_|_|\__|\_, |\___|_||_\__,_|\__|");
    println!(r"                 |__/");
    println!();

    // Get an atomic reference to the task.
    let task = salty.task().expect("Task not set").clone();

    fn on_task<F: Fn(&mut ChatTask)>(task: &Arc<Mutex<Box<Task + Send>>>, closure: F) {
        let mut t = task.lock().expect("Could not lock task mutex");
        let mut chat_task: &mut ChatTask = (&mut **t as &mut Task)
            .downcast_mut::<ChatTask>()
            .expect("Chosen task is not a ChatTask");
        closure(&mut chat_task);
    }

    // Print intro
    on_task(&task, |t| {
        let peer_name: String = t.peer_name.clone().unwrap_or("?".into());
        print!("Hi \"{}\"! We're the {} chatting with \"{}\".\n\n{}> ",
               &t.our_name, t.role.unwrap(), &peer_name, &t.our_name);
        stdout().flush().unwrap();
    });

    // Main loop
    loop {
        //print!("{}> ", )
        let mut input = String::new();
        stdin().read_line(&mut input)
            .expect("Failed to read line");

        match &*input.trim() {
            "/q" | "/quit" => {
                println!("Goodbye.");
                break;
            },
            "/h" | "/help" | "/?" | "" => {
                println!("Enter a message. To quit, enter \"/q\" or \"/quit\".");
                on_task(&task, |t| {
                    print!("{}> ", &t.our_name);
                    stdout().flush().unwrap();
                });
                continue;
            },
            _ => {},
        }

        on_task(&task, |t| {
            t.send_message(&input).expect("Could not send message");
            print!("{}> ", &t.our_name);
            stdout().flush().unwrap();
        });
    }
}

struct ChatTask {
    our_name: String,
    peer_name: Option<String>,
    role: Option<Role>,
    sender: Option<ws::Sender>,
    encrypt_for_peer: Option<Box<Fn(Value) -> SaltyResult<Vec<u8>> + Send>>,
}

impl PartialEq for ChatTask {
    fn eq(&self, other: &ChatTask) -> bool {
        self.our_name == other.our_name &&
            self.peer_name == other.peer_name &&
            self.sender == other.sender
    }
}

impl ChatTask {
    pub fn new<S: Into<String>>(our_name: S) -> Self {
        ChatTask {
            our_name: our_name.into(),
            peer_name: None,
            role: None,
            sender: None,
            encrypt_for_peer: None,
        }
    }

    pub fn send_message(&self, msg: &str) -> Result<(), String> {
        // Get access to WebSocket sender
        let sender = match self.sender {
            Some(ref sender) => sender,
            None => return Err("WebSocket sender not initialized".into()),
        };

        // Convert text to message
        let value = Value::from(msg);

        // Encrypt message
        let encrypted = match self.encrypt_for_peer {
            Some(ref func) => func(value).map_err(|e| format!("Cannot encrypt message: {}", e))?,
            None => return Err("encrypt_for_peer function not set".to_string()),
        };

        // Send message
        let ws_msg = ws::Message::Binary(encrypted);
        sender.send(ws_msg).map_err(|e| format!("Could not send message: {}", e))
    }
}

impl fmt::Debug for ChatTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ChatTask(nick={})", &self.our_name)
    }
}

impl Task for ChatTask {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        let peer_name: String = match *data {
            Some(ref map) => match map.get("nickname") {
                Some(&Value::String(ref nickname)) => nickname.as_str().unwrap_or("?").to_string(),
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
    fn on_peer_handshake_done(
        &mut self,
        role: Role,
        sender: ws::Sender,
        encrypt_for_peer: Box<Fn(Value) -> SaltyResult<Vec<u8>> + Send>,
    ) {
        info!("ChatTask taking over!");
        self.role = Some(role);
        self.sender = Some(sender);
        self.encrypt_for_peer = Some(encrypt_for_peer);
    }

    /// Return a list of message types supported by this task.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn supported_types(&self) -> &[&'static str] {
        &["msg", "nick_change"]
    }

    /// This method is called by SaltyRTC when a task related message
    /// arrives through the WebSocket.
    fn on_task_message(&mut self, message: Value) {
        match message {
            Value::String(utf8str) => {
                let peer_name: String = self.peer_name.clone().unwrap_or("?".into());
                print!("\n{}> {}\n{}> ", &peer_name, utf8str.as_str().unwrap().trim(), &self.our_name);
                stdout().flush().unwrap();
            },
            other => error!("Received invalid message type: {:?}", other),
        }
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
