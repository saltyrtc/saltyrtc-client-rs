//! Connect to a server as initiator and print the connection info.

extern crate chrono;
extern crate clap;
#[macro_use] extern crate crossbeam_channel as cc;
extern crate data_encoding;
extern crate dotenv;
extern crate env_logger;
#[macro_use] extern crate failure;
#[macro_use] extern crate log;
extern crate saltyrtc_client;

mod chat_task;

use std::env;
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

use saltyrtc_client::{SaltyClientBuilder, Role, Task};
use saltyrtc_client::crypto::{KeyPair, AuthToken, public_key_from_hex_str};
use saltyrtc_client::events::{Event};

use chat_task::ChatTask;

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
    let app = App::new("SaltyRTC Chat Demo")
        .version(VERSION)
        .author("Danilo Bargen <mail@dbrgn.ch>")
        .about("Chat demo for SaltyRTC.")
        .subcommand(SubCommand::with_name("initiator")
            .about("Start chat as initiator")
            .arg(arg_ping_interval.clone()))
        .subcommand(SubCommand::with_name("responder")
            .about("Start chat as responder")
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
        Role::Initiator => println!("cargo run --example chat -- responder \\\n    -p {} \\\n    -a {}", path, auth_token_hex),
        Role::Responder => println!("cargo run --example chat -- initiator"),
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

    thread::sleep(Duration::from_millis(1000));

    // Get an atomic reference to the task.
    let task_mutex = salty.task().expect("Task not set").clone();
    let mut task = task_mutex.lock().expect("Could not lock task mutex");
    let chat_task: &mut ChatTask = (&mut **task as &mut Task)
        .downcast_mut::<ChatTask>()
        .expect("Chosen task is not a ChatTask");

    // Start chat loop
    chat_task.main_loop().unwrap();
}
