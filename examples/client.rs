//! Connect to a server as initiator and print the connection info.

extern crate clap;
extern crate data_encoding;
extern crate env_logger;
extern crate native_tls;
extern crate saltyrtc_client;
extern crate tokio_core;

use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;
use std::rc::Rc;

use clap::{Arg, App, SubCommand};
use data_encoding::HEXLOWER;
use native_tls::{TlsConnector, Certificate, Protocol};
use tokio_core::reactor::Core;

use saltyrtc_client::{SaltyClient, KeyStore, Role, AuthToken};


pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    env_logger::init().expect("Could not initialize env_logger");

    const ARG_PATH: &'static str = "path";
    const ARG_AUTHTOKEN: &'static str = "authtoken";

    // Set up CLI arguments
    let app = App::new("SaltyRTC Test Client")
        .version(VERSION)
        .author("Danilo Bargen <mail@dbrgn.ch>")
        .about("Test client for SaltyRTC.")
        .subcommand(SubCommand::with_name("initiator")
            .about("Start client as initiator"))
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
                .help("The auth token (hex encoded)")));

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
        .unwrap()
        .read_to_end(&mut server_cert_bytes)
        .unwrap();

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
    let keystore = KeyStore::new().unwrap();

    // Determine websocket path
    let path = match role {
        Role::Initiator => keystore.public_key_hex(),
        Role::Responder => args.value_of(ARG_PATH).expect("Path not supplied").to_string(),
    };

    // Create new SaltyRTC client instance
    let (salty, auth_token_hex) = match role {
        Role::Initiator => {
            let salty = SaltyClient::new_initiator(keystore);
            let auth_token_hex = HEXLOWER.encode(salty.auth_token().unwrap().secret_key_bytes());
            (
                salty,
                auth_token_hex
            )
        },
        Role::Responder => {
            let auth_token_hex = args.value_of(ARG_AUTHTOKEN).expect("Auth token not supplied").to_string();
            let auth_token = AuthToken::from_hex_str(&auth_token_hex).expect("Invalid auth token hex string");
            (
                SaltyClient::new_responder(keystore, Some(auth_token)),
                auth_token_hex
            )
        },
    };

    // Create connect task
    let task = saltyrtc_client::connect(
            &format!("wss://localhost:8765/{}", path),
            Some(tls_connector),
            &core.handle(),
            Rc::new(RefCell::new(salty)),
        ).unwrap();

    println!("\n\x1B[32m******************************");
    println!("Connecting as {}", role);
    println!("");
    println!("Signaling path: {}", path);
    println!("Auth token: {}", auth_token_hex);
    println!("");
    println!("To connect with a peer:");
    match role {
        Role::Initiator => println!("cargo run --example client -- responder \\\n    -p {} \\\n    -a {}", path, auth_token_hex),
        Role::Responder => println!("cargo run --example client -- initiator"),
    }
    println!("******************************\x1B[0m\n");

    match core.run(task) {
        Ok(x) => {
            println!("Success: {:?}", x);
        },
        Err(e) => {
            println!("{}", e);
            if let Some(cause) = e.cause() {
                println!("Cause: {}", cause);
            }
            process::exit(1);
        },
    };
}
