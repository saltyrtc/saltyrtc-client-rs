//! Connect to a server as initiator and print the connection info.

extern crate data_encoding;
extern crate docopt;
extern crate env_logger;
extern crate native_tls;
extern crate saltyrtc_client;
#[macro_use]
extern crate serde_derive;
extern crate tokio_core;

use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;
use std::rc::Rc;

use data_encoding::HEXLOWER;
use docopt::Docopt;
use native_tls::{TlsConnector, Certificate, Protocol};
use tokio_core::reactor::Core;

use saltyrtc_client::{SaltyClient, KeyStore, Role};


const USAGE: &'static str = "
SaltyRTC test client.

Usage:
  client initiator
  client responder -p <path> -a <auth-token>
  client (-h | --help)
  client --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  -p            The websocket path (hex encoded public key of the initiator).
  -a            The auth token (hex encoded).
";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_initiator: bool,
    cmd_responder: bool,
    arg_path: String,
    arg_auth_token: String,
}

fn main() {
    env_logger::init().expect("Could not initialize env_logger");

    // Parse arguments
    let args: Args = Docopt::new(USAGE)
                        .and_then(|d| d.deserialize())
                        .unwrap_or_else(|e| e.exit());

    let role = if args.cmd_initiator {
        Role::Initiator
    } else {
        Role::Responder
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
        Role::Responder => args.arg_path,
    };

    // Create new SaltyRTC client instance
    let salty = Rc::new(RefCell::new(SaltyClient::new(keystore, role)));
    let task = saltyrtc_client::connect(
            &format!("wss://localhost:8765/{}", path),
            Some(tls_connector),
            &core.handle(),
            salty.clone(),
        ).unwrap();

    println!("\n====================");
    println!("Connecting as {}\n", role);
    println!("Signaling path: {}", path);

    match (*salty).borrow().auth_token().as_ref() {
        Some(token) => println!("Auth token: {}", HEXLOWER.encode(token.secret_key_bytes())),
        None => println!("Auth token: {}", args.arg_auth_token),
    }
    println!("====================\n");

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
