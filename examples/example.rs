extern crate env_logger;
extern crate native_tls;
extern crate saltyrtc_client;
extern crate tokio_core;

use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::rc::Rc;

use native_tls::{TlsConnector, Certificate, Protocol};
use tokio_core::reactor::Core;


fn main() {
    env_logger::init().expect("Could not initialize env_logger");

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

    let path = "0123456789012345678901234567890101234567890123456789012345678901";
    let salty = Rc::new(RefCell::new(saltyrtc_client::SaltyClient::new().unwrap()));
    let task = saltyrtc_client::connect(
            &format!("wss://localhost:8765/{}", path),
            Some(tls_connector),
            &core.handle(),
            salty,
        ).unwrap();

    match core.run(task) {
        Ok(x) => println!("Success: {:?}", x),
        Err(e) => {
            println!("{}", e);
            if let Some(cause) = e.cause() {
                println!("Cause: {}", cause);
            }
        },
    };
}
