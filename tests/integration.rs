//! Integration tests.
//!
//! These tests require a SaltyRTC server running on `localhost:8765`
//! and a `saltyrtc.der` CA certificate in the repository root directory.

extern crate failure;
extern crate saltyrtc_client;

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use failure::Error;
use saltyrtc_client::{SaltyClient, CloseCode};
use saltyrtc_client::crypto::KeyPair;
use saltyrtc_client::dep::native_tls::{Certificate, TlsConnector, Protocol};
use saltyrtc_client::dep::futures::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use saltyrtc_client::dep::futures::sync::oneshot::Sender as OneshotSender;
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::tasks::{Task, TaskMessage};


fn get_tls_connector() -> TlsConnector {
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
    tls_builder.supported_protocols(&[Protocol::Tlsv12, Protocol::Tlsv11, Protocol::Tlsv10])
        .unwrap_or_else(|e| panic!("Could not set TLS protocols: {}", e));
    tls_builder.add_root_certificate(server_cert)
        .unwrap_or_else(|e| panic!("Could not add root certificate: {}", e));

    tls_builder.build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e))
}

/// Connection timeout to a server should be configurable.
#[test]
fn connection_error() {
    let keypair = KeyPair::new();
    let task = DummyTask::new(1);
    let salty = SaltyClient::build(keypair)
        .add_task(Box::new(task))
        .with_ping_interval(Some(Duration::from_secs(30)))
        .initiator()
        .expect("Could not create SaltyClient instance");

    //saltyrtc_client::connect()
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct DummyTask {
    pub id: u8,
    pub initialized: bool,
}

impl DummyTask {
    pub fn new(id: u8) -> Self {
        DummyTask {
            id,
            initialized: false,
        }
    }

    pub fn name_for(id: u8) -> String {
        format!("dummy.{}", id)
    }
}

impl Task for DummyTask {
    fn init(&mut self, _data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        self.initialized = true;
        Ok(())
    }

    fn start(&mut self, _: UnboundedSender<TaskMessage>, _: UnboundedReceiver<TaskMessage>, _: OneshotSender<Option<CloseCode>>) {
        unimplemented!()
    }

    fn supported_types(&self) -> &'static [&'static str] {
        &["dummy"]
    }

    fn send_signaling_message(&self, _payload: &[u8]) {
        unimplemented!()
    }

    fn name(&self) -> Cow<'static, str> {
        DummyTask::name_for(self.id).into()
    }

    fn data(&self) -> Option<HashMap<String, Value>> {
        None
    }

    fn close(&mut self, _reason: CloseCode) {
        unimplemented!()
    }
}
