//! Integration tests.
//!
//! These tests require a SaltyRTC server running on `localhost:8765`
//! and a `saltyrtc.der` CA certificate in the repository root directory.

extern crate failure;
extern crate log;
extern crate log4rs;
extern crate saltyrtc_client;
extern crate tokio_core;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::rc::Rc;
use std::str;
use std::time::Duration;

use failure::Error;
use log::{LevelFilter, Record};
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::Encode;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::writer::simple::SimpleWriter;
use saltyrtc_client::{SaltyClient, CloseCode, WsClient};
use saltyrtc_client::crypto::KeyPair;
use saltyrtc_client::errors::SaltyError;
use saltyrtc_client::dep::futures::Future;
use saltyrtc_client::dep::native_tls::{Certificate, TlsConnector, Protocol};
use saltyrtc_client::dep::futures::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use saltyrtc_client::dep::futures::sync::oneshot::Sender as OneshotSender;
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::tasks::{Task, TaskMessage};
use tokio_core::reactor::Core;


/// An appender that uses println! for logging so that the calls are captured by libtest.
#[derive(Debug)]
struct CapturedConsoleAppender {
    encoder: Box<Encode>,
}

impl CapturedConsoleAppender {
    fn new() -> Self {
        CapturedConsoleAppender {
            encoder: Box::new(PatternEncoder::default()),
        }
    }
}

impl Append for CapturedConsoleAppender {
    fn append(&self, record: &Record) -> Result<(), Box<StdError + Sync + Send>> {
        let mut writer = SimpleWriter(Vec::<u8>::new());
        self.encoder.encode(&mut writer, record)?;
        let line = str::from_utf8(&writer.0).unwrap();
        println!("{}", line);
        Ok(())
    }
    fn flush(&self) {}
}

fn init_logging() {
    let stdout = CapturedConsoleAppender::new();
    let builder = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .logger(Logger::builder().build("saltyrtc_client", LevelFilter::Trace));
    let root = Root::builder().appender("stdout");
    let config = builder.build(root.build(LevelFilter::Info)).unwrap();
    let _ = log4rs::init_config(config);
}

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


fn connect_to(host: &str, port: u16, tls_connector: Option<TlsConnector>) -> Result<WsClient, SaltyError> {
    // Initialize SaltyRTC
    let keypair = KeyPair::new();
    let task = DummyTask::new(1);
    let salty = Rc::new(RefCell::new(
        SaltyClient::build(keypair)
            .add_task(Box::new(task))
            .with_ping_interval(Some(Duration::from_secs(30)))
            .initiator()
            .expect("Could not create SaltyClient instance")
    ));

    // Reactor
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    // Connect
    let timeout = Duration::from_millis(1000);
    let future = saltyrtc_client::connect(
            host,
            port,
            tls_connector,
            &handle,
            salty.clone(),
        )
        .unwrap()
        .and_then(|client| saltyrtc_client::do_handshake(client, salty, Some(timeout)));

    // Run future to completion
    core.run(future)
}

/// Connections to a port without a listening service should fail with a NetworkError.
#[test]
fn connection_error_refused() {
    init_logging();
    let result = connect_to(
        "localhost",
        15431,
        Some(get_tls_connector())
    );
    let errmsg = "Could not connect to server: WebSocketError: I/O failure: Connection refused (os error 111)".into();
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => assert_eq!(e, SaltyError::Network(errmsg)),
    };
}

/// Connections to an invalid host should fail with a NetworkError.
#[test]
fn connection_error_no_host() {
    init_logging();
    let result = connect_to(
        "1.1.1.1",
        8765,
        Some(get_tls_connector())
    );
    let errmsg = "Could not connect to server: WebSocketError: I/O failure: No route to host (os error 113)".into();
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => assert_eq!(e, SaltyError::Network(errmsg)),
    };
}

/// The TLS cert is made for "localhost", so connections to "127.0.0.1" should fail.
#[test]
fn connection_error_tls_error() {
    init_logging();
    let result = connect_to(
        "127.0.0.1",
        8765,
        Some(get_tls_connector())
    );
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => match e {
            SaltyError::Network(msg) => assert!(msg.starts_with(
                "Could not connect to server: WebSocketError: TLS failure: The OpenSSL library reported an error"
            )),
            other => panic!("Connection should have failed with Network error, but failed with {:?}", other),
        },
    };
}

/// A connection should time out.
#[test]
fn connection_timeout() {
    init_logging();
    let result = connect_to(
        "localhost",
        8765,
        Some(get_tls_connector())
    );
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => match e {
            SaltyError::Timeout => { /* yep! */ },
            other => panic!("Connection should have failed with Timeout error, but failed with {:?}", other),
        },
    };
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
