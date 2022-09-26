//! Integration tests.
//!
//! These tests require a SaltyRTC server running on `localhost:8765`
//! and a `saltyrtc.crt` CA certificate (PEM) in the repository root directory.

use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use failure::Error;
use log::{LevelFilter, Record};
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::writer::simple::SimpleWriter;
use log4rs::encode::Encode;
use saltyrtc_client::crypto::KeyPair;
use saltyrtc_client::dep::futures::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use saltyrtc_client::dep::futures::sync::oneshot::Sender as OneshotSender;
use saltyrtc_client::dep::futures::Future;
use saltyrtc_client::dep::native_tls::{Certificate, Protocol, TlsConnector};
use saltyrtc_client::dep::rmpv::Value;
use saltyrtc_client::errors::SaltyError;
use saltyrtc_client::tasks::{Task, TaskMessage};
use saltyrtc_client::{CloseCode, SaltyClient, WsClient};
use tokio_core::reactor::Core;

/// An appender that uses println! for logging so that the calls are captured by libtest.
#[derive(Debug)]
struct CapturedConsoleAppender {
    encoder: Box<dyn Encode>,
}

impl CapturedConsoleAppender {
    fn new() -> Self {
        CapturedConsoleAppender {
            encoder: Box::new(PatternEncoder::default()),
        }
    }
}

impl Append for CapturedConsoleAppender {
    fn append(&self, record: &Record) -> Result<(), Box<dyn StdError + Sync + Send>> {
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
    File::open(&Path::new("saltyrtc.crt"))
        .expect("Could not open saltyrtc.crt")
        .read_to_end(&mut server_cert_bytes)
        .expect("Could not read saltyrtc.crt");

    // Parse server certificate
    let server_cert = Certificate::from_pem(&server_cert_bytes).unwrap_or_else(|e| {
        panic!("Problem with CA cert: {}", e);
    });

    // Create TLS connector instance
    TlsConnector::builder()
        .min_protocol_version(Some(Protocol::Tlsv10))
        .max_protocol_version(None)
        .add_root_certificate(server_cert)
        .build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e))
}

fn connect_to(
    host: &str,
    port: u16,
    tls_connector: Option<TlsConnector>,
) -> Result<WsClient, SaltyError> {
    // Initialize SaltyRTC
    let keypair = KeyPair::new();
    let task = DummyTask::new(1);
    let salty = Arc::new(RwLock::new(
        SaltyClient::build(keypair)
            .add_task(Box::new(task))
            .with_ping_interval(Some(Duration::from_secs(30)))
            .initiator()
            .expect("Could not create SaltyClient instance"),
    ));

    // Reactor
    let mut core = Core::new().unwrap();

    // Connect
    let timeout = Duration::from_millis(1000);
    let (connect_future, event_channel) =
        saltyrtc_client::connect(host, port, tls_connector, salty.clone()).unwrap();
    let future = connect_future.and_then(|client| {
        saltyrtc_client::do_handshake(client, salty, event_channel.clone_tx(), Some(timeout))
    });

    // Run future to completion
    core.run(future)
}

/// Connections to a port without a listening service should fail with a NetworkError.
#[test]
fn connection_error_refused() {
    init_logging();
    let result = connect_to("localhost", 15431, Some(get_tls_connector()));
    let errmsg = "Could not connect to server (localhost:15431): WebSocketError: I/O failure: Connection refused (os error 111)".into();
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => assert_eq!(e, SaltyError::Network(errmsg)),
    };
}

/// The TLS cert is made for "localhost", so connections to "127.0.0.1" should fail.
#[test]
fn connection_error_tls_error() {
    init_logging();
    let result = connect_to("127.0.0.1", 8765, Some(get_tls_connector()));
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => match e {
            SaltyError::Network(msg) => {
                println!("msg is: {}", msg);
                assert!(msg.contains("certificate verify failed"));
                assert!(msg.contains("IP address mismatch"));
            }
            other => panic!(
                "Connection should have failed with Network error, but failed with {:?}",
                other
            ),
        },
    };
}

/// A connection should time out.
#[test]
fn connection_timeout() {
    init_logging();
    let result = connect_to("localhost", 8765, Some(get_tls_connector()));
    match result {
        Ok(_) => panic!("Connection should have failed but did not!"),
        Err(e) => match e {
            SaltyError::Timeout => { /* yep! */ }
            other => panic!(
                "Connection should have failed with Timeout error, but failed with {:?}",
                other
            ),
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

    fn start(
        &mut self,
        _: UnboundedSender<TaskMessage>,
        _: UnboundedReceiver<TaskMessage>,
        _: OneshotSender<Option<CloseCode>>,
    ) {
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
