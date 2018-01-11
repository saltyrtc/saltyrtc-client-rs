//! Helpers for tests.
//!
//! Only compiled in test mode.

use std::borrow::{Cow};
use std::collections::{HashMap};

use crossbeam_channel as cc;
use failure::{Error};
use rmpv::{Value};
use ws;

use errors::{SaltyResult};
use task::{Task};
use protocol::{Role};


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
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        self.initialized = true;
        Ok(())
    }

    fn on_peer_handshake_done(
        &mut self,
        role: Role,
        sender: ws::Sender,
        receiver: cc::Receiver<Value>,
        encrypt_for_peer: Box<Fn(Value) -> SaltyResult<Vec<u8>> + Send>,
    ) {
        unimplemented!()
    }

    fn supported_types(&self) -> &[&'static str] {
        &["foo", "bar"]
    }

    fn send_signaling_message(&self, payload: &[u8]) {
        unimplemented!()
    }

    fn name(&self) -> Cow<'static, str> {
        DummyTask::name_for(self.id).into()
    }

    fn data(&self) -> Option<HashMap<String, Value>> {
        None
    }

    fn close(&mut self, reason: u8) {
        unimplemented!()
    }
}


/// A test-only trait that allows the user to create random instances of
/// certain types (e.g. a public key).
pub trait TestRandom {
    fn random() -> Self;
}
