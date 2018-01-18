//! Helpers for tests.
//!
//! Only compiled in test mode.

use std::borrow::Cow;
use std::collections::HashMap;

use failure::Error;
use futures::sync::mpsc::{Sender, Receiver};
use futures::sync::oneshot::Sender as OneshotSender;
use rmpv::Value;

use ::CloseCode;
use tasks::{Task, TaskMessage};


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

    fn start(&mut self, _: Sender<TaskMessage>, _: Receiver<TaskMessage>, _: OneshotSender<Option<CloseCode>>) {
        unimplemented!()
    }

    fn supported_types(&self) -> &'static [&'static str] {
        &["dummy"]
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

    fn close(&mut self, reason: CloseCode) {
        unimplemented!()
    }
}


/// A test-only trait that allows the user to create random instances of
/// certain types (e.g. a public key).
pub trait TestRandom {
    fn random() -> Self;
}
