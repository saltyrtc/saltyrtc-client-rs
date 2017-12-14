//! Helpers for tests.
//!
//! Only compiled in test mode.

use std::borrow::{Cow};
use std::collections::{HashMap};

use failure::{Error};
use rmpv::{Value};

use task::{Task};


#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct DummyTask(pub u8);

impl Task for DummyTask {
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        unimplemented!()
    }

    fn on_peer_handshake_done(&mut self) {
        unimplemented!()
    }

    fn type_supported(&self, type_: &str) -> bool {
        true
    }

    fn on_task_message(&mut self, message: Value) {
        unimplemented!()
    }

    fn send_signaling_message(&self, payload: &[u8]) {
        unimplemented!()
    }

    fn name(&self) -> Cow<'static, str> {
        format!("dummy.{}", self.0).into()
    }

    fn get_data(&self) -> Option<HashMap<String, Value>> {
        unimplemented!()
    }

    fn close(&mut self, reason: u8) {
        unimplemented!()
    }
}
