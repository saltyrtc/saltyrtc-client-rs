/// A SaltyRTC task is a protocol extension to this protocol that will be
/// negotiated during the client-to-client authentication phase. Once a task
/// has been negotiated and the authentication is complete, the task protocol
/// defines further procedures, messages, etc.
///
/// All tasks need to implement this interface.

use std::borrow::Cow;
use std::collections::{HashMap};
use std::fmt::Debug;

use failure::Error;
use rmpv::Value;


pub trait Task : Debug {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: Option<HashMap<String, Value>>) -> Result<(), Error>;

    /// Used by the signaling class to notify task that the peer handshake is over.
    ///
    /// This is the point where the task can take over.
    fn on_peer_handshake_done(&mut self);

    /// Return whether the specified message type is supported by this task.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn type_supported(&self, type_: &str) -> bool;

    /// This method is called by SaltyRTC when a task related message
    /// arrives through the WebSocket.
    fn on_task_message(&mut self, message: Value);

    /// Send bytes through the task signaling channel.
    ///
    /// This method should only be called after the handover.
    ///
    /// Note that the data passed in to this method should *not* already be encrypted. Otherwise,
    /// data will be encrypted twice.
    fn send_signaling_message(&self, payload: &[u8]);

    /// Return the task protocol name.
    fn name(&self) -> Cow<'static, str>;

    /// Return the task data used for negotiation in the `auth` message.
    fn get_data(&self) -> Option<HashMap<String, Value>>;

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, reason: u8);
}

/// A set of task boxes.
///
/// This data structure wraps the vector and ensures
/// that an empty tasks list cannot be created.
#[derive(Debug)]
pub struct Tasks(pub(crate) Vec<Box<Task>>);

impl Tasks {
    pub fn new(task: Box<Task>) -> Self {
        Tasks(vec![task])
    }

    /// Create a `Tasks` instance from a vector.
    ///
    /// This may fail if the tasks vector is empty.
    pub fn from_vec(tasks: Vec<Box<Task>>) -> Result<Tasks, &'static str> {
        if tasks.is_empty() {
            return Err("Tasks vector may not be empty");
        }
        Ok(Tasks(tasks))
    }

    /// Add a task.
    ///
    /// This may fail if a task with the same `.name()` already exists.
    pub fn add_task(&mut self, task: Box<Task>) -> Result<&mut Self, String> {
        if self.0.iter().any(|t| t.name() == task.name()) {
            return Err(format!("Task with name \"{}\" cannot be added twice", task.name()));
        }
        self.0.push(task);
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct DummyTask(pub u8);

    impl Task for DummyTask {
        fn init(&mut self, data: Option<HashMap<String, Value>>) -> Result<(), Error> {
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

    #[test]
    fn create_tasks() {
        let t1 = Box::new(DummyTask(1));
        let t2 = Box::new(DummyTask(2));
        let t3 = Box::new(DummyTask(3));

        let mut tasks = Tasks::new(t1);
        assert_eq!(tasks.len(), 1);
        tasks.add_task(t2).unwrap();
        tasks.add_task(t3.clone()).unwrap();
        assert_eq!(tasks.len(), 3);

        let err = tasks.add_task(t3).unwrap_err();
        assert_eq!(err, "Task with name \"dummy.3\" cannot be added twice".to_string());
        assert_eq!(tasks.len(), 3);
    }
}
