/// A SaltyRTC task is a protocol extension to this protocol that will be
/// negotiated during the client-to-client authentication phase. Once a task
/// has been negotiated and the authentication is complete, the task protocol
/// defines further procedures, messages, etc.
///
/// All tasks need to implement this interface.

use std::borrow::{Cow};
use std::collections::{HashMap};
use std::fmt::Debug;
use std::iter::IntoIterator;

use failure::Error;
use mopa::Any;
use rmpv::Value;


/// A type alias for a boxed task.
pub type BoxedTask = Box<Task + Send>;


/// An interface that needs to be implemented by every signaling task.
///
/// A task defines how data is exchanged after the server- and peer-handshake
/// have been completed.
pub trait Task : Debug + Any {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error>;

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
    fn data(&self) -> Option<HashMap<String, Value>>;

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, reason: u8);
}

mopafy!(Task);

/// A set of task boxes.
///
/// This data structure wraps the vector and ensures
/// that an empty tasks list cannot be created.
#[derive(Debug)]
pub(crate) struct Tasks(pub(crate) Vec<BoxedTask>);

impl Tasks {
    #[allow(dead_code)]
    pub(crate) fn new(task: BoxedTask) -> Self {
        Tasks(vec![task])
    }

    /// Create a `Tasks` instance from a vector.
    ///
    /// This may fail if the tasks vector is empty.
    pub(crate) fn from_vec(tasks: Vec<BoxedTask>) -> Result<Tasks, &'static str> {
        if tasks.is_empty() {
            return Err("Tasks vector may not be empty");
        }
        Ok(Tasks(tasks))
    }

    /// Add a task.
    ///
    /// This may fail if a task with the same `.name()` already exists.
    #[allow(dead_code)]
    pub(crate) fn add_task(&mut self, task: BoxedTask) -> Result<&mut Self, String> {
        if self.0.iter().any(|t| t.name() == task.name()) {
            return Err(format!("Task with name \"{}\" cannot be added twice", task.name()));
        }
        self.0.push(task);
        Ok(self)
    }

    /// Return the number of registered tasks.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Choose the first task in our own list of supported tasks that is also contained in the list
    /// of supported tasks provided by the peer.
    pub(crate) fn choose_shared_task<S: AsRef<str>>(self, tasks: &[S]) -> Option<BoxedTask> {
        for task in self.0 {
            if tasks.iter().find(|p| p.as_ref() == &*task.name()).is_some() {
                return Some(task);
            }
        }
        None
    }
}

impl IntoIterator for Tasks {
    type Item = BoxedTask;
    type IntoIter = ::std::vec::IntoIter<BoxedTask>;

    /// Return an iterator over the tasks.
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::test_helpers::DummyTask;

    #[test]
    fn create_tasks() {
        let t1 = Box::new(DummyTask::new(1));
        let t2 = Box::new(DummyTask::new(2));
        let t3 = Box::new(DummyTask::new(3));

        let mut tasks = Tasks::new(t1);
        assert_eq!(tasks.len(), 1);
        tasks.add_task(t2).unwrap();
        tasks.add_task(t3.clone()).unwrap();
        assert_eq!(tasks.len(), 3);

        let err = tasks.add_task(t3).unwrap_err();
        assert_eq!(err, "Task with name \"dummy.3\" cannot be added twice".to_string());
        assert_eq!(tasks.len(), 3);
    }

    #[test]
    fn choose_shared_task() {
        fn make_tasks() -> Tasks {
            let t1 = Box::new(DummyTask::new(1));
            let t2 = Box::new(DummyTask::new(2));
            Tasks::from_vec(vec![t1, t2]).unwrap()
        };

        // Parameters as static string references
        let chosen = make_tasks().choose_shared_task(&["dummy.1", "dummy.3"]).expect("No shared task found (1)");
        assert_eq!(chosen.name(), "dummy.1");

        // Parameters from owned strings
        let chosen = make_tasks().choose_shared_task(&vec!["dummy.2".to_string()]).expect("No shared task found (2)");
        assert_eq!(chosen.name(), "dummy.2");

        // Return `None` if no common task is present
        let chosen = make_tasks().choose_shared_task(&vec!["dummy.3".to_string()]);
        assert!(chosen.is_none());

        // Our preference wins
        let chosen = make_tasks().choose_shared_task(&["dummy.2", "dummy.1"]).expect("No shared task found (3)");
        assert_eq!(chosen.name(), "dummy.1");
    }
}
