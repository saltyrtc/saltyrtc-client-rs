/// A SaltyRTC task is a protocol extension to this protocol that will be
/// negotiated during the client-to-client authentication phase. Once a task
/// has been negotiated and the authentication is complete, the task protocol
/// defines further procedures, messages, etc.
///
/// All tasks need to implement this interface.
use std::collections::HashMap;

use rmpv::Value;


pub trait Task {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    ///
    /// TODO: Pass some kind of signaling instance to task.
    fn init(&mut self, data: Option<HashMap<String, Value>>);

    /// Used by the signaling class to notify task that the peer handshake is over.
    ///
    /// This is the point where the task can take over.
    fn on_peer_handshake_done(&mut self);

    /// This method is called by SaltyRTC when a task related message
    /// arrives through the WebSocket.
    fn on_task_message(&mut self, message: Vec<u8>);

    /// Send bytes through the task signaling channel.
    ///
    /// This method should only be called after the handover.
    ///
    /// Note that the data passed in to this method should *not* already be encrypted. Otherwise,
    /// data will be encrypted twice.
    fn send_signaling_message(&self, payload: &[u8]);

    /// Return the task protocol name.
    fn name(&self) -> &str;

    /// Return the list of supported message types.
    ///
    /// Incoming messages with this type will be passed to the task.
    fn supported_message_types(&self) -> &[&str];

    /// Return the task data used for negotiation in the `auth` message.
    fn get_data(&self) -> Option<HashMap<String, Value>>;

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, reason: u8);
}
