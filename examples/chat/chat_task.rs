use std::borrow::Cow;
use std::collections::HashMap;
use std::mem;
use std::sync::{Arc, Mutex};

use failure::Error;
use futures::{Future, Stream, Sink, future};
use futures::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use futures::sync::oneshot::Sender as OneshotSender;
use saltyrtc_client::{BoxedFuture, CloseCode};
use saltyrtc_client::tasks::{Task, TaskMessage};
use saltyrtc_client::dep::rmpv::Value;
use tokio_core::reactor::Remote;


// Message types
const TYPE_MSG: &'static str = "msg";
const TYPE_NICK_CHANGE: &'static str = "nick_change";
const KEY_TYPE: &'static str = "type";
const KEY_TEXT: &'static str = "text";
const KEY_NICK: &'static str = "nick";


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


/// The chat task is used for a simple 1-to-1 chat.
///
/// It supports sending text messages and changing the nickname.
///
/// TODO: Add a `state` enum that will contain all information from `start`.
#[derive(Debug)]
pub(crate) struct ChatTask {
    pub(crate) our_name: String,
    pub(crate) peer_name: Arc<Mutex<Option<String>>>,
    remote: Remote,
    outgoing_tx: Option<UnboundedSender<TaskMessage>>,
    incoming_tx: UnboundedSender<ChatMessage>,
    disconnect_tx: Option<OneshotSender<Option<CloseCode>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatMessage {
    Msg(String),
    NickChange(String),
    Disconnect(CloseCode)
}

impl ChatTask {
    /// Create a new ChatTask.
    ///
    /// Args:
    ///
    /// * `our_name`: Our local chat nickname.
    /// * `remote` A remote reference to a Tokio reactor core.
    /// * `incoming_tx`: The futures channel sender through which incoming chat messages are sent.
    pub fn new<S: Into<String>>(our_name: S, remote: Remote, incoming_tx: UnboundedSender<ChatMessage>) -> Self {
        ChatTask {
            our_name: our_name.into(),
            peer_name: Arc::new(Mutex::new(None)),
            remote,
            outgoing_tx: None,
            incoming_tx,
            disconnect_tx: None,
        }
    }

    /// Send a text message through the secure channel.
    pub fn send_msg(&self, msg: &str) -> Result<(), String> {
        // Prepare message map
        let mut map: HashMap<String, Value> = HashMap::new();
        map.insert(KEY_TYPE.into(), Value::String(TYPE_MSG.into()));
        map.insert(KEY_TEXT.into(), Value::String(msg.into()));

        // Send message through channel
        let tx = self.outgoing_tx.clone().expect("outgoing_tx is None");
        tx
            .unbounded_send(TaskMessage::Value(map))
            .map_err(|e| format!("Could not send message: {}", e))
    }

    /// Change the own nickname.
    pub fn change_nick(&mut self, new_nick: &str) -> Result<(), String> {
        // Prepare message map
        let mut map: HashMap<String, Value> = HashMap::new();
        map.insert(KEY_TYPE.into(), Value::String(TYPE_NICK_CHANGE.into()));
        map.insert(KEY_NICK.into(), Value::String(new_nick.into()));

        // Send message through channel
        let tx = self.outgoing_tx.clone().expect("outgoing_tx is None");
        let res = tx
            .unbounded_send(TaskMessage::Value(map))
            .map_err(|e| format!("Could not change nickname: {}", e));
        if res.is_ok() {
            self.our_name = new_nick.into();
        }
        res
    }
}

impl Task for ChatTask {

    /// Initialize the task with the task data from the peer, sent in the `Auth` message.
    ///
    /// The task should keep track internally whether it has been initialized or not.
    fn init(&mut self, data: &Option<HashMap<String, Value>>) -> Result<(), Error> {
        let peer_name: String = match *data {
            Some(ref map) => match map.get("nickname") {
                Some(&Value::String(ref nickname)) => nickname.as_str().unwrap_or("?").to_string(),
                Some(ref val) => bail!("The \"nickname\" field has the wrong type: {:?}", val),
                None => bail!("No \"nickname\" field in data passed to task initialization"),
            },
            None => bail!("No data passed to task initialization"),
        };
        match self.peer_name.lock() {
            Ok(mut pn) => *pn = Some(peer_name),
            Err(e) => bail!("Could not lock peer_name mutex: {}", e),
        };
        Ok(())
    }

    /// Used by the signaling class to notify task that the peer handshake is done.
    ///
    /// This is the point where the task can take over.
    fn start(
        &mut self,
        outgoing_tx: UnboundedSender<TaskMessage>,
        incoming_rx: UnboundedReceiver<TaskMessage>,
        disconnect_tx: OneshotSender<Option<CloseCode>>,
    ) {
        info!("Peer handshake done");

        // Store reference to channel for sending outgoing messages
        self.outgoing_tx = Some(outgoing_tx);

        // Store reference to disconnect oneshot channel
        self.disconnect_tx = Some(disconnect_tx);

        // Handle incoming messages
        let incoming_tx = self.incoming_tx.clone();
        let peer_name = self.peer_name.clone();
        self.remote.spawn(move |handle| {
            let handle = handle.clone();
            incoming_rx.for_each(move |msg: TaskMessage| {

                let map: HashMap<String, Value> = match msg {
                    TaskMessage::Value(map) => map,
                    TaskMessage::Application(_data) => {
                        info!("Received application message from peer, ignoring");
                        return boxed!(future::ok(()));
                    },
                    TaskMessage::Close(reason) => {
                        // If a Close message from the peer arrives,
                        // send a ChatMessage::Disconnect to the user.
                        info!("Received close message from peer (reason: {})", reason);
                        return boxed!(
                            incoming_tx
                                .clone()
                                .send(ChatMessage::Disconnect(reason))
                                .map(|_| ())
                                .map_err(|_| ())
                        );
                    }
                };

                let msg_type_val = map.get(KEY_TYPE).expect("Message is missing type");
                let msg_type = msg_type_val.as_str().expect("Message type is not a string");

                match msg_type {
                    TYPE_MSG => {
                        match map.get(KEY_TEXT).and_then(|v| v.as_str()) {
                            Some(ref text) => {
                                let incoming_tx = incoming_tx.clone();
                                handle.spawn(
                                    incoming_tx
                                        .send(ChatMessage::Msg(text.to_string()))
                                        .map(|_| ())
                                        .map_err(|_| ())
                                )
                            },
                            None => warn!("Text message is missing valid `{}` key-value", KEY_TEXT),
                        }
                    },
                    TYPE_NICK_CHANGE => {
                        // TODO: DRY
                        match map.get(KEY_NICK).and_then(|v| v.as_str()) {
                            Some(ref nick) => {
                                // Update peer name in task
                                peer_name
                                    .lock()
                                    .map(|mut name| *name = Some(nick.to_string()))
                                    .unwrap_or_else(|e| warn!("Could not set peer name: {}", e));

                                // Send nick change through message channel
                                let incoming_tx = incoming_tx.clone();
                                handle.spawn(
                                    incoming_tx
                                        .send(ChatMessage::NickChange(nick.to_string()))
                                        .map(|_| ())
                                        .map_err(|_| ())
                                )
                            },
                            None => warn!("Nick change message is missing valid `{}` key-value", KEY_NICK),
                        }
                    },
                    other => warn!("Unknown message type: {}", other),
                };

                boxed!(future::ok(()))
            })
            .map(|_| debug!("† Chat task receiving future done"))
        });
    }

    /// Return supported message types.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn supported_types(&self) -> &'static [&'static str] {
        &[TYPE_MSG, TYPE_NICK_CHANGE]
    }

    /// Send bytes through the task signaling channel.
    ///
    /// This method should only be called after the handover.
    ///
    /// Note that the data passed in to this method should *not* already be encrypted. Otherwise,
    /// data will be encrypted twice.
    fn send_signaling_message(&self, _payload: &[u8]) {
        panic!("send_signaling_message called even though task does not implement handover");
    }

    /// Return the task protocol name.
    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("v0.simplechat.tasks.saltyrtc.org")
    }

    /// Return the task data used for negotiation in the `auth` message.
    /// This data will be sent to the peer.
    fn data(&self) -> Option<HashMap<String, Value>> {
        let mut map = HashMap::new();
        map.insert("nickname".to_string(), self.our_name.clone().into());
        Some(map)
    }

    /// This method can be called by the user to close the connection.
    ///
    /// It will send the close reason through the disconnect oneshot channel.
    fn close(&mut self, reason: CloseCode) {
        let disconnect_tx = mem::replace(&mut self.disconnect_tx, None);
        if let Some(channel) = disconnect_tx {
            let _ = channel.send(Some(reason));
        }
    }
}
