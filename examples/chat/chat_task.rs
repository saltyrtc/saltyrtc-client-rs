use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use failure::Error;
use futures::{Future, Stream, Sink, future};
use futures::sync::mpsc::{Sender, Receiver};
use saltyrtc_client::Task;
use saltyrtc_client::rmpv::Value;
use tokio_core::reactor::Remote;


// Message types
const TYPE_MSG: &'static str = "msg";
const TYPE_NICK_CHANGE: &'static str = "nick_change";
const KEY_TEXT: &'static str = "text";
const KEY_NICK: &'static str = "nick";


/// The chat task is used for a simple 1-to-1 chat.
///
/// It supports sending text messages and changing the nickname.
#[derive(Debug, Clone)]
pub(crate) struct ChatTask {
    pub(crate) our_name: String,
    pub(crate) peer_name: Arc<Mutex<Option<String>>>,
    remote: Remote,
    outgoing_tx: Option<Sender<Value>>,
    incoming_tx: Sender<ChatMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatMessage {
    Msg(String),
    NickChange(String),
}

impl ChatTask {
    /// Create a new ChatTask.
    ///
    /// Args:
    ///
    /// * `our_name`: Our local chat nickname.
    /// * `remote` A remote reference to a Tokio reactor core.
    /// * `incoming_tx`: The futures channel sender through which incoming chat messages are sent.
    pub fn new<S: Into<String>>(our_name: S, remote: Remote, incoming_tx: Sender<ChatMessage>) -> Self {
        ChatTask {
            our_name: our_name.into(),
            peer_name: Arc::new(Mutex::new(None)),
            remote,
            outgoing_tx: None,
            incoming_tx,
        }
    }

    /// Send a text message through the secure channel.
    pub fn send_msg(&self, msg: &str) -> Box<Future<Item=(), Error=String>> {
        let val: Value = Value::Map(vec![
            (Value::String("type".into()), Value::String(TYPE_MSG.into())),
            (Value::String(KEY_TEXT.into()), Value::String(msg.into())),
        ]);
        let tx = self.outgoing_tx.clone().expect("outgoing_tx is None");
        let future = tx
            .send(val)
            .map(|_| ())
            .map_err(|e| format!("Could not send message: {}", e));
        Box::new(future)
    }

    /// Change the own nickname.
    pub fn change_nick(&mut self, new_nick: &str) -> Box<Future<Item=(), Error=String>> {
        let val: Value = Value::Map(vec![
            (Value::String("type".into()), Value::String(TYPE_NICK_CHANGE.into())),
            (Value::String(KEY_NICK.into()), Value::String(new_nick.into())),
        ]);
        let tx = self.outgoing_tx.clone().expect("outgoing_tx is None");
        let future = tx
            .send(val)
            .map(|_| ())
            .map_err(|e| format!("Could not change nickname: {}", e));
        self.our_name = new_nick.into();
        Box::new(future)
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
    fn start(&mut self, outgoing_tx: Sender<Value>, incoming_rx: Receiver<Value>) {
        info!("Peer handshake done");

        // Store reference to channel for sending outgoing messages
        self.outgoing_tx = Some(outgoing_tx);

        // Handle incoming messages
        let incoming_tx = self.incoming_tx.clone();
        let peer_name = self.peer_name.clone();
        self.remote.spawn(move |handle| {
            let handle = handle.clone();
            incoming_rx.for_each(move |val: Value| {
                let map = match val {
                    Value::Map(map) => map,
                    _ => panic!("Invalid msgpack message type (not a map)"),
                };

                let msg_type = map
                    .iter()
                    .filter(|&&(ref k, _)| k.as_str() == Some("type"))
                    .filter_map(|&(_, ref v)| v.as_str())
                    .next()
                    .expect("Message is missing valid type");

                match msg_type {
                    TYPE_MSG => {
                        let text_opt = map
                            .iter()
                            .filter(|&&(ref k, _)| k.as_str() == Some(KEY_TEXT))
                            .filter_map(|&(_, ref v)| v.as_str())
                            .next();
                        match text_opt {
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
                        let nick_opt = map
                            .iter()
                            .filter(|&&(ref k, _)| k.as_str() == Some(KEY_NICK))
                            .filter_map(|&(_, ref v)| v.as_str())
                            .next();
                        match nick_opt {
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

                future::ok(())
            })
        });
    }

    /// Return supported message types.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn supported_types(&self) -> &[&'static str] {
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

    /// This method is called by the signaling class when sending and receiving 'close' messages.
    fn close(&mut self, _reason: u8) {
        // TODO
    }
}
