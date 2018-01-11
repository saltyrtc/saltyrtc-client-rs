use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write, stdin, stdout};
use std::fmt;
use std::thread;

use cc;
use failure::{Error};
use saltyrtc_client::{Role, Task};
use saltyrtc_client::errors::{SaltyResult};
use saltyrtc_client::rmpv::{Value};
use saltyrtc_client::ws;


pub(crate) struct ChatTask {
    pub(crate) our_name: String,
    pub(crate) peer_name: Option<String>,
    pub(crate) role: Option<Role>,
    pub(crate) ws_sender: Option<ws::Sender>,
    pub(crate) msg_receiver: Option<cc::Receiver<Value>>,
    pub(crate) encrypt_for_peer: Option<Box<Fn(Value) -> SaltyResult<Vec<u8>> + Send>>,
}

impl PartialEq for ChatTask {
    fn eq(&self, other: &ChatTask) -> bool {
        self.our_name == other.our_name &&
            self.peer_name == other.peer_name &&
            self.ws_sender == other.ws_sender &&
            self.role == other.role
    }
}

impl ChatTask {
    pub fn new<S: Into<String>>(our_name: S) -> Self {
        ChatTask {
            our_name: our_name.into(),
            peer_name: None,
            role: None,
            ws_sender: None,
            msg_receiver: None,
            encrypt_for_peer: None,
        }
    }

    pub fn send_message(&self, msg: &str) -> Result<(), String> {
        // Get access to WebSocket sender
        let sender = match self.ws_sender {
            Some(ref sender) => sender,
            None => return Err("WebSocket sender not initialized".into()),
        };

        // Convert text to message
        let value = Value::from(msg);

        // Encrypt message
        let encrypted = match self.encrypt_for_peer {
            Some(ref func) => func(value).map_err(|e| format!("Cannot encrypt message: {}", e))?,
            None => return Err("encrypt_for_peer function not set".to_string()),
        };

        // Send message
        let ws_msg = ws::Message::Binary(encrypted);
        let res = sender.send(ws_msg).map_err(|e| format!("Could not send message: {}", e));
        res
    }

    fn receive_message(&mut self, message: Value) {
        debug!("Received task message");
        match message {
            Value::String(utf8str) => {
                let peer_name: String = self.peer_name.clone().unwrap_or("?".into());
                print!("\n{}> {}\n{}> ", &peer_name, utf8str.as_str().unwrap().trim(), &self.our_name);
                stdout().flush().unwrap();
            },
            other => error!("Received invalid message type: {:?}", other),
        }
    }

    pub fn main_loop(&mut self) -> Result<(), String> {
        // Print intro
        println!(r" ___       _ _         ___ _         _");
        println!(r"/ __| __ _| | |_ _  _ / __| |_  __ _| |_");
        println!(r"\__ \/ _` | |  _| || | (__| ' \/ _` |  _|");
        println!(r"|___/\__,_|_|\__|\_, |\___|_||_\__,_|\__|");
        println!(r"                 |__/");
        println!();
        let peer_name: String = self.peer_name.clone().unwrap_or("?".into());
        print!("Hi \"{}\"! We're the {} chatting with \"{}\".\n\n{}> ",
               &self.our_name, self.role.unwrap(), &peer_name, &self.our_name);
        stdout().flush().unwrap();

        // Stdin thread
        let (stdin_tx, stdin_rx) = cc::unbounded();
        let stdin_thread = thread::spawn(move || {
            let mut input = String::new();
            loop {
                stdin().read_line(&mut input)
                    .expect("Failed to read line");
                stdin_tx.send(input.clone());
                input.clear();
            }
        });

        // Get reference to msg receiver channel
        let msg_receiver = self.msg_receiver.clone().ok_or("Message receiver not set".to_string())?;

        // Event loop
        'main_loop: loop {
            select_loop! {
                recv(stdin_rx, input) => {
                    match &*input.trim() {
                        "/q" | "/quit" => {
                            println!("Goodbye.");
                            break 'main_loop;
                        },
                        "/h" | "/help" | "/?" | "" => {
                            println!("Enter a message. To quit, enter \"/q\" or \"/quit\".");
                            print!("{}> ", &self.our_name);
                            stdout().flush().unwrap();
                            continue 'main_loop;
                        },
                        other => {
                            info!("Input is {}", other);
                        },
                    }

                    self.send_message(&input).expect("Could not send message");
                    print!("{}> ", &self.our_name);
                    stdout().flush().unwrap();
                },
                recv(msg_receiver, msg) => self.receive_message(msg),
            }
        }

        Ok(())
    }
}

impl fmt::Debug for ChatTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ChatTask(nick={})", &self.our_name)
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
        self.peer_name = Some(peer_name);
        Ok(())
    }

    /// Used by the signaling class to notify task that the peer handshake is over.
    ///
    /// This is the point where the task can take over.
    fn on_peer_handshake_done(
        &mut self,
        role: Role,
        ws_sender: ws::Sender,
        msg_receiver: cc::Receiver<Value>,
        encrypt_for_peer: Box<Fn(Value) -> SaltyResult<Vec<u8>> + Send>,
    ) {
        info!("ChatTask taking over!");
        self.role = Some(role);
        self.ws_sender = Some(ws_sender);
        self.msg_receiver = Some(msg_receiver);
        self.encrypt_for_peer = Some(encrypt_for_peer);
    }

    /// Return a list of message types supported by this task.
    ///
    /// Incoming messages with accepted types will be passed to the task.
    /// Otherwise, the message is dropped.
    fn supported_types(&self) -> &[&'static str] {
        &["msg", "nick_change"]
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
