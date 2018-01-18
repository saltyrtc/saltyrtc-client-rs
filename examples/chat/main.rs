//! Connect to a server as initiator and print the connection info.

extern crate clap;
extern crate cursive;
extern crate data_encoding;
#[macro_use] extern crate failure;
extern crate futures;
#[macro_use] extern crate log;
extern crate native_tls;
extern crate saltyrtc_client;
extern crate log4rs;
extern crate tokio_core;

mod chat_task;

use std::cell::RefCell;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use clap::{Arg, App, SubCommand};
use cursive::{Cursive};
use cursive::traits::{Identifiable};
use cursive::views::{TextView, EditView, BoxView, LinearLayout};
use data_encoding::{HEXLOWER};
use futures::{Sink, Stream, future};
use futures::future::Future;
use futures::sync::mpsc::channel;
use log::LevelFilter;
use log4rs::Handle;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::filter::threshold::ThresholdFilter;
use native_tls::{TlsConnector, Certificate, Protocol};
use saltyrtc_client::{SaltyClientBuilder, Role, WsClient, Task, BoxedFuture, CloseCode};
use saltyrtc_client::crypto::{KeyPair, AuthToken, public_key_from_hex_str};
use saltyrtc_client::errors::{SaltyError};
use tokio_core::reactor::{Core};

use chat_task::{ChatTask, ChatMessage};


pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const VIEW_TEXT_ID: &'static str = "text";
const VIEW_INPUT_ID: &'static str = "input";
const TUI_CHANNEL_BUFFER_SIZE: usize = 64;


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


fn main() {
    const ARG_PATH: &'static str = "path";
    const ARG_AUTHTOKEN: &'static str = "authtoken";
    const ARG_PING_INTERVAL: &'static str = "ping_interval";

    // Set up CLI arguments
    let arg_ping_interval = Arg::with_name(ARG_PING_INTERVAL)
        .short("i")
        .takes_value(true)
        .value_name("SECONDS")
        .required(false)
        .default_value("60")
        .help("The WebSocket ping interval (set to 0 to disable pings)");
    let app = App::new("SaltyRTC Test Client")
        .version(VERSION)
        .author("Danilo Bargen <mail@dbrgn.ch>")
        .about("Test client for SaltyRTC.")
        .subcommand(SubCommand::with_name("initiator")
            .about("Start chat as initiator")
            .arg(arg_ping_interval.clone()))
        .subcommand(SubCommand::with_name("responder")
            .about("Start chat as responder")
            .arg(Arg::with_name(ARG_PATH)
                .short("p")
                .takes_value(true)
                .value_name("PATH")
                .required(true)
                .help("The websocket path (hex encoded public key of the initiator)"))
            .arg(Arg::with_name(ARG_AUTHTOKEN)
                .short("a")
                .alias("token")
                .alias("authtoken")
                .takes_value(true)
                .value_name("AUTHTOKEN")
                .required(true)
                .help("The auth token (hex encoded)"))
            .arg(arg_ping_interval));

    // Parse arguments
    let subcommand = app.get_matches().subcommand.unwrap_or_else(|| {
        println!("Missing subcommand.");
        println!("Use -h or --help to see usage.");
        process::exit(1);
    });
    let args = &subcommand.matches;

    // Determine role
    let role = match &*subcommand.name {
        "initiator" => Role::Initiator,
        "responder" => Role::Responder,
        other => {
            println!("Invalid subcommand: {}", other);
            process::exit(1);
        },
    };

    // Set up logging
    setup_logging(role);

    // Tokio reactor core
    let mut core = Core::new().unwrap();

    // Read server certificate bytes
    let mut server_cert_bytes: Vec<u8> = vec![];
    File::open(&Path::new("saltyrtc.der"))
        .expect("Could not open saltyrtc.der")
        .read_to_end(&mut server_cert_bytes)
        .expect("Could not read saltyrtc.der");

    // Parse server certificate
    let server_cert = Certificate::from_der(&server_cert_bytes)
        .unwrap_or_else(|e| {
            panic!("Problem with CA cert: {}", e);
        });

    // Create TLS connector instance
    let mut tls_builder = TlsConnector::builder()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector builder: {}", e));
    tls_builder.supported_protocols(&[Protocol::Tlsv11, Protocol::Tlsv11, Protocol::Tlsv10])
        .unwrap_or_else(|e| panic!("Could not set TLS protocols: {}", e));
    tls_builder.add_root_certificate(server_cert)
        .unwrap_or_else(|e| panic!("Could not add root certificate: {}", e));
    let tls_connector = tls_builder.build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e));

    // Create new public permanent keypair
    let keypair = KeyPair::new();

    // Determine websocket path
    let path: String = match role {
        Role::Initiator => keypair.public_key_hex(),
        Role::Responder => args.value_of(ARG_PATH).expect("Path not supplied").to_lowercase(),
    };

    // Determine ping interval
    let ping_interval = {
        let seconds: u64 = args.value_of(ARG_PING_INTERVAL).expect("Ping interval not supplied")
                               .parse().expect("Could not parse interval seconds to a number");
        Duration::from_secs(seconds)
    };

    // Create new SaltyRTC client instance
    let (incoming_tx, incoming_rx) = channel::<ChatMessage>(TUI_CHANNEL_BUFFER_SIZE);
    let (salty, auth_token_hex) = match role {
        Role::Initiator => {
            let task = ChatTask::new("initiat0r", core.remote(), incoming_tx);
            let salty = SaltyClientBuilder::new(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval))
                .initiator()
                .expect("Could not create SaltyClient instance");
            let auth_token_hex = HEXLOWER.encode(salty.auth_token().unwrap().secret_key_bytes());
            (salty, auth_token_hex)
        },
        Role::Responder => {
            let task = ChatTask::new("r3spond3r", core.remote(), incoming_tx);
            let auth_token_hex = args.value_of(ARG_AUTHTOKEN).expect("Auth token not supplied").to_string();
            let auth_token = AuthToken::from_hex_str(&auth_token_hex).expect("Invalid auth token hex string");
            let initiator_pubkey = public_key_from_hex_str(&path).unwrap();
            let salty = SaltyClientBuilder::new(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval))
                .responder(initiator_pubkey, Some(auth_token))
                .expect("Could not create SaltyClient instance");
            (salty, auth_token_hex)
        },
    };

    println!("\n\x1B[32m******************************");
    println!("Connecting as {}", role);
    println!();
    println!("Signaling path: {}", path);
    println!("Auth token: {}", auth_token_hex);
    println!();
    println!("To connect with a peer:");
    match role {
        Role::Initiator => println!("cargo run --example chat -- responder \\\n    -p {} \\\n    -a {}", path, auth_token_hex),
        Role::Responder => println!("cargo run --example chat -- initiator"),
    }
    println!("******************************\x1B[0m\n");

    // Wrap SaltyClient in a Rc<RefCell<>>
    let salty_rc = Rc::new(RefCell::new(salty));

    // Connect to server
    let connect_future = saltyrtc_client::connect(
//            &format!("wss://saltyrtc-00.threema.ch:443/{}", path),
            &format!("wss://localhost:8765/{}", path),
            Some(tls_connector),
            &core.handle(),
            salty_rc.clone(),
        )
        .unwrap();

    // Do handshake
    let handshake_future = connect_future
        .map(|client| { println!("Connected to server"); client })
        .and_then(|client| saltyrtc_client::do_handshake(client, salty_rc.clone()))
        .map(|client| { println!("Handshake done"); client });

    // Run future in reactor to process handshake
    let client: WsClient = match core.run(handshake_future) {
        Ok(client) => {
            println!("Handshake success.");
            client
        },
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        },
    };

    // Set up task loop
    let (task, task_loop) = saltyrtc_client::task_loop(client, salty_rc.clone())
        .unwrap_or_else(|e| {
            println!("{}", e);
            process::exit(1);
        });

    // Launch TUI thread
    let (cb_sink_tx, cb_sink_rx) = mpsc::sync_channel(1);
    let (chat_msg_tx, chat_msg_rx) = channel::<String>(TUI_CHANNEL_BUFFER_SIZE);
    let remote = core.remote();
    let tui_thread = thread::spawn(move || {
        // Launch TUI
        let mut tui = Cursive::new();
        tui.set_fps(10);

        // Create text view (for displaying messages)
        let text_view = TextView::new("=== Welcome to SaltyChat! ===\nType /quit to exit.\nType /help to list available commands.\n\n")
            .scrollable(true)
            .with_id(VIEW_TEXT_ID);

        // Create input view (for composing messages)
        let input_view = EditView::new()
            .on_submit(move |tui: &mut Cursive, msg: &str| {
                // Send message through task
                let send_future = chat_msg_tx
                    .clone()
                    .send(msg.to_string())
                    .map(|_| ())
                    .map_err(|_| ());
                remote.spawn(move |_| send_future);

                // Clear input field
                tui.call_on_id(VIEW_INPUT_ID, |view: &mut EditView| {
                    view.set_content("");
                });
            })
            .with_id(VIEW_INPUT_ID);

        // Create layout
        let layout = BoxView::with_full_screen(
            LinearLayout::vertical()
                .child(BoxView::with_full_height(text_view))
                .child(input_view)
        );
        tui.add_fullscreen_layer(layout);

        // Send callback sender to other thread
        cb_sink_tx.send(tui.cb_sink().clone()).unwrap();

        // Launch TUI event loop
        tui.run();
    });
    let tui_sender = cb_sink_rx.recv().expect("Could not get sender from TUI thread");

    // Macro to write a text line to the TUI text view
    macro_rules! log_line {
        ($line:expr) => {{
            let text = $line.to_string();
            tui_sender.send(Box::new(move |tui: &mut Cursive| {
                tui.call_on_id(VIEW_TEXT_ID, |view: &mut TextView| {
                    view.append_content(&text);
                    view.append_content("\n");
                });
            })).unwrap();
        }};
        ($line:expr, $($arg:tt)*) => {{
            log_line!(format!($line, $($arg)*));
        }};
    }

    // Get reference to task and downcast to ChatTask.
    // We can be sure that it's a ChatTask since that's the only one we proposed.
    let mut t = task.lock().expect("Could not lock task mutex");
    let chat_task: &mut ChatTask = (&mut **t as &mut Task)
        .downcast_mut::<ChatTask>()
        .expect("Chosen task is not a ChatTask");

    // Get reference to peer name Arc.
    let peer_name = chat_task.peer_name.clone();

    // Text message send loop
    //
    // The closure passed to `for_each` must return:
    //
    // * `future::ok(())` to continue listening for chat messages
    // * `future::err(Ok(()))` to stop the loop without an error
    // * `future::err(Err(_))` to stop the loop with an error
    let send_loop = chat_msg_rx
        .map_err(|_| Err(()))
        .for_each(|msg: String| {
            if msg.starts_with("/") {
                let mut parts = msg.split_whitespace();
                match parts.next().unwrap() {
                    "/help" => {
                        log_line!("*** Available commands: /help /nick /quit");
                        boxed!(future::ok(()))
                    }
                    "/quit" => {
                        log_line!("*** Exiting");

                        // Stop TUI
                        tui_sender.send(Box::new(move |tui: &mut Cursive| {
                            tui.quit();
                        })).unwrap();

                        // Disconnect
                        chat_task.close(CloseCode::WsGoingAway);

                        boxed!(future::err(Ok(())))
                    }
                    "/nick" => {
                        match parts.next() {
                            Some(nick) => {
                                log_line!("*** Changing nickname to {}", nick);
                                let future = chat_task
                                    .change_nick(&nick)
                                    .map_err(|_| Err(()));
                                boxed!(future)
                            }
                            None => {
                                log_line!("*** Usage: /nick <new-nickname>");
                                boxed!(future::ok(()))
                            }
                        }
                    }
                    other => {
                        log_line!("*** Unknown command: {}", other);
                        boxed!(future::ok(()))
                    }
                }
            } else {
                log_line!("{}> {}", chat_task.our_name, msg);
                let future = chat_task
                    .send_msg(&msg)
                    .map_err(|_| Err(()));
                boxed!(future)
            }
        })
        .or_else(|res| match res {
            Ok(_) => future::ok(debug!("† Send loop future done")),
            Err(_) => future::err(SaltyError::Crash("Something went wrong when forwarding messages to task".into()))
        });

    // Chat message receive loop
    //
    // The closure passed to `for_each` must return:
    //
    // * `future::ok(())` to continue listening for incoming messages
    // * `future::err(Ok(()))` to stop the loop without an error
    // * `future::err(Err(_))` to stop the loop with an error
    let receive_loop = incoming_rx
        .map_err(|_| Err(()))
        .for_each({
            |msg: ChatMessage| {
                match msg {
                    ChatMessage::Msg(text) => {
                        let pn = peer_name
                            .lock()
                            .ok()
                            .and_then(|p| p.clone())
                            .unwrap_or("?".to_string());
                        log_line!("{}> {}", pn, text);
                        future::ok(())
                    },
                    ChatMessage::NickChange(new_nick) => {
                        log_line!("*** Partner nick changed to {}", new_nick);
                        future::ok(())
                    },
                    ChatMessage::Disconnect(reason) => {
                        log_line!("*** Connection closed, reason: {}", reason);
                        future::err(Ok(()))
                    }
                }
            }
        })
        .or_else(|res| match res {
            Ok(_) => future::ok(debug!("† Receive loop future done")),
            Err(_) => future::err(SaltyError::Crash("Something went wrong in message receive loop".into())),
        });

    // Main future
    let main_loop = task_loop
        .join(
            send_loop
                .select(receive_loop)
                .map_err(|(e, ..)| e)
        );

    // Run future in reactor
    match core.run(main_loop) {
        Ok(_) => println!("Success."),
        Err(e) => {
            println!("{}", e);
            process::exit(1);
        },
    };

    // Wait for TUI thread to exit
    tui_thread.join().unwrap();

    info!("Goodbye!");
}

fn setup_logging(role: Role) -> Handle {
    // Log format
    let format = "{d(%Y-%m-%dT%H:%M:%S%.3f)} [{l:<5}] {m} (({f}:{L})){n}";

    // Instantiate appenders
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(format)))
        .build();
    let file = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(format)))
        .build(match role {
            Role::Initiator => "chat.initiator.log",
            Role::Responder => "chat.responder.log",
        })
        .unwrap();

    // Instantiate filters
    let info_filter = ThresholdFilter::new(LevelFilter::Info);

    let config = Config::builder()
        // Appenders
        .appender(Appender::builder().filter(Box::new(info_filter)).build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file)))

        // Loggers
        .logger(Logger::builder().build("saltyrtc_client", LevelFilter::Debug))
        .logger(Logger::builder().build("chat", LevelFilter::Debug))

        // Root logger
        .build(Root::builder().appender("stdout").appender("file").build(LevelFilter::Info))
        .unwrap();

    log4rs::init_config(config).unwrap()
}
