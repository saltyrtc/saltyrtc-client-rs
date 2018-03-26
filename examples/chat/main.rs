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
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::Duration;

use clap::{Arg, App, SubCommand};
use cursive::{Cursive};
use cursive::traits::{Identifiable};
use cursive::view::ScrollStrategy;
use cursive::views::{TextView, EditView, BoxView, LinearLayout};
use data_encoding::{HEXLOWER};
use futures::{Sink, Stream, future};
use futures::future::Future;
use futures::sync::mpsc as futures_mpsc;
use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::filter::threshold::ThresholdFilter;
use native_tls::{TlsConnector, Certificate, Protocol};
use saltyrtc_client::{SaltyClient, Role, WsClient, BoxedFuture, CloseCode};
use saltyrtc_client::crypto::{KeyPair, AuthToken, public_key_from_hex_str, private_key_from_hex_str};
use saltyrtc_client::errors::SaltyError;
use saltyrtc_client::tasks::Task;
use tokio_core::reactor::Core;

use chat_task::{ChatTask, ChatMessage};


pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const VIEW_TEXT_ID: &'static str = "text";
const VIEW_INPUT_ID: &'static str = "input";


/// Wrap future in a box with type erasure.
macro_rules! boxed {
    ($future:expr) => {{
        Box::new($future) as BoxedFuture<_, _>
    }}
}


fn main() {
    const ARG_PATH: &'static str = "path";
    const ARG_RESPONDER_KEY: &'static str = "responder_key";
    const ARG_PRIVATE_KEY: &'static str = "private_key";
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
        .subcommand(SubCommand::with_name("initiator_trusted")
            .about("Start chat as initiator with a trusted responder key")
            .arg(Arg::with_name(ARG_PRIVATE_KEY)
                .long("private-key")
                .takes_value(true)
                .value_name("PRIVATE_KEY")
                .required(true)
                .help("The own private key (hex encoded)"))
            .arg(Arg::with_name(ARG_RESPONDER_KEY)
                .long("responder-key")
                .takes_value(true)
                .value_name("RESPONDER_KEY")
                .required(true)
                .help("The trusted responder public key (hex encoded)"))
            .arg(arg_ping_interval.clone()))
        .subcommand(SubCommand::with_name("responder")
            .about("Start chat as responder")
            .arg(Arg::with_name(ARG_PATH)
                .long("path")
                .takes_value(true)
                .value_name("PATH")
                .required(true)
                .help("The websocket path (hex encoded public key of the initiator)"))
            .arg(Arg::with_name(ARG_AUTHTOKEN)
                .long("auth-token")
                .alias("token")
                .alias("authtoken")
                .takes_value(true)
                .value_name("AUTHTOKEN")
                .required(true)
                .help("The auth token (hex encoded)"))
            .arg(arg_ping_interval.clone()))
        .subcommand(SubCommand::with_name("responder_trusted")
            .about("Start chat as responder with a trusted initiator key")
            .arg(Arg::with_name(ARG_PATH)
                .long("path")
                .takes_value(true)
                .value_name("PATH")
                .required(true)
                .help("The websocket path (hex encoded public key of the initiator)"))
            .arg(Arg::with_name(ARG_PRIVATE_KEY)
                .long("private-key")
                .takes_value(true)
                .value_name("PRIVATE_KEY")
                .required(true)
                .help("The own private key (hex encoded)"))
            .arg(arg_ping_interval));

    // Parse arguments
    let subcommand = app.get_matches().subcommand.unwrap_or_else(|| {
        println!("Missing subcommand.");
        println!("Use -h or --help to see usage.");
        process::exit(1);
    });
    let args = &subcommand.matches;

    // Determine role
    let (role, is_trusted) = match &*subcommand.name {
        "initiator" => (Role::Initiator, false),
        "initiator_trusted" => (Role::Initiator, true),
        "responder" => (Role::Responder, false),
        "responder_trusted" => (Role::Responder, true),
        other => {
            println!("Invalid subcommand: {}", other);
            process::exit(1);
        },
    };

    // Set up logging
    let log_handle = log4rs::init_config(setup_logging(role, true)).unwrap();

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
    tls_builder.supported_protocols(&[Protocol::Tlsv12, Protocol::Tlsv11, Protocol::Tlsv10])
        .unwrap_or_else(|e| panic!("Could not set TLS protocols: {}", e));
    tls_builder.add_root_certificate(server_cert)
        .unwrap_or_else(|e| panic!("Could not add root certificate: {}", e));
    let tls_connector = tls_builder.build()
        .unwrap_or_else(|e| panic!("Could not initialize TlsConnector: {}", e));

    // Create or restore public permanent keypair
    let keypair = if is_trusted {
        let private_key_hex = args.value_of(ARG_PRIVATE_KEY).unwrap();
        let private_key = private_key_from_hex_str(private_key_hex).unwrap();
        KeyPair::from_private_key(private_key)
    } else {
        KeyPair::new()
    };
    let own_pubkey_hex = keypair.public_key_hex();
    let own_privkey_hex = keypair.private_key_hex();

    // Determine websocket path
    let path: String = match role {
        Role::Initiator => own_pubkey_hex.clone(),
        Role::Responder => args.value_of(ARG_PATH).expect("Path not supplied").to_lowercase(),
    };

    // Determine ping interval
    let ping_interval = {
        let seconds: u64 = args.value_of(ARG_PING_INTERVAL).expect("Ping interval not supplied")
                               .parse().expect("Could not parse interval seconds to a number");
        Duration::from_secs(seconds)
    };

    // Create new SaltyRTC client instance
    let (incoming_tx, incoming_rx) = futures_mpsc::unbounded::<ChatMessage>();
    let (salty, auth_token_hex) = match role {
        Role::Initiator => {
            let task = ChatTask::new("initiat0r", core.remote(), incoming_tx);
            let builder = SaltyClient::build(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval));
            let salty = if is_trusted {
                let trusted_key = args.value_of(ARG_RESPONDER_KEY).unwrap();
                builder.initiator_trusted(public_key_from_hex_str(trusted_key).unwrap())
            } else {
                builder.initiator()
            }.expect("Could not create SaltyClient instance");
            let auth_token_hex = salty.auth_token().map(|t| HEXLOWER.encode(t.secret_key_bytes()));
            (salty, auth_token_hex)
        },
        Role::Responder => {
            let task = ChatTask::new("r3spond3r", core.remote(), incoming_tx);
            let initiator_pubkey = public_key_from_hex_str(&path).unwrap();
            let builder = SaltyClient::build(keypair)
                .add_task(Box::new(task))
                .with_ping_interval(Some(ping_interval));
            if is_trusted {
                (builder.responder_trusted(initiator_pubkey).unwrap(), None)
            } else {
                let auth_token_hex = args.value_of(ARG_AUTHTOKEN).unwrap().to_string();
                let auth_token = AuthToken::from_hex_str(&auth_token_hex).expect("Invalid auth token hex string");
                (builder.responder(initiator_pubkey, auth_token).unwrap(), Some(auth_token_hex))
            }
        },
    };

    println!("\n\x1B[32m******************************");
    println!("Connecting as {} ({})", role, if is_trusted { "trusted" } else { "not trusted" });
    println!();
    println!("   Own permanent public key: {}", &own_pubkey_hex);
    println!("  Own permanent private key: {}", &own_privkey_hex);
    println!("             Signaling path: {}", path);
    if let Some(ref auth_token) = auth_token_hex {
        println!("                 Auth token: {}", auth_token);
    } else {
        println!("Using trusted key");
    }
    println!();
    println!("To connect with a peer:");
    match (role, auth_token_hex) {
        (Role::Initiator, Some(ath)) => println!("cargo run --example chat -- responder \\\n    --path {} \\\n    --auth-token {}", path, ath),
        (Role::Initiator, None) => println!("cargo run --example chat -- responder_trusted \\\n    --path {} \\\n    --private-key XXX", path),
        (Role::Responder, Some(_)) => println!("cargo run --example chat -- initiator"),
        (Role::Responder, None) => println!("cargo run --example chat -- initiator_trusted \\\n    --responder-key {} \\\n    --private-key XXX", &own_pubkey_hex),
    };
    println!("******************************\x1B[0m\n");

    // Wrap SaltyClient in a Rc<RefCell<>>
    let salty_rc = Rc::new(RefCell::new(salty));

    // Connect to server
    let connect_future = saltyrtc_client::connect(
            "localhost",
            8765,
            Some(tls_connector),
            &core.handle(),
            salty_rc.clone(),
        )
        .unwrap();

    // Do handshake
    let handshake_future = connect_future
        .map(|client| { println!("Connected to server"); client })
        .and_then(|client| saltyrtc_client::do_handshake(client, salty_rc.clone(), None))
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
    let (task, task_loop, _event_rx) = saltyrtc_client::task_loop(client, salty_rc.clone())
        .unwrap_or_else(|e| {
            println!("{}", e);
            process::exit(1);
        });

    // Disable logging to stdout
    // (Causes errors in combination with TUI
    println!("Starting TUI and disabling logging to stdout. See `chat.{}.log` for logs.",
             role.to_string().to_lowercase());
    log_handle.set_config(setup_logging(role, false));

    // Launch TUI thread
    let (cb_sink_tx, cb_sink_rx) = std_mpsc::sync_channel(1);
    let (chat_msg_tx, chat_msg_rx) = futures_mpsc::unbounded::<String>();
    let remote = core.remote();
    let tui_thread = thread::spawn(move || {
        // Launch TUI
        let mut tui = Cursive::new();
        tui.set_fps(10);

        // Create text view (for displaying messages)
        let text_view = TextView::new("=== Welcome to SaltyChat! ===\nType /quit to exit.\nType /help to list available commands.\n\n")
            .scrollable(true)
            .scroll_strategy(ScrollStrategy::StickToBottom)
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
                                match chat_task.change_nick(&nick) {
                                    Ok(_) => boxed!(future::ok(())),
                                    Err(e) => {
                                        log_line!("*** Error: {}", e);
                                        boxed!(future::err(Err(())))
                                    }
                                }
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
                match chat_task.send_msg(&msg) {
                    Ok(_) => boxed!(future::ok(())),
                    Err(e) => {
                        log_line!("*** Error: {}", e);
                        boxed!(future::err(Err(())))
                    }
                }
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
                        log_line!("*** Connection with peer closed, reason: {}", reason);
                        log_line!("*** Use Ctrl+C to exit");
                        future::err(Ok(()))
                    },
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

fn setup_logging(role: Role, log_to_stdout: bool) -> Config {
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

    // Config builder
    let builder = Config::builder()

        // Appenders
        .appender(Appender::builder().filter(Box::new(info_filter)).build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file)))

        // Loggers
        .logger(Logger::builder().build("saltyrtc_client", LevelFilter::Trace))
        .logger(Logger::builder().build("chat", LevelFilter::Trace));

    // Root logger
    let root = match log_to_stdout {
        true => Root::builder().appender("stdout").appender("file"),
        false => Root::builder().appender("file"),
    };

    // Build configuration
    builder.build(root.build(LevelFilter::Info)).unwrap()
}
