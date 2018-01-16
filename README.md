# saltyrtc-client-rs

[![CircleCI][circle-ci-badge]][circle-ci]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

**Note:** This library is in early development stage. During this phase,
force-pushes may happen to the `develop` branch. Once the codebase stabilizes a
bit, we'll switch to `master`.


## Testing

### Unit Tests

To run the testsuite:

    cargo test

### Fuzz Testing

To run fuzz tests, first install cargo-fuzz:

    cargo install cargo-fuzz

Then run the fuzzer against a target:

    cargo fuzz run <target>

You can list all targets with `cargo fuzz list`.

### Linting

To run clippy lints, compile the library with `--features clippy` on a nightly
compiler:

    $ cargo build --features clippy

If `nightly` is not your default compiler:

    $ rustup run nightly cargo build --features clippy


## Example Client

There is an example client at `examples/client.rs`. You can invoke it both as
initiator or responder.

If you start the client as initiator, the signaling path and auth token will be
randomly generated and printed:

    $ export RUST_LOG=saltyrtc_client=DEBUG
    $ cargo run --example client -- initiator
    INFO:saltyrtc_client::crypto: Generating new key pair
    INFO:saltyrtc_client::crypto: Generating new auth token

    ******************************
    Connecting as Initiator

    Signaling path: f637d7fff53defe8db111b17b2c445f7888a83c13dc40d7ff8449f700910f01f
    Auth token: 0e94b54a49e4ec7f4398ec9bec5d4359cca810f7eca31704e6c0afadd54a7818

    To connect with a peer:
    cargo run --example client -- responder \
        -p f637d7fff53defe8db111b17b2c445f7888a83c13dc40d7ff8449f700910f01f \
        -a 0e94b54a49e4ec7f4398ec9bec5d4359cca810f7eca31704e6c0afadd54a7818
    ******************************

    INFO:saltyrtc_client: Connected to server as Initiator
    ...

Simply copy that command in the second half of the output to another terminal
to connect to the initiator with a responder.

To see all options, use `cargo run --example client -- initiator --help` and
`cargo run --example client -- responder --help`.

**Note:** The example client currently expects a [SaltyRTC
Server](https://github.com/saltyrtc/saltyrtc-server-python/) instance to run on
`localhost:6699`.

## Logging

The examples use [`env_logger`](https://doc.rust-lang.org/log/env_logger/index.html).
To see the logs, export an env variable:

    export RUST_LOG=saltyrtc_client=TRACE

The examples initialize the [`dotenv`](https://crates.io/crates/dotenv) crate,
so you can also store this setting in an `.env` file:

    echo "RUST_LOG=saltyrtc_client=DEBUG" >> .env


## Msgpack Debugging

If you enable the `msgpack-debugging` compile flag, you'll get direct msgpack
analysis URLs for all decoded messages in your `TRACE` level logs.

    cargo build --features 'msgpack-debugging'

You can customize that URL prefix at compile time using the `MSGPACK_DEBUG_URL`
env var. This is the default URL:

    MSGPACK_DEBUG_URL='https://msgpack.dbrgn.ch/#base64='


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop.svg?style=shield
