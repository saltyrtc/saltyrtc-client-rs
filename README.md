# saltyrtc-client-rs

[![CircleCI][circle-ci-badge]][circle-ci]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

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

    $ cargo +nightly build --features clippy

## Example Client

There is an example chat client at `examples/chat/main.rs`. You can invoke it both as
initiator or responder.

If you start the chat as initiator, the signaling path and auth token will be
randomly generated and printed:

    $ cargo run --example chat -- initiator
    INFO:saltyrtc_client::crypto: Generating new key pair
    INFO:saltyrtc_client::crypto: Generating new auth token

    ******************************
    Connecting as Initiator

    Signaling path: f637d7fff53defe8db111b17b2c445f7888a83c13dc40d7ff8449f700910f01f
    Auth token: 0e94b54a49e4ec7f4398ec9bec5d4359cca810f7eca31704e6c0afadd54a7818

    To connect with a peer:
    cargo run --example chat -- responder \
        --path f637d7fff53defe8db111b17b2c445f7888a83c13dc40d7ff8449f700910f01f \
        --auth-token 0e94b54a49e4ec7f4398ec9bec5d4359cca810f7eca31704e6c0afadd54a7818
    ******************************

    INFO:saltyrtc_client: Connected to server as Initiator
    ...

Simply copy that command in the second half of the output to another terminal
to connect to the initiator with a responder.

To see all options, use `cargo run --example chat -- initiator --help` and
`cargo run --example chat -- responder --help`.

The chat example will log to a file called `chat.<role>.log`.

**Note:** The example chat currently expects a [SaltyRTC
Server](https://github.com/saltyrtc/saltyrtc-server-python/) instance to run on
`localhost:6699`.


## Msgpack Debugging

If you enable the `msgpack-debugging` compile flag, you'll get direct msgpack
analysis URLs for all decoded messages in your `TRACE` level logs.

    cargo build --features 'msgpack-debugging'

You can customize that URL prefix at compile time using the `MSGPACK_DEBUG_URL`
env var. This is the default URL:

    MSGPACK_DEBUG_URL='https://msgpack.dbrgn.ch/#base64='


## FFI

You can find C FFI bindings in the `ffi` subdirectory of this source repository.


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop.svg?style=shield
