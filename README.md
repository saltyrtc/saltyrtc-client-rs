# saltyrtc-client-rs

[![CircleCI][circle-ci-badge]][circle-ci]
[![Rust][rust-badge]][github]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

Asynchronous [SaltyRTC][saltyrtc] client implementation for Rust 1.36+.

SaltyRTC is an end-to-end encrypted signalling protocol. It offers to freely
choose from a range of signalling tasks, such as setting up a WebRTC or ORTC
peer-to-peer connection, or using the WebSocket based signaling server as a
relay. SaltyRTC is completely open to new and custom signalling tasks for
everything feasible.

[Docs](https://docs.rs/saltyrtc-client)


## Testing

### Setup

The integration tests currently expect a [SaltyRTC Server][server] instance to
run on `localhost:8765`.

First, create a test certificate for localhost.

    openssl req \
       -newkey rsa:1024 \
       -x509 \
       -nodes \
       -keyout saltyrtc.key \
       -new \
       -out saltyrtc.crt \
       -subj /CN=localhost \
       -reqexts SAN \
       -extensions SAN \
       -config <(cat /etc/ssl/openssl.cnf \
         <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
       -sha256 \
       -days 1825

Create a Python virtualenv with dependencies:

    python3 -m virtualenv venv
    venv/bin/pip install saltyrtc.server[logging]

Finally, start the server with the following test permanent key:

    export SALTYRTC_SERVER_PERMANENT_KEY=0919b266ce1855419e4066fc076b39855e728768e3afa773105edd2e37037c20 # Public: 09a59a5fa6b45cb07638a3a6e347ce563a948b756fd22f9527465f7c79c2a864
    venv/bin/saltyrtc-server -v 5 serve -p 8765 \
        -sc saltyrtc.crt -sk saltyrtc.key \
        -k $SALTYRTC_SERVER_PERMANENT_KEY

Before you run the client tests, symlink the `saltyrtc.crt` file into your
`saltyrtc-client-rs` directory.

### Unit Tests

To run the testsuite:

    cargo test

### Fuzz Testing

To run fuzz tests, first install cargo-fuzz:

    cargo install cargo-fuzz

Then run the fuzzer against a target:

    cargo +nightly fuzz run <target>

You can list all targets with `cargo fuzz list`.

### Linting

To run clippy lints, first get the latest clippy version:

    $ rustup update
    $ rustup install nightly
    $ rustup component add clippy-preview --toolchain=nightly

Then run `clippy` through nightly cargo:

    $ cargo +nightly clippy


## Example Client

There is an example chat client at `examples/chat/main.rs`. You can invoke it
both as initiator or responder. Note that you need to have libncurses installed
on your system for the chat example to work.

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

**Note:** The tests currently expect a [SaltyRTC Server][server] instance to
run on `localhost:8765`.


## Msgpack Debugging

If you enable the `msgpack-debugging` compile flag, you'll get direct msgpack
analysis URLs for all decoded messages in your `TRACE` level logs.

    cargo build --features 'msgpack-debugging'

You can customize that URL prefix at compile time using the `MSGPACK_DEBUG_URL`
env var. This is the default URL:

    MSGPACK_DEBUG_URL='https://msgpack.dbrgn.ch/#base64='


## Release Signatures

Release commits and tags are signed with the
[Threema signing key](https://keybase.io/threema)
(`E7ADD9914E260E8B35DFB50665FDE935573ACDA6`).


## FFI

You can find C FFI bindings in the `ffi` subdirectory of this source repository.

**Note:** The FFI bindings are currently incomplete and blocked by
[rust-lang/rust#36342](https://github.com/rust-lang/rust/issues/36342).


## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT) at your option.


### Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.


<!-- Links -->
[saltyrtc]: https://saltyrtc.org/
[server]: https://github.com/saltyrtc/saltyrtc-server-python/

<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/master
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/master.svg?style=shield
[github]: https://github.com/saltyrtc/saltyrtc-client-rs
[rust-badge]: https://img.shields.io/badge/rust-1.36%2B-blue.svg?maxAge=3600
