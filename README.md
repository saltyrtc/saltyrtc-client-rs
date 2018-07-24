# saltyrtc-client-rs

[![CircleCI][circle-ci-badge]][circle-ci]
[![Rust][rust-badge]][github]
[![Join our chat on Gitter](https://badges.gitter.im/saltyrtc/Lobby.svg)](https://gitter.im/saltyrtc/Lobby)

Asynchronous [SaltyRTC][saltyrtc] client implementation for Rust 1.26+.

SaltyRTC is an end-to-end encrypted signalling protocol. It offers to freely
choose from a range of signalling tasks, such as setting up a WebRTC or ORTC
peer-to-peer connection, or using the WebSocket based signaling server as a
relay. SaltyRTC is completely open to new and custom signalling tasks for
everything feasible.

[Docs](https://docs.rs/saltyrtc-client)


## Testing

**Note:** The tests currently expect a [SaltyRTC Server][server] instance to
run on `localhost:6699`.

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

**Note:** The tests currently expect a [SaltyRTC Server][server] instance to
run on `localhost:6699`.


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
[rust-badge]: https://img.shields.io/badge/rust-1.26%2B-blue.svg?maxAge=3600
