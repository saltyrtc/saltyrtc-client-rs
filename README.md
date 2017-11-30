# saltyrtc-client-rs

[![CircleCI][circle-ci-badge]][circle-ci]

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

    MSGPACK_DEBUG_URL='https://sugendran.github.io/msgpack-visualizer/#base64='


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop.svg?style=shield
