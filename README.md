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


<!-- Badges -->
[circle-ci]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop
[circle-ci-badge]: https://circleci.com/gh/saltyrtc/saltyrtc-client-rs/tree/develop.svg?style=shield
