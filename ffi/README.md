# saltyrtc-client FFI bindings

This crate contains some FFI bindings for the saltyrtc-client library.

Note: Due to a [Rust bug](https://github.com/rust-lang/rust/issues/36342), C
bindings cannot be re-exported. This means that the saltyrtc-client FFI
bindings are currently a bit useless as a separate crate. Instead, every task
implementation needs to write its own bindings. The bindings in this crate can
be copy-pasted if desired.

## Testing

### Rust tests

Simply run `cargo test`.

### C tests

The C tests are built using meson / ninja. They are run automatically when
calling `cargo test`.

If you want to build the tests manually, in the root directory, type:

    $ meson build
    $ cd build
    $ ninja
