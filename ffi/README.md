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
