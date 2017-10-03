#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate saltyrtc_client;

fuzz_target!(|data: &[u8]| {
    // Parse nonce from bytes. Should never panic.
    let _ = saltyrtc_client::nonce::Nonce::from_bytes(data);
});
