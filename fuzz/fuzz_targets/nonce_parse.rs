#![no_main]

use libfuzzer_sys::fuzz_target;
use saltyrtc_client;

fuzz_target!(|data: &[u8]| {
    // Parse nonce from bytes. Should never panic.
    let _ = saltyrtc_client::nonce::Nonce::from_bytes(data);
});
