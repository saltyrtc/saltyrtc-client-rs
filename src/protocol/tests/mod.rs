//! Protocol tests.

use super::*;

mod validate_nonce;
mod signaling_messages;

#[test]
fn test_responder_counter() {
    let mut rc = ResponderCounter::new();
    assert_eq!(rc.0, 0);
    assert_eq!(rc.increment(), Ok(0));
    assert_eq!(rc.0, 1);
}

#[test]
fn test_responder_counter_overflow() {
    let mut rc = ResponderCounter(::std::u32::MAX);
    assert_eq!(rc.0, ::std::u32::MAX);
    assert_eq!(
        rc.increment(),
        Err(SignalingError::Crash("Overflow when incrementing responder counter".into())),
    );
    assert_eq!(rc.0, ::std::u32::MAX);
}
