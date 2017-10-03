//! Nonce related functionality.
//!
//! This includes serialization and deserialization.

use errors::Error;

/// Newtype for the sender address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct Sender(u8);

/// Newtype for the receiver address.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
struct Receiver(u8);

/// The SaltyRTC nonce.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nonce {
    cookie: [u8; 16],
    source: Sender,
    destination: Receiver,
    overflow: u16,
    sequence: u32,
}
