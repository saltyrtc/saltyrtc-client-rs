//! Combined sequence numbers.
//!
//! This module handles the overflow checking of the 48 bit combined sequence
//! number (CSN) in the SaltyRTC nonce consisting of the 32 bit sequence number
//! and the 16 bit overflow number.

use rust_sodium::randombytes::randombytes;

use errors::{Result, ResultExt, ErrorKind};
use helpers::libsodium_init;

/// The `CombinedSequence` type handles the overflow checking of the 48 bit
/// combined sequence number (CSN) consisting of the sequence number and the
/// overflow number.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CombinedSequence {
    overflow: u16,
    sequence: u32,
}

impl CombinedSequence {

    /// Create a new `CombinedSequence` from the specified parts.
    pub fn new(overflow: u16, sequence: u32) -> Self {
        CombinedSequence { overflow, sequence }
    }

    /// Create a new random `CombinedSequence`.
    ///
    /// The overflow number will be initialized to 0, while a cryptographically
    /// secure random value will be generated for the sequence number.
    pub fn random() -> Result<Self> {
        // Make sure that libsodium is initialized
        libsodium_init()
            .chain_err(|| ErrorKind::Crypto("could not create new random combined sequence".into()))?;

        // Create 32 bits of cryptographically secure random data
        let rand = randombytes(4);

        // Create combined sequence from that data
        let overflow = 0u16;
        let sequence = ((rand[0] as u32) << 24)
                     + ((rand[1] as u32) << 16)
                     + ((rand[2] as u32) << 8)
                     + (rand[3] as u32);

        Ok(CombinedSequence {
            overflow: overflow,
            sequence: sequence,
        })
    }

    /// Return the 16 bit overflow number.
    pub fn overflow_number(&self) -> u16 {
        self.overflow
    }

    /// Return the 32 bit sequence number.
    pub fn sequence_number(&self) -> u32 {
        self.sequence
    }

    /// Return the 48 bit combined sequence number.
    pub fn combined_sequence_number(&self) -> u64 {
        ((self.overflow as u64) << 32) + (self.sequence as u64)
    }

    /// Return the next `CombinedSequence` by incrementing.
    ///
    /// This will fail if the overflow number overflows. This is extremely
    /// unlikely and must be treated as a protocol error.
    pub fn next(self) -> Result<Self> {
        match self.sequence.checked_add(1) {
            Some(incremented) => Ok(CombinedSequence::new(self.overflow, incremented)),
            None => match self.overflow.checked_add(1) {
                Some(incremented) => Ok(CombinedSequence::new(incremented, 0)),
                None => Err(ErrorKind::CsnOverflow.into()),
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// 100 generated random CSNs should be different
    #[test]
    fn random_distinct() {
        let mut numbers = HashSet::new();
        for _ in 0..100 {
            let csn = CombinedSequence::random().unwrap();
            numbers.insert(csn);
        }
        assert_eq!(numbers.len(), 100);
    }

    /// 100 generated random CSNs should all be smaller than the largest
    /// possible 48 bit unsigned integer.
    #[test]
    fn combined_value_range() {
        for _ in 0..100 {
            let csn = CombinedSequence::random().unwrap();
            let number = csn.combined_sequence_number();
            assert!(number < (1 << 48));
        }
    }

    #[test]
    fn increment_without_overflow() {
        // Find a CSN that will not overflow
        let mut old = CombinedSequence::random().unwrap();
        while old.sequence_number() == ::std::u32::MAX {
            old = CombinedSequence::random().unwrap();
        }

        // Get previous numbers
        let old_sequence = old.sequence_number();
        let old_overflow = old.overflow_number();
        let old_combined_sequence = old.combined_sequence_number();

        // Increment
        let new = old.next().unwrap();

        assert_eq!(old_sequence + 1, new.sequence_number());
        assert_eq!(old_overflow, new.overflow_number());
        assert_eq!(old_combined_sequence + 1, new.combined_sequence_number());
    }

    #[test]
    fn increment_with_sequence_overflow() {
        let old = CombinedSequence::new(0, ::std::u32::MAX);
        let new = old.next().unwrap();

        assert_eq!(new.sequence_number(), 0);
        assert_eq!(new.overflow_number(), 1);
        assert_eq!(new.combined_sequence_number(), (::std::u32::MAX as u64) + 1);
    }

    #[test]
    fn increment_with_overflow_overflow() {
        let old = CombinedSequence::new(::std::u16::MAX, ::std::u32::MAX);
        let new = old.next();
        assert!(new.is_err());
        match new.unwrap_err().kind() {
            &ErrorKind::CsnOverflow => {},
            ref ek @ _ => panic!("Wrong error kind: {:?}", ek),
        };
    }
}