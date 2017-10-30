//! Combined sequence numbers.
//!
//! This module handles the overflow checking of the 48 bit combined sequence
//! number (CSN) in the SaltyRTC nonce consisting of the 32 bit sequence number
//! and the 16 bit overflow number.

use std::cmp;

use rust_sodium::randombytes::randombytes;

use errors::{Result, ErrorKind};
use helpers::libsodium_init_or_panic;


/// This type handles the overflow checking of the 48 bit combined sequence
/// number (CSN) consisting of the sequence number and the overflow number.
///
/// This type cannot be cloned.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct CombinedSequence {
    /// The overflow number.
    overflow: u16,
    /// The sequence number.
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
    pub fn random() -> Self {
        // Make sure that libsodium is initialized
        libsodium_init_or_panic();

        // Create 32 bits of cryptographically secure random data
        let rand = randombytes(4);

        // Create combined sequence from that data
        let overflow = 0u16;
        let sequence = ((rand[0] as u32) << 24)
                     + ((rand[1] as u32) << 16)
                     + ((rand[2] as u32) << 8)
                     + (rand[3] as u32);

        CombinedSequence {
            overflow: overflow,
            sequence: sequence,
        }
    }

    /// Return the 48 bit combined sequence number.
    fn combined_sequence_number(&self) -> u64 {
        ((self.overflow as u64) << 32) + (self.sequence as u64)
    }

    /// Increment the `CombinedSequence` and return a snapshot.
    ///
    /// This will fail if the overflow number overflows. This is extremely
    /// unlikely and must be treated as a protocol error.
    pub fn next(&mut self) -> Result<CombinedSequenceSnapshot> {
        let next_result: Result<CombinedSequence> = match self.sequence.checked_add(1) {
            Some(incremented) => {
                Ok(CombinedSequence::new(self.overflow, incremented))
            },
            None => match self.overflow.checked_add(1) {
                Some(incremented) => Ok(CombinedSequence::new(incremented, 0)),
                None => Err(ErrorKind::CsnOverflow.into()),
            }
        };
        let next = next_result?;
        let snapshot = (&next).into();
        *self = next;
        Ok(snapshot)
    }

}

impl<'a> From<&'a CombinedSequenceSnapshot> for CombinedSequence {
    fn from(val: &'a CombinedSequenceSnapshot) -> Self {
        Self {
            overflow: val.overflow,
            sequence: val.sequence,
        }
    }
}

impl cmp::PartialEq<CombinedSequenceSnapshot> for CombinedSequence {
    fn eq(&self, other: &CombinedSequenceSnapshot) -> bool {
        self.combined_sequence_number().eq(&other.combined_sequence_number())
    }
}

impl cmp::PartialOrd<CombinedSequenceSnapshot> for CombinedSequence {
    fn partial_cmp(&self, other: &CombinedSequenceSnapshot) -> Option<cmp::Ordering> {
        Some(self.combined_sequence_number().cmp(&other.combined_sequence_number()))
    }
}


/// An immutable snapshot of a [`CombinedSequence`](struct.CombinedSequence.html).
///
/// This type is returned by the [`next()`](struct.CombinedSequence.html#method.next)
/// method on a combined sequence instance.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CombinedSequenceSnapshot {
    /// The overflow number.
    overflow: u16,
    /// The sequence number.
    sequence: u32,
}

impl CombinedSequenceSnapshot {
    /// Create a new `CombinedSequenceSnapshot` from the specified parts.
    pub fn new(overflow: u16, sequence: u32) -> Self {
        CombinedSequenceSnapshot { overflow, sequence }
    }

    #[cfg(test)]
    pub fn random() -> Self {
        let cs = CombinedSequence::random();
        CombinedSequenceSnapshot {
            sequence: cs.sequence,
            overflow: cs.overflow,
        }
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

}

impl<'a> From<&'a CombinedSequence> for CombinedSequenceSnapshot {
    fn from(val: &'a CombinedSequence) -> Self {
        Self {
            overflow: val.overflow,
            sequence: val.sequence,
        }
    }
}

impl cmp::Ord for CombinedSequenceSnapshot {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.combined_sequence_number().cmp(&other.combined_sequence_number())
    }
}

impl cmp::PartialOrd for CombinedSequenceSnapshot {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::PartialEq<CombinedSequence> for CombinedSequenceSnapshot {
    fn eq(&self, other: &CombinedSequence) -> bool {
        self.combined_sequence_number().eq(&other.combined_sequence_number())
    }
}

impl cmp::PartialOrd<CombinedSequence> for CombinedSequenceSnapshot {
    fn partial_cmp(&self, other: &CombinedSequence) -> Option<cmp::Ordering> {
        Some(self.combined_sequence_number().cmp(&other.combined_sequence_number()))
    }
}


/// A pair of a [`CombinedSequence`](struct.CombinedSequence.html) and a
/// [`CombinedSequenceSnapshot`](struct.CombinedSequenceSnapshot.html).
#[derive(Debug, PartialEq, Eq)]
pub struct CombinedSequencePair {
    pub ours: CombinedSequence,
    pub theirs: Option<CombinedSequenceSnapshot>,
}

impl CombinedSequencePair {
    /// Create a new [`CombinedSequencePair`](struct.CombinedSequencePair.html).
    pub fn new() -> Self {
        CombinedSequencePair {
            ours: CombinedSequence::random(),
            theirs: None,
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
            let csn = CombinedSequence::random();
            numbers.insert(csn);
        }
        assert_eq!(numbers.len(), 100);
    }

    /// 100 generated random CSNs should all be smaller than the largest
    /// possible 48 bit unsigned integer.
    #[test]
    fn combined_value_range() {
        for _ in 0..100 {
            let csn = CombinedSequence::random();
            let number = csn.combined_sequence_number();
            assert!(number < (1 << 48));
        }
    }

    #[test]
    fn increment_without_overflow() {
        // Find a CSN that will not overflow
        let mut old = CombinedSequence::random();
        while old.sequence == ::std::u32::MAX {
            old = CombinedSequence::random();
        }

        // Get previous numbers
        let old_sequence = old.sequence;
        let old_overflow = old.overflow;
        let old_combined_sequence = old.combined_sequence_number();

        // Increment
        let new = old.next().unwrap();

        assert_eq!(old_sequence + 1, new.sequence_number());
        assert_eq!(old_overflow, new.overflow_number());
        assert_eq!(old_combined_sequence + 1, new.combined_sequence_number());
    }

    #[test]
    fn increment_with_sequence_overflow() {
        let mut old = CombinedSequence::new(0, ::std::u32::MAX);
        let new = old.next().unwrap();

        assert_eq!(new.sequence_number(), 0);
        assert_eq!(new.overflow_number(), 1);
        assert_eq!(new.combined_sequence_number(), (::std::u32::MAX as u64) + 1);
    }

    #[test]
    fn increment_with_overflow_overflow() {
        let mut old = CombinedSequence::new(::std::u16::MAX, ::std::u32::MAX);
        let new = old.next();
        assert!(new.is_err());
        match new.unwrap_err().kind() {
            &ErrorKind::CsnOverflow => {},
            ref ek @ _ => panic!("Wrong error kind: {:?}", ek),
        };
    }
}
