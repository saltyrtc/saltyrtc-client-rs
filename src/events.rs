//! Everything related to events.

pub(crate) const BUS_SIZE: usize = 32;


/// All possible events that can happen in the SaltyRTC implementation.
///
/// Since more events may be added in future versions,
/// matching on this enum should not be exhaustive!
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The server and peer handshakes have been done.
    HandshakeDone,

    #[doc(hidden)]
    ___ForExtensibility,
}
