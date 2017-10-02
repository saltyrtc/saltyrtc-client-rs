//! Message types used in the SaltyRTC protocol.

use sodiumoxide::crypto::box_::PublicKey;

struct ClientHello {
    type_: String,
    key: PublicKey,
}

struct ServerHello {
    type_: String,
    key: PublicKey,
}
