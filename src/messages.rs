//! Message types used in the SaltyRTC protocol.

use sodiumoxide::crypto::box_::PublicKey;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ClientHello {
    #[serde(rename = "type")]
    pub type_: String,
    pub key: PublicKey,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct ServerHello {
    #[serde(rename = "type")]
    pub type_: String,
    pub key: PublicKey,
}
