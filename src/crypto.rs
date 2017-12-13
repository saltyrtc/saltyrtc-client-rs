//! Functionality related to Libsodium key management and encryption.

use std::cmp;
use std::fmt;

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use rust_sodium::crypto::{box_, secretbox};
use rust_sodium_sys::crypto_scalarmult_base;
use serde::ser::{Serialize, Serializer};
use serde::de::{Deserialize, Deserializer, Visitor, Error as SerdeError};

use errors::{SaltyResult, SaltyError, SignalingResult, SignalingError};
use helpers::{libsodium_init_or_panic};
use protocol::Nonce;

/// A public key used for decrypting data.
///
/// Re-exported from the [`rust_sodium`](../rust_sodium/) crate.
pub type PublicKey = box_::PublicKey;

/// A private key used for encrypting data.
///
/// Re-exported from the [`rust_sodium`](../rust_sodium/) crate.
pub type PrivateKey = box_::SecretKey;

/// A symmetric key used for both encrypting and decrypting data.
///
/// Re-exported from the [`rust_sodium`](../rust_sodium/) crate.
pub type SecretKey = secretbox::Key;

/// Create a `PublicKey` instance from hex bytes.
pub fn public_key_from_hex_str(hex_str: &str) -> SaltyResult<PublicKey> {
    let bytes = HEXLOWER_PERMISSIVE.decode(hex_str.as_bytes())
        .map_err(|_| SaltyError::Decode("Could not decode public key hex string".to_string()))?;
    PublicKey::from_slice(&bytes)
        .ok_or(SaltyError::Decode("Invalid public key hex string".to_string()))
}


/// Wrapper for holding a keypair and encrypting / decrypting messages.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyStore {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl KeyStore {

    /// Create a new key pair and wrap it in a key store.
    ///
    /// ## Panics
    ///
    /// This may panic if libsodium initialization fails.
    pub fn new() -> Self {
        info!("Generating new key pair");

        // Initialize libsodium if it hasn't been initialized already
        libsodium_init_or_panic();

        // Generate key pair
        let (pk, sk) = box_::gen_keypair();
        trace!("Public key: {:?}", pk);

        KeyStore {
            public_key: pk,
            private_key: sk,
        }
    }

    /// Create a new key pair from an existing private key.
    ///
    /// The private key is consumed and transferred into the `KeyStore`.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = unsafe {
            // Use crypto_scalarmult_base as described here:
            // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html#key-pair-generation
            let mut buf = [0u8; box_::PUBLICKEYBYTES];
            crypto_scalarmult_base(buf.as_mut_ptr(), private_key.0.as_ptr());
            box_::PublicKey(buf)
        };
        KeyStore {
            public_key: public_key,
            private_key: private_key,
        }
    }

    /// Create a new key pair from an existing public and private key.
    ///
    /// The two keys are consumed and transferred into the `KeyStore`.
    pub fn from_keypair(public_key: PublicKey, private_key: PrivateKey) -> Self {
        KeyStore {
            public_key: public_key,
            private_key: private_key,
        }
    }

    /// Return a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return the public key as hex-encoded string.
    pub fn public_key_hex(&self) -> String {
        HEXLOWER.encode(self.public_key.as_ref())
    }

    /// Return a reference to the private key.
    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Encrypt data for the specified public key with the private key.
    pub(crate) fn encrypt(&self, data: &[u8], nonce: Nonce, other_key: &PublicKey) -> Vec<u8> {
        let rust_sodium_nonce: box_::Nonce = nonce.into();
        box_::seal(data, &rust_sodium_nonce, other_key, &self.private_key)
    }

    /// Decrypt data using the specified public key with the own private key.
    ///
    /// If decryption succeeds, the decrypted bytes are returned. Otherwise, a
    /// [`SignalingError::Crypto`](../enum.SignalingError.html#variant.Crypto)
    /// is returned.
    pub(crate) fn decrypt(&self, data: &[u8], nonce: Nonce, other_key: &PublicKey) -> SignalingResult<Vec<u8>> {
        let rust_sodium_nonce: box_::Nonce = nonce.into();
        box_::open(data, &rust_sodium_nonce, other_key, &self.private_key)
            .map_err(|_| SignalingError::Crypto("Could not decrypt data".to_string()))
    }

}


/// Wrapper for holding an auth token and encrypting / decrypting messages.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthToken(SecretKey);

impl AuthToken {

    /// Create a new auth token.
    ///
    /// This can fail only if libsodium initialization fails.
    pub fn new() -> Self {
        info!("Generating new auth token");

        // Initialize libsodium if it hasn't been initialized already
        libsodium_init_or_panic();

        // Generate key pair
        let key = secretbox::gen_key();

        AuthToken(key)
    }

    /// Create an `AuthToken` instance from hex bytes.
    pub fn from_hex_str(hex_str: &str) -> SaltyResult<Self> {
        let bytes = HEXLOWER_PERMISSIVE.decode(hex_str.as_bytes())
            .map_err(|e| SaltyError::Decode(format!("Could not decode auth token hex string: {}", e)))?;
        let key = SecretKey::from_slice(&bytes)
            .ok_or(SaltyError::Decode("Invalid auth token hex string".to_string()))?;
        Ok(AuthToken(key))
    }

    /// Return a reference to the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.0
    }

    /// Return a reference to the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &(self.0).0
    }

    /// Encrypt data with the secret key.
    pub(crate) fn encrypt(&self, plaintext: &[u8], nonce: Nonce) -> Vec<u8> {
        let rust_sodium_nonce: secretbox::Nonce = nonce.into();
        secretbox::seal(plaintext, &rust_sodium_nonce, self.secret_key())
    }

    /// Decrypt data with the secret key.
    ///
    /// If decryption succeeds, the decrypted bytes are returned. Otherwise, a
    /// [`SignalingError::Crypto`](../enum.SignalingError.html#variant.Crypto)
    /// is returned.
    pub(crate) fn decrypt(&self, ciphertext: &[u8], nonce: Nonce) -> SignalingResult<Vec<u8>> {
        let rust_sodium_nonce: secretbox::Nonce = nonce.into();
        secretbox::open(ciphertext, &rust_sodium_nonce, self.secret_key())
            .map_err(|_| SignalingError::Crypto("Could not decrypt data".to_string()))
    }

}


/// A pair of not-yet-signed keys used in the [`ServerAuth`](../messages/struct.ServerAuth.html)
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedKeys {
    server_session_key: PublicKey,
    client_permanent_key: PublicKey,
}

impl UnsignedKeys {
    pub fn new(server_session_key: PublicKey, client_permanent_key: PublicKey) -> Self {
        UnsignedKeys {
            server_session_key: server_session_key,
            client_permanent_key: client_permanent_key,
        }
    }
}


/// The number of bytes in the [`SignedKeys`](struct.SignedKeys.html) array.
const SIGNED_KEYS_BYTES: usize = 2 * box_::PUBLICKEYBYTES + box_::MACBYTES;

/// Concatenated signed keys used in the [`ServerAuth`](../messages/struct.ServerAuth.html)
/// message.
pub struct SignedKeys([u8; SIGNED_KEYS_BYTES]);

impl SignedKeys {
    pub fn new(bytes: [u8; SIGNED_KEYS_BYTES]) -> Self {
        SignedKeys(bytes)
    }
}

/// Implementation required because Clone cannot be derived for `[u8; 80]` on
/// Rust < 1.21.
impl Clone for SignedKeys {
    fn clone(&self) -> Self {
        SignedKeys(self.0)
    }
}

/// Implementation required because Debug cannot be derived for `[u8; 80]`.
impl fmt::Debug for SignedKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.0[..].fmt(formatter)
    }
}

/// Implementation required because `PartialEq` cannot be derived for `[u8; 80]`.
impl cmp::PartialEq<SignedKeys> for SignedKeys {
    fn eq(&self, other: &SignedKeys) -> bool {
        self.0[..].eq(&other.0[..])
    }
}

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl Serialize for SignedKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
        serializer.serialize_bytes(&self.0)
    }
}

/// Visitor used to serialize the [`SignedKeys`](struct.SignedKeys.html)
/// struct with Serde.
struct SignedKeysVisitor;

impl<'de> Visitor<'de> for SignedKeysVisitor {
    type Value = SignedKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("80 bytes of binary data")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: SerdeError {
        if v.len() != SIGNED_KEYS_BYTES {
            return Err(SerdeError::invalid_length(v.len(), &self));
        }
        Ok(SignedKeys::new([
            v[ 0], v[ 1], v[ 2], v[ 3], v[ 4], v[ 5], v[ 6], v[ 7],
            v[ 8], v[ 9], v[10], v[11], v[12], v[13], v[14], v[15],
            v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23],
            v[24], v[25], v[26], v[27], v[28], v[29], v[30], v[31],
            v[32], v[33], v[34], v[35], v[36], v[37], v[38], v[39],
            v[40], v[41], v[42], v[43], v[44], v[45], v[46], v[47],
            v[48], v[49], v[50], v[51], v[52], v[53], v[54], v[55],
            v[56], v[57], v[58], v[59], v[60], v[61], v[62], v[63],
            v[64], v[65], v[66], v[67], v[68], v[69], v[70], v[71],
            v[72], v[73], v[74], v[75], v[76], v[77], v[78], v[79],
        ]))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E> where E: SerdeError {
        self.visit_bytes(&v)
    }
}

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl<'de> Deserialize<'de> for SignedKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
        deserializer.deserialize_bytes(SignedKeysVisitor)
    }
}

#[cfg(test)]
use helpers::TestRandom;
#[cfg(test)]
impl TestRandom for PublicKey {
    fn random() -> PublicKey {
        use rust_sodium::randombytes::randombytes_into;
        libsodium_init_or_panic();
        let mut rand = [0; 32];
        randombytes_into(&mut rand);
        PublicKey::from_slice(&rand).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        for _ in 0..255 {
            let ks1 = KeyStore::new();
            let ks2 = KeyStore::new();
            assert_ne!(ks1.public_key(), ks2.public_key());
            assert_ne!(ks1.private_key(), ks2.private_key());
            assert_ne!(ks1, ks2);
        }
    }

    #[test]
    fn from_private_key() {
        for _ in 0..255 {
            let ks1 = KeyStore::new();
            let ks2 = KeyStore::from_private_key(ks1.private_key().clone());
            assert_eq!(ks1.public_key(), ks2.public_key());
        }
    }

    #[test]
    fn from_keypair() {
        for _ in 0..255 {
            let ks1 = KeyStore::new();
            let ks2 = KeyStore::new();
            let ks3 = KeyStore::from_keypair(ks1.public_key().clone(), ks1.private_key().clone());
            assert_ne!(ks1, ks2);
            assert_ne!(ks2, ks3);
            assert_eq!(ks1, ks3);
        }
    }

    /// Test the `KeyStore::from_private_key` method against a precomputed
    /// public/private key pair.
    #[test]
    fn from_private_key_precomputed() {
        let sk_hex = b"8bb6b6ae1497bf0288e6f82923e8875f2fdeab2ab6833e770182b35936232af9";
        let sk_bytes = HEXLOWER.decode(sk_hex).unwrap();
        let sk = PrivateKey::from_slice(&sk_bytes).unwrap();
        let ks = KeyStore::from_private_key(sk);
        assert_eq!(
            ks.public_key_hex(),
            "133798235bc42d37ce009b4b202cfe08bfd133c8e6eea75037fabb88f01fd959"
        );
    }

    /// Test the `KeyStore::encrypt` method against a precomputed
    /// value. The value of the encrypted bytes was computed using
    /// tweetnacl-js.
    #[test]
    fn encrypt_precomputed() {
        let sk_hex = b"8bb6b6ae1497bf0288e6f82923e8875f2fdeab2ab6833e770182b35936232af9";
        let sk_bytes = HEXLOWER.decode(sk_hex).unwrap();
        let sk = PrivateKey::from_slice(&sk_bytes).unwrap();

        let other_key_hex = b"424291495954d3fa8ffbcecc99b208f49016096ef84dffe33355cbc1f0348b20";
        let other_key_bytes = HEXLOWER.decode(other_key_hex).unwrap();
        let other_key = PublicKey::from_slice(&other_key_bytes).unwrap();

        let nonce_hex = b"fe381c4bdb8bfc2a27d2c9a6485113e7638613ffb02b3747";
        let nonce_bytes = HEXLOWER.decode(nonce_hex).unwrap();
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        let ks = KeyStore::from_private_key(sk);

        let plaintext = b"hello";
        let encrypted = ks.encrypt(plaintext, nonce, &other_key);
        let encrypted_hex = HEXLOWER.encode(&encrypted);
        assert_eq!(encrypted_hex, "687f2cb605d80a0660bacb2c6ce6e076591b58f9c9");
    }

    /// Test the `KeyStore::decrypt` method.
    #[test]
    fn decrypt_precomputed() {
        let sk_hex = b"717284c21d52489ddd8afa1adda32fa332cb0410b72ef83b415314cb12521bfe";
        let sk_bytes = HEXLOWER.decode(sk_hex).unwrap();
        let sk = PrivateKey::from_slice(&sk_bytes).unwrap();

        let other_key_hex = b"133798235bc42d37ce009b4b202cfe08bfd133c8e6eea75037fabb88f01fd959";
        let other_key_bytes = HEXLOWER.decode(other_key_hex).unwrap();
        let other_key = PublicKey::from_slice(&other_key_bytes).unwrap();

        let nonce_hex = b"fe381c4bdb8bfc2a27d2c9a6485113e7638613ffb02b3747";
        let nonce_bytes = HEXLOWER.decode(nonce_hex).unwrap();
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        let ks = KeyStore::from_private_key(sk);

        // This should succeed
        let good_ciphertext_hex = b"687f2cb605d80a0660bacb2c6ce6e076591b58f9c9";
        let good_ciphertext_bytes = HEXLOWER.decode(good_ciphertext_hex).unwrap();
        let decrypted_good = ks.decrypt(&good_ciphertext_bytes, nonce, &other_key);
        assert!(decrypted_good.is_ok());
        assert_eq!(decrypted_good.unwrap(), b"hello".to_vec());

        // This should fail
        let mut bad_ciphertext_bytes = good_ciphertext_bytes.clone();
        bad_ciphertext_bytes[0] += 1;
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();
        let decrypted_bad = ks.decrypt(&bad_ciphertext_bytes, nonce, &other_key);
        assert!(decrypted_bad.is_err());
        let error = decrypted_bad.unwrap_err();
        assert_eq!(format!("{}", error), "Crypto error: Could not decrypt data");
    }

    /// Test the `AuthToken::from_hex_str` method.
    #[test]
    fn auth_token_from_hex_str() {
        let invalid_hex = "foobar";
        let res1 = AuthToken::from_hex_str(&invalid_hex);
        assert_eq!(res1, Err(SaltyError::Decode("Could not decode auth token hex string: invalid symbol at 1".into())));

        let invalid_key = "012345ab";
        let res2 = AuthToken::from_hex_str(&invalid_key);
        assert_eq!(res2, Err(SaltyError::Decode("Invalid auth token hex string".into())));

        let valid_key = "53459fb52fdeeb74103a2932a5eff8095ea1efbaf657f2181722c4e61e6f7e79";
        let res3 = AuthToken::from_hex_str(&valid_key);
        let _ = res3.unwrap();
    }

}
