//! Functionality related to Libsodium key management and encryption.

use data_encoding::HEXLOWER;
use rust_sodium::crypto::box_::{self, PublicKey, SecretKey};
use rust_sodium_sys::crypto_scalarmult_base;

use errors::Result;
use helpers::libsodium_init;

/// A KeyStore contains a keypair and handles encrypting / decrypting messages.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyStore {
    public_key: PublicKey,
    secret_key: SecretKey,
}

impl KeyStore {

    /// Create a new key pair and wrap it in a key store.
    ///
    /// This can fail only if libsodium initialization fails.
    pub fn new() -> Result<Self> {
        info!("Generating new key pair");

        // Initialize libsodium if it hasn't been initialized already
        libsodium_init()?;

        // Generate key pair
        let (pk, sk) = box_::gen_keypair();
        debug!("Public key: {:?}", pk);

        Ok(KeyStore {
            public_key: pk,
            secret_key: sk,
        })
    }

    /// Create a new key pair from an existing secret key.
    ///
    /// The secret key is consumed and transferred into the `KeyStore`.
    pub fn from_secret_key(sk: SecretKey) -> Self {
        let pk = unsafe {
            // Use crypto_scalarmult_base as described here:
            // https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html#key-pair-generation
            let mut buf = [0u8; box_::PUBLICKEYBYTES];
            crypto_scalarmult_base(buf.as_mut_ptr(), sk.0.as_ptr());
            PublicKey(buf)
        };
        KeyStore {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Create a new key pair from an existing public and secret key.
    ///
    /// The two keys are consumed and transferred into the `KeyStore`.
    pub fn from_keypair(pk: PublicKey, sk: SecretKey) -> Self {
        KeyStore {
            public_key: pk,
            secret_key: sk,
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

    /// Return a reference to the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        for _ in 0..255 {
            let ks1 = KeyStore::new().unwrap();
            let ks2 = KeyStore::new().unwrap();
            assert_ne!(ks1.public_key(), ks2.public_key());
            assert_ne!(ks1.secret_key(), ks2.secret_key());
            assert_ne!(ks1, ks2);
        }
    }

    #[test]
    fn from_secret_key() {
        for _ in 0..255 {
            let ks1 = KeyStore::new().unwrap();
            let ks2 = KeyStore::from_secret_key(ks1.secret_key().clone());
            assert_eq!(ks1.public_key(), ks2.public_key());
        }
    }

    #[test]
    fn from_keypair() {
        for _ in 0..255 {
            let ks1 = KeyStore::new().unwrap();
            let ks2 = KeyStore::new().unwrap();
            let ks3 = KeyStore::from_keypair(ks1.public_key.clone(), ks1.secret_key.clone());
            assert_ne!(ks1, ks2);
            assert_ne!(ks2, ks3);
            assert_eq!(ks1, ks3);
        }
    }

    /// Test the `KeyStore::from_secret_key` method against a precomputed
    /// public/secret key pair.
    #[test]
    fn from_secret_key_precomputed() {
        let sk_hex = b"8bb6b6ae1497bf0288e6f82923e8875f2fdeab2ab6833e770182b35936232af9";
        let sk_bytes = HEXLOWER.decode(sk_hex).unwrap();
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let ks = KeyStore::from_secret_key(sk);
        assert_eq!(
            ks.public_key_hex(),
            "133798235bc42d37ce009b4b202cfe08bfd133c8e6eea75037fabb88f01fd959"
        );
    }
}
