//! Functionality related to Libsodium key management and encryption.

use data_encoding::HEXLOWER;
use rust_sodium::crypto::box_;
use rust_sodium_sys::crypto_scalarmult_base;

use errors::{Result, ResultExt, Error, ErrorKind};
use helpers::libsodium_init;
use nonce::Nonce;

/// A public key used for decrypting data.
///
/// Re-exported from the [`rust_sodium`](../rust_sodium/) crate.
pub type PublicKey = box_::PublicKey;

/// A private key used for encrypting data.
///
/// Re-exported from the [`rust_sodium`](../rust_sodium/) crate.
pub type PrivateKey = box_::SecretKey;


/// Wrapper for holding a keypair and encrypting / decrypting messages.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyStore {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl KeyStore {

    /// Create a new key pair and wrap it in a key store.
    ///
    /// This can fail only if libsodium initialization fails.
    pub fn new() -> Result<Self> {
        info!("Generating new key pair");

        // Initialize libsodium if it hasn't been initialized already
        libsodium_init()
            .chain_err(|| ErrorKind::Crypto("could not generate keystore".into()))?;

        // Generate key pair
        let (pk, sk) = box_::gen_keypair();
        debug!("Public key: {:?}", pk);

        Ok(KeyStore {
            public_key: pk,
            private_key: sk,
        })
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
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Encrypt data for the specified public key with the private key.
    pub fn encrypt(&self, data: &[u8], nonce: Nonce, other_key: &PublicKey) -> Vec<u8> {
        let rust_sodium_nonce: box_::Nonce = nonce.into();
        box_::seal(data, &rust_sodium_nonce, other_key, &self.private_key)
    }

    /// Decrypt data using the specified public key with the own private key.
    ///
    /// If decryption succeeds, the decrypted bytes are returned. Otherwise, an
    /// error with error kind `Crypto` is returned.
    pub fn decrypt(&self, data: &[u8], nonce: Nonce, other_key: &PublicKey) -> Result<Vec<u8>> {
        let rust_sodium_nonce: box_::Nonce = nonce.into();
        box_::open(data, &rust_sodium_nonce, other_key, &self.private_key)
            .map_err(|_| Error::from_kind(ErrorKind::Crypto("Could not decrypt data".to_string())))
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
            assert_ne!(ks1.private_key(), ks2.private_key());
            assert_ne!(ks1, ks2);
        }
    }

    #[test]
    fn from_private_key() {
        for _ in 0..255 {
            let ks1 = KeyStore::new().unwrap();
            let ks2 = KeyStore::from_private_key(ks1.private_key().clone());
            assert_eq!(ks1.public_key(), ks2.public_key());
        }
    }

    #[test]
    fn from_keypair() {
        for _ in 0..255 {
            let ks1 = KeyStore::new().unwrap();
            let ks2 = KeyStore::new().unwrap();
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
        assert_eq!(format!("{}", error), "crypto error: Could not decrypt data");
    }

}
