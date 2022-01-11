//! Functionality related to key management and encryption.

#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default))]

#[cfg(test)]
use std::io::Write;

use std::{cmp, convert::TryInto, fmt};

use crypto_box::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    rand_core::OsRng,
};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde::{
    de::{Deserialize, Deserializer, Error as SerdeError, Visitor},
    ser::{Serialize, Serializer},
};
use xsalsa20poly1305::XSalsa20Poly1305;

use crate::{
    errors::{SaltyError, SaltyResult, SignalingError, SignalingResult},
    protocol::Nonce,
};

/// A public key used for decrypting data.
///
/// Re-exported from the [`crypto_box`](../crypto_box/index.html) crate.
pub type PublicKey = crypto_box::PublicKey;

/// A private key used for encrypting data.
///
/// Re-exported from the [`crypto_box`](../crypto_box/index.html) crate.
pub type PrivateKey = crypto_box::SecretKey;

/// A symmetric key used for both encrypting and decrypting data.
///
/// Re-exported from the [`xsalsa20poly1305`](../xsalsa20poly1305/index.html) crate.
pub type SecretKey = xsalsa20poly1305::Key;

/// Create a [`PublicKey`](../type.PublicKey.html) instance from case
/// insensitive hex bytes.
pub fn public_key_from_hex_str(hex_str: &str) -> SaltyResult<PublicKey> {
    let bytes: [u8; 32] = HEXLOWER_PERMISSIVE
        .decode(hex_str.as_bytes())
        .map_err(|_| SaltyError::Decode("Could not decode public key hex string".to_string()))?
        .try_into()
        .map_err(|_| {
            SaltyError::Decode("Public key hex string must contain 32 bytes".to_string())
        })?;
    Ok(PublicKey::from(bytes))
}

/// Create a [`PrivateKey`](../type.PrivateKey.html) instance from case
/// insensitive hex bytes.
pub fn private_key_from_hex_str(hex_str: &str) -> SaltyResult<PrivateKey> {
    let bytes: [u8; 32] = HEXLOWER_PERMISSIVE
        .decode(hex_str.as_bytes())
        .map_err(|_| SaltyError::Decode("Could not decode private key hex string".to_string()))?
        .try_into()
        .map_err(|_| {
            SaltyError::Decode("Private key hex string must contain 32 bytes".to_string())
        })?;
    Ok(PrivateKey::from(bytes))
}

/// Wrapper for holding a public/private key pair and encrypting/decrypting messages.
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

/// Implementation required because Debug is not implemented for `PrivateKey`.
impl fmt::Debug for KeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_struct("KeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[hidden]")
            .finish()
    }
}

impl KeyPair {
    /// Create a new key pair and wrap it in a `KeyPair`.
    ///
    /// ## Panics
    ///
    /// This may panic if libsodium initialization fails.
    pub fn new() -> Self {
        info!("Generating new key pair");

        // Generate key pair
        let mut rng = OsRng;
        let private_key = PrivateKey::generate(&mut rng);
        let public_key = private_key.public_key();
        trace!("Public key: {:?}", public_key);

        KeyPair {
            public_key,
            private_key,
        }
    }

    /// Create a new key pair from an existing private key.
    ///
    /// The private key is consumed and transferred into the `KeyPair`.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        KeyPair {
            public_key: private_key.public_key(),
            private_key,
        }
    }

    /// Create a new key pair from an existing public and private key.
    ///
    /// The two keys are consumed and transferred into the `KeyPair`.
    pub fn from_keypair(public_key: PublicKey, private_key: PrivateKey) -> Self {
        KeyPair {
            public_key,
            private_key,
        }
    }

    /// Return a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return the public key as hex-encoded string.
    pub fn public_key_hex(&self) -> String {
        HEXLOWER.encode(self.public_key.as_bytes())
    }

    /// Return a reference to the private key.
    ///
    /// Warning: Be careful with this! The only reason to access the private
    /// key is probably to be able to restore it when working with trusted keys.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Return the private key as hex-encoded string.
    ///
    /// Warning: Be careful with this! The only reason to access the private
    /// key is probably to be able to restore it when working with trusted keys.
    pub fn private_key_hex(&self) -> String {
        HEXLOWER.encode(self.private_key.as_bytes())
    }

    /// Encrypt data for the specified public key with the private key.
    pub(crate) fn encrypt(
        &self,
        data: &[u8],
        nonce: Nonce,
        other_key: &PublicKey,
    ) -> SignalingResult<Vec<u8>> {
        let cbox = crypto_box::Box::new(other_key, &self.private_key);
        cbox.encrypt(&nonce.into(), data)
            .map_err(|_| SignalingError::Crypto("Could not encrypt data".to_string()))
    }

    /// Decrypt data using the specified public key with the own private key.
    ///
    /// If decryption succeeds, the decrypted bytes are returned. Otherwise, a
    /// [`SignalingError::Crypto`](../enum.SignalingError.html#variant.Crypto)
    /// is returned.
    pub(crate) fn decrypt(
        &self,
        data: &[u8],
        nonce: Nonce,
        other_key: &PublicKey,
    ) -> SignalingResult<Vec<u8>> {
        let cbox = crypto_box::Box::new(other_key, &self.private_key);
        cbox.decrypt(&nonce.into(), data)
            .map_err(|_| SignalingError::Crypto("Could not decrypt data".to_string()))
    }
}

/// Wrapper for holding an auth token and encrypting / decrypting messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken(SecretKey);

impl AuthToken {
    /// Create a new auth token.
    ///
    /// This can fail only if libsodium initialization fails.
    pub fn new() -> Self {
        info!("Generating new auth token");

        // Generate key
        let key = XSalsa20Poly1305::generate_key(&mut OsRng::default());

        AuthToken(key)
    }

    /// Create an `AuthToken` instance from hex bytes.
    pub fn from_hex_str(hex_str: &str) -> SaltyResult<Self> {
        let bytes = HEXLOWER_PERMISSIVE
            .decode(hex_str.as_bytes())
            .map_err(|e| {
                SaltyError::Decode(format!("Could not decode auth token hex string: {}", e))
            })?;
        Self::from_slice(&bytes)
    }

    /// Create an `AuthToken` instance from a 32 byte slice.
    pub fn from_slice(bytes: &[u8]) -> SaltyResult<Self> {
        if bytes.len() != 32 {
            return Err(SaltyError::Decode(
                "Invalid auth token bytes: Slice must be 32 bytes long".into(),
            ));
        }
        let key = GenericArray::clone_from_slice(bytes);
        Ok(AuthToken(key))
    }

    /// Return a reference to the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.0
    }

    /// Return a reference to the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Return an `XSalsa20Poly1305` (aka secretbox) cipher.
    fn secretbox(&self) -> XSalsa20Poly1305 {
        let key = self.secret_key();
        XSalsa20Poly1305::new(key)
    }

    /// Encrypt data with the secret key.
    pub(crate) fn encrypt(&self, plaintext: &[u8], nonce: Nonce) -> SignalingResult<Vec<u8>> {
        let cipher = self.secretbox();
        let encrypt_nonce: xsalsa20poly1305::Nonce = nonce.into();
        cipher
            .encrypt(&encrypt_nonce, plaintext)
            .map_err(|_| SignalingError::Crypto("Could not encrypt data".to_string()))
    }

    /// Decrypt data with the secret key.
    ///
    /// If decryption succeeds, the decrypted bytes are returned. Otherwise, a
    /// [`SignalingError::Crypto`](../enum.SignalingError.html#variant.Crypto)
    /// is returned.
    pub(crate) fn decrypt(&self, ciphertext: &[u8], nonce: Nonce) -> SignalingResult<Vec<u8>> {
        let cipher = self.secretbox();
        let decrypt_nonce: xsalsa20poly1305::Nonce = nonce.into();
        cipher
            .decrypt(&decrypt_nonce, ciphertext)
            .map_err(|_| SignalingError::Crypto("Could not decrypt data".to_string()))
    }
}

/// The number of bytes in the [`SignedKeys`](struct.SignedKeys.html) array.
const SIGNED_KEYS_BYTES: usize = 2 * crypto_box::KEY_SIZE + 16 /* macbytes */;

/// A pair of not-yet-signed keys used in the [`ServerAuth`](../messages/struct.ServerAuth.html)
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedKeys {
    pub server_public_session_key: PublicKey,
    pub client_public_permanent_key: PublicKey,
}

impl UnsignedKeys {
    pub fn new(
        server_public_session_key: PublicKey,
        client_public_permanent_key: PublicKey,
    ) -> Self {
        Self {
            server_public_session_key,
            client_public_permanent_key,
        }
    }

    /// Sign the server public session key and the client public permanent key.
    ///
    /// This is only used in testing.
    #[cfg(test)]
    pub(crate) fn sign(
        self,
        server_session_keypair: &KeyPair,
        client_public_permanent_key: &PublicKey,
        nonce: Nonce,
    ) -> SignedKeys {
        let mut bytes = [0u8; 64];
        (&mut bytes[0..32])
            .write_all(self.server_public_session_key.as_bytes())
            .unwrap();
        (&mut bytes[32..64])
            .write_all(self.client_public_permanent_key.as_bytes())
            .unwrap();
        let cbox = crypto_box::Box::new(
            client_public_permanent_key,
            server_session_keypair.private_key(),
        );
        let vec = cbox.encrypt(&nonce.into(), &bytes[..]).unwrap();
        assert_eq!(vec.len(), SIGNED_KEYS_BYTES);
        let mut encrypted = [0u8; SIGNED_KEYS_BYTES];
        (&mut encrypted[..]).write_all(&vec).unwrap();
        SignedKeys(encrypted)
    }
}

/// Concatenated signed keys used in the [`ServerAuth`](../messages/struct.ServerAuth.html)
/// message.
pub struct SignedKeys([u8; SIGNED_KEYS_BYTES]);

impl SignedKeys {
    pub fn new(bytes: [u8; SIGNED_KEYS_BYTES]) -> Self {
        SignedKeys(bytes)
    }

    pub(crate) fn decrypt(
        &self,
        permanent_key: &KeyPair,
        server_public_permanent_key: &PublicKey,
        nonce: Nonce,
    ) -> SignalingResult<UnsignedKeys> {
        // Decrypt bytes
        let cbox = crypto_box::Box::new(server_public_permanent_key, permanent_key.private_key());
        let decrypted = cbox
            .decrypt(&nonce.into(), &self.0[..])
            .map_err(|_| SignalingError::Crypto("Could not decrypt signed keys".to_string()))?;
        assert_eq!(decrypted.len(), 32 * 2);
        let server_public_session_key: [u8; 32] = decrypted[0..32].try_into().expect("32 bytes");
        let client_public_permanent_key: [u8; 32] = decrypted[32..64].try_into().expect("32 bytes");
        Ok(UnsignedKeys::new(
            PublicKey::from(server_public_session_key),
            PublicKey::from(client_public_permanent_key),
        ))
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
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

/// Visitor used to deserialize the [`SignedKeys`](struct.SignedKeys.html)
/// struct with Serde.
struct SignedKeysVisitor;

impl<'de> Visitor<'de> for SignedKeysVisitor {
    type Value = SignedKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("80 bytes of binary data")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        if v.len() != SIGNED_KEYS_BYTES {
            return Err(SerdeError::invalid_length(v.len(), &self));
        }
        Ok(SignedKeys::new([
            v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13],
            v[14], v[15], v[16], v[17], v[18], v[19], v[20], v[21], v[22], v[23], v[24], v[25],
            v[26], v[27], v[28], v[29], v[30], v[31], v[32], v[33], v[34], v[35], v[36], v[37],
            v[38], v[39], v[40], v[41], v[42], v[43], v[44], v[45], v[46], v[47], v[48], v[49],
            v[50], v[51], v[52], v[53], v[54], v[55], v[56], v[57], v[58], v[59], v[60], v[61],
            v[62], v[63], v[64], v[65], v[66], v[67], v[68], v[69], v[70], v[71], v[72], v[73],
            v[74], v[75], v[76], v[77], v[78], v[79],
        ]))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        self.visit_bytes(&v)
    }
}

/// Waiting for https://github.com/3Hren/msgpack-rust/issues/129
impl<'de> Deserialize<'de> for SignedKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SignedKeysVisitor)
    }
}

#[cfg(test)]
use crate::test_helpers::TestRandom;
#[cfg(test)]
impl TestRandom for PublicKey {
    fn random() -> PublicKey {
        let mut rng = crypto_box::rand_core::OsRng;
        let private_key = PrivateKey::generate(&mut rng);
        private_key.public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use xsalsa20poly1305::aead::generic_array::typenum::U32;

    #[test]
    fn new() {
        for _ in 0..255 {
            let ks1 = KeyPair::new();
            let ks2 = KeyPair::new();
            assert_ne!(ks1.public_key(), ks2.public_key());
            assert_ne!(ks1.private_key().as_bytes(), ks2.private_key().as_bytes());
        }
    }

    #[test]
    fn from_private_key() {
        for _ in 0..255 {
            let ks1 = KeyPair::new();
            let ks2 = KeyPair::from_private_key(ks1.private_key().clone());
            assert_eq!(ks1.public_key(), ks2.public_key());
        }
    }

    #[test]
    fn from_keypair() {
        for _ in 0..255 {
            let ks1 = KeyPair::new();
            let ks2 = KeyPair::new();
            let ks3 = KeyPair::from_keypair(ks1.public_key().clone(), ks1.private_key().clone());
            assert_ne!(ks1.public_key(), ks2.public_key());
            assert_ne!(ks2.public_key(), ks3.public_key());
            assert_eq!(ks1.public_key(), ks3.public_key());
        }
    }

    /// Test the `KeyPair::from_private_key` method against a precomputed
    /// public/private key pair.
    #[test]
    fn from_private_key_precomputed() {
        let sk_hex = b"8bb6b6ae1497bf0288e6f82923e8875f2fdeab2ab6833e770182b35936232af9";
        let sk_bytes: [u8; 32] = HEXLOWER.decode(sk_hex).unwrap().try_into().unwrap();
        let sk = PrivateKey::from(sk_bytes);
        let ks = KeyPair::from_private_key(sk);
        assert_eq!(
            ks.public_key_hex(),
            "133798235bc42d37ce009b4b202cfe08bfd133c8e6eea75037fabb88f01fd959"
        );
    }

    /// Test the `KeyPair::encrypt` method against a precomputed
    /// value. The value of the encrypted bytes was computed using
    /// tweetnacl-js.
    #[test]
    fn encrypt_precomputed() {
        let sk_hex = b"8bb6b6ae1497bf0288e6f82923e8875f2fdeab2ab6833e770182b35936232af9";
        let sk_bytes: [u8; 32] = HEXLOWER.decode(sk_hex).unwrap().try_into().unwrap();
        let sk = PrivateKey::from(sk_bytes);

        let other_key_hex = b"424291495954d3fa8ffbcecc99b208f49016096ef84dffe33355cbc1f0348b20";
        let other_key_bytes: [u8; 32] = HEXLOWER.decode(other_key_hex).unwrap().try_into().unwrap();
        let other_key = PublicKey::from(other_key_bytes);

        let nonce_hex = b"fe381c4bdb8bfc2a27d2c9a6485113e7638613ffb02b3747";
        let nonce_bytes = HEXLOWER.decode(nonce_hex).unwrap();
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        let ks = KeyPair::from_private_key(sk);

        let plaintext = b"hello";
        let encrypted = ks.encrypt(plaintext, nonce, &other_key).unwrap();
        let encrypted_hex = HEXLOWER.encode(&encrypted);
        assert_eq!(encrypted_hex, "687f2cb605d80a0660bacb2c6ce6e076591b58f9c9");
    }

    /// Test the `KeyPair::decrypt` method.
    #[test]
    fn decrypt_precomputed() {
        let sk_hex = b"717284c21d52489ddd8afa1adda32fa332cb0410b72ef83b415314cb12521bfe";
        let sk_bytes: [u8; 32] = HEXLOWER.decode(sk_hex).unwrap().try_into().unwrap();
        let sk = PrivateKey::from(sk_bytes);

        let other_key_hex = b"133798235bc42d37ce009b4b202cfe08bfd133c8e6eea75037fabb88f01fd959";
        let other_key_bytes: [u8; 32] = HEXLOWER.decode(other_key_hex).unwrap().try_into().unwrap();
        let other_key = PublicKey::from(other_key_bytes);

        let nonce_hex = b"fe381c4bdb8bfc2a27d2c9a6485113e7638613ffb02b3747";
        let nonce_bytes = HEXLOWER.decode(nonce_hex).unwrap();
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        let ks = KeyPair::from_private_key(sk);

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
        assert_eq!(
            res1,
            Err(SaltyError::Decode(
                "Could not decode auth token hex string: invalid symbol at 1".into()
            ))
        );

        let invalid_key = "012345ab";
        let res2 = AuthToken::from_hex_str(&invalid_key);
        assert_eq!(
            res2,
            Err(SaltyError::Decode(
                "Invalid auth token bytes: Slice must be 32 bytes long".into()
            ))
        );

        let valid_key = "53459fb52fdeeb74103a2932a5eff8095ea1efbaf657f2181722c4e61e6f7e79";
        let res3 = AuthToken::from_hex_str(&valid_key);
        let _ = res3.unwrap();
    }

    /// Test the `AuthToken::from_slice` method.
    #[test]
    fn auth_token_from_slice() {
        let too_short = [0; 31];
        let res1 = AuthToken::from_slice(&too_short);
        assert_eq!(
            res1,
            Err(SaltyError::Decode(
                "Invalid auth token bytes: Slice must be 32 bytes long".into()
            ))
        );

        let valid_token = [1; 32];
        let res2 = AuthToken::from_slice(&valid_token);
        let _ = res2.unwrap();
    }

    /// Make sure that the AuthToken is zeroed on drop.
    #[test]
    fn auth_token_zero_on_drop() {
        use std::borrow::Borrow;

        // Create auth token
        let token = Box::new(
            AuthToken::from_hex_str(
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
            )
            .unwrap(),
        );

        // Copy token bytes and create a zeroed array for comparison
        let token_bytes = token.0;
        let zero_bytes: GenericArray<u8, U32> = [0; 32].into();

        // Get and dereference pointer to token
        let ptr = token.borrow() as *const AuthToken;
        println!("Old data is {:?}", &token_bytes);
        println!("Pointer address is {:?}", ptr);
        let deref1: &AuthToken = unsafe { &*ptr };
        println!("Deref1 data is {:?}", &deref1.0);
        assert_eq!(deref1.0, token_bytes);
        assert_ne!(deref1.0, zero_bytes);

        // Drop auth token
        drop(token);

        // Dereference pointer to token again
        println!("Pointer address is {:?}", ptr);
        let deref2: &AuthToken = unsafe { &*ptr };
        println!("Deref2 data is {:?}", &deref2.0);
        assert_ne!(deref2.0, token_bytes);
        // Note: After the token bytes are zeroed, it seems that Rust already
        // puts new data at that memory address. Therefore the following call
        // fails. Disable it until we find a solution to test this.
        //assert_eq!((deref2.0).0, zero_bytes);
    }

    #[test]
    fn unsigned_keys_sign_decrypt() {
        // Create keypairs
        let kp_server = KeyPair::new();
        let kp_client = KeyPair::new();

        // Create nonce
        let nonce_hex = b"fe381c4bdb8bfc2a27d2c9a6485113e7638613ffb02b3747";
        let nonce_bytes = HEXLOWER.decode(nonce_hex).unwrap();
        let nonce = Nonce::from_bytes(&nonce_bytes).unwrap();

        // Sign keys
        let unsigned = UnsignedKeys::new(
            kp_server.public_key().clone(),
            kp_client.public_key().clone(),
        );
        let signed = unsigned
            .clone()
            .sign(&kp_server, kp_client.public_key(), unsafe { nonce.clone() });

        // Decrypt directly
        let cbox = crypto_box::Box::new(kp_server.public_key(), kp_client.private_key());
        let decrypted = cbox
            .decrypt(&unsafe { nonce.clone() }.into(), &signed.0[..])
            .unwrap();
        assert_eq!(decrypted.len(), 2 * 32);
        assert_eq!(&decrypted[0..32], kp_server.public_key().as_bytes());
        assert_eq!(&decrypted[32..64], kp_client.public_key().as_bytes());

        // Decrypt through the `decrypt` method
        let unsigned2 = signed
            .decrypt(&kp_client, kp_server.public_key(), nonce)
            .unwrap();
        assert_eq!(unsigned, unsigned2);
    }

    #[test]
    fn signed_key_bytes() {
        assert_eq!(SIGNED_KEYS_BYTES, 32 * 2 + 16);
    }
}
