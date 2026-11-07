//! Untrusted Node Storage Encryption & Cryptographic Envelopes.
//!
//! Provides chunk-level AEAD encryption (AES-256-GCM and ChaCha20-Poly1305)
//! allowing untrusted storage nodes / VPS instances to store, replicate, and serve
//! chunks without inspecting plaintext data.

use std::fmt;
use rand::RngCore;
use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use serde::{Deserialize, Serialize};

/// Supported AEAD cipher algorithms for chunk-level envelope encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
    #[serde(rename = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

/// Errors occurring during chunk encryption, decryption, or key derivation.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength(usize),
    InvalidNonceLength(usize),
    EncryptionFailed,
    DecryptionFailed,
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength(len) => write!(f, "Invalid cryptographic key length: {} (expected 32 bytes)", len),
            Self::InvalidNonceLength(len) => write!(f, "Invalid AEAD nonce length: {} (expected 12 bytes)", len),
            Self::EncryptionFailed => write!(f, "Failed to encrypt chunk payload"),
            Self::DecryptionFailed => write!(f, "Failed to decrypt chunk payload: authentication tag mismatch or corrupted ciphertext"),
            Self::SerializationError(msg) => write!(f, "Envelope serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Envelope deserialization error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Cryptographic wrapper envelope around a content-addressed chunk.
///
/// Untrusted nodes store this envelope without having the key to decrypt `ciphertext`.
/// Plaintext content is protected with either AES-256-GCM or ChaCha20-Poly1305.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedChunkEnvelope {
    /// Identifier or content hash of the chunk
    pub chunk_hash: String,
    /// Cipher algorithm used for encryption
    pub algorithm: EncryptionAlgorithm,
    /// 96-bit (12-byte) initialization vector / nonce
    pub nonce: Vec<u8>,
    /// Ciphertext payload
    pub ciphertext: Vec<u8>,
    /// 128-bit (16-byte) authentication tag
    pub tag: Vec<u8>,
    /// Optional Additional Authenticated Data (AAD)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad: Option<Vec<u8>>,
    /// Original unencrypted chunk size in bytes
    pub original_size: usize,
    /// Optional Key derivation salt if derived from a passphrase
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
}

impl EncryptedChunkEnvelope {
    /// Encrypts plaintext data using AES-256-GCM.
    pub fn encrypt_aes_256_gcm(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        key: &[u8; 32],
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        Self::encrypt(chunk_hash, plaintext, key, EncryptionAlgorithm::Aes256Gcm, aad)
    }

    /// Encrypts plaintext data using ChaCha20-Poly1305.
    pub fn encrypt_chacha20_poly1305(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        key: &[u8; 32],
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        Self::encrypt(chunk_hash, plaintext, key, EncryptionAlgorithm::ChaCha20Poly1305, aad)
    }

    /// Encrypts plaintext chunk data with specified AEAD algorithm.
    pub fn encrypt(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        key: &[u8; 32],
        algorithm: EncryptionAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let ring_alg = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => &AES_256_GCM,
            EncryptionAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };

        let unbound_key = UnboundKey::new(ring_alg, key)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut in_out = plaintext.to_vec();
        let aad_bytes = aad.unwrap_or(b"");
        less_safe_key
            .seal_in_place_append_tag(nonce, Aad::from(aad_bytes), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let tag_len = ring_alg.tag_len();
        let ciphertext_len = in_out.len().saturating_sub(tag_len);
        let tag = in_out[ciphertext_len..].to_vec();
        let ciphertext = in_out[..ciphertext_len].to_vec();

        Ok(Self {
            chunk_hash: chunk_hash.into(),
            algorithm,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            tag,
            aad: aad.map(|a| a.to_vec()),
            original_size: plaintext.len(),
            salt: None,
        })
    }

    /// Decrypts the envelope using the provided 256-bit symmetric key.
    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let aad_bytes = self.aad.as_deref().unwrap_or(b"");
        self.decrypt_with_aad(key, aad_bytes)
    }

    /// Decrypts the envelope with an explicit AAD slice.
    pub fn decrypt_with_aad(&self, key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ring_alg = match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => &AES_256_GCM,
            EncryptionAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        };

        let unbound_key = UnboundKey::new(ring_alg, key)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let less_safe_key = LessSafeKey::new(unbound_key);

        if self.nonce.len() != 12 {
            return Err(CryptoError::InvalidNonceLength(self.nonce.len()));
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&self.nonce);

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let mut in_out = self.ciphertext.clone();
        in_out.extend_from_slice(&self.tag);

        let plaintext = less_safe_key
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    /// Derives a 32-byte AEAD symmetric key from a passphrase and salt using BLAKE3 KDF.
    pub fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
        let mut material = passphrase.as_bytes().to_vec();
        material.extend_from_slice(salt);
        blake3::derive_key("synapse-untrusted-node-envelope-v1", &material)
    }

    /// Derives a 32-byte AEAD symmetric key using PBKDF2-HMAC-SHA256 (RFC 2898).
    pub fn derive_key_pbkdf2(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
        let n = std::num::NonZeroU32::new(iterations.max(1)).unwrap();
        let mut key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            n,
            salt,
            passphrase.as_bytes(),
            &mut key,
        );
        key
    }

    /// Derives a 32-byte AEAD symmetric key using HKDF-SHA256 (RFC 5869).
    pub fn derive_key_hkdf(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
        struct KeyLen(usize);
        impl ring::hkdf::KeyType for KeyLen {
            fn len(&self) -> usize {
                self.0
            }
        }

        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt);
        let prk = salt.extract(secret);
        let info_slice = [info];
        let okm = prk
            .expand(&info_slice, KeyLen(32))
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let mut key = [0u8; 32];
        okm.fill(&mut key).map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(key)
    }

    /// Encrypts plaintext chunk data using a key derived from a folder passphrase.
    pub fn encrypt_with_passphrase(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        passphrase: &str,
        algorithm: EncryptionAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = Self::derive_key(passphrase, &salt);
        let mut envelope = Self::encrypt(chunk_hash, plaintext, &key, algorithm, aad)?;
        envelope.salt = Some(salt.to_vec());
        Ok(envelope)
    }

    /// Decrypts envelope using a folder passphrase and embedded salt.
    pub fn decrypt_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
        let salt = self.salt.as_deref().unwrap_or(b"synapse-default-salt");
        let key = Self::derive_key(passphrase, salt);
        self.decrypt(&key)
    }

    /// Encrypts plaintext chunk data using PBKDF2-HMAC-SHA256 key derivation.
    pub fn encrypt_with_pbkdf2(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        passphrase: &str,
        iterations: u32,
        algorithm: EncryptionAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let key = Self::derive_key_pbkdf2(passphrase, &salt, iterations);
        let mut envelope = Self::encrypt(chunk_hash, plaintext, &key, algorithm, aad)?;
        envelope.salt = Some(salt.to_vec());
        Ok(envelope)
    }

    /// Decrypts envelope using PBKDF2-HMAC-SHA256 and embedded salt.
    pub fn decrypt_with_pbkdf2(&self, passphrase: &str, iterations: u32) -> Result<Vec<u8>, CryptoError> {
        let salt = self.salt.as_deref().unwrap_or(b"synapse-default-salt");
        let key = Self::derive_key_pbkdf2(passphrase, salt, iterations);
        self.decrypt(&key)
    }

    /// Encrypts plaintext chunk data using HKDF-SHA256 key derivation.
    pub fn encrypt_with_hkdf(
        chunk_hash: impl Into<String>,
        plaintext: &[u8],
        secret: &[u8],
        salt: &[u8],
        info: &[u8],
        algorithm: EncryptionAlgorithm,
        aad: Option<&[u8]>,
    ) -> Result<Self, CryptoError> {
        let key = Self::derive_key_hkdf(secret, salt, info)?;
        Self::encrypt(chunk_hash, plaintext, &key, algorithm, aad)
    }

    /// Decrypts envelope using HKDF-SHA256 key derivation.
    pub fn decrypt_with_hkdf(
        &self,
        secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Self::derive_key_hkdf(secret, salt, info)?;
        self.decrypt(&key)
    }

    /// Serializes envelope to JSON bytes for storage or network transmission.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        serde_json::to_vec(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Deserializes envelope from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(bytes).map_err(|e| CryptoError::DeserializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_gcm_roundtrip() {
        let plaintext = b"Top secret chunk payload stored on untrusted VPS node";
        let key = [0x42u8; 32];
        let chunk_hash = "b3_chunk_hash_01";

        let envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            chunk_hash,
            plaintext,
            &key,
            Some(b"folder_vault"),
        ).expect("encryption should succeed");

        assert_eq!(envelope.chunk_hash, chunk_hash);
        assert_eq!(envelope.algorithm, EncryptionAlgorithm::Aes256Gcm);
        assert_eq!(envelope.original_size, plaintext.len());
        assert_ne!(envelope.ciphertext, plaintext);
        assert_eq!(envelope.tag.len(), 16);
        assert_eq!(envelope.nonce.len(), 12);

        // Decryption succeeds with correct key
        let decrypted = envelope.decrypt(&key).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let plaintext = b"Another confidential chunk saved without plaintext exposure";
        let key = [0x77u8; 32];
        let chunk_hash = "b3_chunk_hash_02";

        let envelope = EncryptedChunkEnvelope::encrypt_chacha20_poly1305(
            chunk_hash,
            plaintext,
            &key,
            None,
        ).expect("encryption should succeed");

        assert_eq!(envelope.algorithm, EncryptionAlgorithm::ChaCha20Poly1305);
        let decrypted = envelope.decrypt(&key).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tamper_detection_fails_decryption() {
        let plaintext = b"Data integrity is paramount across all cluster nodes";
        let key = [0x55u8; 32];
        let envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_03",
            plaintext,
            &key,
            None,
        ).unwrap();

        // 1. Corrupt ciphertext at multiple bit positions: first byte, middle, last byte
        for &pos in &[0, envelope.ciphertext.len() / 2, envelope.ciphertext.len() - 1] {
            let mut tampered = envelope.clone();
            tampered.ciphertext[pos] ^= 0x01; // single bit flip
            assert!(
                tampered.decrypt(&key).is_err(),
                "decryption must fail for single bit flip at position {}",
                pos
            );
        }

        // 2. Corrupt auth tag at multiple positions: first byte, last byte
        for &pos in &[0, envelope.tag.len() - 1] {
            let mut tampered = envelope.clone();
            tampered.tag[pos] ^= 0x80;
            assert!(
                tampered.decrypt(&key).is_err(),
                "decryption must fail for tampered auth tag at byte {}",
                pos
            );
        }

        // 3. Corrupt nonce byte
        for &pos in &[0, envelope.nonce.len() - 1] {
            let mut tampered = envelope.clone();
            tampered.nonce[pos] ^= 0x01;
            assert!(
                tampered.decrypt(&key).is_err(),
                "decryption must fail for tampered nonce byte {}",
                pos
            );
        }

        // 4. Truncate ciphertext
        let mut truncated = envelope.clone();
        truncated.ciphertext.pop();
        assert!(truncated.decrypt(&key).is_err(), "truncated ciphertext must fail");
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let plaintext = b"Sensitive document content";
        let key1 = [0x11u8; 32];
        let mut key2 = [0x11u8; 32];
        key2[31] ^= 0x01; // Single bit difference in key

        let envelope = EncryptedChunkEnvelope::encrypt_chacha20_poly1305(
            "chunk_04",
            plaintext,
            &key1,
            None,
        ).unwrap();

        let res = envelope.decrypt(&key2);
        assert!(res.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn test_aad_mismatch_fails_decryption() {
        let plaintext = b"Bound to specific folder metadata";
        let key = [0x33u8; 32];
        let envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_05",
            plaintext,
            &key,
            Some(b"folder_a"),
        ).unwrap();

        // 1. Decrypt with different AAD
        let res1 = envelope.decrypt_with_aad(&key, b"folder_b");
        assert!(res1.is_err(), "different AAD must fail authentication");

        // 2. Decrypt with empty AAD when encrypted with non-empty AAD
        let res2 = envelope.decrypt_with_aad(&key, b"");
        assert!(res2.is_err(), "empty AAD must fail authentication");

        // 3. Decrypt with 1-bit corrupted AAD
        let res3 = envelope.decrypt_with_aad(&key, b"folder_`"); // 'a' ^ 1 = '`'
        assert!(res3.is_err(), "1-bit corrupted AAD must fail authentication");

        // 4. Decrypt with correct AAD succeeds
        let ok = envelope.decrypt_with_aad(&key, b"folder_a").unwrap();
        assert_eq!(ok, plaintext);
    }

    #[test]
    fn test_passphrase_blake3_key_derivation_roundtrip() {
        let plaintext = b"Encrypted using BLAKE3 password derivation";
        let passphrase = "my-super-secret-cluster-passphrase-2026!";

        let envelope = EncryptedChunkEnvelope::encrypt_with_passphrase(
            "chunk_blake3_06",
            plaintext,
            passphrase,
            EncryptionAlgorithm::Aes256Gcm,
            Some(b"aad_metadata"),
        ).unwrap();

        assert!(envelope.salt.is_some());
        let decrypted = envelope.decrypt_with_passphrase(passphrase).unwrap();
        assert_eq!(decrypted, plaintext);

        // Wrong passphrase fails
        assert!(envelope.decrypt_with_passphrase("wrong_passphrase").is_err());
    }

    #[test]
    fn test_pbkdf2_key_derivation_roundtrip() {
        let plaintext = b"Highly confidential payload protected with PBKDF2-HMAC-SHA256";
        let passphrase = "vault-pbkdf2-passphrase-2026";
        let salt = b"salt_pbkdf2_1234";
        let iterations = 10_000;

        // 1. Deterministic key derivation check
        let key1 = EncryptedChunkEnvelope::derive_key_pbkdf2(passphrase, salt, iterations);
        let key2 = EncryptedChunkEnvelope::derive_key_pbkdf2(passphrase, salt, iterations);
        assert_eq!(key1, key2);

        // Different salt derives different key
        let key_diff_salt = EncryptedChunkEnvelope::derive_key_pbkdf2(passphrase, b"different_salt!!", iterations);
        assert_ne!(key1, key_diff_salt);

        // Different iterations derives different key
        let key_diff_iter = EncryptedChunkEnvelope::derive_key_pbkdf2(passphrase, salt, 20_000);
        assert_ne!(key1, key_diff_iter);

        // 2. PBKDF2 Envelope encryption and decryption
        let envelope = EncryptedChunkEnvelope::encrypt_with_pbkdf2(
            "chunk_pbkdf2_01",
            plaintext,
            passphrase,
            iterations,
            EncryptionAlgorithm::ChaCha20Poly1305,
            Some(b"aad_folder_bound"),
        ).expect("encryption with PBKDF2 must succeed");

        let decrypted = envelope.decrypt_with_pbkdf2(passphrase, iterations)
            .expect("decryption with PBKDF2 must succeed");
        assert_eq!(decrypted, plaintext);

        // Wrong passphrase fails
        assert!(envelope.decrypt_with_pbkdf2("incorrect_passphrase", iterations).is_err());
        // Wrong iterations fails
        assert!(envelope.decrypt_with_pbkdf2(passphrase, 5_000).is_err());
    }

    #[test]
    fn test_hkdf_key_derivation_roundtrip() {
        let plaintext = b"Ephemeral secret session chunk encrypted with HKDF-SHA256";
        let secret = b"shared-cluster-premaster-secret-32b!";
        let salt = b"hkdf-salt-cluster-context";
        let info = b"synapse:chunk-transport:untrusted:v1";

        // 1. Deterministic HKDF derivation
        let key1 = EncryptedChunkEnvelope::derive_key_hkdf(secret, salt, info).unwrap();
        let key2 = EncryptedChunkEnvelope::derive_key_hkdf(secret, salt, info).unwrap();
        assert_eq!(key1, key2);

        // Different info derives different key (context domain separation)
        let key_diff_info = EncryptedChunkEnvelope::derive_key_hkdf(secret, salt, b"other-info").unwrap();
        assert_ne!(key1, key_diff_info);

        // 2. HKDF Envelope encryption and decryption
        let envelope = EncryptedChunkEnvelope::encrypt_with_hkdf(
            "chunk_hkdf_01",
            plaintext,
            secret,
            salt,
            info,
            EncryptionAlgorithm::Aes256Gcm,
            None,
        ).expect("encryption with HKDF must succeed");

        let decrypted = envelope.decrypt_with_hkdf(secret, salt, info)
            .expect("decryption with HKDF must succeed");
        assert_eq!(decrypted, plaintext);

        // Wrong secret fails
        assert!(envelope.decrypt_with_hkdf(b"wrong-secret-key-32b!", salt, info).is_err());
        // Wrong info context fails
        assert!(envelope.decrypt_with_hkdf(secret, salt, b"wrong-context").is_err());
    }

    #[test]
    fn test_large_chunk_payload_encryption_roundtrip() {
        // 1 MiB chunk typical for CAS block engine
        let chunk_size = 1024 * 1024;
        let mut large_plaintext = vec![0u8; chunk_size];
        for i in 0..chunk_size {
            large_plaintext[i] = (i % 256) as u8;
        }

        let key = [0x88u8; 32];

        // AES-256-GCM with 1 MiB
        let env_aes = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_1mb_aes",
            &large_plaintext,
            &key,
            Some(b"large_chunk_aad"),
        ).expect("large AES encryption must succeed");
        assert_eq!(env_aes.original_size, chunk_size);
        let dec_aes = env_aes.decrypt(&key).expect("large AES decryption must succeed");
        assert_eq!(dec_aes, large_plaintext);

        // ChaCha20-Poly1305 with 1 MiB
        let env_chacha = EncryptedChunkEnvelope::encrypt_chacha20_poly1305(
            "chunk_1mb_chacha",
            &large_plaintext,
            &key,
            Some(b"large_chunk_aad"),
        ).expect("large ChaCha20 encryption must succeed");
        assert_eq!(env_chacha.original_size, chunk_size);
        let dec_chacha = env_chacha.decrypt(&key).expect("large ChaCha20 decryption must succeed");
        assert_eq!(dec_chacha, large_plaintext);
    }

    #[test]
    fn test_envelope_serialization_wire_format_roundtrip() {
        let plaintext = b"Chunk envelope serializable to bytes for CAS storage";
        let key = [0x99u8; 32];
        let envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_cas_07",
            plaintext,
            &key,
            None,
        ).unwrap();

        let serialized = envelope.to_bytes().unwrap();
        let deserialized = EncryptedChunkEnvelope::from_bytes(&serialized).unwrap();
        assert_eq!(envelope, deserialized);

        let decrypted = deserialized.decrypt(&key).unwrap();
        assert_eq!(decrypted, plaintext);

        // Corrupted JSON wire format rejection
        let mut bad_json = serialized.clone();
        bad_json[0] = b'{';
        bad_json[1] = b'!'; // Corrupt json syntax
        assert!(EncryptedChunkEnvelope::from_bytes(&bad_json).is_err());
    }
}
