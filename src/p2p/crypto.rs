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
        let plaintext = b"Data integrity is paramount";
        let key = [0x55u8; 32];
        let mut envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_03",
            plaintext,
            &key,
            None,
        ).unwrap();

        // 1. Corrupt ciphertext byte
        envelope.ciphertext[0] ^= 0xFF;
        let res = envelope.decrypt(&key);
        assert!(res.is_err(), "tampered ciphertext must fail authentication");

        // Restore and corrupt tag
        envelope.ciphertext[0] ^= 0xFF;
        envelope.tag[0] ^= 0x01;
        let res2 = envelope.decrypt(&key);
        assert!(res2.is_err(), "tampered auth tag must fail authentication");
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let plaintext = b"Sensitive document content";
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];

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
        let plaintext = b"Bound to specific folder";
        let key = [0x33u8; 32];
        let envelope = EncryptedChunkEnvelope::encrypt_aes_256_gcm(
            "chunk_05",
            plaintext,
            &key,
            Some(b"folder_a"),
        ).unwrap();

        // Decrypt with incorrect AAD
        let res = envelope.decrypt_with_aad(&key, b"folder_b");
        assert!(res.is_err(), "AAD mismatch must fail authentication");

        // Decrypt with correct AAD
        let ok = envelope.decrypt_with_aad(&key, b"folder_a").unwrap();
        assert_eq!(ok, plaintext);
    }

    #[test]
    fn test_passphrase_key_derivation_roundtrip() {
        let plaintext = b"Encrypted using user password derivation";
        let passphrase = "my-super-secret-cluster-passphrase-2026!";

        let envelope = EncryptedChunkEnvelope::encrypt_with_passphrase(
            "chunk_06",
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
    fn test_envelope_serialization_roundtrip() {
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
    }
}
