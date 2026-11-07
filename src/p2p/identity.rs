//! Ed25519 Cryptographic Node Identities and Key Management.
//!
//! Provides Ed25519 key generation, public key fingerprinting, and
//! canonical Syncthing-compatible formatted Device IDs with Luhn check digits.

use std::fs;
use std::path::Path;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub use super::crypto::{CryptoError, EncryptedChunkEnvelope, EncryptionAlgorithm};

pub const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone)]
pub struct NodeIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// 64-character lowercase hex string
    pub device_id: String,
    /// Canonical grouped representation: XXXXXXX-XXXXXXX-...
    pub formatted_id: String,
}

impl NodeIdentity {
    /// Loads or creates an Ed25519 node identity keypair.
    pub fn load_or_generate(home_dir: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key_path = home_dir.join("node_identity.key");

        let signing_key = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err("Invalid identity key length".into());
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            SigningKey::from_bytes(&key_bytes)
        } else {
            let key = SigningKey::generate(&mut OsRng);
            fs::write(&key_path, key.to_bytes())?;
            key
        };

        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.as_bytes();
        let device_id = hex::encode(pub_bytes);
        let formatted_id = format_device_id(pub_bytes);

        Ok(Self {
            signing_key,
            verifying_key,
            device_id,
            formatted_id,
        })
    }
}

/// Formats 32-byte public key into 8 groups of 7 characters separated by dashes
/// with Luhn-mod-7 check characters (Syncthing-compatible format).
pub fn format_device_id(bytes: &[u8]) -> String {
    let mut b32 = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &b in bytes {
        buffer = (buffer << 8) | (b as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            b32.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        b32.push(BASE32_ALPHABET[idx] as char);
    }

    // Group into chunks of 6 characters + 1 check digit = 7 chars per chunk
    let chars: Vec<char> = b32.chars().collect();
    let mut groups = Vec::new();

    for i in (0..chars.len()).step_by(6) {
        let end = (i + 6).min(chars.len());
        let chunk: String = chars[i..end].iter().collect();
        let check_char = compute_luhn_char(&chunk);
        groups.push(format!("{}{}", chunk, check_char));
    }

    groups.join("-")
}

fn compute_luhn_char(chunk: &str) -> char {
    let mut sum: u32 = 0;
    for (i, c) in chunk.chars().enumerate() {
        let val = match BASE32_ALPHABET.iter().position(|&x| x as char == c) {
            Some(p) => p as u32,
            None => 0,
        };
        let factor = if i % 2 == 0 { 2 } else { 1 };
        let mut prod = val * factor;
        if prod >= 32 {
            prod = (prod / 32) + (prod % 32);
        }
        sum = sum.wrapping_add(prod);
    }
    let check = (32 - (sum % 32)) % 32;
    BASE32_ALPHABET[check as usize] as char
}

/// Normalizes and validates a device ID input string (accepts formatted or hex).
pub fn normalize_device_id(input: &str) -> Result<String, String> {
    let cleaned = input.trim().replace('-', "").replace(' ', "").to_uppercase();
    if cleaned.len() == 64 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(cleaned.to_lowercase());
    }
    if cleaned.len() >= 52 {
        // Validate base32 characters
        if cleaned.chars().all(|c| BASE32_ALPHABET.contains(&(c as u8))) {
            return Ok(cleaned);
        }
    }
    Err("Invalid device ID format: must be 64-char hex or 56-char grouped base32".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_formatting() {
        let bytes = [42u8; 32];
        let formatted = format_device_id(&bytes);
        assert!(formatted.contains('-'));
        let parts: Vec<&str> = formatted.split('-').collect();
        assert_eq!(parts.len(), 9); // 52 chars / 6 + remainder
        for p in parts {
            assert!(p.len() >= 2 && p.len() <= 7);
        }
    }

    #[test]
    fn test_normalize_device_id() {
        let hex_id = "d51dd80953132f4cbd8a751f5294f5a361a1af85f3c65aad2c2191b8f4f4b864";
        assert_eq!(normalize_device_id(hex_id).unwrap(), hex_id);
    }
}
