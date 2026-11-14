//! Ed25519 Cryptographic Node Identities and Key Management.
//!
//! Provides Ed25519 key generation, public key fingerprinting, and
//! canonical Syncthing-compatible formatted Device IDs with Luhn check digits.

use std::fs;
use std::path::Path;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

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

pub fn compute_luhn_char(chunk: &str) -> char {
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

/// Normalizes and validates a device ID input string (accepts formatted Base32 or 64-char hex).
///
/// Validates Luhn check digits on Base32 grouped representations, rejecting tampered
/// check digits, altered data characters, or invalid Base32 alphabet characters.
pub fn normalize_device_id(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Device ID cannot be empty".into());
    }

    // Check if 64-character hex representation
    let cleaned_hex = trimmed.replace(['-', ' '], "");
    if cleaned_hex.len() == 64 && cleaned_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(cleaned_hex.to_lowercase());
    }

    // Process as grouped Base32 with Luhn check digits
    let groups: Vec<String> = if trimmed.contains('-') || trimmed.contains(' ') {
        trimmed
            .split(['-', ' '])
            .filter(|s| !s.is_empty())
            .map(|s| s.to_uppercase())
            .collect()
    } else {
        let upper = trimmed.to_uppercase();
        if upper.len() == 61 {
            // 8 groups of 7 chars + 1 group of 5 chars (from 32-byte Ed25519 pubkey)
            let mut grps = Vec::new();
            for i in (0..56).step_by(7) {
                grps.push(upper[i..i + 7].to_string());
            }
            grps.push(upper[56..61].to_string());
            grps
        } else if upper.len() == 56 {
            // 8 groups of 7 chars
            let mut grps = Vec::new();
            for i in (0..56).step_by(7) {
                grps.push(upper[i..i + 7].to_string());
            }
            grps
        } else {
            return Err("Invalid device ID format: must be 64-char hex or 56/61-char grouped Base32 with Luhn check digits".into());
        }
    };

    if groups.is_empty() {
        return Err("Invalid device ID: empty groups".into());
    }

    // Validate each group: characters must be in BASE32_ALPHABET and check digit must match
    for group in &groups {
        if group.len() < 2 {
            return Err(format!("Group '{}' too short to contain payload and check digit", group));
        }
        for c in group.chars() {
            if !BASE32_ALPHABET.contains(&(c as u8)) {
                return Err(format!("Invalid character '{}' in device ID: not in Base32 alphabet", c));
            }
        }

        let payload = &group[..group.len() - 1];
        let given_check = group.chars().last().unwrap();
        let expected_check = compute_luhn_char(payload);

        if given_check != expected_check {
            return Err(format!(
                "Luhn check digit mismatch in group '{}': expected '{}', found '{}'",
                group, expected_check, given_check
            ));
        }
    }

    Ok(groups.join("-"))
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
            // Verify each group has valid Base32 characters
            for c in p.chars() {
                assert!(BASE32_ALPHABET.contains(&(c as u8)));
            }
            // Verify check digit
            let payload = &p[..p.len() - 1];
            let check = p.chars().last().unwrap();
            assert_eq!(check, compute_luhn_char(payload));
        }
    }

    #[test]
    fn test_device_id_formatting_determinism_and_uniqueness() {
        let bytes1 = [0xAAu8; 32];
        let bytes2 = [0xBBu8; 32];
        let f1 = format_device_id(&bytes1);
        let f2 = format_device_id(&bytes1);
        let f3 = format_device_id(&bytes2);

        assert_eq!(f1, f2, "Formatting must be deterministic");
        assert_ne!(f1, f3, "Different public keys must produce distinct device IDs");
    }

    #[test]
    fn test_normalize_device_id() {
        let hex_id = "d51dd80953132f4cbd8a751f5294f5a361a1af85f3c65aad2c2191b8f4f4b864";
        assert_eq!(normalize_device_id(hex_id).unwrap(), hex_id);

        // Uppercase hex should normalize to lowercase hex
        let upper_hex = hex_id.to_uppercase();
        assert_eq!(normalize_device_id(&upper_hex).unwrap(), hex_id);

        // Hex with spaces or hyphens
        let spaced_hex = format!("{} {}", &hex_id[..32], &hex_id[32..]);
        assert_eq!(normalize_device_id(&spaced_hex).unwrap(), hex_id);

        // Formatted Base32 normalization
        let bytes = [0x55u8; 32];
        let formatted = format_device_id(&bytes);
        assert_eq!(normalize_device_id(&formatted).unwrap(), formatted);

        // Lowercase Base32 should normalize to uppercase canonical
        assert_eq!(normalize_device_id(&formatted.to_lowercase()).unwrap(), formatted);

        // Space-separated Base32 groups should normalize to hyphen-separated
        let space_formatted = formatted.replace('-', " ");
        assert_eq!(normalize_device_id(&space_formatted).unwrap(), formatted);

        // Unhyphenated Base32 string should normalize to hyphen-separated
        let unhyphenated = formatted.replace('-', "");
        assert_eq!(normalize_device_id(&unhyphenated).unwrap(), formatted);
    }

    #[test]
    fn test_tamper_detection_check_digit_failure() {
        let bytes = [0x12u8; 32];
        let formatted = format_device_id(&bytes);
        let groups: Vec<&str> = formatted.split('-').collect();

        // Tamper with check digit of each group individually
        for i in 0..groups.len() {
            let mut tampered_groups = groups.clone();
            let g = tampered_groups[i];
            let check_char = g.chars().last().unwrap();
            // Pick a different character from Base32 alphabet
            let alt_check = if check_char == 'A' { 'B' } else { 'A' };
            let tampered_g = format!("{}{}", &g[..g.len() - 1], alt_check);
            tampered_groups[i] = &tampered_g;
            let tampered_id = tampered_groups.join("-");

            let res = normalize_device_id(&tampered_id);
            assert!(
                res.is_err(),
                "Tampered check digit in group {} must fail validation: {}",
                i,
                tampered_id
            );
        }
    }

    #[test]
    fn test_tamper_detection_payload_character_failure() {
        let bytes = [0x34u8; 32];
        let formatted = format_device_id(&bytes);
        let groups: Vec<&str> = formatted.split('-').collect();

        // Tamper with data payload of each group individually
        for i in 0..groups.len() {
            let mut tampered_groups = groups.clone();
            let g = tampered_groups[i];
            let first_char = g.chars().next().unwrap();
            let alt_char = if first_char == 'A' { 'Z' } else { 'A' };
            let tampered_g = format!("{}{}", alt_char, &g[1..]);
            tampered_groups[i] = &tampered_g;
            let tampered_id = tampered_groups.join("-");

            let res = normalize_device_id(&tampered_id);
            assert!(
                res.is_err(),
                "Tampered payload character in group {} must fail validation: {}",
                i,
                tampered_id
            );
        }
    }

    #[test]
    fn test_tamper_detection_invalid_characters_and_malformed() {
        // Characters not in Base32 alphabet ('1', '8', '9', '0', punctuation)
        let invalid_ids = [
            "",
            "   ",
            "not-a-valid-device-id",
            "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ12", // '1' is invalid in RFC 4648 Base32
            "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ82", // '8' is invalid
            "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ92", // '9' is invalid
            "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ02", // '0' is invalid
            "d51dd80953132f4cbd8a751f5294f5a361a1af85f3c65aad2c2191b8f4f4b86Z", // invalid hex 'Z'
            "d51dd80953132f4cbd8a751f5294f5a", // 32 hex chars (too short)
        ];

        for invalid in &invalid_ids {
            assert!(
                normalize_device_id(invalid).is_err(),
                "Invalid input '{}' must be rejected",
                invalid
            );
        }
    }

    #[test]
    fn test_node_identity_persistence_and_signing() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_node_id_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. Generate identity
        let id1 = NodeIdentity::load_or_generate(&temp_dir).unwrap();
        assert_eq!(id1.device_id.len(), 64);
        assert!(id1.formatted_id.contains('-'));
        assert_eq!(
            normalize_device_id(&id1.formatted_id).unwrap(),
            id1.formatted_id
        );

        // 2. Reload from same directory - keys must be identical
        let id2 = NodeIdentity::load_or_generate(&temp_dir).unwrap();
        assert_eq!(id1.device_id, id2.device_id);
        assert_eq!(id1.formatted_id, id2.formatted_id);
        assert_eq!(id1.signing_key.to_bytes(), id2.signing_key.to_bytes());

        // 3. Ed25519 signing and verification
        use ed25519_dalek::Signer;
        let message = b"Synapse cluster node pairing verification message 2026";
        let signature = id1.signing_key.sign(message);
        assert!(id1.verifying_key.verify_strict(message, &signature).is_ok());

        // Verification fails if message is tampered
        let tampered_message = b"Synapse cluster node pairing verification message 2027";
        assert!(id1.verifying_key.verify_strict(tampered_message, &signature).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
