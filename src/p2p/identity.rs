//! Ed25519 Cryptographic Node Identities and Key Management.

use std::fs;
use std::path::Path;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub struct NodeIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub device_id: String,
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
        let device_id = hex::encode(verifying_key.as_bytes());

        Ok(Self {
            signing_key,
            verifying_key,
            device_id,
        })
    }
}
