//! Encrypted Relay Fallback Protocol for Symmetric NATs and CGNAT.
//!
//! Provides zero-trust end-to-end encrypted relay message structures
//! (`RelayJoin`, `RelayInvitation`, `RelayTunnelData`), wire protocol framing,
//! and session sequencing for nodes that cannot establish direct peer-to-peer connections.

use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Returns the current system timestamp in milliseconds since the UNIX epoch.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// 1. RelayJoin: Node registration with relay server
// ============================================================================

/// Message sent by a client to join or authenticate with an encrypted relay server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayJoin {
    /// Unique session identifier generated for this relay connection
    pub session_id: String,
    /// Canonical device ID of the joining node
    pub device_id: String,
    /// 32-byte public key hex representation of the node
    pub public_key: String,
    /// Timestamp in milliseconds since UNIX epoch
    pub timestamp: u64,
    /// Ed25519 signature over `session_id:device_id:timestamp`
    pub signature: Vec<u8>,
    /// Optional authorization token / passphrase for restricted relays
    pub auth_token: Option<String>,
}

impl RelayJoin {
    /// Constructs and cryptographically signs a new `RelayJoin` message.
    pub fn new(
        signing_key: &SigningKey,
        device_id: String,
        session_id: String,
        auth_token: Option<String>,
    ) -> Self {
        let timestamp = current_timestamp_ms();
        let verifying_key = signing_key.verifying_key();
        let public_key = hex::encode(verifying_key.as_bytes());

        let sign_payload = format!("{}:{}:{}", session_id, device_id, timestamp);
        let signature = signing_key.sign(sign_payload.as_bytes());

        Self {
            session_id,
            device_id,
            public_key,
            timestamp,
            signature: signature.to_vec(),
            auth_token,
        }
    }

    /// Payload string that was signed by the node's private key.
    pub fn sign_payload(&self) -> String {
        format!("{}:{}:{}", self.session_id, self.device_id, self.timestamp)
    }

    /// Verifies the Ed25519 signature against the embedded public key.
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let pub_bytes = hex::decode(&self.public_key)?;
        if pub_bytes.len() != 32 {
            return Ok(false);
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pub_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)?;

        if self.signature.len() != 64 {
            return Ok(false);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let signature = Signature::from_bytes(&sig_arr);

        let sign_payload = self.sign_payload();
        match verifying_key.verify(sign_payload.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ============================================================================
// 2. RelayInvitation: Peer rendezvous coordination
// ============================================================================

/// Message used to invite or signal a target peer to rendezvous via an encrypted relay tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayInvitation {
    /// Unique invitation identifier (UUID v4)
    pub invitation_id: String,
    /// Relay session identifier assigned for rendezvous
    pub session_id: String,
    /// Socket address or host endpoint of the relay server (e.g. "relay.synapse.network:443")
    pub relay_addr: String,
    /// Device ID of the peer initiating the invitation
    pub from_device_id: String,
    /// Device ID of the target peer invited to connect
    pub to_device_id: String,
    /// Hex-encoded public key of the initiating node
    pub initiator_pubkey: String,
    /// Ephemeral public key / ECDH key share for end-to-end forward secrecy
    pub session_pubkey: String,
    /// Timestamp in milliseconds when the invitation was created
    pub created_at: u64,
    /// Expiration timestamp in milliseconds
    pub expires_at: u64,
    /// Ed25519 signature over invitation metadata by the initiator
    pub signature: Vec<u8>,
}

impl RelayInvitation {
    /// Constructs and cryptographically signs a new `RelayInvitation`.
    pub fn new(
        signing_key: &SigningKey,
        from_device_id: String,
        to_device_id: String,
        relay_addr: String,
        session_id: String,
        session_pubkey: String,
        ttl_ms: u64,
    ) -> Self {
        let created_at = current_timestamp_ms();
        let expires_at = created_at + ttl_ms;
        let invitation_id = uuid::Uuid::new_v4().to_string();
        let verifying_key = signing_key.verifying_key();
        let initiator_pubkey = hex::encode(verifying_key.as_bytes());

        let sign_payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            invitation_id,
            session_id,
            relay_addr,
            from_device_id,
            to_device_id,
            session_pubkey,
            expires_at
        );
        let signature = signing_key.sign(sign_payload.as_bytes());

        Self {
            invitation_id,
            session_id,
            relay_addr,
            from_device_id,
            to_device_id,
            initiator_pubkey,
            session_pubkey,
            created_at,
            expires_at,
            signature: signature.to_vec(),
        }
    }

    /// Payload string that was signed by the initiator.
    pub fn sign_payload(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.invitation_id,
            self.session_id,
            self.relay_addr,
            self.from_device_id,
            self.to_device_id,
            self.session_pubkey,
            self.expires_at
        )
    }

    /// Verifies the initiator's signature against the embedded `initiator_pubkey`.
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let pub_bytes = hex::decode(&self.initiator_pubkey)?;
        if pub_bytes.len() != 32 {
            return Ok(false);
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pub_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)?;

        if self.signature.len() != 64 {
            return Ok(false);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let signature = Signature::from_bytes(&sig_arr);

        let sign_payload = self.sign_payload();
        match verifying_key.verify(sign_payload.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Checks if the invitation has expired past the given timestamp.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.expires_at
    }
}

// ============================================================================
// 3. RelayTunnelData: Blind forwarded end-to-end encrypted frame
// ============================================================================

/// End-to-end encrypted frame tunneled through the relay fallback server.
/// The relay server blindly routes this frame without having access to plaintext payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTunnelData {
    /// Relay session ID this tunnel frame belongs to
    pub session_id: String,
    /// Monotonically increasing sequence number for ordering and replay attack prevention
    pub sequence_number: u64,
    /// Device ID of the node transmitting the frame
    pub sender_id: String,
    /// Device ID of the intended destination node
    pub recipient_id: String,
    /// Zero-trust end-to-end encrypted payload (ciphertext)
    pub encrypted_payload: Vec<u8>,
    /// Authentication tag / MAC for integrity validation
    pub auth_tag: Vec<u8>,
    /// Initialization vector / nonce used for this encrypted payload
    pub nonce: Vec<u8>,
    /// Transmission timestamp in milliseconds
    pub timestamp: u64,
}

impl RelayTunnelData {
    /// Constructs a new encrypted tunnel data packet.
    pub fn new(
        session_id: String,
        sequence_number: u64,
        sender_id: String,
        recipient_id: String,
        encrypted_payload: Vec<u8>,
        auth_tag: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            sequence_number,
            sender_id,
            recipient_id,
            encrypted_payload,
            auth_tag,
            nonce,
            timestamp: current_timestamp_ms(),
        }
    }

    /// Returns the length of the encrypted payload in bytes.
    pub fn payload_size(&self) -> usize {
        self.encrypted_payload.len()
    }

    /// Validates structural integrity and non-emptiness of required fields.
    pub fn validate(&self) -> Result<(), String> {
        if self.session_id.is_empty() {
            return Err("Session ID cannot be empty".into());
        }
        if self.sender_id.is_empty() {
            return Err("Sender ID cannot be empty".into());
        }
        if self.recipient_id.is_empty() {
            return Err("Recipient ID cannot be empty".into());
        }
        if self.sender_id == self.recipient_id {
            return Err("Sender ID and Recipient ID cannot be identical".into());
        }
        if self.encrypted_payload.is_empty() {
            return Err("Encrypted payload cannot be empty".into());
        }
        if self.auth_tag.is_empty() {
            return Err("Authentication tag cannot be empty".into());
        }
        if self.nonce.is_empty() {
            return Err("Nonce cannot be empty".into());
        }
        Ok(())
    }
}

// ============================================================================
// 4. RelayMessage: Protocol Message Multiplexer & Framing
// ============================================================================

/// Wire message enum for the encrypted relay fallback protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayMessage {
    /// Peer registration / join request sent to the relay
    Join(RelayJoin),
    /// Relay acknowledgment of join request
    JoinAck {
        session_id: String,
        accepted: bool,
        reason: Option<String>,
    },
    /// Peer invitation to rendezvous at the relay
    Invitation(RelayInvitation),
    /// Response from target peer accepting or declining invitation
    InvitationResponse {
        invitation_id: String,
        accepted: bool,
        reason: Option<String>,
    },
    /// Blind forwarded tunnel frame between peers
    Tunnel(RelayTunnelData),
    /// Relay keepalive ping
    Ping {
        session_id: String,
        timestamp: u64,
    },
    /// Relay keepalive pong
    Pong {
        session_id: String,
        timestamp: u64,
    },
    /// Teardown of the relay session
    CloseSession {
        session_id: String,
        reason: String,
    },
}

impl RelayMessage {
    /// Serializes message to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserializes message from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Serializes message prefixed with a 4-byte big-endian frame length.
    pub fn to_length_prefixed(&self) -> Result<Vec<u8>, serde_json::Error> {
        let payload = self.to_bytes()?;
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Deserializes length-prefixed frame from a buffer.
    /// Returns the parsed message and the total number of bytes consumed (4 + payload length).
    pub fn from_length_prefixed(buf: &[u8]) -> Result<(Self, usize), String> {
        if buf.len() < 4 {
            return Err("Buffer too short for length prefix".into());
        }
        let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let total_len = 4 + frame_len;
        if buf.len() < total_len {
            return Err(format!(
                "Incomplete frame: expected {} bytes, got {}",
                total_len,
                buf.len()
            ));
        }

        let msg = Self::from_bytes(&buf[4..total_len])
            .map_err(|e| format!("Failed to parse relay message: {}", e))?;
        Ok((msg, total_len))
    }

    /// Retrieves the session ID associated with the message, if present.
    pub fn session_id(&self) -> Option<&str> {
        match self {
            RelayMessage::Join(j) => Some(&j.session_id),
            RelayMessage::JoinAck { session_id, .. } => Some(session_id),
            RelayMessage::Invitation(i) => Some(&i.session_id),
            RelayMessage::Tunnel(t) => Some(&t.session_id),
            RelayMessage::Ping { session_id, .. } => Some(session_id),
            RelayMessage::Pong { session_id, .. } => Some(session_id),
            RelayMessage::CloseSession { session_id, .. } => Some(session_id),
            RelayMessage::InvitationResponse { .. } => None,
        }
    }
}

// ============================================================================
// 5. RelaySession: Active fallback session manager & state tracking
// ============================================================================

/// Connection state of an active relay session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelaySessionState {
    Disconnected,
    Connecting,
    Joined,
    Invited,
    Active,
    Closed,
}

/// Tracks state and sequence monotonicity for an established relay fallback session.
pub struct RelaySession {
    pub session_id: String,
    pub local_device_id: String,
    pub remote_device_id: String,
    pub relay_addr: String,
    pub state: RelaySessionState,
    pub outbound_seq: u64,
    pub inbound_seq: u64,
    pub last_activity_ms: u64,
}

impl RelaySession {
    /// Creates a new `RelaySession` tracking state between local and remote peers.
    pub fn new(
        session_id: String,
        local_device_id: String,
        remote_device_id: String,
        relay_addr: String,
    ) -> Self {
        Self {
            session_id,
            local_device_id,
            remote_device_id,
            relay_addr,
            state: RelaySessionState::Disconnected,
            outbound_seq: 0,
            inbound_seq: 0,
            last_activity_ms: current_timestamp_ms(),
        }
    }

    /// Validates whether a state transition is legal according to the relay fallback protocol.
    pub fn can_transition_to(&self, next: RelaySessionState) -> bool {
        match (self.state, next) {
            (RelaySessionState::Disconnected, RelaySessionState::Connecting) => true,
            (RelaySessionState::Connecting, RelaySessionState::Joined) => true,
            (RelaySessionState::Connecting, RelaySessionState::Closed) => true,
            (RelaySessionState::Joined, RelaySessionState::Invited) => true,
            (RelaySessionState::Joined, RelaySessionState::Active) => true,
            (RelaySessionState::Joined, RelaySessionState::Closed) => true,
            (RelaySessionState::Invited, RelaySessionState::Active) => true,
            (RelaySessionState::Invited, RelaySessionState::Closed) => true,
            (RelaySessionState::Active, RelaySessionState::Closed) => true,
            (s1, s2) if s1 == s2 => true,
            _ => false,
        }
    }

    /// Transitions to a target state, verifying lifecycle invariants.
    pub fn transition_to(&mut self, next: RelaySessionState) -> Result<(), crate::state::StateTransitionError> {
        if !self.can_transition_to(next) {
            return Err(crate::state::StateTransitionError {
                entity: "relay_session".to_string(),
                entity_id: self.session_id.clone(),
                current_state: format!("{:?}", self.state),
                attempted_transition: format!("{:?}", next),
                allowed_transitions: vec![],
                available_actions: vec![],
                is_terminal: self.state == RelaySessionState::Closed,
            });
        }
        self.state = next;
        Ok(())
    }

    /// Constructs an outbound tunnel data packet, incrementing outbound sequence counter.
    pub fn pack_tunnel_data(
        &mut self,
        encrypted_payload: Vec<u8>,
        auth_tag: Vec<u8>,
        nonce: Vec<u8>,
    ) -> RelayTunnelData {
        self.outbound_seq += 1;
        self.last_activity_ms = current_timestamp_ms();

        RelayTunnelData::new(
            self.session_id.clone(),
            self.outbound_seq,
            self.local_device_id.clone(),
            self.remote_device_id.clone(),
            encrypted_payload,
            auth_tag,
            nonce,
        )
    }

    /// Validates an inbound tunnel packet: checks session ID, peer endpoints,
    /// and ensures strictly increasing sequence numbers to prevent replay attacks.
    pub fn verify_inbound_data<'a>(&mut self, frame: &'a RelayTunnelData) -> Result<&'a [u8], String> {
        if frame.session_id != self.session_id {
            return Err(format!(
                "Session mismatch: expected {}, got {}",
                self.session_id, frame.session_id
            ));
        }
        if frame.sender_id != self.remote_device_id {
            return Err(format!(
                "Sender mismatch: expected {}, got {}",
                self.remote_device_id, frame.sender_id
            ));
        }
        if frame.recipient_id != self.local_device_id {
            return Err(format!(
                "Recipient mismatch: expected {}, got {}",
                self.local_device_id, frame.recipient_id
            ));
        }
        if frame.sequence_number <= self.inbound_seq {
            return Err(format!(
                "Replay or out-of-order packet: expected > {}, got {}",
                self.inbound_seq, frame.sequence_number
            ));
        }

        self.inbound_seq = frame.sequence_number;
        self.last_activity_ms = current_timestamp_ms();
        Ok(&frame.encrypted_payload)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_relay_join_creation_and_verification() {
        let key = SigningKey::generate(&mut OsRng);
        let device_id = hex::encode(key.verifying_key().as_bytes());
        let session_id = "sess-12345".to_string();

        let join = RelayJoin::new(&key, device_id.clone(), session_id.clone(), Some("token_abc".into()));
        assert_eq!(join.device_id, device_id);
        assert_eq!(join.session_id, session_id);
        assert_eq!(join.signature.len(), 64);
        assert_eq!(join.auth_token.as_deref(), Some("token_abc"));

        let verified = join.verify().expect("Verification threw error");
        assert!(verified, "RelayJoin signature should be valid");
    }

    #[test]
    fn test_relay_join_tamper_detection() {
        let key = SigningKey::generate(&mut OsRng);
        let device_id = hex::encode(key.verifying_key().as_bytes());
        let mut join = RelayJoin::new(&key, device_id, "sess-1".into(), None);

        // Tamper with session_id
        join.session_id = "sess-tampered".into();
        let verified = join.verify().expect("Verification threw error");
        assert!(!verified, "Tampered RelayJoin should fail verification");
    }

    #[test]
    fn test_relay_invitation_flow_and_expiry() {
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        let dev_a = hex::encode(key_a.verifying_key().as_bytes());
        let dev_b = hex::encode(key_b.verifying_key().as_bytes());

        let invitation = RelayInvitation::new(
            &key_a,
            dev_a.clone(),
            dev_b.clone(),
            "relay.synapse.network:443".into(),
            "session-abc".into(),
            "session-pubkey-share-010203".into(),
            60_000, // 60s TTL
        );

        assert_eq!(invitation.from_device_id, dev_a);
        assert_eq!(invitation.to_device_id, dev_b);
        assert_eq!(invitation.signature.len(), 64);
        assert!(!invitation.is_expired(invitation.created_at + 1000));
        assert!(invitation.is_expired(invitation.created_at + 70_000));

        let verified = invitation.verify().expect("Verification threw error");
        assert!(verified, "RelayInvitation signature should be valid");
    }

    #[test]
    fn test_relay_invitation_tamper_detection() {
        let key = SigningKey::generate(&mut OsRng);
        let dev = hex::encode(key.verifying_key().as_bytes());

        let mut inv = RelayInvitation::new(
            &key,
            dev.clone(),
            "target-dev".into(),
            "relay.example.com:443".into(),
            "session-1".into(),
            "pubkey".into(),
            60_000,
        );

        // Tamper with to_device_id
        inv.to_device_id = "malicious-dev".into();
        assert!(!inv.verify().unwrap());
    }

    #[test]
    fn test_relay_tunnel_data_validation() {
        let data = RelayTunnelData::new(
            "sess-99".into(),
            1,
            "peer-a".into(),
            "peer-b".into(),
            vec![1, 2, 3, 4, 5],
            vec![9, 9, 9],
            vec![7, 7],
        );

        assert_eq!(data.payload_size(), 5);
        assert!(data.validate().is_ok());

        // Empty payload validation failure
        let invalid = RelayTunnelData::new(
            "sess-99".into(),
            1,
            "peer-a".into(),
            "peer-b".into(),
            vec![], // Empty
            vec![1],
            vec![1],
        );
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_relay_message_serialization_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let dev = hex::encode(key.verifying_key().as_bytes());
        let join = RelayJoin::new(&key, dev, "sess-01".into(), None);
        let msg = RelayMessage::Join(join);

        let bytes = msg.to_bytes().expect("Failed to serialize");
        let decoded = RelayMessage::from_bytes(&bytes).expect("Failed to deserialize");
        assert_eq!(msg, decoded);
        assert_eq!(decoded.session_id(), Some("sess-01"));
    }

    #[test]
    fn test_relay_length_prefixed_framing() {
        let tunnel = RelayTunnelData::new(
            "sess-framing".into(),
            42,
            "dev-1".into(),
            "dev-2".into(),
            vec![0xAA, 0xBB, 0xCC],
            vec![0xFF],
            vec![0x01],
        );
        let msg = RelayMessage::Tunnel(tunnel);

        let framed = msg.to_length_prefixed().expect("Framing failed");
        assert!(framed.len() > 4);

        let (unframed, consumed) = RelayMessage::from_length_prefixed(&framed).expect("Unframing failed");
        assert_eq!(consumed, framed.len());
        assert_eq!(msg, unframed);
    }

    #[test]
    fn test_relay_session_sequencing_and_replay_protection() {
        let mut session = RelaySession::new(
            "session-relay-01".into(),
            "local-node".into(),
            "remote-node".into(),
            "relay.synapse.network:443".into(),
        );

        // Outbound packaging increments sequence monotonically
        let frame1 = session.pack_tunnel_data(vec![1, 2, 3], vec![9], vec![0]);
        assert_eq!(frame1.sequence_number, 1);
        let frame2 = session.pack_tunnel_data(vec![4, 5, 6], vec![9], vec![1]);
        assert_eq!(frame2.sequence_number, 2);

        // Inbound processing verifies sender/recipient and sequence
        let inbound_frame1 = RelayTunnelData::new(
            "session-relay-01".into(),
            1,
            "remote-node".into(),
            "local-node".into(),
            vec![10, 20, 30],
            vec![99],
            vec![5],
        );
        let decrypted1 = session.verify_inbound_data(&inbound_frame1).expect("Inbound packet 1 failed");
        assert_eq!(decrypted1, &[10, 20, 30]);

        // Inbound replay attack (same sequence number) rejected!
        let replay = session.verify_inbound_data(&inbound_frame1);
        assert!(replay.is_err(), "Replay packet with seq 1 must be rejected");

        // Out-of-order older packet rejected
        let mut older_frame = inbound_frame1.clone();
        older_frame.sequence_number = 0;
        assert!(session.verify_inbound_data(&older_frame).is_err());

        // Inbound next packet accepted
        let mut inbound_frame2 = inbound_frame1.clone();
        inbound_frame2.sequence_number = 2;
        inbound_frame2.encrypted_payload = vec![40, 50];
        let decrypted2 = session.verify_inbound_data(&inbound_frame2).expect("Inbound packet 2 failed");
        assert_eq!(decrypted2, &[40, 50]);
    }

    #[test]
    fn test_relay_session_peer_mismatch_rejection() {
        let mut session = RelaySession::new(
            "sess-xyz".into(),
            "node-a".into(),
            "node-b".into(),
            "relay.addr:1234".into(),
        );

        let spoofed = RelayTunnelData::new(
            "sess-xyz".into(),
            1,
            "evil-node".into(),
            "node-a".into(),
            vec![1],
            vec![1],
            vec![1],
        );

        assert!(session.verify_inbound_data(&spoofed).is_err());
    }

    // ========================================================================
    // Additional RelayJoin Tests
    // ========================================================================

    #[test]
    fn test_relay_join_exhaustive_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let device_id = hex::encode(key.verifying_key().as_bytes());

        // Tamper device_id
        let mut join_dev = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_dev.device_id = "tampered_device".into();
        assert!(!join_dev.verify().unwrap());

        // Tamper timestamp
        let mut join_time = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_time.timestamp += 1000;
        assert!(!join_time.verify().unwrap());

        // Tamper signature byte
        let mut join_sig = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_sig.signature[0] ^= 0xFF;
        assert!(!join_sig.verify().unwrap());

        // Invalid signature length (< 64)
        let mut join_short_sig = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_short_sig.signature.truncate(32);
        assert!(!join_short_sig.verify().unwrap());

        // Invalid signature length (> 64)
        let mut join_long_sig = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_long_sig.signature.push(0x00);
        assert!(!join_long_sig.verify().unwrap());

        // Invalid public key hex
        let mut join_bad_hex = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_bad_hex.public_key = "not_valid_hex!".into();
        assert!(join_bad_hex.verify().is_err());

        // Wrong length public key hex (16 bytes = 32 hex chars)
        let mut join_short_pk = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_short_pk.public_key = hex::encode([0u8; 16]);
        assert!(!join_short_pk.verify().unwrap());

        // Different public key
        let key2 = SigningKey::generate(&mut OsRng);
        let mut join_diff_pk = RelayJoin::new(&key, device_id.clone(), "s1".into(), None);
        join_diff_pk.public_key = hex::encode(key2.verifying_key().as_bytes());
        assert!(!join_diff_pk.verify().unwrap());
    }

    #[test]
    fn test_relay_join_auth_token_options() {
        let key = SigningKey::generate(&mut OsRng);
        let device_id = hex::encode(key.verifying_key().as_bytes());

        let join_none = RelayJoin::new(&key, device_id.clone(), "s-none".into(), None);
        assert!(join_none.auth_token.is_none());
        assert!(join_none.verify().unwrap());

        let join_some = RelayJoin::new(&key, device_id, "s-some".into(), Some("my_auth_token".into()));
        assert_eq!(join_some.auth_token.as_deref(), Some("my_auth_token"));
        assert!(join_some.verify().unwrap());
    }

    // ========================================================================
    // Additional RelayInvitation Tests
    // ========================================================================

    #[test]
    fn test_relay_invitation_exhaustive_tamper() {
        let key = SigningKey::generate(&mut OsRng);
        let dev_a = hex::encode(key.verifying_key().as_bytes());
        let dev_b = "target_peer_id".to_string();

        let base_inv = RelayInvitation::new(
            &key,
            dev_a.clone(),
            dev_b.clone(),
            "relay.synapse.network:443".into(),
            "sess-123".into(),
            "ecdh-share-data".into(),
            30_000,
        );
        assert!(base_inv.verify().unwrap());

        // Tamper invitation_id
        let mut inv = base_inv.clone();
        inv.invitation_id = uuid::Uuid::new_v4().to_string();
        assert!(!inv.verify().unwrap());

        // Tamper session_id
        let mut inv = base_inv.clone();
        inv.session_id = "tampered-sess".into();
        assert!(!inv.verify().unwrap());

        // Tamper relay_addr
        let mut inv = base_inv.clone();
        inv.relay_addr = "evil.relay.network:443".into();
        assert!(!inv.verify().unwrap());

        // Tamper from_device_id
        let mut inv = base_inv.clone();
        inv.from_device_id = "attacker-id".into();
        assert!(!inv.verify().unwrap());

        // Tamper to_device_id
        let mut inv = base_inv.clone();
        inv.to_device_id = "wrong-recipient".into();
        assert!(!inv.verify().unwrap());

        // Tamper session_pubkey
        let mut inv = base_inv.clone();
        inv.session_pubkey = "corrupted-share".into();
        assert!(!inv.verify().unwrap());

        // Tamper expires_at
        let mut inv = base_inv.clone();
        inv.expires_at += 10_000;
        assert!(!inv.verify().unwrap());

        // Tamper signature
        let mut inv = base_inv.clone();
        inv.signature[5] ^= 0xAA;
        assert!(!inv.verify().unwrap());

        // Short signature
        let mut inv = base_inv.clone();
        inv.signature.truncate(63);
        assert!(!inv.verify().unwrap());

        // Bad hex initiator pubkey
        let mut inv = base_inv.clone();
        inv.initiator_pubkey = "NOT_HEX".into();
        assert!(inv.verify().is_err());

        // Short initiator pubkey
        let mut inv = base_inv.clone();
        inv.initiator_pubkey = hex::encode([0u8; 16]);
        assert!(!inv.verify().unwrap());
    }

    #[test]
    fn test_relay_invitation_expiry_boundaries() {
        let key = SigningKey::generate(&mut OsRng);
        let dev = hex::encode(key.verifying_key().as_bytes());

        let inv = RelayInvitation::new(
            &key,
            dev.clone(),
            "target".into(),
            "relay:443".into(),
            "sess-exp".into(),
            "pubkey".into(),
            5000,
        );

        assert!(!inv.is_expired(inv.created_at.saturating_sub(100)));
        assert!(!inv.is_expired(inv.created_at));
        assert!(!inv.is_expired(inv.expires_at - 1));
        assert!(inv.is_expired(inv.expires_at));
        assert!(inv.is_expired(inv.expires_at + 1));
        assert!(inv.is_expired(u64::MAX));
    }

    // ========================================================================
    // Additional RelayTunnelData Validation Tests
    // ========================================================================

    #[test]
    fn test_relay_tunnel_data_validation_matrix() {
        // Valid
        let valid = RelayTunnelData::new(
            "sess".into(),
            1,
            "alice".into(),
            "bob".into(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        );
        assert!(valid.validate().is_ok());

        // Empty session_id
        let mut bad = valid.clone();
        bad.session_id = "".into();
        assert_eq!(bad.validate().unwrap_err(), "Session ID cannot be empty");

        // Empty sender_id
        let mut bad = valid.clone();
        bad.sender_id = "".into();
        assert_eq!(bad.validate().unwrap_err(), "Sender ID cannot be empty");

        // Empty recipient_id
        let mut bad = valid.clone();
        bad.recipient_id = "".into();
        assert_eq!(bad.validate().unwrap_err(), "Recipient ID cannot be empty");

        // sender_id == recipient_id
        let mut bad = valid.clone();
        bad.sender_id = "same_peer".into();
        bad.recipient_id = "same_peer".into();
        assert_eq!(bad.validate().unwrap_err(), "Sender ID and Recipient ID cannot be identical");

        // Empty encrypted_payload
        let mut bad = valid.clone();
        bad.encrypted_payload = vec![];
        assert_eq!(bad.validate().unwrap_err(), "Encrypted payload cannot be empty");

        // Empty auth_tag
        let mut bad = valid.clone();
        bad.auth_tag = vec![];
        assert_eq!(bad.validate().unwrap_err(), "Authentication tag cannot be empty");

        // Empty nonce
        let mut bad = valid.clone();
        bad.nonce = vec![];
        assert_eq!(bad.validate().unwrap_err(), "Nonce cannot be empty");
    }

    // ========================================================================
    // RelayMessage Framing & All Variants Round-trip Tests
    // ========================================================================

    #[test]
    fn test_relay_message_all_variants_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let dev = hex::encode(key.verifying_key().as_bytes());

        let join = RelayJoin::new(&key, dev.clone(), "sess-01".into(), Some("tok".into()));
        let invitation = RelayInvitation::new(&key, dev.clone(), "target".into(), "relay:443".into(), "sess-02".into(), "key-share".into(), 60_000);
        let tunnel = RelayTunnelData::new("sess-03".into(), 10, "sender".into(), "receiver".into(), vec![1, 2], vec![3], vec![4]);

        let variants = vec![
            RelayMessage::Join(join),
            RelayMessage::JoinAck {
                session_id: "sess-01".into(),
                accepted: true,
                reason: None,
            },
            RelayMessage::JoinAck {
                session_id: "sess-01b".into(),
                accepted: false,
                reason: Some("Quota exceeded".into()),
            },
            RelayMessage::Invitation(invitation),
            RelayMessage::InvitationResponse {
                invitation_id: "inv-99".into(),
                accepted: true,
                reason: None,
            },
            RelayMessage::InvitationResponse {
                invitation_id: "inv-100".into(),
                accepted: false,
                reason: Some("Busy".into()),
            },
            RelayMessage::Tunnel(tunnel),
            RelayMessage::Ping {
                session_id: "sess-ping".into(),
                timestamp: 1234567890,
            },
            RelayMessage::Pong {
                session_id: "sess-ping".into(),
                timestamp: 1234567891,
            },
            RelayMessage::CloseSession {
                session_id: "sess-close".into(),
                reason: "Normal teardown".into(),
            },
        ];

        for msg in variants {
            let bytes = msg.to_bytes().expect("Serialization failed");
            let decoded = RelayMessage::from_bytes(&bytes).expect("Deserialization failed");
            assert_eq!(msg, decoded);

            let framed = msg.to_length_prefixed().expect("Framing failed");
            let (unframed, consumed) = RelayMessage::from_length_prefixed(&framed).expect("Unframing failed");
            assert_eq!(consumed, framed.len());
            assert_eq!(msg, unframed);
        }
    }

    #[test]
    fn test_relay_message_session_id_accessor() {
        let key = SigningKey::generate(&mut OsRng);
        let dev = hex::encode(key.verifying_key().as_bytes());

        let join = RelayJoin::new(&key, dev.clone(), "s-join".into(), None);
        assert_eq!(RelayMessage::Join(join).session_id(), Some("s-join"));

        assert_eq!(
            RelayMessage::JoinAck { session_id: "s-ack".into(), accepted: true, reason: None }.session_id(),
            Some("s-ack")
        );

        let inv = RelayInvitation::new(&key, dev.clone(), "t".into(), "r".into(), "s-inv".into(), "k".into(), 1000);
        assert_eq!(RelayMessage::Invitation(inv).session_id(), Some("s-inv"));

        assert_eq!(
            RelayMessage::InvitationResponse { invitation_id: "inv-1".into(), accepted: true, reason: None }.session_id(),
            None
        );

        let tun = RelayTunnelData::new("s-tun".into(), 1, "a".into(), "b".into(), vec![1], vec![1], vec![1]);
        assert_eq!(RelayMessage::Tunnel(tun).session_id(), Some("s-tun"));

        assert_eq!(RelayMessage::Ping { session_id: "s-p".into(), timestamp: 0 }.session_id(), Some("s-p"));
        assert_eq!(RelayMessage::Pong { session_id: "s-po".into(), timestamp: 0 }.session_id(), Some("s-po"));
        assert_eq!(RelayMessage::CloseSession { session_id: "s-cl".into(), reason: "".into() }.session_id(), Some("s-cl"));
    }

    #[test]
    fn test_relay_framing_partial_and_corrupt() {
        // Buffer < 4 bytes
        assert!(RelayMessage::from_length_prefixed(&[]).is_err());
        assert!(RelayMessage::from_length_prefixed(&[0, 0, 1]).is_err());

        // Incomplete frame (declared length 50, but only 10 bytes present)
        let mut incomplete = Vec::new();
        incomplete.extend_from_slice(&50u32.to_be_bytes());
        incomplete.extend_from_slice(&[0u8; 10]);
        assert!(RelayMessage::from_length_prefixed(&incomplete).is_err());

        // Corrupted JSON payload
        let mut corrupt = Vec::new();
        let payload = b"NOT_VALID_JSON{";
        corrupt.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        corrupt.extend_from_slice(payload);
        assert!(RelayMessage::from_length_prefixed(&corrupt).is_err());
    }

    #[test]
    fn test_relay_multi_frame_stream_unframing() {
        let msg1 = RelayMessage::Ping { session_id: "stream-1".into(), timestamp: 100 };
        let msg2 = RelayMessage::Tunnel(RelayTunnelData::new(
            "stream-1".into(),
            1,
            "peer-a".into(),
            "peer-b".into(),
            vec![10, 20, 30],
            vec![99],
            vec![77],
        ));
        let msg3 = RelayMessage::Pong { session_id: "stream-1".into(), timestamp: 101 };
        let msg4 = RelayMessage::CloseSession { session_id: "stream-1".into(), reason: "done".into() };

        // Concatenate all 4 frames into a single continuous byte stream
        let mut stream = Vec::new();
        stream.extend_from_slice(&msg1.to_length_prefixed().unwrap());
        stream.extend_from_slice(&msg2.to_length_prefixed().unwrap());
        stream.extend_from_slice(&msg3.to_length_prefixed().unwrap());
        stream.extend_from_slice(&msg4.to_length_prefixed().unwrap());

        // Iteratively unframing each message
        let (unframed1, consumed1) = RelayMessage::from_length_prefixed(&stream).unwrap();
        assert_eq!(unframed1, msg1);

        let rem1 = &stream[consumed1..];
        let (unframed2, consumed2) = RelayMessage::from_length_prefixed(rem1).unwrap();
        assert_eq!(unframed2, msg2);

        let rem2 = &rem1[consumed2..];
        let (unframed3, consumed3) = RelayMessage::from_length_prefixed(rem2).unwrap();
        assert_eq!(unframed3, msg3);

        let rem3 = &rem2[consumed3..];
        let (unframed4, consumed4) = RelayMessage::from_length_prefixed(rem3).unwrap();
        assert_eq!(unframed4, msg4);

        assert_eq!(consumed1 + consumed2 + consumed3 + consumed4, stream.len());
    }

    // ========================================================================
    // RelaySession State & Replay Protection Tests
    // ========================================================================

    #[test]
    fn test_relay_session_state_transitions() {
        let mut session = RelaySession::new(
            "sess-state".into(),
            "local".into(),
            "remote".into(),
            "relay:443".into(),
        );

        assert_eq!(session.state, RelaySessionState::Disconnected);
        session.state = RelaySessionState::Connecting;
        assert_eq!(session.state, RelaySessionState::Connecting);
        session.state = RelaySessionState::Joined;
        assert_eq!(session.state, RelaySessionState::Joined);
        session.state = RelaySessionState::Invited;
        assert_eq!(session.state, RelaySessionState::Invited);
        session.state = RelaySessionState::Active;
        assert_eq!(session.state, RelaySessionState::Active);
        session.state = RelaySessionState::Closed;
        assert_eq!(session.state, RelaySessionState::Closed);
    }

    #[test]
    fn test_relay_session_inbound_rejections() {
        let mut session = RelaySession::new(
            "sess-rej".into(),
            "local_node".into(),
            "remote_node".into(),
            "relay.synapse.network:443".into(),
        );

        // Sequence number 0 rejected
        let zero_seq = RelayTunnelData::new(
            "sess-rej".into(),
            0,
            "remote_node".into(),
            "local_node".into(),
            vec![1],
            vec![1],
            vec![1],
        );
        let err = session.verify_inbound_data(&zero_seq).unwrap_err();
        assert!(err.contains("Replay or out-of-order"));

        // Normal packet 1 accepted
        let mut frame = zero_seq.clone();
        frame.sequence_number = 1;
        assert!(session.verify_inbound_data(&frame).is_ok());

        // Replay of packet 1 rejected
        assert!(session.verify_inbound_data(&frame).is_err());

        // Packet 5 accepted (gaps allowed in datagram sequence)
        frame.sequence_number = 5;
        assert!(session.verify_inbound_data(&frame).is_ok());

        // Packet 3 (older) rejected
        frame.sequence_number = 3;
        assert!(session.verify_inbound_data(&frame).is_err());

        // Session ID mismatch
        frame.sequence_number = 6;
        frame.session_id = "wrong-session".into();
        let err = session.verify_inbound_data(&frame).unwrap_err();
        assert!(err.contains("Session mismatch"));

        // Sender mismatch
        frame.session_id = "sess-rej".into();
        frame.sender_id = "imposter".into();
        let err = session.verify_inbound_data(&frame).unwrap_err();
        assert!(err.contains("Sender mismatch"));

        // Recipient mismatch
        frame.sender_id = "remote_node".into();
        frame.recipient_id = "someone_else".into();
        let err = session.verify_inbound_data(&frame).unwrap_err();
        assert!(err.contains("Recipient mismatch"));
    }

    // ========================================================================
    // Stress Testing: Sequences, Replay Attacks & Concurrency
    // ========================================================================

    #[test]
    fn test_stress_relay_tunnel_sequencing_10000_frames() {
        let mut sender_session = RelaySession::new(
            "stress-seq-10k".into(),
            "peer-a".into(),
            "peer-b".into(),
            "relay.server:443".into(),
        );
        let mut receiver_session = RelaySession::new(
            "stress-seq-10k".into(),
            "peer-b".into(),
            "peer-a".into(),
            "relay.server:443".into(),
        );

        for expected_seq in 1..=10_000u64 {
            let payload = vec![(expected_seq & 0xFF) as u8; 32];
            let tag = vec![0xAA; 16];
            let nonce = vec![0xBB; 12];

            let frame = sender_session.pack_tunnel_data(payload.clone(), tag, nonce);
            assert_eq!(frame.sequence_number, expected_seq);

            let verified_payload = receiver_session.verify_inbound_data(&frame).expect("Inbound frame verification failed");
            assert_eq!(verified_payload, &payload[..]);
        }

        assert_eq!(sender_session.outbound_seq, 10_000);
        assert_eq!(receiver_session.inbound_seq, 10_000);
    }

    #[test]
    fn test_stress_relay_replay_attack_storm() {
        let mut sender_session = RelaySession::new(
            "stress-replay".into(),
            "peer-a".into(),
            "peer-b".into(),
            "relay:443".into(),
        );
        let mut receiver_session = RelaySession::new(
            "stress-replay".into(),
            "peer-b".into(),
            "peer-a".into(),
            "relay:443".into(),
        );

        let mut captured_frames = Vec::new();
        // Exchange 250 legitimate frames
        for _ in 1..=250 {
            let frame = sender_session.pack_tunnel_data(vec![1, 2, 3], vec![9], vec![0]);
            receiver_session.verify_inbound_data(&frame).expect("Legitimate frame should be accepted");
            captured_frames.push(frame);
        }
        assert_eq!(receiver_session.inbound_seq, 250);

        // Adversary re-injects all 250 captured frames in reverse order (replay attack storm)
        for replayed_frame in captured_frames.iter().rev() {
            let res = receiver_session.verify_inbound_data(replayed_frame);
            assert!(res.is_err(), "Replay frame seq {} must be rejected!", replayed_frame.sequence_number);
        }

        // Receiver state remains at seq 250
        assert_eq!(receiver_session.inbound_seq, 250);

        // Next legitimate frame 251 succeeds
        let frame251 = sender_session.pack_tunnel_data(vec![4, 5, 6], vec![9], vec![1]);
        assert_eq!(frame251.sequence_number, 251);
        assert!(receiver_session.verify_inbound_data(&frame251).is_ok());
    }

    #[tokio::test]
    async fn test_stress_relay_concurrent_sessions() {
        let mut handles = Vec::new();

        for session_idx in 0..25 {
            let handle = tokio::spawn(async move {
                let session_id = format!("concurrent-sess-{}", session_idx);
                let mut sender = RelaySession::new(
                    session_id.clone(),
                    format!("peer-a-{}", session_idx),
                    format!("peer-b-{}", session_idx),
                    "relay:443".into(),
                );
                let mut receiver = RelaySession::new(
                    session_id,
                    format!("peer-b-{}", session_idx),
                    format!("peer-a-{}", session_idx),
                    "relay:443".into(),
                );

                for i in 1..=200u64 {
                    let frame = sender.pack_tunnel_data(vec![(i % 256) as u8; 64], vec![0x55; 16], vec![0x33; 12]);
                    assert_eq!(frame.sequence_number, i);
                    let payload = receiver.verify_inbound_data(&frame).expect("Concurrent inbound frame failed");
                    assert_eq!(payload.len(), 64);
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.await.expect("Concurrent session task failed");
        }
    }
}
