//! Formal State Machine Architecture for Synapse Core.
//!
//! Replaces implicit, stringly-typed state variables and primitive obsession
//! with type-safe, introspectable, and verifiable state machines.
//!
//! Elevates:
//! - **Developer Experience (DX)**: Strong compile-time exhaustiveness, typed transition guards,
//!   explicit error types, and self-documenting lifecycle models.
//! - **User Experience (UX)**: Guards against double-execution and race conditions, delivers
//!   accurate real-time operational status (no stuck "idle" states), and prevents data corruption.
//! - **Agent Experience (AX)**: Machine-readable state metadata, explicit action affordances
//!   (HATEOAS / capabilities), self-healing transition error diagnostics, and a runtime
//!   introspection schema endpoint (`/api/v1/system/statemachines`).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub mod runtime;

// =============================================================================
// 1. CORE INTROSPECTION & ERROR TYPES
// =============================================================================

/// Machine-readable metadata for a state within a state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMetadata {
    /// Canonical state identifier string
    pub state: String,
    /// Human and agent-readable description of what this state represents
    pub description: String,
    /// Whether this is a terminal (final) state from which no further transitions occur
    pub is_terminal: bool,
    /// List of canonical state names that can be legally transitioned to from here
    pub allowed_transitions: Vec<String>,
    /// Permitted user or agent action commands valid when in this state
    pub available_actions: Vec<String>,
}

/// Machine-readable definition of an entire state machine in Synapse Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateMachineDef {
    /// Unique identifier for this state machine
    pub machine_id: String,
    /// Human-friendly display title
    pub display_name: String,
    /// Subsystem or domain (e.g. "conflict", "sync", "p2p", "cluster")
    pub subsystem: String,
    /// High-level description of the workflow or entity managed by this machine
    pub description: String,
    /// Initial state of the entity
    pub initial_state: String,
    /// Complete catalog of states, transitions, and action capabilities
    pub states: Vec<StateMetadata>,
}

/// Structured error returned when an illegal state transition is attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransitionError {
    /// Entity kind (e.g. "conflict", "folder", "device", "session")
    pub entity: String,
    /// Identifier of the specific entity instance
    pub entity_id: String,
    /// Current state of the entity
    pub current_state: String,
    /// State that was attempted
    pub attempted_transition: String,
    /// Valid target states from current state
    pub allowed_transitions: Vec<String>,
    /// Actions permitted in the current state
    pub available_actions: Vec<String>,
    /// Whether the entity is in a terminal state
    pub is_terminal: bool,
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Invalid state transition for {} '{}': cannot move from '{}' to '{}'. Allowed transitions: {:?}",
            self.entity, self.entity_id, self.current_state, self.attempted_transition, self.allowed_transitions
        )
    }
}

impl std::error::Error for StateTransitionError {}

// =============================================================================
// 2. CONFLICT LIFECYCLE STATE MACHINE
// =============================================================================

/// Lifecycle status of a quarantined divergence conflict in Tier 2 / Tier 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConflictStatus {
    /// Staged in `.synapse/quarantine/<conflict_id>.<ext>`. Awaiting human or agent decision.
    #[default]
    Pending,
    /// Resolved via `ACCEPT_LOCAL`, `ACCEPT_REMOTE`, `CUSTOM_MERGE`, or `KEEP_BOTH`.
    /// Staged file is unlinked; local disk and DAG revision are committed. Terminal state.
    Resolved,
    /// Dismissed or postponed by user/agent. Quarantined payload preserved.
    Ignored,
}

impl ConflictStatus {
    pub const ALL: [ConflictStatus; 3] = [
        ConflictStatus::Pending,
        ConflictStatus::Resolved,
        ConflictStatus::Ignored,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Resolved => "RESOLVED",
            Self::Ignored => "IGNORED",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "Conflict is actively quarantined awaiting resolution decision",
            Self::Resolved => {
                "Conflict has been reconciled and applied; working copy is up to date"
            }
            Self::Ignored => "Conflict resolution was postponed or dismissed",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Resolved)
    }

    pub fn can_transition_to(&self, next: ConflictStatus) -> bool {
        match (self, next) {
            (Self::Pending, Self::Resolved) => true,
            (Self::Pending, Self::Ignored) => true,
            (Self::Ignored, Self::Pending) => true,
            (Self::Ignored, Self::Resolved) => true,
            // Resolved is terminal: cannot be re-resolved or reopened
            (Self::Resolved, _) => false,
            // Idempotent transitions
            (s1, s2) if *s1 == s2 => true,
            _ => false,
        }
    }

    pub fn allowed_transitions(&self) -> Vec<ConflictStatus> {
        match self {
            Self::Pending => vec![Self::Resolved, Self::Ignored],
            Self::Ignored => vec![Self::Pending, Self::Resolved],
            Self::Resolved => vec![],
        }
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Pending => vec![
                "ACCEPT_LOCAL",
                "ACCEPT_REMOTE",
                "CUSTOM_MERGE",
                "KEEP_BOTH",
                "IGNORE",
            ],
            Self::Ignored => vec![
                "REOPEN",
                "ACCEPT_LOCAL",
                "ACCEPT_REMOTE",
                "CUSTOM_MERGE",
                "KEEP_BOTH",
            ],
            Self::Resolved => vec![],
        }
    }

    pub fn metadata(&self) -> StateMetadata {
        StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: self.is_terminal(),
            allowed_transitions: self
                .allowed_transitions()
                .into_iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            available_actions: self
                .available_actions()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }
}

impl fmt::Display for ConflictStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// Lets callers compare against the wire value directly (`status == "PENDING"`).
impl PartialEq<&str> for ConflictStatus {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<str> for ConflictStatus {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl FromStr for ConflictStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "PENDING" => Ok(ConflictStatus::Pending),
            "RESOLVED" => Ok(ConflictStatus::Resolved),
            "IGNORED" => Ok(ConflictStatus::Ignored),
            other => Err(format!("Unknown conflict status: '{}'", other)),
        }
    }
}

// =============================================================================
// 3. FOLDER SYNC LIFECYCLE STATE MACHINE
// =============================================================================

/// Dynamic operational synchronization state of a monitored folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FolderSyncState {
    /// Folder is in steady state, watching for local filesystem modifications.
    #[default]
    Idle,
    /// Active recursive directory traversal, metadata hashing, and delta chunking in progress.
    Scanning,
    /// Active block transfer, remote revision download, or 3-way reconciliation in progress.
    Syncing,
    /// Folder synchronization is manually suspended by user. Watchers and indexing skipped.
    Paused,
    /// Folder encountered an unrecoverable fault (e.g. missing mount marker, permissions).
    Error,
}

impl FolderSyncState {
    pub const ALL: [FolderSyncState; 5] = [
        FolderSyncState::Idle,
        FolderSyncState::Scanning,
        FolderSyncState::Syncing,
        FolderSyncState::Paused,
        FolderSyncState::Error,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Scanning => "scanning",
            Self::Syncing => "syncing",
            Self::Paused => "paused",
            Self::Error => "error",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Idle => "Folder is synchronized and actively monitoring filesystem events",
            Self::Scanning => {
                "Folder is scanning directory structure and hashing local file deltas"
            }
            Self::Syncing => {
                "Folder is transferring blocks or reconciling incoming remote revisions"
            }
            Self::Paused => "Folder synchronization is paused; no watcher or sync tasks run",
            Self::Error => {
                "Folder encountered a filesystem error or mount safety marker check failure"
            }
        }
    }

    pub fn is_terminal(&self) -> bool {
        false
    }

    pub fn can_transition_to(&self, next: FolderSyncState) -> bool {
        match (self, next) {
            // From Idle: can start scan, start sync, be paused, or encounter error
            (Self::Idle, Self::Scanning) => true,
            (Self::Idle, Self::Syncing) => true,
            (Self::Idle, Self::Paused) => true,
            (Self::Idle, Self::Error) => true,

            // From Scanning: returns to Idle, enters Syncing, can be Paused or Error
            (Self::Scanning, Self::Idle) => true,
            (Self::Scanning, Self::Syncing) => true,
            (Self::Scanning, Self::Paused) => true,
            (Self::Scanning, Self::Error) => true,

            // From Syncing: returns to Idle, can start another Scan, Paused, or Error
            (Self::Syncing, Self::Idle) => true,
            (Self::Syncing, Self::Scanning) => true,
            (Self::Syncing, Self::Paused) => true,
            (Self::Syncing, Self::Error) => true,

            // From Paused: resuming lands in whatever the folder is doing underneath
            // (idle, a scan or sync still in flight, or an unresolved error)
            (Self::Paused, Self::Idle) => true,
            (Self::Paused, Self::Scanning) => true,
            (Self::Paused, Self::Syncing) => true,
            (Self::Paused, Self::Error) => true,

            // From Error: recovered by a successful rescan; incoming syncs and pausing
            // still apply while the error is outstanding
            (Self::Error, Self::Idle) => true,
            (Self::Error, Self::Scanning) => true,
            (Self::Error, Self::Syncing) => true,
            (Self::Error, Self::Paused) => true,

            (s1, s2) if *s1 == s2 => true,
            _ => false,
        }
    }

    pub fn allowed_transitions(&self) -> Vec<FolderSyncState> {
        Self::ALL
            .iter()
            .copied()
            .filter(|&target| self.can_transition_to(target))
            .collect()
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Idle => vec!["RESCAN", "PAUSE", "DELETE", "SET_IGNORES", "SHARE"],
            Self::Scanning => vec!["CANCEL", "PAUSE"],
            Self::Syncing => vec!["PAUSE"],
            Self::Paused => vec!["RESUME", "DELETE", "SET_IGNORES"],
            Self::Error => vec!["RESCAN", "RETRY_MOUNT", "DELETE"],
        }
    }

    pub fn metadata(&self) -> StateMetadata {
        StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: self.is_terminal(),
            allowed_transitions: self
                .allowed_transitions()
                .into_iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            available_actions: self
                .available_actions()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }
}

impl fmt::Display for FolderSyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for FolderSyncState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "idle" => Ok(FolderSyncState::Idle),
            "scanning" => Ok(FolderSyncState::Scanning),
            "syncing" => Ok(FolderSyncState::Syncing),
            "paused" => Ok(FolderSyncState::Paused),
            "error" => Ok(FolderSyncState::Error),
            other => Err(format!("Unknown folder sync state: '{}'", other)),
        }
    }
}

// =============================================================================
// 4. FOLDER SYNC MODE POLICY
// =============================================================================

/// Synchronization directionality constraint for a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SyncMode {
    /// Bi-directional: propagates local edits and accepts remote edits.
    #[default]
    SendReceive,
    /// Unidirectional upload: propagates local changes to peers, rejects incoming remote modifications.
    SendOnly,
    /// Unidirectional download: accepts remote peer changes, ignores/discards local disk edits.
    ReceiveOnly,
}

impl SyncMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendReceive => "SendReceive",
            Self::SendOnly => "SendOnly",
            Self::ReceiveOnly => "ReceiveOnly",
        }
    }

    pub fn can_send(&self) -> bool {
        matches!(self, Self::SendReceive | Self::SendOnly)
    }

    pub fn can_receive(&self) -> bool {
        matches!(self, Self::SendReceive | Self::ReceiveOnly)
    }
}

impl fmt::Display for SyncMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SyncMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "sendreceive" | "send_receive" => Ok(SyncMode::SendReceive),
            "sendonly" | "send_only" => Ok(SyncMode::SendOnly),
            "receiveonly" | "receive_only" => Ok(SyncMode::ReceiveOnly),
            other => Err(format!("Unknown sync mode: '{}'", other)),
        }
    }
}

// =============================================================================
// 5. CONFLICT POLICY
// =============================================================================

/// Strategy used when concurrent divergent revisions occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ConflictPolicy {
    /// Tier 1 3-way semantic diff3 merge $\to$ Tier 2 virtual quarantine. Zero pollution.
    #[default]
    ThreeWayAuto,
    /// Last-Write-Wins: revision with largest modification timestamp supersedes cleanly.
    Lww,
    /// Manual: bypass Tier 1 automated merge and always stage in virtual quarantine.
    Manual,
}

impl ConflictPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ThreeWayAuto => "THREE_WAY_AUTO",
            Self::Lww => "LWW",
            Self::Manual => "MANUAL",
        }
    }
}

impl fmt::Display for ConflictPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ConflictPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "THREE_WAY_AUTO" | "THREEWAYAUTO" | "AUTO" => Ok(ConflictPolicy::ThreeWayAuto),
            "LWW" | "LAST_WRITE_WINS" => Ok(ConflictPolicy::Lww),
            "MANUAL" => Ok(ConflictPolicy::Manual),
            other => Err(format!("Unknown conflict policy: '{}'", other)),
        }
    }
}

// =============================================================================
// 5b. FOLDER CONFIGURATION VALIDATION
// =============================================================================

/// `400 Bad Request` body for a configuration value the engine doesn't understand.
/// Lists the accepted values so a UI can show a picker and an agent can self-correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidFieldError {
    /// Always `"invalid_field"`.
    pub error: String,
    pub field: String,
    pub value: String,
    /// Canonical accepted values (matching is case-insensitive; `_` is optional).
    pub allowed: Vec<String>,
    pub message: String,
}

impl InvalidFieldError {
    fn new(field: &str, value: &str, allowed: &[&str]) -> Self {
        Self {
            error: "invalid_field".into(),
            field: field.into(),
            value: value.into(),
            allowed: allowed.iter().map(|s| s.to_string()).collect(),
            message: format!(
                "Unsupported {field} '{value}'. Accepted values: {}",
                allowed.join(", ")
            ),
        }
    }
}

impl fmt::Display for InvalidFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for InvalidFieldError {}

pub const SYNC_MODES: &[&str] = &["SendReceive", "SendOnly", "ReceiveOnly"];
pub const CONFLICT_POLICIES: &[&str] = &["THREE_WAY_AUTO", "LWW", "MANUAL"];
/// `random` is Syncthing's default; it is accepted for compatibility and pulls in
/// alphabetical order.
pub const PULL_ORDERS: &[&str] = &[
    "alphabetical",
    "smallestFirst",
    "largestFirst",
    "newestFirst",
    "oldestFirst",
    "random",
];
pub const VERSIONING_TYPES: &[&str] = &["None", "TrashCan", "Simple", "Staggered"];

/// Validates folder policy strings before they are persisted.
///
/// Previously any string was stored and later silently replaced by a default when
/// parsed (e.g. a typo in `sync_mode` meant "send and receive"). Only values the
/// engine actually understands are accepted now; every spelling that worked before is
/// still accepted.
pub fn validate_folder_config(
    conflict_policy: &str,
    sync_mode: Option<&str>,
    pull_order: Option<&str>,
    versioning_type: Option<&str>,
) -> Result<(), InvalidFieldError> {
    if conflict_policy.parse::<ConflictPolicy>().is_err() {
        return Err(InvalidFieldError::new(
            "conflict_policy",
            conflict_policy,
            CONFLICT_POLICIES,
        ));
    }
    if let Some(v) = sync_mode {
        if v.parse::<SyncMode>().is_err() {
            return Err(InvalidFieldError::new("sync_mode", v, SYNC_MODES));
        }
    }
    if let Some(v) = pull_order {
        let ok =
            v.trim().eq_ignore_ascii_case("random") || v.parse::<crate::p2p::PullOrder>().is_ok();
        if !ok {
            return Err(InvalidFieldError::new("pull_order", v, PULL_ORDERS));
        }
    }
    if let Some(v) = versioning_type {
        let norm = v.trim().to_ascii_lowercase().replace('_', "");
        if !matches!(
            norm.as_str(),
            "" | "none" | "trashcan" | "trash" | "simple" | "staggered"
        ) {
            return Err(InvalidFieldError::new(
                "versioning_type",
                v,
                VERSIONING_TYPES,
            ));
        }
    }
    Ok(())
}

// =============================================================================
// 6. CLUSTER DEVICE PAIRING STATE MACHINE
// =============================================================================

/// Pairing and cluster membership lifecycle for a remote device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DevicePairingState {
    /// Discovered over UDP broadcast or announced by introducer, awaiting explicit pairing approval.
    #[default]
    Pending,
    /// Accepted into cluster configuration; eligible for block transfer and QUIC connection.
    Paired,
    /// Paired but communication temporarily suspended.
    Paused,
    /// Pairing request explicitly rejected and removed from pending queue.
    Rejected,
}

impl DevicePairingState {
    pub const ALL: [DevicePairingState; 4] = [
        DevicePairingState::Pending,
        DevicePairingState::Paired,
        DevicePairingState::Paused,
        DevicePairingState::Rejected,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Paired => "paired",
            Self::Paused => "paused",
            Self::Rejected => "rejected",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "Device pairing request is pending user or agent confirmation",
            Self::Paired => "Device is mutually paired and participating in the cluster",
            Self::Paused => "Device communication is temporarily paused",
            Self::Rejected => "Pairing request was rejected and is remembered: the device is not re-staged as pending on later discovery. FORGET (DELETE /api/v1/cluster/rejected/devices/:id) clears it; adding the device explicitly overrides it",
        }
    }

    pub fn can_transition_to(&self, next: DevicePairingState) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Paired)
                | (Self::Pending, Self::Rejected)
                | (Self::Paired, Self::Paused)
                | (Self::Paused, Self::Paired)
        )
    }

    pub fn allowed_transitions(&self) -> Vec<DevicePairingState> {
        Self::ALL
            .iter()
            .copied()
            .filter(|&target| self.can_transition_to(target))
            .collect()
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Pending => vec!["ACCEPT", "REJECT"],
            Self::Paired => vec!["PAUSE", "REMOVE", "SHARE_FOLDER", "UNSHARE_FOLDER"],
            Self::Paused => vec!["RESUME", "REMOVE"],
            Self::Rejected => vec!["FORGET"],
        }
    }

    pub fn metadata(&self) -> StateMetadata {
        StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: matches!(self, Self::Rejected),
            allowed_transitions: self
                .allowed_transitions()
                .into_iter()
                .map(|s| s.as_str().to_string())
                .collect(),
            available_actions: self
                .available_actions()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }
}

impl fmt::Display for DevicePairingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DevicePairingState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "pending" => Ok(DevicePairingState::Pending),
            "paired" => Ok(DevicePairingState::Paired),
            "paused" => Ok(DevicePairingState::Paused),
            "rejected" => Ok(DevicePairingState::Rejected),
            other => Err(format!("Unknown device pairing state: '{}'", other)),
        }
    }
}

// =============================================================================
// 6b. REMOTE FOLDER OFFER STATE MACHINE
// =============================================================================

/// Lifecycle of a folder that a paired device offered to share with us.
/// Keyed by `(folder_id, offering device_id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FolderOfferState {
    /// Offer received; waiting for the user to accept (with a local path) or reject.
    #[default]
    Pending,
    /// Accepted: the folder exists locally and is shared with the offering device.
    Accepted,
    /// Rejected and remembered, so the same offer doesn't come back.
    Rejected,
}

impl FolderOfferState {
    pub const ALL: [FolderOfferState; 3] = [Self::Pending, Self::Accepted, Self::Rejected];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "A paired device offered this folder; accept with a local path or reject",
            Self::Accepted => "The folder is registered locally and shared with the offering device",
            Self::Rejected => "The offer was rejected and is remembered so it is not shown again. FORGET (DELETE /api/v1/cluster/rejected/folders/:id?device_id=…) clears it",
        }
    }

    pub fn can_transition_to(&self, next: FolderOfferState) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Accepted) | (Self::Pending, Self::Rejected)
        )
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Pending => vec!["ACCEPT", "REJECT"],
            Self::Accepted => vec![],
            Self::Rejected => vec!["FORGET"],
        }
    }

    pub fn metadata(&self) -> StateMetadata {
        StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: !matches!(self, Self::Pending),
            allowed_transitions: Self::ALL
                .iter()
                .filter(|s| self.can_transition_to(**s))
                .map(|s| s.as_str().to_string())
                .collect(),
            available_actions: self
                .available_actions()
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }
}

impl fmt::Display for FolderOfferState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

// =============================================================================
// 7. SWARM CHUNK REPLICATION STATE MACHINE
// =============================================================================

/// Download lifecycle of an individual Content-Addressable chunk in the Swarm Scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "details")]
pub enum ChunkDownloadState {
    /// Chunk is needed for a queued file but has not yet been assigned to a peer.
    Pending,
    /// Chunk has been requested from a specific peer over QUIC stream and is awaiting data.
    InFlight {
        peer_id: String,
        elapsed_millis: u64,
    },
    /// Chunk has been fetched, verified by BLAKE3 hash, and committed to CAS block store.
    Completed,
    /// Chunk download failed or timed out; eligible for requeueing or terminal failure.
    Failed { reason: String, attempts: usize },
}

impl ChunkDownloadState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::InFlight { .. } => "IN_FLIGHT",
            Self::Completed => "COMPLETED",
            Self::Failed { .. } => "FAILED",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Pending => "Chunk is queued in scheduler awaiting peer assignment",
            Self::InFlight { .. } => "Chunk request is actively in-flight to a swarm peer",
            Self::Completed => "Chunk was successfully downloaded, verified, and saved to CAS",
            Self::Failed { .. } => "Chunk transfer failed and requires retry or peer escalation",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

// =============================================================================
// 8. 3-TIER CONFLICT RESOLUTION PIPELINE MODEL
// =============================================================================

/// Tier classification within the Multi-Strategy Conflict Resolution Pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConflictPipelineTier {
    /// Tier 1: Automated 3-way diff3 merge for text files with non-overlapping edits.
    Tier1AutoMerge,
    /// Tier 2: Non-polluting virtual quarantine into `.synapse/quarantine/<id>.<ext>`.
    Tier2VirtualQuarantine,
    /// Tier 3: Interactive UI visual diff inspection and user decision execution.
    Tier3Interactive,
}

impl ConflictPipelineTier {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tier1AutoMerge => "Tier 1: Automated 3-Way Semantic Merge",
            Self::Tier2VirtualQuarantine => "Tier 2: Zero-Pollution Virtual Quarantine",
            Self::Tier3Interactive => "Tier 3: Interactive Visual Resolution",
        }
    }
}

// =============================================================================
// 9. COMPLETE STATE MACHINE REGISTRY & INTROSPECTION
// =============================================================================

/// Returns the comprehensive catalog of all formal state machines in Synapse Core.
///
/// Designed specifically for AI agent discovery (AX) and dynamic runtime verification.
pub fn get_all_state_machines() -> Vec<StateMachineDef> {
    vec![
        StateMachineDef {
            machine_id: "conflict_lifecycle".to_string(),
            display_name: "Quarantine Conflict Resolution State Machine".to_string(),
            subsystem: "conflict".to_string(),
            description: "Controls the staging, inspection, and 3-way resolution of divergent concurrent edits without filesystem pollution.".to_string(),
            initial_state: ConflictStatus::Pending.as_str().to_string(),
            states: ConflictStatus::ALL.iter().map(|s| s.metadata()).collect(),
        },
        StateMachineDef {
            machine_id: "folder_sync_lifecycle".to_string(),
            display_name: "Folder Synchronization Lifecycle State Machine".to_string(),
            subsystem: "engine".to_string(),
            description: "Runtime state of a synchronization root, derived from in-flight work: paused (persisted) > scanning > syncing > error > idle. Every change is broadcast as a FOLDER_STATE_CHANGED event; entering/leaving syncing also emits SYNC_STARTED/SYNC_COMPLETED. An error carries a reason (GET /api/v1/folders/:id/status -> error) and is cleared by the next successful rescan.".to_string(),
            initial_state: FolderSyncState::Idle.as_str().to_string(),
            states: FolderSyncState::ALL.iter().map(|s| s.metadata()).collect(),
        },
        StateMachineDef {
            machine_id: "device_pairing_lifecycle".to_string(),
            display_name: "Cluster Device Pairing State Machine".to_string(),
            subsystem: "cluster".to_string(),
            description: "Governs node discovery, mutual cryptographic handshake, trust verification, and cluster participation.".to_string(),
            initial_state: DevicePairingState::Pending.as_str().to_string(),
            states: DevicePairingState::ALL.iter().map(|s| s.metadata()).collect(),
        },
        StateMachineDef {
            machine_id: "folder_offer_lifecycle".to_string(),
            display_name: "Remote Folder Offer State Machine".to_string(),
            subsystem: "cluster".to_string(),
            description: "A folder offered by a paired device, keyed by (folder_id, device_id). Accepting registers it locally (mount marker created, initial scan started) and shares it back; rejecting is remembered. Invalid actions return 409 with the allowed transitions.".to_string(),
            initial_state: FolderOfferState::Pending.as_str().to_string(),
            states: FolderOfferState::ALL.iter().map(|s| s.metadata()).collect(),
        },
        StateMachineDef {
            machine_id: "engine_lifecycle".to_string(),
            display_name: "Engine Lifecycle State Machine".to_string(),
            subsystem: "system".to_string(),
            description: "Lifecycle of the engine process. Reported as `lifecycle` in GET /api/v1/system/status. POST /api/v1/system/restart moves ready -> restarting: the engine stops and starts again in-process (same PID, same API address, storage reloaded). POST /api/v1/system/shutdown, SIGTERM, a dead parent or closed stdin move to stopping.".to_string(),
            initial_state: runtime::EngineLifecycleState::Starting.as_str().to_string(),
            states: runtime::EngineLifecycleState::ALL
                .iter()
                .map(|s| s.metadata())
                .collect(),
        },
        StateMachineDef {
            machine_id: "peer_presence".to_string(),
            display_name: "Peer Presence State Machine".to_string(),
            subsystem: "p2p".to_string(),
            description: "Heartbeat-based liveness of a known peer. Any discovery announcement or protocol message marks it online (PEER_CONNECTED); 30 s of silence marks it offline (PEER_DISCONNECTED). Drives peer_count, /api/v1/connections is_connected, and device 'online'. Offline peers are still contacted for sync.".to_string(),
            initial_state: runtime::PeerPresenceState::Offline.as_str().to_string(),
            states: runtime::PeerPresenceState::ALL
                .iter()
                .map(|s| s.metadata())
                .collect(),
        },
        StateMachineDef {
            machine_id: "relay_session_lifecycle".to_string(),
            display_name: "Encrypted Relay Fallback Session State Machine".to_string(),
            subsystem: "p2p".to_string(),
            description: "Sequences zero-trust end-to-end encrypted relay rendezvous and tunnel data transmission across symmetric NATs.".to_string(),
            initial_state: "disconnected".to_string(),
            states: vec![
                StateMetadata {
                    state: "disconnected".to_string(),
                    description: "No active connection to fallback relay".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["connecting".to_string()],
                    available_actions: vec!["CONNECT".to_string()],
                },
                StateMetadata {
                    state: "connecting".to_string(),
                    description: "TCP/TLS handshake to relay server in progress".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["joined".to_string(), "closed".to_string()],
                    available_actions: vec!["ABORT".to_string()],
                },
                StateMetadata {
                    state: "joined".to_string(),
                    description: "Authenticated with relay server via signed RelayJoin".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["invited".to_string(), "active".to_string(), "closed".to_string()],
                    available_actions: vec!["INVITE_PEER".to_string(), "DISCONNECT".to_string()],
                },
                StateMetadata {
                    state: "invited".to_string(),
                    description: "RelayInvitation dispatched to target peer; awaiting rendezvous".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["active".to_string(), "closed".to_string()],
                    available_actions: vec!["CANCEL_INVITATION".to_string()],
                },
                StateMetadata {
                    state: "active".to_string(),
                    description: "Encrypted tunnel established; bidirectional blind forwarding active".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["closed".to_string()],
                    available_actions: vec!["SEND_TUNNEL_DATA".to_string(), "CLOSE_SESSION".to_string()],
                },
                StateMetadata {
                    state: "closed".to_string(),
                    description: "Relay tunnel cleanly torn down".to_string(),
                    is_terminal: true,
                    allowed_transitions: vec![],
                    available_actions: vec![],
                },
            ],
        },
        StateMachineDef {
            machine_id: "swarm_chunk_lifecycle".to_string(),
            display_name: "Swarm Chunk Replication State Machine".to_string(),
            subsystem: "swarm".to_string(),
            description: "Tracks individual CAS chunk replication across multiple parallel QUIC swarm peers with rarest-first scheduling.".to_string(),
            initial_state: "PENDING".to_string(),
            states: vec![
                StateMetadata {
                    state: "PENDING".to_string(),
                    description: "Chunk needed for file reconstruction; awaiting peer assignment".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["IN_FLIGHT".to_string()],
                    available_actions: vec!["SCHEDULE".to_string()],
                },
                StateMetadata {
                    state: "IN_FLIGHT".to_string(),
                    description: "Chunk requested from target peer over QUIC stream".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["COMPLETED".to_string(), "FAILED".to_string(), "PENDING".to_string()],
                    available_actions: vec!["CANCEL".to_string(), "TIMEOUT".to_string()],
                },
                StateMetadata {
                    state: "COMPLETED".to_string(),
                    description: "Chunk received, BLAKE3 verified, and written to CAS".to_string(),
                    is_terminal: true,
                    allowed_transitions: vec![],
                    available_actions: vec![],
                },
                StateMetadata {
                    state: "FAILED".to_string(),
                    description: "Chunk request timed out or received corrupt data; requeued".to_string(),
                    is_terminal: false,
                    allowed_transitions: vec!["PENDING".to_string()],
                    available_actions: vec!["RETRY".to_string()],
                },
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_status_transitions_and_guards() {
        let pending = ConflictStatus::Pending;
        assert!(pending.can_transition_to(ConflictStatus::Resolved));
        assert!(pending.can_transition_to(ConflictStatus::Ignored));
        assert!(!pending.is_terminal());

        let resolved = ConflictStatus::Resolved;
        assert!(resolved.is_terminal());
        // Resolved cannot transition anywhere
        assert!(!resolved.can_transition_to(ConflictStatus::Pending));
        assert!(!resolved.can_transition_to(ConflictStatus::Ignored));

        let ignored = ConflictStatus::Ignored;
        assert!(ignored.can_transition_to(ConflictStatus::Pending));
        assert!(ignored.can_transition_to(ConflictStatus::Resolved));
    }

    #[test]
    fn test_conflict_status_string_and_serde_roundtrip() {
        assert_eq!(ConflictStatus::Pending.to_string(), "PENDING");
        assert_eq!(ConflictStatus::Resolved.to_string(), "RESOLVED");
        assert_eq!(ConflictStatus::Ignored.to_string(), "IGNORED");

        assert_eq!(
            ConflictStatus::from_str("pending").unwrap(),
            ConflictStatus::Pending
        );
        assert_eq!(
            ConflictStatus::from_str("RESOLVED").unwrap(),
            ConflictStatus::Resolved
        );
        assert_eq!(
            ConflictStatus::from_str("ignored").unwrap(),
            ConflictStatus::Ignored
        );

        let json = serde_json::to_string(&ConflictStatus::Pending).unwrap();
        assert_eq!(json, "\"PENDING\"");
        let deserialized: ConflictStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ConflictStatus::Pending);
    }

    #[test]
    fn test_folder_sync_state_transitions() {
        let idle = FolderSyncState::Idle;
        assert!(idle.can_transition_to(FolderSyncState::Scanning));
        assert!(idle.can_transition_to(FolderSyncState::Syncing));
        assert!(idle.can_transition_to(FolderSyncState::Paused));
        assert!(idle.can_transition_to(FolderSyncState::Error));

        let scanning = FolderSyncState::Scanning;
        assert!(scanning.can_transition_to(FolderSyncState::Idle));
        assert!(scanning.can_transition_to(FolderSyncState::Syncing));

        let paused = FolderSyncState::Paused;
        assert!(paused.can_transition_to(FolderSyncState::Idle));
        // Resuming while a remote sync is still in flight lands directly in syncing
        // (state is derived from running work; see state::runtime).
        assert!(paused.can_transition_to(FolderSyncState::Syncing));
        assert!(FolderSyncState::Error.can_transition_to(FolderSyncState::Scanning));

        let json = serde_json::to_string(&FolderSyncState::Scanning).unwrap();
        assert_eq!(json, "\"scanning\"");
    }

    #[test]
    fn folder_config_validation_accepts_every_known_spelling() {
        for (cp, sm, po, vt) in [
            ("THREE_WAY_AUTO", "SEND_RECEIVE", "ALPHABETICAL", "SIMPLE"),
            ("three_way_auto", "SendReceive", "Alphabetical", "None"),
            ("LWW", "sendonly", "smallestFirst", "trashcan"),
            ("MANUAL", "receive_only", "random", "staggered"),
            ("auto", "ReceiveOnly", "newest", "TrashCan"),
        ] {
            assert!(
                validate_folder_config(cp, Some(sm), Some(po), Some(vt)).is_ok(),
                "{cp} {sm} {po} {vt}"
            );
        }
        assert!(validate_folder_config("THREE_WAY_AUTO", None, None, None).is_ok());
    }

    #[test]
    fn folder_config_validation_rejects_unknown_values_with_choices() {
        let err = validate_folder_config("THREE_WAY_AUTO", Some("mirror"), None, None).unwrap_err();
        assert_eq!(err.field, "sync_mode");
        assert_eq!(err.value, "mirror");
        assert_eq!(err.allowed, SYNC_MODES);
        assert_eq!(
            validate_folder_config("NEWEST_WINS", None, None, None)
                .unwrap_err()
                .field,
            "conflict_policy"
        );
        assert_eq!(
            validate_folder_config("LWW", None, Some("biggest"), None)
                .unwrap_err()
                .field,
            "pull_order"
        );
        assert_eq!(
            validate_folder_config("LWW", None, None, Some("external"))
                .unwrap_err()
                .field,
            "versioning_type"
        );
    }

    #[test]
    fn test_all_state_machines_registry_intact() {
        let registry = get_all_state_machines();
        assert!(!registry.is_empty());

        for sm in &registry {
            assert!(!sm.machine_id.is_empty());
            assert!(!sm.subsystem.is_empty());
            assert!(
                sm.states.iter().any(|s| s.state == sm.initial_state),
                "State machine '{}' missing initial state '{}'",
                sm.machine_id,
                sm.initial_state
            );
            for s in &sm.states {
                assert!(!s.description.is_empty());
                if s.is_terminal {
                    assert!(s.allowed_transitions.is_empty());
                }
            }
        }
    }
}
