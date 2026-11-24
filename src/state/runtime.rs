//! Runtime state machines: state that only exists while the engine is running.
//!
//! Two machines that used to be implicit live here:
//!
//! * **Folder activity** ([`FolderStateTracker`]). Previously a bare
//!   `HashMap<folder, FolderSyncState>` written with "set Scanning … set Idle" pairs.
//!   Any early `return`/`?` between the pair left the folder stuck in `scanning` or
//!   `syncing` forever, concurrent scans clobbered each other, and the `SYNC_STARTED` /
//!   `SYNC_COMPLETED` events were never emitted. The state is now *derived* from RAII
//!   activity guards, so it is correct by construction on every exit path.
//!
//! * **Peer presence** ([`PeerPresence`]). Previously a peer stayed "connected" forever
//!   after a single discovery packet, `PEER_DISCONNECTED` was never emitted, and the API
//!   reported `is_connected = !paused`. Presence is now `online` / `offline` with a
//!   heartbeat TTL. The routing table is untouched: offline peers are still contacted.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::conflict::CoreEvent;
use crate::state::FolderSyncState;

// =============================================================================
// Folder activity
// =============================================================================

/// Kind of work running against a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderActivityKind {
    /// Local directory walk + hashing (`index_folder`).
    Scan,
    /// Applying a remote revision (`apply_remote_revision`).
    Sync,
}

#[derive(Debug, Default)]
struct FolderEntry {
    scans: u32,
    syncs: u32,
    /// Last scan failure; cleared by the next successful scan.
    error: Option<String>,
    /// Explicit state set through [`FolderStateTracker::set_override`] (tests, tooling).
    override_state: Option<FolderSyncState>,
    /// Successful sync activities in the current `syncing` episode.
    synced_in_episode: usize,
    /// Last state observed/emitted, used to detect transitions.
    last: FolderSyncState,
}

impl FolderEntry {
    /// Derivation rule (highest priority first):
    /// paused (persisted config) > scanning > syncing > error > override > idle.
    fn derive(&self, paused: bool) -> FolderSyncState {
        if paused {
            FolderSyncState::Paused
        } else if self.scans > 0 {
            FolderSyncState::Scanning
        } else if self.syncs > 0 {
            FolderSyncState::Syncing
        } else if self.error.is_some() {
            FolderSyncState::Error
        } else {
            self.override_state.unwrap_or(FolderSyncState::Idle)
        }
    }
}

/// Snapshot of a folder's runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRuntimeState {
    pub state: FolderSyncState,
    pub error: Option<String>,
}

/// Reads the persisted "paused" flag for a folder (the source of truth for pausing).
pub type PausedLookup = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Owns the folder activity state machine and emits transition events.
#[derive(Clone)]
pub struct FolderStateTracker {
    entries: Arc<RwLock<HashMap<String, FolderEntry>>>,
    events: broadcast::Sender<CoreEvent>,
    paused: PausedLookup,
}

impl FolderStateTracker {
    pub fn new(events: broadcast::Sender<CoreEvent>, paused: PausedLookup) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            events,
            paused,
        }
    }

    /// Starts tracking a folder at its current state without emitting an event.
    /// Called when folders are loaded at startup or registered, so the first later
    /// change (e.g. a pause) is reported relative to the right starting state.
    pub fn track(&self, folder_id: &str) {
        let paused = (self.paused)(folder_id);
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        entries.entry(folder_id.to_string()).or_insert_with(|| {
            let mut fresh = FolderEntry::default();
            fresh.last = fresh.derive(paused);
            fresh
        });
    }

    /// Current state of a folder.
    pub fn get(&self, folder_id: &str) -> FolderRuntimeState {
        let paused = (self.paused)(folder_id);
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        match entries.get(folder_id) {
            Some(e) => FolderRuntimeState {
                state: e.derive(paused),
                error: e.error.clone(),
            },
            None => FolderRuntimeState {
                state: if paused {
                    FolderSyncState::Paused
                } else {
                    FolderSyncState::Idle
                },
                error: None,
            },
        }
    }

    /// Starts tracked work. The returned guard ends it on drop, on **every** exit path
    /// (early return, `?`, panic). Call [`FolderActivity::succeed`] or
    /// [`FolderActivity::fail`] to record the outcome.
    pub fn begin(&self, folder_id: &str, kind: FolderActivityKind) -> FolderActivity {
        self.mutate(folder_id, |e| match kind {
            FolderActivityKind::Scan => e.scans += 1,
            FolderActivityKind::Sync => e.syncs += 1,
        });
        FolderActivity {
            tracker: self.clone(),
            folder_id: folder_id.to_string(),
            kind,
            done: false,
        }
    }

    /// Explicitly sets a state. Kept for tooling and tests; engine code uses [`begin`].
    /// `Idle` also clears a recorded error.
    ///
    /// [`begin`]: Self::begin
    pub fn set_override(&self, folder_id: &str, state: FolderSyncState) {
        self.mutate(folder_id, |e| match state {
            FolderSyncState::Idle => {
                e.override_state = None;
                e.error = None;
            }
            FolderSyncState::Error => {
                e.error
                    .get_or_insert_with(|| "error state set explicitly".into());
            }
            other => e.override_state = Some(other),
        });
    }

    /// Re-evaluates the state after persisted config changed (pause/resume) and emits
    /// the transition if there is one.
    pub fn refresh(&self, folder_id: &str) {
        self.mutate(folder_id, |_| {});
    }

    /// Drops all runtime state for a deleted folder.
    pub fn forget(&self, folder_id: &str) {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        entries.remove(folder_id);
    }

    /// Count of folders per state, for dashboards.
    pub fn summarize<'a>(
        &self,
        folder_ids: impl IntoIterator<Item = &'a str>,
    ) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for id in folder_ids {
            *out.entry(self.get(id).state.as_str().to_string())
                .or_insert(0) += 1;
        }
        out
    }

    fn finish(&self, folder_id: &str, kind: FolderActivityKind, outcome: Result<(), String>) {
        self.mutate(folder_id, |e| {
            match kind {
                FolderActivityKind::Scan => {
                    e.scans = e.scans.saturating_sub(1);
                    match &outcome {
                        Ok(()) => e.error = None,
                        Err(msg) => e.error = Some(msg.clone()),
                    }
                }
                FolderActivityKind::Sync => {
                    e.syncs = e.syncs.saturating_sub(1);
                    // A single bad remote revision must not flag the whole folder; it is
                    // logged by the caller and the folder returns to its previous state.
                    if outcome.is_ok() {
                        e.synced_in_episode += 1;
                    }
                }
            }
            // Activity outcomes supersede any explicit override.
            e.override_state = None;
        });
    }

    fn mutate(&self, folder_id: &str, f: impl FnOnce(&mut FolderEntry)) {
        // Read persisted config before taking our lock (never nest storage inside it).
        let paused = (self.paused)(folder_id);
        let (from, to, error, synced) = {
            let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
            let e = entries.entry(folder_id.to_string()).or_insert_with(|| {
                let mut fresh = FolderEntry::default();
                fresh.last = fresh.derive(paused);
                fresh
            });
            let from = e.last;
            f(e);
            let to = e.derive(paused);
            e.last = to;
            let synced = if from == FolderSyncState::Syncing && to != FolderSyncState::Syncing {
                std::mem::take(&mut e.synced_in_episode)
            } else {
                0
            };
            (from, to, e.error.clone(), synced)
        };
        if from == to {
            return;
        }
        if !from.can_transition_to(to) {
            // The derivation guarantees consistency; this flags a gap in the declared table.
            warn!("folder {folder_id}: undeclared transition {from} -> {to}");
        }
        debug!("folder {folder_id}: {from} -> {to}");
        let _ = self.events.send(CoreEvent::FolderStateChanged {
            folder_id: folder_id.to_string(),
            from: from.as_str().to_string(),
            to: to.as_str().to_string(),
            error: if to == FolderSyncState::Error {
                error
            } else {
                None
            },
        });
        if to == FolderSyncState::Syncing {
            let _ = self.events.send(CoreEvent::SyncStarted {
                folder_id: folder_id.to_string(),
            });
        } else if from == FolderSyncState::Syncing {
            let _ = self.events.send(CoreEvent::SyncCompleted {
                folder_id: folder_id.to_string(),
                files_synced: synced,
            });
        }
    }
}

/// RAII handle for one unit of folder work. See [`FolderStateTracker::begin`].
#[must_use = "dropping the guard immediately ends the activity"]
pub struct FolderActivity {
    tracker: FolderStateTracker,
    folder_id: String,
    kind: FolderActivityKind,
    done: bool,
}

impl FolderActivity {
    pub fn succeed(mut self) {
        self.done = true;
        self.tracker.finish(&self.folder_id, self.kind, Ok(()));
    }

    pub fn fail(mut self, error: impl Into<String>) {
        self.done = true;
        self.tracker
            .finish(&self.folder_id, self.kind, Err(error.into()));
    }

    /// Records the outcome of `result` and passes it through unchanged.
    pub fn finish_with<T, E: std::fmt::Display>(self, result: Result<T, E>) -> Result<T, E> {
        match &result {
            Ok(_) => self.succeed(),
            Err(e) => self.fail(e.to_string()),
        }
        result
    }
}

impl Drop for FolderActivity {
    fn drop(&mut self) {
        if !self.done {
            let reason = if std::thread::panicking() {
                "interrupted by a panic"
            } else {
                "interrupted before completion"
            };
            self.tracker
                .finish(&self.folder_id, self.kind, Err(reason.into()));
        }
    }
}

// =============================================================================
// Peer presence
// =============================================================================

/// Presence of a known peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerPresenceState {
    /// Heard from within [`PeerPresence::ttl`].
    Online,
    /// Previously online; no discovery announcement or message within the TTL.
    Offline,
}

impl PeerPresenceState {
    pub const ALL: [PeerPresenceState; 2] = [Self::Online, Self::Offline];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Online => "Peer was heard from (discovery announcement or protocol message) within the presence TTL",
            Self::Offline => "Peer has been silent for longer than the presence TTL; it is still contacted for sync",
        }
    }

    pub fn can_transition_to(&self, next: PeerPresenceState) -> bool {
        self != &next
    }

    pub fn metadata(&self) -> crate::state::StateMetadata {
        crate::state::StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: false,
            allowed_transitions: Self::ALL
                .iter()
                .filter(|s| self.can_transition_to(**s))
                .map(|s| s.as_str().to_string())
                .collect(),
            available_actions: vec![],
        }
    }
}

#[derive(Debug, Clone)]
struct PresenceEntry {
    last_seen: Instant,
    state: PeerPresenceState,
}

/// Change produced by [`PeerPresence::heard_from`] / [`PeerPresence::sweep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceChange {
    CameOnline,
    WentOffline,
}

/// Heartbeat-based presence registry shared by the P2P layer and the API.
#[derive(Clone)]
pub struct PeerPresence {
    entries: Arc<RwLock<HashMap<String, PresenceEntry>>>,
    ttl: Duration,
}

/// Discovery announces every 5 s; six missed announcements mean offline.
pub const DEFAULT_PRESENCE_TTL: Duration = Duration::from_secs(30);

impl Default for PeerPresence {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_PRESENCE_TTL)
    }
}

impl PeerPresence {
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Records a heartbeat. Returns `Some(CameOnline)` when the peer was unknown or offline.
    pub fn heard_from(&self, device_id: &str) -> Option<PresenceChange> {
        self.heard_from_at(device_id, Instant::now())
    }

    fn heard_from_at(&self, device_id: &str, now: Instant) -> Option<PresenceChange> {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        let entry = entries
            .entry(device_id.to_string())
            .or_insert(PresenceEntry {
                last_seen: now,
                state: PeerPresenceState::Offline,
            });
        entry.last_seen = now;
        if entry.state == PeerPresenceState::Offline {
            entry.state = PeerPresenceState::Online;
            Some(PresenceChange::CameOnline)
        } else {
            None
        }
    }

    /// Moves silent peers offline. Returns the device ids that just went offline.
    pub fn sweep(&self) -> Vec<String> {
        self.sweep_at(Instant::now())
    }

    fn sweep_at(&self, now: Instant) -> Vec<String> {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        let mut gone = Vec::new();
        for (id, e) in entries.iter_mut() {
            if e.state == PeerPresenceState::Online && now.duration_since(e.last_seen) > self.ttl {
                e.state = PeerPresenceState::Offline;
                gone.push(id.clone());
            }
        }
        gone.sort();
        gone
    }

    pub fn state(&self, device_id: &str) -> Option<PeerPresenceState> {
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        entries.get(device_id).map(|e| e.state)
    }

    pub fn is_online(&self, device_id: &str) -> bool {
        self.state(device_id) == Some(PeerPresenceState::Online)
    }

    pub fn online_count(&self) -> usize {
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        entries
            .values()
            .filter(|e| e.state == PeerPresenceState::Online)
            .count()
    }

    /// Seconds since the peer was last heard from, if ever.
    pub fn last_seen_secs(&self, device_id: &str) -> Option<u64> {
        let entries = self.entries.read().unwrap_or_else(|p| p.into_inner());
        entries
            .get(device_id)
            .map(|e| e.last_seen.elapsed().as_secs())
    }
}

// =============================================================================
// Engine lifecycle
// =============================================================================

/// Lifecycle of one engine generation (a restart starts a new generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EngineLifecycleState {
    /// Opening storage, binding the API socket.
    #[default]
    Starting,
    /// Serving requests; `runtime.json` is published.
    Ready,
    /// Graceful shutdown in progress (API request, signal, parent exit, stdin closed).
    Stopping,
    /// Shutting down this generation; a fresh one starts on the same API address.
    Restarting,
}

impl EngineLifecycleState {
    pub const ALL: [EngineLifecycleState; 4] = [
        Self::Starting,
        Self::Ready,
        Self::Stopping,
        Self::Restarting,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Stopping => "stopping",
            Self::Restarting => "restarting",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Starting => "Opening storage and binding the control-plane API",
            Self::Ready => "Serving the API; runtime.json is published",
            Self::Stopping => "Graceful shutdown in progress; the process exits with code 0",
            Self::Restarting => "Stopping this engine generation; a new one starts in-process on the same API address",
        }
    }

    pub fn can_transition_to(&self, next: EngineLifecycleState) -> bool {
        matches!(
            (self, next),
            (Self::Starting, Self::Ready)
                | (Self::Starting, Self::Stopping)
                | (Self::Ready, Self::Stopping)
                | (Self::Ready, Self::Restarting)
                // A shutdown request during a restart wins: don't come back up.
                | (Self::Restarting, Self::Stopping)
        )
    }

    pub fn available_actions(&self) -> Vec<&'static str> {
        match self {
            Self::Ready => vec!["SHUTDOWN", "RESTART"],
            Self::Starting | Self::Restarting => vec!["SHUTDOWN"],
            Self::Stopping => vec![],
        }
    }

    pub fn metadata(&self) -> crate::state::StateMetadata {
        crate::state::StateMetadata {
            state: self.as_str().to_string(),
            description: self.description().to_string(),
            is_terminal: matches!(self, Self::Stopping),
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

/// Shared handle to the engine lifecycle machine.
#[derive(Clone, Default)]
pub struct EngineLifecycle {
    state: Arc<RwLock<EngineLifecycleState>>,
}

impl EngineLifecycle {
    pub fn get(&self) -> EngineLifecycleState {
        *self.state.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Applies `next` if the transition is declared. Returns the resulting state.
    pub fn transition(
        &self,
        next: EngineLifecycleState,
    ) -> Result<EngineLifecycleState, EngineLifecycleState> {
        let mut st = self.state.write().unwrap_or_else(|p| p.into_inner());
        if *st == next {
            return Ok(next);
        }
        if st.can_transition_to(next) {
            debug!("engine lifecycle: {} -> {}", st.as_str(), next.as_str());
            *st = next;
            Ok(next)
        } else {
            Err(*st)
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    type PausedSet = Arc<RwLock<HashSet<String>>>;

    fn tracker_with(
        cap: usize,
    ) -> (
        FolderStateTracker,
        broadcast::Receiver<CoreEvent>,
        PausedSet,
    ) {
        let (tx, rx) = broadcast::channel(cap);
        let paused: PausedSet = Arc::default();
        let lookup = paused.clone();
        let t = FolderStateTracker::new(
            tx,
            Arc::new(move |id: &str| lookup.read().unwrap().contains(id)),
        );
        (t, rx, paused)
    }

    fn tracker() -> (FolderStateTracker, broadcast::Receiver<CoreEvent>) {
        let (t, rx, _) = tracker_with(256);
        (t, rx)
    }

    fn set_paused(p: &PausedSet, id: &str, on: bool) {
        if on {
            p.write().unwrap().insert(id.to_string());
        } else {
            p.write().unwrap().remove(id);
        }
    }

    fn drain(rx: &mut broadcast::Receiver<CoreEvent>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(match ev {
                CoreEvent::FolderStateChanged { from, to, .. } => format!("{from}->{to}"),
                CoreEvent::SyncStarted { .. } => "SYNC_STARTED".into(),
                CoreEvent::SyncCompleted { files_synced, .. } => {
                    format!("SYNC_COMPLETED({files_synced})")
                }
                other => format!("{other:?}"),
            });
        }
        out
    }

    #[test]
    fn early_return_never_leaves_folder_stuck() {
        let (t, _rx) = tracker();
        fn work(t: &FolderStateTracker) -> Result<(), String> {
            let _scan = t.begin("f", FolderActivityKind::Scan);
            Err::<(), String>("disk vanished".to_string())?;
            Ok(())
        }
        assert!(work(&t).is_err());
        let st = t.get("f");
        assert_eq!(st.state, FolderSyncState::Error);
        assert_eq!(st.error.as_deref(), Some("interrupted before completion"));
    }

    #[test]
    fn panic_inside_activity_releases_state() {
        let (t, _rx) = tracker();
        let t2 = t.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _sync = t2.begin("f", FolderActivityKind::Sync);
            panic!("boom");
        }));
        // A failed sync does not flag the folder; it returns to idle.
        assert_eq!(t.get("f").state, FolderSyncState::Idle);
    }

    #[test]
    fn overlapping_scans_stay_scanning_until_last_finishes() {
        let (t, _rx) = tracker();
        let a = t.begin("f", FolderActivityKind::Scan);
        let b = t.begin("f", FolderActivityKind::Scan);
        a.succeed();
        assert_eq!(t.get("f").state, FolderSyncState::Scanning);
        b.succeed();
        assert_eq!(t.get("f").state, FolderSyncState::Idle);
    }

    #[test]
    fn scan_error_is_reported_and_cleared_by_next_successful_scan() {
        let (t, mut rx) = tracker();
        t.begin("f", FolderActivityKind::Scan)
            .fail("mount marker missing");
        let st = t.get("f");
        assert_eq!(st.state, FolderSyncState::Error);
        assert_eq!(st.error.as_deref(), Some("mount marker missing"));

        t.begin("f", FolderActivityKind::Scan).succeed();
        assert_eq!(
            t.get("f"),
            FolderRuntimeState {
                state: FolderSyncState::Idle,
                error: None
            }
        );
        assert_eq!(
            drain(&mut rx),
            [
                "idle->scanning",
                "scanning->error",
                "error->scanning",
                "scanning->idle"
            ]
        );
    }

    #[test]
    fn sync_episode_emits_started_and_completed_once() {
        let (t, mut rx) = tracker();
        let a = t.begin("f", FolderActivityKind::Sync);
        let b = t.begin("f", FolderActivityKind::Sync);
        a.succeed();
        b.succeed();
        t.begin("f", FolderActivityKind::Sync).fail("bad hash");
        assert_eq!(
            drain(&mut rx),
            [
                "idle->syncing",
                "SYNC_STARTED",
                "syncing->idle",
                "SYNC_COMPLETED(2)",
                "idle->syncing",
                "SYNC_STARTED",
                "syncing->idle",
                "SYNC_COMPLETED(0)",
            ]
        );
    }

    #[test]
    fn paused_config_wins_and_refresh_emits_transition() {
        let (t, mut rx, paused) = tracker_with(256);
        t.track("f");
        let scan = t.begin("f", FolderActivityKind::Scan);
        set_paused(&paused, "f", true);
        t.refresh("f");
        assert_eq!(t.get("f").state, FolderSyncState::Paused);
        scan.succeed();
        set_paused(&paused, "f", false);
        t.refresh("f");
        assert_eq!(t.get("f").state, FolderSyncState::Idle);
        let ev = drain(&mut rx);
        assert_eq!(ev.first().map(String::as_str), Some("idle->scanning"));
        assert!(ev.contains(&"scanning->paused".to_string()), "{ev:?}");
        assert!(ev.contains(&"paused->idle".to_string()), "{ev:?}");
    }

    #[test]
    fn tracked_folder_reports_first_pause() {
        let (t, mut rx, paused) = tracker_with(16);
        t.track("f");
        set_paused(&paused, "f", true);
        t.refresh("f");
        assert_eq!(drain(&mut rx), ["idle->paused"]);
        // Tracking an already-paused folder emits nothing.
        t.track("g");
        set_paused(&paused, "g", true);
        let (t2, mut rx2, paused2) = tracker_with(16);
        set_paused(&paused2, "h", true);
        t2.track("h");
        t2.refresh("h");
        assert!(drain(&mut rx2).is_empty());
    }

    #[test]
    fn override_is_compatible_with_legacy_set_folder_state() {
        let (t, _rx) = tracker();
        t.set_override("f", FolderSyncState::Scanning);
        assert_eq!(t.get("f").state, FolderSyncState::Scanning);
        t.set_override("f", FolderSyncState::Idle);
        assert_eq!(t.get("f").state, FolderSyncState::Idle);
        t.set_override("f", FolderSyncState::Error);
        assert_eq!(t.get("f").state, FolderSyncState::Error);
        t.set_override("f", FolderSyncState::Idle);
        assert_eq!(t.get("f").state, FolderSyncState::Idle);
    }

    #[test]
    fn every_derived_transition_is_declared() {
        // Exhaustively walk short activity sequences and check the declared table.
        let ops = [
            "scan+", "scan-ok", "scan-err", "sync+", "sync-ok", "pause", "resume",
        ];
        fn run(seq: &[&str]) {
            let (t, mut rx, paused) = tracker_with(1024);
            let mut scans = Vec::new();
            let mut syncs = Vec::new();
            for op in seq {
                match *op {
                    "scan+" => scans.push(t.begin("f", FolderActivityKind::Scan)),
                    "scan-ok" => {
                        if let Some(g) = scans.pop() {
                            g.succeed()
                        }
                    }
                    "scan-err" => {
                        if let Some(g) = scans.pop() {
                            g.fail("x")
                        }
                    }
                    "sync+" => syncs.push(t.begin("f", FolderActivityKind::Sync)),
                    "sync-ok" => {
                        if let Some(g) = syncs.pop() {
                            g.succeed()
                        }
                    }
                    "pause" => {
                        set_paused(&paused, "f", true);
                        t.refresh("f")
                    }
                    "resume" => {
                        set_paused(&paused, "f", false);
                        t.refresh("f")
                    }
                    _ => unreachable!(),
                }
            }
            while let Ok(ev) = rx.try_recv() {
                if let CoreEvent::FolderStateChanged { from, to, .. } = ev {
                    let f: FolderSyncState = from.parse().unwrap();
                    let to: FolderSyncState = to.parse().unwrap();
                    assert!(f.can_transition_to(to), "undeclared {f} -> {to} in {seq:?}");
                }
            }
        }
        let mut seq = Vec::new();
        fn walk<'a>(ops: &[&'a str], seq: &mut Vec<&'a str>, depth: usize, run: &dyn Fn(&[&str])) {
            run(seq);
            if depth == 0 {
                return;
            }
            for op in ops {
                seq.push(op);
                walk(ops, seq, depth - 1, run);
                seq.pop();
            }
        }
        walk(&ops, &mut seq, 5, &run);
    }

    #[test]
    fn engine_lifecycle_transitions() {
        use EngineLifecycleState as S;
        let l = EngineLifecycle::default();
        assert_eq!(l.get(), S::Starting);
        assert_eq!(
            l.transition(S::Restarting),
            Err(S::Starting),
            "can't restart before ready"
        );
        assert_eq!(l.transition(S::Ready), Ok(S::Ready));
        assert_eq!(l.transition(S::Restarting), Ok(S::Restarting));
        assert_eq!(l.transition(S::Restarting), Ok(S::Restarting), "idempotent");
        assert_eq!(
            l.transition(S::Stopping),
            Ok(S::Stopping),
            "shutdown wins over restart"
        );
        assert_eq!(
            l.transition(S::Ready),
            Err(S::Stopping),
            "stopping is terminal"
        );
    }

    #[test]
    fn presence_goes_offline_after_ttl_and_back_online() {
        let p = PeerPresence::with_ttl(Duration::from_secs(30));
        let t0 = Instant::now();
        assert_eq!(p.heard_from_at("A", t0), Some(PresenceChange::CameOnline));
        assert_eq!(p.heard_from_at("A", t0 + Duration::from_secs(10)), None);
        assert!(p.sweep_at(t0 + Duration::from_secs(39)).is_empty());
        assert_eq!(
            p.sweep_at(t0 + Duration::from_secs(41)),
            vec!["A".to_string()]
        );
        assert_eq!(p.state("A"), Some(PeerPresenceState::Offline));
        assert_eq!(p.online_count(), 0);
        assert!(
            p.sweep_at(t0 + Duration::from_secs(90)).is_empty(),
            "no duplicate offline"
        );
        assert_eq!(
            p.heard_from_at("A", t0 + Duration::from_secs(95)),
            Some(PresenceChange::CameOnline)
        );
        assert!(p.is_online("A"));
        assert_eq!(p.state("B"), None);
    }
}
