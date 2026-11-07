//! Multi-Peer Swarm Scheduling and Rarest-First Chunk Selection.
//!
//! Coordinates Content-Addressable Storage (CAS) block replication across
//! all active cluster peers. Supports:
//! - Rarest-first chunk prioritization across multiple connected peers
//! - Load balancing and parallel pipelining across swarm peers
//! - Configurable pull ordering policies: Alphabetical, SmallestFirst, LargestFirst, NewestFirst, OldestFirst
//! - Dynamic peer disconnect handling, failure re-queuing, and request timeout detection

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::storage::FileRecord;

/// Pull ordering policy defining the priority order in which files and chunks are downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum PullOrder {
    /// Alphabetical order by relative path (A to Z).
    #[default]
    Alphabetical,
    /// Smallest files first (by size ascending).
    SmallestFirst,
    /// Largest files first (by size descending).
    LargestFirst,
    /// Newest modified files first (by mtime descending).
    NewestFirst,
    /// Oldest modified files first (by mtime ascending).
    OldestFirst,
}

impl fmt::Display for PullOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PullOrder::Alphabetical => write!(f, "alphabetical"),
            PullOrder::SmallestFirst => write!(f, "smallestFirst"),
            PullOrder::LargestFirst => write!(f, "largestFirst"),
            PullOrder::NewestFirst => write!(f, "newestFirst"),
            PullOrder::OldestFirst => write!(f, "oldestFirst"),
        }
    }
}

impl FromStr for PullOrder {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "alphabetical" | "alphabetic" => Ok(PullOrder::Alphabetical),
            "smallestfirst" | "smallest" => Ok(PullOrder::SmallestFirst),
            "largestfirst" | "largest" => Ok(PullOrder::LargestFirst),
            "newestfirst" | "newest" => Ok(PullOrder::NewestFirst),
            "oldestfirst" | "oldest" => Ok(PullOrder::OldestFirst),
            other => Err(format!("Unknown pull order: '{}'", other)),
        }
    }
}

impl PullOrder {
    /// Sorts a mutable slice of [`FileRecord`]s according to the current pull order.
    pub fn sort_file_records(&self, files: &mut [FileRecord]) {
        match self {
            PullOrder::Alphabetical => {
                files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
            }
            PullOrder::SmallestFirst => {
                files.sort_by(|a, b| {
                    a.size
                        .cmp(&b.size)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::LargestFirst => {
                files.sort_by(|a, b| {
                    b.size
                        .cmp(&a.size)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::NewestFirst => {
                files.sort_by(|a, b| {
                    b.mtime_nanos
                        .cmp(&a.mtime_nanos)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::OldestFirst => {
                files.sort_by(|a, b| {
                    a.mtime_nanos
                        .cmp(&b.mtime_nanos)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
        }
    }

    /// Sorts a mutable slice of [`FilePullItem`]s according to the current pull order.
    pub fn sort_pull_items(&self, items: &mut [FilePullItem]) {
        match self {
            PullOrder::Alphabetical => {
                items.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
            }
            PullOrder::SmallestFirst => {
                items.sort_by(|a, b| {
                    a.size
                        .cmp(&b.size)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::LargestFirst => {
                items.sort_by(|a, b| {
                    b.size
                        .cmp(&a.size)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::NewestFirst => {
                items.sort_by(|a, b| {
                    b.mtime_nanos
                        .cmp(&a.mtime_nanos)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
            PullOrder::OldestFirst => {
                items.sort_by(|a, b| {
                    a.mtime_nanos
                        .cmp(&b.mtime_nanos)
                        .then_with(|| a.relative_path.cmp(&b.relative_path))
                });
            }
        }
    }
}

/// Scheduling strategy defining the balance between global swarm rarity and file-by-file priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchedulingStrategy {
    /// Rarest chunks across all files are prioritized globally. Pull order breaks ties.
    #[default]
    RarestFirstSwarm,
    /// Highest-priority files (by pull order) are completed first, with rarest chunks inside prioritized.
    FilePriorityRarest,
}

/// Item representing a file queued for synchronization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilePullItem {
    pub folder_id: String,
    pub relative_path: String,
    pub size: u64,
    pub mtime_nanos: i64,
    pub chunk_hashes: Vec<String>,
}

/// An assigned chunk download instruction dispatched to a specific peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAssignment {
    /// ID of the target peer from whom to request the chunk.
    pub peer_id: String,
    /// Content hash (BLAKE3) of the block to fetch.
    pub chunk_hash: String,
    /// Associated folder identifier if known.
    pub folder_id: Option<String>,
    /// Associated relative path if known.
    pub relative_path: Option<String>,
}

/// Internal state tracking a peer in the swarm.
#[derive(Debug, Clone)]
struct PeerState {
    peer_id: String,
    available_chunks: HashSet<String>,
    in_flight_chunks: HashSet<String>,
    is_connected: bool,
    failed_attempts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ChunkCandidateScore {
    primary: usize,
    secondary: usize,
    chunk_index_in_file: usize,
    tie_breaker: String,
}

/// Coordinates multi-peer parallel swarming and rarest-first chunk selection.
pub struct SwarmScheduler {
    pull_order: PullOrder,
    strategy: SchedulingStrategy,
    peers: HashMap<String, PeerState>,
    files: Vec<FilePullItem>,
    // Mapping from chunk_hash to a list of (file_index, chunk_index_in_file)
    chunk_to_files: HashMap<String, Vec<(usize, usize)>>,
    pending_chunks: HashSet<String>,
    in_flight: HashMap<String, (String, tokio::time::Instant)>,
    completed_chunks: HashSet<String>,
    max_in_flight_per_peer: usize,
    max_total_in_flight: usize,
}

impl SwarmScheduler {
    /// Creates a new `SwarmScheduler` with the specified pull ordering policy.
    pub fn new(pull_order: PullOrder) -> Self {
        Self::with_strategy(pull_order, SchedulingStrategy::default())
    }

    /// Creates a new `SwarmScheduler` with a pull order and explicit scheduling strategy.
    pub fn with_strategy(pull_order: PullOrder, strategy: SchedulingStrategy) -> Self {
        Self {
            pull_order,
            strategy,
            peers: HashMap::new(),
            files: Vec::new(),
            chunk_to_files: HashMap::new(),
            pending_chunks: HashSet::new(),
            in_flight: HashMap::new(),
            completed_chunks: HashSet::new(),
            max_in_flight_per_peer: 8,
            max_total_in_flight: 64,
        }
    }

    /// Returns the active pull ordering policy.
    pub fn pull_order(&self) -> PullOrder {
        self.pull_order
    }

    /// Updates the pull ordering policy, immediately re-sorting pending files.
    pub fn set_pull_order(&mut self, order: PullOrder) {
        self.pull_order = order;
        self.pull_order.sort_pull_items(&mut self.files);
        self.rebuild_chunk_file_index();
    }

    /// Returns the scheduling strategy.
    pub fn strategy(&self) -> SchedulingStrategy {
        self.strategy
    }

    /// Updates the scheduling strategy.
    pub fn set_strategy(&mut self, strategy: SchedulingStrategy) {
        self.strategy = strategy;
    }

    /// Returns the maximum concurrent in-flight chunk requests permitted per peer.
    pub fn max_in_flight_per_peer(&self) -> usize {
        self.max_in_flight_per_peer
    }

    /// Sets the maximum concurrent in-flight chunk requests per peer.
    pub fn set_max_in_flight_per_peer(&mut self, max: usize) {
        self.max_in_flight_per_peer = max.max(1);
    }

    /// Returns the global maximum concurrent in-flight chunk requests across all peers.
    pub fn max_total_in_flight(&self) -> usize {
        self.max_total_in_flight
    }

    /// Sets the global maximum concurrent in-flight requests.
    pub fn set_max_total_in_flight(&mut self, max: usize) {
        self.max_total_in_flight = max.max(1);
    }

    /// Registers a peer with its initially known set of available chunks.
    pub fn register_peer(
        &mut self,
        peer_id: impl Into<String>,
        available_chunks: impl IntoIterator<Item = impl Into<String>>,
    ) {
        let id = peer_id.into();
        let chunks: HashSet<String> = available_chunks.into_iter().map(Into::into).collect();
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.available_chunks.extend(chunks);
            peer.is_connected = true;
        } else {
            self.peers.insert(
                id.clone(),
                PeerState {
                    peer_id: id,
                    available_chunks: chunks,
                    in_flight_chunks: HashSet::new(),
                    is_connected: true,
                    failed_attempts: 0,
                },
            );
        }
    }

    /// Updates the available chunks for an existing peer.
    pub fn update_peer_chunks(
        &mut self,
        peer_id: &str,
        chunks: impl IntoIterator<Item = impl Into<String>>,
    ) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.available_chunks
                .extend(chunks.into_iter().map(Into::into));
        }
    }

    /// Adds a single available chunk to a peer's inventory.
    pub fn add_peer_chunk(&mut self, peer_id: &str, chunk_hash: impl Into<String>) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.available_chunks.insert(chunk_hash.into());
        }
    }

    /// Unregisters a peer and re-queues all in-flight requests assigned to it.
    pub fn unregister_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.remove(peer_id) {
            for chunk in peer.in_flight_chunks {
                self.in_flight.remove(&chunk);
                if !self.completed_chunks.contains(&chunk) {
                    self.pending_chunks.insert(chunk);
                }
            }
        }
    }

    /// Marks a peer as disconnected, immediately cancelling and re-queuing any active chunk downloads.
    pub fn mark_peer_disconnected(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.is_connected = false;
            let requeue: Vec<String> = peer.in_flight_chunks.drain().collect();
            for chunk in requeue {
                self.in_flight.remove(&chunk);
                if !self.completed_chunks.contains(&chunk) {
                    self.pending_chunks.insert(chunk);
                }
            }
        }
    }

    /// Marks a peer as reconnected.
    pub fn mark_peer_connected(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.is_connected = true;
        }
    }

    /// Lists all currently connected peer IDs.
    pub fn connected_peers(&self) -> Vec<String> {
        self.peers
            .values()
            .filter(|p| p.is_connected)
            .map(|p| p.peer_id.clone())
            .collect()
    }

    /// Queues a file and its required chunks into the download schedule.
    pub fn queue_file(
        &mut self,
        folder_id: impl Into<String>,
        relative_path: impl Into<String>,
        size: u64,
        mtime_nanos: i64,
        chunk_hashes: Vec<String>,
    ) {
        let item = FilePullItem {
            folder_id: folder_id.into(),
            relative_path: relative_path.into(),
            size,
            mtime_nanos,
            chunk_hashes,
        };

        for chunk in &item.chunk_hashes {
            if !self.completed_chunks.contains(chunk) && !self.in_flight.contains_key(chunk) {
                self.pending_chunks.insert(chunk.clone());
            }
        }

        self.files.push(item);
        self.pull_order.sort_pull_items(&mut self.files);
        self.rebuild_chunk_file_index();
    }

    /// Queues a file from a database [`FileRecord`].
    pub fn queue_file_record(&mut self, record: &FileRecord, chunk_hashes: Vec<String>) {
        self.queue_file(
            &record.folder_id,
            &record.relative_path,
            record.size,
            record.mtime_nanos,
            chunk_hashes,
        );
    }

    /// Queues a single chunk directly for replication.
    pub fn queue_chunk(&mut self, chunk_hash: impl Into<String>) {
        let hash = chunk_hash.into();
        if !self.completed_chunks.contains(&hash) && !self.in_flight.contains_key(&hash) {
            self.pending_chunks.insert(hash);
        }
    }

    /// Queues multiple chunks for replication.
    pub fn queue_chunks(&mut self, chunk_hashes: impl IntoIterator<Item = impl Into<String>>) {
        for chunk in chunk_hashes {
            self.queue_chunk(chunk);
        }
    }

    /// Schedules the next chunk request using rarest-first and peer load balancing.
    ///
    /// Returns `Some(ChunkAssignment)` if a candidate chunk and eligible peer are found,
    /// or `None` if no chunks can be scheduled currently.
    pub fn schedule_next(&mut self) -> Option<ChunkAssignment> {
        if self.in_flight.len() >= self.max_total_in_flight {
            return None;
        }

        let mut best_candidate: Option<(ChunkCandidateScore, String, String)> = None;

        for chunk in &self.pending_chunks {
            // Count total connected peers holding this chunk (its rarity in the active swarm)
            let total_holding_peers = self
                .peers
                .values()
                .filter(|p| p.is_connected && p.available_chunks.contains(chunk))
                .count();

            if total_holding_peers == 0 {
                // Chunk is currently unavailable from any connected peer
                continue;
            }

            // Find peers that possess the chunk and still have spare in-flight capacity
            let mut eligible_peers: Vec<&PeerState> = self
                .peers
                .values()
                .filter(|p| {
                    p.is_connected
                        && p.available_chunks.contains(chunk)
                        && p.in_flight_chunks.len() < self.max_in_flight_per_peer
                })
                .collect();

            if eligible_peers.is_empty() {
                // All peers having this chunk are saturated with maximum in-flight requests
                continue;
            }

            // Load balancing: pick peer with lowest in-flight count, fewest failures, then ID
            eligible_peers.sort_by(|a, b| {
                a.in_flight_chunks
                    .len()
                    .cmp(&b.in_flight_chunks.len())
                    .then_with(|| a.failed_attempts.cmp(&b.failed_attempts))
                    .then_with(|| a.peer_id.cmp(&b.peer_id))
            });
            let selected_peer_id = eligible_peers[0].peer_id.clone();

            // Find file priority from pull order
            let (min_file_idx, chunk_idx_in_file) = self
                .chunk_to_files
                .get(chunk)
                .and_then(|list| list.iter().min_by_key(|(f_idx, c_idx)| (*f_idx, *c_idx)).copied())
                .unwrap_or((usize::MAX, usize::MAX));

            let score = match self.strategy {
                SchedulingStrategy::RarestFirstSwarm => ChunkCandidateScore {
                    primary: total_holding_peers,
                    secondary: min_file_idx,
                    chunk_index_in_file: chunk_idx_in_file,
                    tie_breaker: chunk.clone(),
                },
                SchedulingStrategy::FilePriorityRarest => ChunkCandidateScore {
                    primary: min_file_idx,
                    secondary: total_holding_peers,
                    chunk_index_in_file: chunk_idx_in_file,
                    tie_breaker: chunk.clone(),
                },
            };

            let candidate = (score, chunk.clone(), selected_peer_id);
            if let Some((best_score, _, _)) = &best_candidate {
                if candidate.0 < *best_score {
                    best_candidate = Some(candidate);
                }
            } else {
                best_candidate = Some(candidate);
            }
        }

        if let Some((_score, chunk_hash, peer_id)) = best_candidate {
            self.pending_chunks.remove(&chunk_hash);
            self.in_flight
                .insert(chunk_hash.clone(), (peer_id.clone(), tokio::time::Instant::now()));

            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.in_flight_chunks.insert(chunk_hash.clone());
            }

            let (folder_id, relative_path) = if let Some(indices) = self.chunk_to_files.get(&chunk_hash) {
                if let Some(&(idx, _)) = indices.first() {
                    if let Some(file) = self.files.get(idx) {
                        (Some(file.folder_id.clone()), Some(file.relative_path.clone()))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            debug!(
                "SwarmScheduler assigned chunk {} to peer {} (in-flight: {})",
                chunk_hash, peer_id, self.in_flight.len()
            );

            Some(ChunkAssignment {
                peer_id,
                chunk_hash,
                folder_id,
                relative_path,
            })
        } else {
            None
        }
    }

    /// Schedules a batch of up to `max_batch` chunk assignments.
    pub fn schedule_batch(&mut self, max_batch: usize) -> Vec<ChunkAssignment> {
        let mut assignments = Vec::with_capacity(max_batch);
        for _ in 0..max_batch {
            if let Some(assignment) = self.schedule_next() {
                assignments.push(assignment);
            } else {
                break;
            }
        }
        assignments
    }

    /// Marks a chunk as successfully received and verified.
    pub fn mark_completed(&mut self, chunk_hash: &str) {
        if let Some((peer_id, _)) = self.in_flight.remove(chunk_hash) {
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.in_flight_chunks.remove(chunk_hash);
            }
        }
        self.pending_chunks.remove(chunk_hash);
        self.completed_chunks.insert(chunk_hash.to_string());
    }

    /// Marks a chunk request as failed for a specific peer, re-queuing the chunk.
    pub fn mark_failed(&mut self, peer_id: &str, chunk_hash: &str) {
        if let Some((assigned_peer, _)) = self.in_flight.remove(chunk_hash) {
            if let Some(peer) = self.peers.get_mut(&assigned_peer) {
                peer.in_flight_chunks.remove(chunk_hash);
            }
        }
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.failed_attempts += 1;
        }
        if !self.completed_chunks.contains(chunk_hash) {
            self.pending_chunks.insert(chunk_hash.to_string());
        }
        warn!(
            "Chunk request {} failed on peer {}, re-queued to pending",
            chunk_hash, peer_id
        );
    }

    /// Scans active in-flight requests and times out any that have exceeded `timeout`.
    ///
    /// Timed-out chunks are re-queued to `pending_chunks` so other peers can attempt them.
    /// Returns the list of timed-out chunk hashes.
    pub fn check_timeouts(&mut self, timeout: Duration) -> Vec<String> {
        let now = tokio::time::Instant::now();
        let mut timed_out = Vec::new();

        for (chunk, (peer_id, start_time)) in &self.in_flight {
            if now.duration_since(*start_time) >= timeout {
                timed_out.push((chunk.clone(), peer_id.clone()));
            }
        }

        let mut result = Vec::new();
        for (chunk, peer_id) in timed_out {
            self.in_flight.remove(&chunk);
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.in_flight_chunks.remove(&chunk);
                peer.failed_attempts += 1;
            }
            if !self.completed_chunks.contains(&chunk) {
                self.pending_chunks.insert(chunk.clone());
            }
            warn!("Chunk request {} on peer {} timed out and re-queued", chunk, peer_id);
            result.push(chunk);
        }
        result
    }

    /// Returns the number of pending chunks waiting to be scheduled.
    pub fn pending_count(&self) -> usize {
        self.pending_chunks.len()
    }

    /// Returns the number of chunks currently in-flight across all peers.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Returns the number of completed chunks.
    pub fn completed_count(&self) -> usize {
        self.completed_chunks.len()
    }

    /// Returns `true` if all queued chunks have been downloaded and none are in-flight.
    pub fn is_finished(&self) -> bool {
        self.pending_chunks.is_empty() && self.in_flight.is_empty()
    }

    /// Returns the swarm availability (number of connected peers possessing the chunk) for a given chunk.
    pub fn rarity_of(&self, chunk_hash: &str) -> usize {
        self.peers
            .values()
            .filter(|p| p.is_connected && p.available_chunks.contains(chunk_hash))
            .count()
    }

    /// Returns the number of currently active in-flight requests on a specific peer.
    pub fn peer_in_flight(&self, peer_id: &str) -> usize {
        self.peers
            .get(peer_id)
            .map(|p| p.in_flight_chunks.len())
            .unwrap_or(0)
    }

    /// Returns `(completed_chunks, total_chunks)` for a specific queued file.
    pub fn file_progress(&self, folder_id: &str, relative_path: &str) -> Option<(usize, usize)> {
        let file = self
            .files
            .iter()
            .find(|f| f.folder_id == folder_id && f.relative_path == relative_path)?;
        let total = file.chunk_hashes.len();
        let completed = file
            .chunk_hashes
            .iter()
            .filter(|c| self.completed_chunks.contains(*c))
            .count();
        Some((completed, total))
    }

    /// Clears all files, pending chunks, and in-flight states while preserving peer inventory.
    pub fn reset(&mut self) {
        self.files.clear();
        self.chunk_to_files.clear();
        self.pending_chunks.clear();
        self.in_flight.clear();
        self.completed_chunks.clear();
        for peer in self.peers.values_mut() {
            peer.in_flight_chunks.clear();
        }
    }

    fn rebuild_chunk_file_index(&mut self) {
        self.chunk_to_files.clear();
        for (file_idx, file) in self.files.iter().enumerate() {
            for (chunk_idx, chunk) in file.chunk_hashes.iter().enumerate() {
                self.chunk_to_files
                    .entry(chunk.clone())
                    .or_default()
                    .push((file_idx, chunk_idx));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pull_order_string_parsing() {
        assert_eq!("alphabetical".parse::<PullOrder>().unwrap(), PullOrder::Alphabetical);
        assert_eq!("smallestFirst".parse::<PullOrder>().unwrap(), PullOrder::SmallestFirst);
        assert_eq!("largestfirst".parse::<PullOrder>().unwrap(), PullOrder::LargestFirst);
        assert_eq!("newestFirst".parse::<PullOrder>().unwrap(), PullOrder::NewestFirst);
        assert_eq!("oldest".parse::<PullOrder>().unwrap(), PullOrder::OldestFirst);
        assert!("invalid".parse::<PullOrder>().is_err());

        assert_eq!(PullOrder::Alphabetical.to_string(), "alphabetical");
        assert_eq!(PullOrder::SmallestFirst.to_string(), "smallestFirst");
    }

    #[test]
    fn test_pull_ordering_policies() {
        let files = vec![
            FilePullItem {
                folder_id: "default".into(),
                relative_path: "zoo.txt".into(),
                size: 500,
                mtime_nanos: 1_000,
                chunk_hashes: vec!["c_zoo".into()],
            },
            FilePullItem {
                folder_id: "default".into(),
                relative_path: "alpha.txt".into(),
                size: 100,
                mtime_nanos: 3_000,
                chunk_hashes: vec!["c_alpha".into()],
            },
            FilePullItem {
                folder_id: "default".into(),
                relative_path: "middle.txt".into(),
                size: 1_000,
                mtime_nanos: 2_000,
                chunk_hashes: vec!["c_middle".into()],
            },
        ];

        // 1. Alphabetical: alpha -> middle -> zoo
        let mut sorted = files.clone();
        PullOrder::Alphabetical.sort_pull_items(&mut sorted);
        assert_eq!(sorted[0].relative_path, "alpha.txt");
        assert_eq!(sorted[1].relative_path, "middle.txt");
        assert_eq!(sorted[2].relative_path, "zoo.txt");

        // 2. SmallestFirst: alpha (100) -> zoo (500) -> middle (1000)
        let mut sorted = files.clone();
        PullOrder::SmallestFirst.sort_pull_items(&mut sorted);
        assert_eq!(sorted[0].relative_path, "alpha.txt");
        assert_eq!(sorted[1].relative_path, "zoo.txt");
        assert_eq!(sorted[2].relative_path, "middle.txt");

        // 3. LargestFirst: middle (1000) -> zoo (500) -> alpha (100)
        let mut sorted = files.clone();
        PullOrder::LargestFirst.sort_pull_items(&mut sorted);
        assert_eq!(sorted[0].relative_path, "middle.txt");
        assert_eq!(sorted[1].relative_path, "zoo.txt");
        assert_eq!(sorted[2].relative_path, "alpha.txt");

        // 4. NewestFirst: alpha (3000) -> middle (2000) -> zoo (1000)
        let mut sorted = files.clone();
        PullOrder::NewestFirst.sort_pull_items(&mut sorted);
        assert_eq!(sorted[0].relative_path, "alpha.txt");
        assert_eq!(sorted[1].relative_path, "middle.txt");
        assert_eq!(sorted[2].relative_path, "zoo.txt");

        // 5. OldestFirst: zoo (1000) -> middle (2000) -> alpha (3000)
        let mut sorted = files.clone();
        PullOrder::OldestFirst.sort_pull_items(&mut sorted);
        assert_eq!(sorted[0].relative_path, "zoo.txt");
        assert_eq!(sorted[1].relative_path, "middle.txt");
        assert_eq!(sorted[2].relative_path, "alpha.txt");
    }

    #[test]
    fn test_rarest_first_selection() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);

        // Peer 1 has c1, c2, c3
        // Peer 2 has c2, c3
        // Peer 3 has c3
        //
        // Availability:
        // c1: 1 peer (rarest)
        // c2: 2 peers
        // c3: 3 peers (common)
        scheduler.register_peer("peer_1", vec!["c1", "c2", "c3"]);
        scheduler.register_peer("peer_2", vec!["c2", "c3"]);
        scheduler.register_peer("peer_3", vec!["c3"]);

        scheduler.queue_chunk("c3");
        scheduler.queue_chunk("c2");
        scheduler.queue_chunk("c1");

        assert_eq!(scheduler.rarity_of("c1"), 1);
        assert_eq!(scheduler.rarity_of("c2"), 2);
        assert_eq!(scheduler.rarity_of("c3"), 3);

        // First schedule must pick c1 (rarest, only on peer_1)
        let a1 = scheduler.schedule_next().expect("assignment 1");
        assert_eq!(a1.chunk_hash, "c1");
        assert_eq!(a1.peer_id, "peer_1");

        // Second schedule must pick c2 (rarity 2)
        // peer_1 has 1 in-flight, peer_2 has 0 in-flight -> assigns to peer_2!
        let a2 = scheduler.schedule_next().expect("assignment 2");
        assert_eq!(a2.chunk_hash, "c2");
        assert_eq!(a2.peer_id, "peer_2");

        // Third schedule must pick c3 (rarity 3)
        // peer_3 has 0 in-flight -> assigns to peer_3!
        let a3 = scheduler.schedule_next().expect("assignment 3");
        assert_eq!(a3.chunk_hash, "c3");
        assert_eq!(a3.peer_id, "peer_3");

        // All peers are now actively working in parallel
        assert_eq!(scheduler.peer_in_flight("peer_1"), 1);
        assert_eq!(scheduler.peer_in_flight("peer_2"), 1);
        assert_eq!(scheduler.peer_in_flight("peer_3"), 1);
        assert_eq!(scheduler.in_flight_count(), 3);
        assert_eq!(scheduler.pending_count(), 0);
    }

    #[test]
    fn test_multi_peer_parallel_distribution() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.set_max_in_flight_per_peer(2);

        // 3 peers, all having all chunks
        let chunks = vec!["b1", "b2", "b3", "b4", "b5", "b6"];
        scheduler.register_peer("node_a", chunks.clone());
        scheduler.register_peer("node_b", chunks.clone());
        scheduler.register_peer("node_c", chunks.clone());

        scheduler.queue_chunks(chunks);

        let assignments = scheduler.schedule_batch(6);
        assert_eq!(assignments.len(), 6);

        // Load must be distributed evenly across all 3 nodes (2 requests each)
        assert_eq!(scheduler.peer_in_flight("node_a"), 2);
        assert_eq!(scheduler.peer_in_flight("node_b"), 2);
        assert_eq!(scheduler.peer_in_flight("node_c"), 2);

        // Any further request cannot be scheduled until a slot frees up
        assert!(scheduler.schedule_next().is_none());

        // Complete b1 on node_a
        scheduler.mark_completed("b1");
        assert_eq!(scheduler.peer_in_flight("node_a"), 1);
    }

    #[test]
    fn test_peer_disconnect_and_requeue() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("node_1", vec!["chunk_x"]);
        scheduler.register_peer("node_2", vec!["chunk_x"]);

        scheduler.queue_chunk("chunk_x");

        let a1 = scheduler.schedule_next().expect("assigned");
        assert_eq!(a1.chunk_hash, "chunk_x");
        let assigned_peer = a1.peer_id.clone();
        assert_eq!(scheduler.in_flight_count(), 1);
        assert_eq!(scheduler.pending_count(), 0);

        // Peer disconnects
        scheduler.mark_peer_disconnected(&assigned_peer);

        // Chunk must be re-queued to pending
        assert_eq!(scheduler.in_flight_count(), 0);
        assert_eq!(scheduler.pending_count(), 1);

        // Next schedule must assign to the remaining connected peer
        let other_peer = if assigned_peer == "node_1" { "node_2" } else { "node_1" };
        let a2 = scheduler.schedule_next().expect("re-assigned");
        assert_eq!(a2.chunk_hash, "chunk_x");
        assert_eq!(a2.peer_id, other_peer);
    }

    #[test]
    fn test_chunk_failure_and_retry() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("node_1", vec!["chunk_f"]);
        scheduler.register_peer("node_2", vec!["chunk_f"]);

        scheduler.queue_chunk("chunk_f");
        let a = scheduler.schedule_next().unwrap();

        // Mark failed
        scheduler.mark_failed(&a.peer_id, &a.chunk_hash);
        assert_eq!(scheduler.in_flight_count(), 0);
        assert_eq!(scheduler.pending_count(), 1);

        // Second attempt schedules to the other peer due to load balancing / failure penalization
        let a2 = scheduler.schedule_next().unwrap();
        assert_eq!(a2.chunk_hash, "chunk_f");
        assert_ne!(a2.peer_id, a.peer_id);
    }

    #[tokio::test]
    async fn test_request_timeout() {
        tokio::time::pause();

        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("node_1", vec!["slow_chunk"]);
        scheduler.queue_chunk("slow_chunk");

        let a = scheduler.schedule_next().unwrap();
        assert_eq!(a.chunk_hash, "slow_chunk");

        // Advance time past 10s timeout
        tokio::time::advance(Duration::from_secs(15)).await;

        let timed_out = scheduler.check_timeouts(Duration::from_secs(10));
        assert_eq!(timed_out, vec!["slow_chunk"]);

        assert_eq!(scheduler.in_flight_count(), 0);
        assert_eq!(scheduler.pending_count(), 1);
    }

    #[test]
    fn test_file_priority_strategy() {
        let mut scheduler = SwarmScheduler::with_strategy(
            PullOrder::SmallestFirst,
            SchedulingStrategy::FilePriorityRarest,
        );

        scheduler.register_peer("peer_a", vec!["large_rare", "small_common"]);
        scheduler.register_peer("peer_b", vec!["small_common"]);

        // File 1: large (size 10,000), chunk large_rare (rarity 1)
        scheduler.queue_file("f1", "large.iso", 10_000, 100, vec!["large_rare".into()]);

        // File 2: small (size 500), chunk small_common (rarity 2)
        scheduler.queue_file("f1", "small.txt", 500, 100, vec!["small_common".into()]);

        // Under FilePriorityRarest + SmallestFirst:
        // small.txt is evaluated first, so small_common is requested BEFORE large_rare
        // even though large_rare has lower swarm rarity!
        let a1 = scheduler.schedule_next().unwrap();
        assert_eq!(a1.chunk_hash, "small_common");

        let a2 = scheduler.schedule_next().unwrap();
        assert_eq!(a2.chunk_hash, "large_rare");
    }

    #[test]
    fn test_file_progress_tracking() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("peer_1", vec!["c1", "c2", "c3"]);
        scheduler.queue_file("f", "doc.pdf", 300, 1, vec!["c1".into(), "c2".into(), "c3".into()]);

        assert_eq!(scheduler.file_progress("f", "doc.pdf"), Some((0, 3)));

        let _ = scheduler.schedule_next();
        scheduler.mark_completed("c1");
        assert_eq!(scheduler.file_progress("f", "doc.pdf"), Some((1, 3)));

        scheduler.mark_completed("c2");
        scheduler.mark_completed("c3");
        assert_eq!(scheduler.file_progress("f", "doc.pdf"), Some((3, 3)));
        assert!(scheduler.is_finished());
    }

    #[test]
    fn test_rarest_first_complex_mesh_parallel_distribution() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.set_max_in_flight_per_peer(2);

        // 5 peers:
        // node_1: c_rare1, c_rare2, c_med1, c_med2, c_com
        // node_2: c_med1, c_med2, c_med3, c_com
        // node_3: c_med3, c_com
        // node_4: c_med3, c_com
        // node_5: c_com
        //
        // Rarities:
        // c_rare1, c_rare2: 1 peer (node_1)
        // c_med1, c_med2: 2 peers (node_1, node_2)
        // c_med3: 3 peers (node_2, node_3, node_4)
        // c_com: 5 peers (all)
        scheduler.register_peer("node_1", vec!["c_rare1", "c_rare2", "c_med1", "c_med2", "c_com"]);
        scheduler.register_peer("node_2", vec!["c_med1", "c_med2", "c_med3", "c_com"]);
        scheduler.register_peer("node_3", vec!["c_med3", "c_com"]);
        scheduler.register_peer("node_4", vec!["c_med3", "c_com"]);
        scheduler.register_peer("node_5", vec!["c_com"]);

        assert_eq!(scheduler.rarity_of("c_rare1"), 1);
        assert_eq!(scheduler.rarity_of("c_rare2"), 1);
        assert_eq!(scheduler.rarity_of("c_med1"), 2);
        assert_eq!(scheduler.rarity_of("c_med2"), 2);
        assert_eq!(scheduler.rarity_of("c_med3"), 3);
        assert_eq!(scheduler.rarity_of("c_com"), 5);

        scheduler.queue_chunks(vec!["c_com", "c_med3", "c_med2", "c_med1", "c_rare2", "c_rare1"]);

        // First two scheduled must be rarity 1 (c_rare1 and c_rare2), assigned to node_1
        let a1 = scheduler.schedule_next().unwrap();
        let a2 = scheduler.schedule_next().unwrap();
        assert!(a1.chunk_hash == "c_rare1" || a1.chunk_hash == "c_rare2");
        assert!(a2.chunk_hash == "c_rare1" || a2.chunk_hash == "c_rare2");
        assert_ne!(a1.chunk_hash, a2.chunk_hash);
        assert_eq!(a1.peer_id, "node_1");
        assert_eq!(a2.peer_id, "node_1");

        // node_1 is now full (in-flight = 2).
        assert_eq!(scheduler.peer_in_flight("node_1"), 2);

        // Next two chunks must be rarity 2 (c_med1 and c_med2).
        // Since node_1 is saturated, they must be assigned to node_2!
        let a3 = scheduler.schedule_next().unwrap();
        let a4 = scheduler.schedule_next().unwrap();
        assert!(a3.chunk_hash == "c_med1" || a3.chunk_hash == "c_med2");
        assert!(a4.chunk_hash == "c_med1" || a4.chunk_hash == "c_med2");
        assert_ne!(a3.chunk_hash, a4.chunk_hash);
        assert_eq!(a3.peer_id, "node_2");
        assert_eq!(a4.peer_id, "node_2");

        // node_2 is now full (in-flight = 2).
        assert_eq!(scheduler.peer_in_flight("node_2"), 2);

        // Next chunk is rarity 3 (c_med3).
        // Held by node_2, node_3, node_4. Since node_2 is saturated, must go to node_3 or node_4.
        let a5 = scheduler.schedule_next().unwrap();
        assert_eq!(a5.chunk_hash, "c_med3");
        assert!(a5.peer_id == "node_3" || a5.peer_id == "node_4");

        // Last chunk is rarity 5 (c_com).
        // Goes to one of the remaining eligible peers with lowest load.
        let a6 = scheduler.schedule_next().unwrap();
        assert_eq!(a6.chunk_hash, "c_com");

        // All 6 chunks are in flight, 0 pending
        assert_eq!(scheduler.in_flight_count(), 6);
        assert_eq!(scheduler.pending_count(), 0);
    }

    #[test]
    fn test_dynamic_peer_inventory_update_modifies_rarity() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("peer_1", vec!["chunk_a", "chunk_b"]);
        scheduler.register_peer("peer_2", vec!["chunk_a"]);

        scheduler.queue_chunk("chunk_a");
        scheduler.queue_chunk("chunk_b");

        // chunk_b: rarity 1, chunk_a: rarity 2
        assert_eq!(scheduler.rarity_of("chunk_b"), 1);
        assert_eq!(scheduler.rarity_of("chunk_a"), 2);

        // peer_3 connects and announces chunk_b
        scheduler.register_peer("peer_3", vec!["chunk_b"]);
        assert_eq!(scheduler.rarity_of("chunk_b"), 2);

        // peer_2 downloads/discovers chunk_b dynamically
        scheduler.add_peer_chunk("peer_2", "chunk_b");
        assert_eq!(scheduler.rarity_of("chunk_b"), 3);

        // Now chunk_a is rarer than chunk_b (2 vs 3)!
        let a1 = scheduler.schedule_next().unwrap();
        assert_eq!(a1.chunk_hash, "chunk_a");

        let a2 = scheduler.schedule_next().unwrap();
        assert_eq!(a2.chunk_hash, "chunk_b");
    }

    #[test]
    fn test_max_total_in_flight_concurrency_ceiling() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.set_max_total_in_flight(3);
        scheduler.set_max_in_flight_per_peer(4);

        let chunks = vec!["c1", "c2", "c3", "c4", "c5", "c6"];
        scheduler.register_peer("peer_1", chunks.clone());
        scheduler.queue_chunks(chunks);

        // Request batch of 6, but max_total_in_flight = 3
        let batch = scheduler.schedule_batch(6);
        assert_eq!(batch.len(), 3);
        assert_eq!(scheduler.in_flight_count(), 3);
        assert_eq!(scheduler.pending_count(), 3);

        // No more can be scheduled right now
        assert!(scheduler.schedule_next().is_none());

        // Complete 1 chunk
        scheduler.mark_completed(&batch[0].chunk_hash);
        assert_eq!(scheduler.in_flight_count(), 2);

        // Now exactly 1 can be scheduled
        let _next_a = scheduler.schedule_next().unwrap();
        assert_eq!(scheduler.in_flight_count(), 3);
        assert_eq!(scheduler.pending_count(), 2);
    }

    #[test]
    fn test_all_five_pull_ordering_policies_in_scheduler() {
        let make_scheduler = |order: PullOrder| {
            let mut s = SwarmScheduler::with_strategy(order, SchedulingStrategy::FilePriorityRarest);
            s.register_peer("seed", vec!["c_a", "c_b", "c_c", "c_d", "c_e"]);

            // File items:
            // a: size 50_000, mtime 100 -> c_a
            // b: size 10_000, mtime 500 -> c_b
            // c: size 30_000, mtime 300 -> c_c
            // d: size 20_000, mtime 200 -> c_d
            // e: size 40_000, mtime 400 -> c_e
            s.queue_file("f", "a.bin", 50_000, 100, vec!["c_a".into()]);
            s.queue_file("f", "b.bin", 10_000, 500, vec!["c_b".into()]);
            s.queue_file("f", "c.bin", 30_000, 300, vec!["c_c".into()]);
            s.queue_file("f", "d.bin", 20_000, 200, vec!["c_d".into()]);
            s.queue_file("f", "e.bin", 40_000, 400, vec!["c_e".into()]);
            s
        };

        // 1. Alphabetical: a -> b -> c -> d -> e
        let mut s = make_scheduler(PullOrder::Alphabetical);
        let order: Vec<String> = s.schedule_batch(5).into_iter().map(|a| a.chunk_hash).collect();
        assert_eq!(order, vec!["c_a", "c_b", "c_c", "c_d", "c_e"]);

        // 2. SmallestFirst: b (10k) -> d (20k) -> c (30k) -> e (40k) -> a (50k)
        let mut s = make_scheduler(PullOrder::SmallestFirst);
        let order: Vec<String> = s.schedule_batch(5).into_iter().map(|a| a.chunk_hash).collect();
        assert_eq!(order, vec!["c_b", "c_d", "c_c", "c_e", "c_a"]);

        // 3. LargestFirst: a (50k) -> e (40k) -> c (30k) -> d (20k) -> b (10k)
        let mut s = make_scheduler(PullOrder::LargestFirst);
        let order: Vec<String> = s.schedule_batch(5).into_iter().map(|a| a.chunk_hash).collect();
        assert_eq!(order, vec!["c_a", "c_e", "c_c", "c_d", "c_b"]);

        // 4. NewestFirst: b (500) -> e (400) -> c (300) -> d (200) -> a (100)
        let mut s = make_scheduler(PullOrder::NewestFirst);
        let order: Vec<String> = s.schedule_batch(5).into_iter().map(|a| a.chunk_hash).collect();
        assert_eq!(order, vec!["c_b", "c_e", "c_c", "c_d", "c_a"]);

        // 5. OldestFirst: a (100) -> d (200) -> c (300) -> e (400) -> b (500)
        let mut s = make_scheduler(PullOrder::OldestFirst);
        let order: Vec<String> = s.schedule_batch(5).into_iter().map(|a| a.chunk_hash).collect();
        assert_eq!(order, vec!["c_a", "c_d", "c_c", "c_e", "c_b"]);
    }

    #[test]
    fn test_dynamic_pull_order_reconfiguration() {
        let mut scheduler = SwarmScheduler::with_strategy(
            PullOrder::Alphabetical,
            SchedulingStrategy::FilePriorityRarest,
        );
        scheduler.register_peer("peer_1", vec!["c_alpha", "c_middle", "c_zeta"]);

        scheduler.queue_file("f", "alpha.txt", 10_000, 100, vec!["c_alpha".into()]);
        scheduler.queue_file("f", "middle.txt", 50_000, 200, vec!["c_middle".into()]);
        scheduler.queue_file("f", "zeta.txt", 5_000, 300, vec!["c_zeta".into()]);

        // Schedule first item under Alphabetical -> alpha.txt
        let a1 = scheduler.schedule_next().unwrap();
        assert_eq!(a1.chunk_hash, "c_alpha");

        // Reconfigure to LargestFirst dynamically
        scheduler.set_pull_order(PullOrder::LargestFirst);
        assert_eq!(scheduler.pull_order(), PullOrder::LargestFirst);

        // Next item must be middle.txt (size 50_000 > zeta.txt size 5_000)
        let a2 = scheduler.schedule_next().unwrap();
        assert_eq!(a2.chunk_hash, "c_middle");

        let a3 = scheduler.schedule_next().unwrap();
        assert_eq!(a3.chunk_hash, "c_zeta");
    }

    #[test]
    fn test_multi_peer_disconnect_reconnect_lifecycle() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("peer_1", vec!["c1", "c2"]);
        scheduler.register_peer("peer_2", vec!["c3", "c4"]);
        scheduler.register_peer("peer_3", vec!["c1", "c2", "c3", "c4"]);

        scheduler.queue_chunks(vec!["c1", "c2", "c3", "c4"]);

        // Schedule 4 requests across peers
        let b = scheduler.schedule_batch(4);
        assert_eq!(b.len(), 4);
        assert_eq!(scheduler.in_flight_count(), 4);
        assert_eq!(scheduler.pending_count(), 0);

        // Disconnect peer_1 and peer_2
        scheduler.mark_peer_disconnected("peer_1");
        scheduler.mark_peer_disconnected("peer_2");

        assert_eq!(scheduler.connected_peers(), vec!["peer_3"]);

        // The chunks assigned to peer_1 and peer_2 must be back in pending
        assert!(scheduler.pending_count() >= 2);

        // Peer 3 can now pick up the orphaned chunks
        let reassigned = scheduler.schedule_next();
        assert!(reassigned.is_some());
        assert_eq!(reassigned.unwrap().peer_id, "peer_3");

        // Reconnect peer_1
        scheduler.mark_peer_connected("peer_1");
        assert!(scheduler.connected_peers().contains(&"peer_1".to_string()));
    }

    #[test]
    fn test_unregister_peer_cleanup() {
        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("leaving_peer", vec!["c_orphan"]);
        scheduler.register_peer("staying_peer", vec!["c_orphan"]);

        scheduler.queue_chunk("c_orphan");
        let a = scheduler.schedule_next().unwrap();

        if a.peer_id == "leaving_peer" {
            scheduler.unregister_peer("leaving_peer");
            assert_eq!(scheduler.in_flight_count(), 0);
            assert_eq!(scheduler.pending_count(), 1);

            let a2 = scheduler.schedule_next().unwrap();
            assert_eq!(a2.peer_id, "staying_peer");
        } else {
            scheduler.unregister_peer("staying_peer");
            assert_eq!(scheduler.in_flight_count(), 0);
            assert_eq!(scheduler.pending_count(), 1);

            let a2 = scheduler.schedule_next().unwrap();
            assert_eq!(a2.peer_id, "leaving_peer");
        }
    }

    #[tokio::test]
    async fn test_timeout_detection_and_peer_penalty() {
        tokio::time::pause();

        let mut scheduler = SwarmScheduler::new(PullOrder::Alphabetical);
        scheduler.register_peer("faulty_peer", vec!["timeout_block"]);
        scheduler.register_peer("backup_peer", vec!["timeout_block"]);

        scheduler.queue_chunk("timeout_block");

        let a1 = scheduler.schedule_next().unwrap();
        let first_peer = a1.peer_id.clone();

        // Advance 15s (past 10s timeout threshold)
        tokio::time::advance(Duration::from_secs(15)).await;

        let timed_out = scheduler.check_timeouts(Duration::from_secs(10));
        assert_eq!(timed_out, vec!["timeout_block"]);
        assert_eq!(scheduler.in_flight_count(), 0);
        assert_eq!(scheduler.pending_count(), 1);

        // Next schedule must pick the OTHER peer because first_peer was penalized with failed_attempts
        let a2 = scheduler.schedule_next().unwrap();
        assert_eq!(a2.chunk_hash, "timeout_block");
        assert_ne!(a2.peer_id, first_peer);
    }

    #[tokio::test]
    async fn test_end_to_end_swarm_lifecycle() {
        tokio::time::pause();

        let mut scheduler = SwarmScheduler::with_strategy(
            PullOrder::SmallestFirst,
            SchedulingStrategy::RarestFirstSwarm,
        );

        // 4 nodes in cluster
        scheduler.register_peer("node_1", vec!["b1", "b2", "b3"]);
        scheduler.register_peer("node_2", vec!["b3", "b4", "b5"]);
        scheduler.register_peer("node_3", vec!["b5", "b6", "b7"]);
        scheduler.register_peer("node_4", vec!["b1", "b4", "b7", "b8"]);

        // 3 files totaling 8 blocks
        scheduler.queue_file("docs", "readme.txt", 100, 1, vec!["b1".into(), "b2".into()]);
        scheduler.queue_file("docs", "data.csv", 500, 2, vec!["b3".into(), "b4".into(), "b5".into()]);
        scheduler.queue_file("docs", "archive.tar", 1000, 3, vec!["b6".into(), "b7".into(), "b8".into()]);

        assert_eq!(scheduler.pending_count(), 8);
        assert_eq!(scheduler.completed_count(), 0);
        assert!(!scheduler.is_finished());

        // Step 1: Schedule first batch of 4
        let b1 = scheduler.schedule_batch(4);
        assert_eq!(b1.len(), 4);

        // Node 1 disconnects unexpectedly
        scheduler.mark_peer_disconnected("node_1");

        // Complete 2 assignments that were not on node_1
        for a in &b1 {
            if a.peer_id != "node_1" {
                scheduler.mark_completed(&a.chunk_hash);
            }
        }

        // Advance time to trigger timeouts on any lingering requests
        tokio::time::advance(Duration::from_secs(20)).await;
        scheduler.check_timeouts(Duration::from_secs(10));

        // Node 1 reconnects
        scheduler.mark_peer_connected("node_1");

        // Drain remainder until scheduler finishes
        let mut max_steps = 50;
        while !scheduler.is_finished() && max_steps > 0 {
            max_steps -= 1;
            if let Some(a) = scheduler.schedule_next() {
                // Simulate successful download
                scheduler.mark_completed(&a.chunk_hash);
            }
        }

        assert!(scheduler.is_finished());
        assert_eq!(scheduler.pending_count(), 0);
        assert_eq!(scheduler.in_flight_count(), 0);
        assert_eq!(scheduler.completed_count(), 8);

        // Progress for all files is 100%
        assert_eq!(scheduler.file_progress("docs", "readme.txt"), Some((2, 2)));
        assert_eq!(scheduler.file_progress("docs", "data.csv"), Some((3, 3)));
        assert_eq!(scheduler.file_progress("docs", "archive.tar"), Some((3, 3)));
    }
}
