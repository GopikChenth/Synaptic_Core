//! Causality Tracking & The Merkle Revision DAG.
//!
//! Maintains revision ancestry graphs and calculates Lowest Common Ancestors (LCA)
//! to differentiate fast-forwards from divergent edits.

use std::collections::{HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use crate::storage::StorageEngine;

/// Revision Node representation in the Merkle Revision DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionNode {
    /// BLAKE3(parent_hashes + manifest_hash)
    pub revision_hash: String,
    /// 1 parent = normal update; 2 parents = merge commit
    pub parent_hashes: Vec<String>,
    /// Hash of chunk-list representation
    pub manifest_hash: String,
    /// Public key fingerprint of authoring node
    pub author_device_id: String,
    /// Monotonically increasing local counter
    pub sequence_number: u64,
    /// POSIX timestamp in nanoseconds
    pub mtime_nanos: i64,
    /// Total size in bytes
    pub file_size: u64,
}

impl RevisionNode {
    /// Computes deterministic BLAKE3 revision hash over parents, manifest, author, and sequence.
    pub fn compute_hash(
        parent_hashes: &[String],
        manifest_hash: &str,
        author_device_id: &str,
        sequence_number: u64,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        for parent in parent_hashes {
            hasher.update(parent.as_bytes());
            hasher.update(b";");
        }
        hasher.update(b"|");
        hasher.update(manifest_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(author_device_id.as_bytes());
        hasher.update(b"|");
        hasher.update(&sequence_number.to_le_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Creates a new revision node with computed hash.
    pub fn new(
        parent_hashes: Vec<String>,
        manifest_hash: String,
        author_device_id: String,
        sequence_number: u64,
        mtime_nanos: i64,
        file_size: u64,
    ) -> Self {
        let revision_hash = Self::compute_hash(
            &parent_hashes,
            &manifest_hash,
            &author_device_id,
            sequence_number,
        );
        Self {
            revision_hash,
            parent_hashes,
            manifest_hash,
            author_device_id,
            sequence_number,
            mtime_nanos,
            file_size,
        }
    }
}

/// Result of evaluating ancestry between two revisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LcaResult {
    /// Revisions are identical.
    Identical,
    /// Local is a descendant of remote: local already has remote's changes.
    FastForwardLocal,
    /// Remote is a descendant of local: remote cleanly supersedes local.
    FastForwardRemote,
    /// Both branches diverged: 3-way merge or quarantine required.
    Diverged {
        base_revision: Option<String>,
    },
}

/// DAG Traversal and Lowest Common Ancestor (LCA) Resolver.
pub struct MerkleDag<'a> {
    storage: &'a StorageEngine,
}

impl<'a> MerkleDag<'a> {
    pub fn new(storage: &'a StorageEngine) -> Self {
        Self { storage }
    }

    /// Helper to get parent hashes for a revision from the storage engine.
    fn get_parents(&self, rev_hash: &str) -> Vec<String> {
        match self.storage.get_revision(rev_hash) {
            Ok(Some(record)) => {
                let mut parents = Vec::new();
                if let Some(p1) = record.parent_1 {
                    parents.push(p1);
                }
                if let Some(p2) = record.parent_2 {
                    parents.push(p2);
                }
                parents
            }
            _ => Vec::new(),
        }
    }

    /// Traverses backward using Breadth-First Search (BFS) to collect all reachable ancestors.
    pub fn collect_ancestors(&self, start_rev: &str) -> HashSet<String> {
        let mut ancestors = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_rev.to_string());

        while let Some(current) = queue.pop_front() {
            let parents = self.get_parents(&current);
            for p in parents {
                if ancestors.insert(p.clone()) {
                    queue.push_back(p);
                }
            }
        }

        ancestors
    }

    /// Finds Lowest Common Ancestor between local and remote revisions according to Section 4.2.
    pub fn find_lca(&self, local_rev: &str, remote_rev: &str) -> LcaResult {
        if local_rev == remote_rev {
            return LcaResult::Identical;
        }

        // 1. Collect all ancestors of local_rev
        let local_ancestors = self.collect_ancestors(local_rev);

        // If remote_rev is in local_ancestors => R_base = remote_rev => fast-forward local
        if local_ancestors.contains(remote_rev) {
            return LcaResult::FastForwardLocal;
        }

        // 2. Collect all ancestors of remote_rev
        let remote_ancestors = self.collect_ancestors(remote_rev);

        // If local_rev is in remote_ancestors => R_base = local_rev => fast-forward remote
        if remote_ancestors.contains(local_rev) {
            return LcaResult::FastForwardRemote;
        }

        // 3. Find the lowest common ancestor (latest divergence point) using BFS from remote_rev
        // Queue traverses remote's lineage; the first ancestor encountered that also belongs to local is the LCA.
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        queue.push_back(remote_rev.to_string());

        while let Some(current) = queue.pop_front() {
            let parents = self.get_parents(&current);
            for p in parents {
                if local_ancestors.contains(&p) {
                    return LcaResult::Diverged {
                        base_revision: Some(p),
                    };
                }
                if visited.insert(p.clone()) {
                    queue.push_back(p);
                }
            }
        }

        // Diverged with no recorded common ancestor in database
        LcaResult::Diverged {
            base_revision: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RevisionRecord;

    fn setup_test_storage() -> (StorageEngine, std::path::PathBuf) {
        let temp_dir = std::env::temp_dir().join(format!("synapse_dag_{}", uuid::Uuid::new_v4()));
        let storage = StorageEngine::new(&temp_dir).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_merkle_dag_lca() {
        let (storage, temp_dir) = setup_test_storage();

        // Build DAG:
        //       R0 (Root)
        //       /      \
        //      R1      R2
        //      |        |
        //      R3       |
        //
        // Local: R3 (lineage R3 -> R1 -> R0)
        // Remote: R2 (lineage R2 -> R0)
        // Expected LCA: R0

        let rev0 = RevisionRecord {
            revision_hash: "R0".into(),
            parent_1: None,
            parent_2: None,
            manifest_hash: "m0".into(),
            author_device: "devA".into(),
            created_at: 100,
        };
        let rev1 = RevisionRecord {
            revision_hash: "R1".into(),
            parent_1: Some("R0".into()),
            parent_2: None,
            manifest_hash: "m1".into(),
            author_device: "devA".into(),
            created_at: 101,
        };
        let rev2 = RevisionRecord {
            revision_hash: "R2".into(),
            parent_1: Some("R0".into()),
            parent_2: None,
            manifest_hash: "m2".into(),
            author_device: "devB".into(),
            created_at: 102,
        };
        let rev3 = RevisionRecord {
            revision_hash: "R3".into(),
            parent_1: Some("R1".into()),
            parent_2: None,
            manifest_hash: "m3".into(),
            author_device: "devA".into(),
            created_at: 103,
        };

        storage.insert_revision(&rev0, &[]).unwrap();
        storage.insert_revision(&rev1, &[]).unwrap();
        storage.insert_revision(&rev2, &[]).unwrap();
        storage.insert_revision(&rev3, &[]).unwrap();

        let dag = MerkleDag::new(&storage);

        // 1. Identical
        assert_eq!(dag.find_lca("R1", "R1"), LcaResult::Identical);

        // 2. Fast-forward local (R3 has R1 as ancestor)
        assert_eq!(dag.find_lca("R3", "R1"), LcaResult::FastForwardLocal);

        // 3. Fast-forward remote (R1 is ancestor of R3)
        assert_eq!(dag.find_lca("R1", "R3"), LcaResult::FastForwardRemote);

        // 4. Divergence with LCA = R0
        let lca = dag.find_lca("R3", "R2");
        assert_eq!(
            lca,
            LcaResult::Diverged {
                base_revision: Some("R0".into())
            }
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
