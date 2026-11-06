//! FastCDC Content-Defined Chunking and BLAKE3 Block Hashing Engine.
//!
//! Provides variable-size deduplication chunking using normalized rolling Gear hash
//! with BLAKE3 cryptographic verification.

use serde::{Deserialize, Serialize};

/// Minimum chunk size: 64 KiB
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;
/// Target / Average chunk size: 512 KiB
pub const AVG_CHUNK_SIZE: usize = 512 * 1024;
/// Maximum chunk size: 2048 KiB (2 MiB)
pub const MAX_CHUNK_SIZE: usize = 2048 * 1024;

/// Metadata describing an individual Content-Defined Chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// BLAKE3 256-bit hash in hexadecimal format
    pub chunk_hash: String,
    /// Byte offset in the source file
    pub offset: u64,
    /// Chunk size in bytes
    pub size: usize,
}

/// Result of chunking a byte payload: chunk metadata and raw payload slices.
pub struct ChunkedFile {
    pub chunks: Vec<ChunkInfo>,
    pub total_size: u64,
    pub manifest_hash: String,
}

/// Content-Defined Chunker utilizing FastCDC v2020 and BLAKE3.
pub struct Chunker {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
}

impl Default for Chunker {
    fn default() -> Self {
        Self {
            min_size: MIN_CHUNK_SIZE,
            avg_size: AVG_CHUNK_SIZE,
            max_size: MAX_CHUNK_SIZE,
        }
    }
}

impl Chunker {
    /// Creates a chunker with custom chunk size parameters.
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    /// Computes BLAKE3 cryptographic hash for a byte slice.
    pub fn hash_block(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// Computes manifest hash from an ordered sequence of chunk hashes.
    pub fn compute_manifest_hash(chunk_hashes: &[String]) -> String {
        let mut hasher = blake3::Hasher::new();
        for hash in chunk_hashes {
            hasher.update(hash.as_bytes());
            hasher.update(b"\n");
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Chunks arbitrary bytes using FastCDC and hashes each block with BLAKE3.
    /// Returns chunk metadata and calculates the Merkle manifest hash.
    pub fn chunk_slice(&self, data: &[u8]) -> (Vec<(ChunkInfo, Vec<u8>)>, String) {
        if data.is_empty() {
            let manifest = Self::compute_manifest_hash(&[]);
            return (Vec::new(), manifest);
        }

        let chunker = fastcdc::v2020::FastCDC::new(data, self.min_size, self.avg_size, self.max_size);
        let mut result = Vec::new();
        let mut hashes = Vec::new();

        for entry in chunker {
            let chunk_data = &data[entry.offset..entry.offset + entry.length];
            let chunk_hash = Self::hash_block(chunk_data);
            hashes.push(chunk_hash.clone());

            let info = ChunkInfo {
                chunk_hash,
                offset: entry.offset as u64,
                size: entry.length,
            };
            result.push((info, chunk_data.to_vec()));
        }

        let manifest = Self::compute_manifest_hash(&hashes);
        (result, manifest)
    }

    /// Inspects and slices data without copying buffer data.
    pub fn chunk_metadata_only(&self, data: &[u8]) -> (Vec<ChunkInfo>, String) {
        if data.is_empty() {
            let manifest = Self::compute_manifest_hash(&[]);
            return (Vec::new(), manifest);
        }

        let chunker = fastcdc::v2020::FastCDC::new(data, self.min_size, self.avg_size, self.max_size);
        let mut result = Vec::new();
        let mut hashes = Vec::new();

        for entry in chunker {
            let chunk_data = &data[entry.offset..entry.offset + entry.length];
            let chunk_hash = Self::hash_block(chunk_data);
            hashes.push(chunk_hash.clone());

            result.push(ChunkInfo {
                chunk_hash,
                offset: entry.offset as u64,
                size: entry.length,
            });
        }

        let manifest = Self::compute_manifest_hash(&hashes);
        (result, manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_slice() {
        let chunker = Chunker::default();
        let (chunks, manifest) = chunker.chunk_slice(&[]);
        assert!(chunks.is_empty());
        assert!(!manifest.is_empty());
    }

    #[test]
    fn test_small_data() {
        let chunker = Chunker::default();
        let data = b"Hello, Synapse Core! Decentralized file synchronization engine.";
        let (chunks, manifest) = chunker.chunk_slice(data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0.size, data.len());
        assert_eq!(chunks[0].0.offset, 0);
        assert_eq!(chunks[0].1, data);
        assert!(!manifest.is_empty());
    }

    #[test]
    fn test_cdc_boundary_shift_resilience() {
        let chunker = Chunker::new(1024, 4096, 8192);
        // Realistic pseudo-random data
        let mut original_data = Vec::with_capacity(60_000);
        let mut state: u32 = 123456789;
        for _ in 0..60_000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            original_data.push((state >> 24) as u8);
        }
        let (orig_chunks, _) = chunker.chunk_metadata_only(&original_data);

        // Prepend 100 bytes
        let mut modified_data = vec![0xAA; 100];
        modified_data.extend_from_slice(&original_data);
        let (mod_chunks, _) = chunker.chunk_metadata_only(&modified_data);

        let orig_hashes: Vec<_> = orig_chunks.iter().map(|c| &c.chunk_hash).collect();
        let mod_hashes: Vec<_> = mod_chunks.iter().map(|c| &c.chunk_hash).collect();

        let common_hashes = mod_hashes.iter().filter(|h| orig_hashes.contains(h)).count();
        assert!(common_hashes > 0, "FastCDC must preserve downstream chunks across shifts");
    }
}
