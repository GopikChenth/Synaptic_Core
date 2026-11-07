//! File Versioning Retention Policies and Garbage Collection Engine.
//!
//! Implements:
//! - `VersioningPolicy`: `None`, `TrashCan`, `Simple(max_versions)`, and `Staggered(clean_interval, max_age)`.
//! - Staggered Interval Retention: keeps hourly versions for the past 24 hours,
//!   daily versions for the past 30 days, and weekly versions thereafter until `max_age`.
//! - Version discovery, parsing, and automated filesystem garbage collection.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Number of seconds in 1 hour (3,600s).
pub const ONE_HOUR_SECS: u64 = 3600;

/// Number of seconds in 1 day / 24 hours (86,400s).
pub const ONE_DAY_SECS: u64 = 86400;

/// Number of seconds in 30 days (2,592,000s).
pub const THIRTY_DAYS_SECS: u64 = 30 * ONE_DAY_SECS;

/// Number of seconds in 1 week / 7 days (604,800s).
pub const ONE_WEEK_SECS: u64 = 7 * ONE_DAY_SECS;

/// Retention scheduling policy for folder historical file revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersioningPolicy {
    /// No versioning: previous revisions are not retained when files change or are deleted.
    None,
    /// Trash can: files are moved to versions archive and kept for a cleanout period.
    TrashCan,
    /// Simple versioning: keep up to `max_versions` prior versions for each file.
    Simple(usize),
    /// Staggered versioning: retain hourly for past 24h, daily for past 30 days,
    /// and weekly thereafter up to `max_age` seconds.
    ///
    /// Tuple fields: `(clean_interval_secs, max_age_secs)`.
    Staggered(u64, u64),
}

impl Default for VersioningPolicy {
    fn default() -> Self {
        Self::None
    }
}

impl VersioningPolicy {
    /// Creates a Simple versioning policy with the specified maximum version count.
    pub fn simple(max_versions: usize) -> Self {
        Self::Simple(max_versions)
    }

    /// Creates a Staggered versioning policy with clean interval and max age in seconds.
    pub fn staggered(clean_interval_secs: u64, max_age_secs: u64) -> Self {
        Self::Staggered(clean_interval_secs, max_age_secs)
    }

    /// Returns the cleanout interval in seconds, if defined.
    pub fn clean_interval(&self) -> Option<u64> {
        match self {
            Self::Staggered(interval, _) => Some(*interval),
            _ => None,
        }
    }

    /// Returns the maximum retention age in seconds, if defined.
    pub fn max_age(&self) -> Option<u64> {
        match self {
            Self::Staggered(_, max_age) => Some(*max_age),
            _ => None,
        }
    }

    /// Converts database folder config strings and keep days into a `VersioningPolicy`.
    pub fn from_folder_config(versioning_type: &str, keep_days: i64) -> Self {
        match versioning_type.to_lowercase().as_str() {
            "trashcan" | "trash_can" | "trash" => Self::TrashCan,
            "simple" => {
                let max = if keep_days > 0 { keep_days as usize } else { 5 };
                Self::Simple(max)
            }
            "staggered" => {
                let max_age_secs = if keep_days > 0 {
                    (keep_days as u64) * ONE_DAY_SECS
                } else {
                    365 * ONE_DAY_SECS // default 365 days
                };
                Self::Staggered(ONE_HOUR_SECS, max_age_secs)
            }
            _ => Self::None,
        }
    }

    /// Plans retention for historical versions of a file evaluated against `now`.
    pub fn plan_retention(&self, versions: &[FileVersion], now: DateTime<Utc>) -> RetentionPlan {
        match self {
            Self::None => RetentionPlan {
                keep: Vec::new(),
                remove: versions.to_vec(),
            },
            Self::TrashCan => apply_trashcan_retention(versions, now, THIRTY_DAYS_SECS),
            Self::Simple(max_versions) => apply_simple_retention(versions, *max_versions),
            Self::Staggered(_clean_interval, max_age) => {
                apply_staggered_retention(versions, now, *max_age)
            }
        }
    }

    /// Plans retention for historical versions allowing a custom TrashCan keep duration (in days).
    pub fn plan_retention_with_trash_days(
        &self,
        versions: &[FileVersion],
        now: DateTime<Utc>,
        trash_keep_days: u32,
    ) -> RetentionPlan {
        match self {
            Self::TrashCan => {
                let max_age = (trash_keep_days as u64) * ONE_DAY_SECS;
                apply_trashcan_retention(versions, now, max_age)
            }
            other => other.plan_retention(versions, now),
        }
    }
}

/// Metadata representation of an archived file revision in the versions directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVersion {
    /// Absolute path to the version file on disk.
    pub path: PathBuf,
    /// Normalized relative path of the file (e.g. "docs/report.pdf").
    pub relative_path: String,
    /// Timestamp when this version was created or archived.
    pub timestamp: DateTime<Utc>,
    /// File size in bytes.
    pub size: u64,
}

impl FileVersion {
    pub fn new(
        path: PathBuf,
        relative_path: impl Into<String>,
        timestamp: DateTime<Utc>,
        size: u64,
    ) -> Self {
        Self {
            path,
            relative_path: relative_path.into(),
            timestamp,
            size,
        }
    }

    /// Returns the age of this file version in seconds relative to `now`.
    pub fn age_secs(&self, now: DateTime<Utc>) -> u64 {
        if now >= self.timestamp {
            (now - self.timestamp).num_seconds().max(0) as u64
        } else {
            0
        }
    }
}

/// Disjoint interval buckets for the staggered retention algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetentionBucket {
    /// Hourly intervals for the first 24 hours: `Hourly(0..23)`.
    Hourly(u64),
    /// Daily intervals from 24 hours up to 30 days: `Daily(1..29)`.
    Daily(u64),
    /// Weekly intervals from 30 days up to `max_age`: `Weekly(0..)`.
    Weekly(u64),
}

/// Determines the retention interval bucket for a given age in seconds.
/// Returns `None` if the version exceeds `max_age_secs` (when `max_age_secs > 0`).
pub fn get_staggered_bucket(age_secs: u64, max_age_secs: u64) -> Option<RetentionBucket> {
    if max_age_secs > 0 && age_secs > max_age_secs {
        return None; // Expired past max age
    }

    if age_secs < ONE_DAY_SECS {
        Some(RetentionBucket::Hourly(age_secs / ONE_HOUR_SECS))
    } else if age_secs < THIRTY_DAYS_SECS {
        Some(RetentionBucket::Daily(age_secs / ONE_DAY_SECS))
    } else {
        Some(RetentionBucket::Weekly((age_secs - THIRTY_DAYS_SECS) / ONE_WEEK_SECS))
    }
}

/// Partitioned retention result differentiating retained vs expired versions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionPlan {
    pub keep: Vec<FileVersion>,
    pub remove: Vec<FileVersion>,
}

/// Applies the staggered retention algorithm on a set of historical versions for a file.
///
/// Policy specification:
/// - Keep at most 1 version per hour for the past 24 hours
/// - Keep at most 1 version per day for the past 30 days (days 1 to 30)
/// - Keep at most 1 version per week thereafter until `max_age_secs`
/// - Purge any versions older than `max_age_secs` (if `max_age_secs > 0`)
pub fn apply_staggered_retention(
    versions: &[FileVersion],
    now: DateTime<Utc>,
    max_age_secs: u64,
) -> RetentionPlan {
    let mut sorted = versions.to_vec();
    // Sort descending by timestamp so the newest version in each bucket is processed first
    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let mut keep = Vec::new();
    let mut remove = Vec::new();
    let mut seen_buckets = HashSet::new();

    for ver in sorted {
        let age_secs = ver.age_secs(now);

        match get_staggered_bucket(age_secs, max_age_secs) {
            None => {
                // Expired past max_age
                remove.push(ver);
            }
            Some(bucket) => {
                if seen_buckets.insert(bucket) {
                    // First (newest) version encountered in this interval bucket -> retain
                    keep.push(ver);
                } else {
                    // A newer version in the same interval bucket has already been retained
                    remove.push(ver);
                }
            }
        }
    }

    RetentionPlan { keep, remove }
}

/// Pure timestamp evaluation helper for the staggered retention algorithm.
/// Returns `(kept_timestamps, removed_timestamps)` sorted descending.
pub fn evaluate_staggered_timestamps(
    timestamps_secs: &[i64],
    now_secs: i64,
    max_age_secs: u64,
) -> (Vec<i64>, Vec<i64>) {
    let mut sorted = timestamps_secs.to_vec();
    sorted.sort_by(|a, b| b.cmp(a));

    let mut keep = Vec::new();
    let mut remove = Vec::new();
    let mut seen_buckets = HashSet::new();

    for &ts in &sorted {
        let age_secs = if now_secs >= ts {
            (now_secs - ts).max(0) as u64
        } else {
            0
        };

        match get_staggered_bucket(age_secs, max_age_secs) {
            None => {
                remove.push(ts);
            }
            Some(bucket) => {
                if seen_buckets.insert(bucket) {
                    keep.push(ts);
                } else {
                    remove.push(ts);
                }
            }
        }
    }

    (keep, remove)
}

/// Applies Simple retention: keeps the newest `max_versions` entries.
pub fn apply_simple_retention(versions: &[FileVersion], max_versions: usize) -> RetentionPlan {
    let mut sorted = versions.to_vec();
    sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if max_versions == 0 {
        return RetentionPlan {
            keep: Vec::new(),
            remove: sorted,
        };
    }

    let keep_count = sorted.len().min(max_versions);
    let keep = sorted[..keep_count].to_vec();
    let remove = sorted[keep_count..].to_vec();

    RetentionPlan { keep, remove }
}

/// Applies TrashCan retention: preserves versions until `max_age_secs` is exceeded.
pub fn apply_trashcan_retention(
    versions: &[FileVersion],
    now: DateTime<Utc>,
    max_age_secs: u64,
) -> RetentionPlan {
    let mut keep = Vec::new();
    let mut remove = Vec::new();

    for ver in versions {
        let age_secs = ver.age_secs(now);
        if max_age_secs > 0 && age_secs > max_age_secs {
            remove.push(ver.clone());
        } else {
            keep.push(ver.clone());
        }
    }

    RetentionPlan { keep, remove }
}

/// Parses historical timestamps from archived directory names or filenames.
pub fn parse_version_timestamp(s: &str) -> Option<DateTime<Utc>> {
    // 1. Standard Synapse / Syncthing timestamp: "%Y%m%d-%H%M%S"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d-%H%M%S") {
        return Some(naive.and_utc());
    }

    // 2. Sub-second timestamp: "%Y%m%d-%H%M%S%.f"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d-%H%M%S%.f") {
        return Some(naive.and_utc());
    }

    // 3. Hyphenated timestamp: "%Y-%m-%d-%H%M%S"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d-%H%M%S") {
        return Some(naive.and_utc());
    }

    // 4. Underscore timestamp: "%Y%m%d_%H%M%S"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d_%H%M%S") {
        return Some(naive.and_utc());
    }

    // 5. RFC3339 / ISO8601
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }

    // 6. Date only: "%Y%m%d"
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y%m%d") {
        if let Some(naive) = date.and_hms_opt(0, 0, 0) {
            return Some(naive.and_utc());
        }
    }

    None
}

/// Recursively scans `.synapse/versions` or `.stversions` inside `folder_root` for all version files.
pub fn list_folder_versions(folder_root: &Path) -> Result<Vec<FileVersion>, std::io::Error> {
    let mut versions_dir = folder_root.join(".synapse").join("versions");
    if !versions_dir.exists() {
        let fallback = folder_root.join(".stversions");
        if fallback.exists() {
            versions_dir = fallback;
        } else {
            return Ok(Vec::new());
        }
    }

    let mut result = Vec::new();
    scan_versions_recursive(&versions_dir, &versions_dir, &mut result)?;
    Ok(result)
}

fn scan_versions_recursive(
    versions_root: &Path,
    current_dir: &Path,
    out: &mut Vec<FileVersion>,
) -> Result<(), std::io::Error> {
    if !current_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(current_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            scan_versions_recursive(versions_root, &path, out)?;
        } else if path.is_file() {
            if let Ok(rel_to_versions) = path.strip_prefix(versions_root) {
                let (rel_path, timestamp) = resolve_version_metadata(rel_to_versions, &path);
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push(FileVersion {
                    path,
                    relative_path: rel_path,
                    timestamp,
                    size,
                });
            }
        }
    }

    Ok(())
}

fn resolve_version_metadata(rel_to_versions: &Path, file_path: &Path) -> (String, DateTime<Utc>) {
    let components: Vec<_> = rel_to_versions.components().collect();

    if !components.is_empty() {
        let first_str = components[0].as_os_str().to_string_lossy();
        if let Some(ts) = parse_version_timestamp(&first_str) {
            let sub_path = components[1..].iter().collect::<PathBuf>();
            let rel_str = sub_path.to_string_lossy().replace('\\', "/");
            return (rel_str, ts);
        }
    }

    // Check if filename has `~<timestamp>` suffix
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
    if let Some((base, ts_str)) = file_name.rsplit_once('~') {
        if let Some(ts) = parse_version_timestamp(ts_str) {
            let parent = rel_to_versions.parent().unwrap_or(Path::new(""));
            let final_path = parent.join(base);
            let rel_str = final_path.to_string_lossy().replace('\\', "/");
            return (rel_str, ts);
        }
    }

    // Fallback: use filesystem modification timestamp
    let mtime = fs::metadata(file_path)
        .and_then(|m| m.modified())
        .ok()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(Utc::now);

    let rel_str = rel_to_versions.to_string_lossy().replace('\\', "/");
    (rel_str, mtime)
}

/// Prunes empty directories under `dir` recursively from the bottom up.
pub fn prune_empty_directories(dir: &Path) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            prune_empty_directories(&path)?;
            if let Ok(mut sub_entries) = fs::read_dir(&path) {
                if sub_entries.next().is_none() {
                    let _ = fs::remove_dir(&path);
                }
            }
        }
    }

    Ok(())
}

/// Execution summary of a version cleanup/garbage collection run.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    /// Number of expired or redundant version files deleted from disk.
    pub deleted_files_count: usize,
    /// Total bytes freed on the storage volume.
    pub freed_bytes: u64,
    /// Absolute paths of deleted version files.
    pub removed_paths: Vec<PathBuf>,
}

/// Garbage collects expired and redundant historical file versions based on `policy`.
pub fn cleanup_expired_versions(
    folder_root: &Path,
    policy: &VersioningPolicy,
) -> Result<CleanupReport, std::io::Error> {
    cleanup_expired_versions_at(folder_root, policy, Utc::now())
}

/// Garbage collects expired versions evaluated at a specific reference time `now`.
pub fn cleanup_expired_versions_at(
    folder_root: &Path,
    policy: &VersioningPolicy,
    now: DateTime<Utc>,
) -> Result<CleanupReport, std::io::Error> {
    let mut versions_dir = folder_root.join(".synapse").join("versions");
    if !versions_dir.exists() {
        let fallback = folder_root.join(".stversions");
        if fallback.exists() {
            versions_dir = fallback;
        } else {
            return Ok(CleanupReport::default());
        }
    }

    let all_versions = list_folder_versions(folder_root)?;
    if all_versions.is_empty() {
        return Ok(CleanupReport::default());
    }

    // Group historical versions by normalized relative path
    let mut grouped: HashMap<String, Vec<FileVersion>> = HashMap::new();
    for ver in all_versions {
        grouped.entry(ver.relative_path.clone()).or_default().push(ver);
    }

    let mut report = CleanupReport::default();

    for (_rel, versions) in grouped {
        let plan = policy.plan_retention(&versions, now);
        for ver in plan.remove {
            if ver.path.exists() {
                let size = ver.size;
                if fs::remove_file(&ver.path).is_ok() {
                    report.deleted_files_count += 1;
                    report.freed_bytes += size;
                    report.removed_paths.push(ver.path);
                }
            }
        }
    }

    // Remove empty directories left behind
    let _ = prune_empty_directories(&versions_dir);

    Ok(report)
}

/// Archives a file into `.synapse/versions/` respecting the folder's `VersioningPolicy`.
pub fn archive_file(
    folder_root: &Path,
    relative_path: &str,
    policy: &VersioningPolicy,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    if *policy == VersioningPolicy::None {
        return Ok(None);
    }
    crate::engine::fs_utils::archive_file_version(folder_root, relative_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_staggered_bucket_calculation() {
        let max_age = 90 * ONE_DAY_SECS; // 90 days

        // Past 24 hours -> Hourly buckets
        assert_eq!(get_staggered_bucket(0, max_age), Some(RetentionBucket::Hourly(0)));
        assert_eq!(get_staggered_bucket(1800, max_age), Some(RetentionBucket::Hourly(0)));
        assert_eq!(get_staggered_bucket(3600, max_age), Some(RetentionBucket::Hourly(1)));
        assert_eq!(get_staggered_bucket(23 * ONE_HOUR_SECS + 10, max_age), Some(RetentionBucket::Hourly(23)));

        // Past 30 days -> Daily buckets
        assert_eq!(get_staggered_bucket(ONE_DAY_SECS, max_age), Some(RetentionBucket::Daily(1)));
        assert_eq!(get_staggered_bucket(2 * ONE_DAY_SECS + 500, max_age), Some(RetentionBucket::Daily(2)));
        assert_eq!(get_staggered_bucket(29 * ONE_DAY_SECS + 3600, max_age), Some(RetentionBucket::Daily(29)));

        // Beyond 30 days -> Weekly buckets
        assert_eq!(get_staggered_bucket(THIRTY_DAYS_SECS, max_age), Some(RetentionBucket::Weekly(0)));
        assert_eq!(get_staggered_bucket(THIRTY_DAYS_SECS + 5 * ONE_DAY_SECS, max_age), Some(RetentionBucket::Weekly(0)));
        assert_eq!(get_staggered_bucket(THIRTY_DAYS_SECS + ONE_WEEK_SECS, max_age), Some(RetentionBucket::Weekly(1)));

        // Exceeded max_age
        assert_eq!(get_staggered_bucket(max_age + 1, max_age), None);
        assert_eq!(get_staggered_bucket(100 * ONE_DAY_SECS, max_age), None);

        // Unlimited max_age (0) -> never expires
        assert_eq!(get_staggered_bucket(1000 * ONE_DAY_SECS, 0), Some(RetentionBucket::Weekly((1000 * ONE_DAY_SECS - THIRTY_DAYS_SECS) / ONE_WEEK_SECS)));
    }

    #[test]
    fn test_staggered_interval_retention_algorithm() {
        let now_secs = 100_000_000;
        let max_age_secs = 60 * ONE_DAY_SECS; // 60 days

        let mut timestamps = Vec::new();

        // 3 versions in the first hour (age: 10m, 20m, 40m)
        timestamps.push(now_secs - 600);
        timestamps.push(now_secs - 1200);
        timestamps.push(now_secs - 2400);

        // 1 version in hour 2 (age: 2h 10m)
        timestamps.push(now_secs - 7800);

        // 2 versions on Day 3 (age: 3 days + 1h, 3 days + 4h)
        timestamps.push(now_secs - (3 * ONE_DAY_SECS + 3600) as i64);
        timestamps.push(now_secs - (3 * ONE_DAY_SECS + 14400) as i64);

        // 2 versions on Week 1 after 30 days (age: 32 days, 33 days)
        timestamps.push(now_secs - (32 * ONE_DAY_SECS) as i64);
        timestamps.push(now_secs - (33 * ONE_DAY_SECS) as i64);

        // 1 version exceeding max_age (age: 70 days)
        timestamps.push(now_secs - (70 * ONE_DAY_SECS) as i64);

        let (kept, removed) = evaluate_staggered_timestamps(&timestamps, now_secs, max_age_secs);

        // In first hour: newest (now - 600) is kept, other two are removed
        assert!(kept.contains(&(now_secs - 600)));
        assert!(removed.contains(&(now_secs - 1200)));
        assert!(removed.contains(&(now_secs - 2400)));

        // In hour 2: kept
        assert!(kept.contains(&(now_secs - 7800)));

        // On day 3: newest (3 days + 1h) is kept, older (3 days + 4h) is removed
        assert!(kept.contains(&(now_secs - (3 * ONE_DAY_SECS + 3600) as i64)));
        assert!(removed.contains(&(now_secs - (3 * ONE_DAY_SECS + 14400) as i64)));

        // On week after 30 days: newest (32 days) is kept, older (33 days) is removed
        assert!(kept.contains(&(now_secs - (32 * ONE_DAY_SECS) as i64)));
        assert!(removed.contains(&(now_secs - (33 * ONE_DAY_SECS) as i64)));

        // 70 days version is removed (expired)
        assert!(removed.contains(&(now_secs - (70 * ONE_DAY_SECS) as i64)));

        assert_eq!(kept.len(), 4);
        assert_eq!(removed.len(), 5);
    }

    #[test]
    fn test_simple_retention() {
        let now = Utc::now();
        let versions: Vec<FileVersion> = (0..5)
            .map(|i| FileVersion {
                path: PathBuf::from(format!("/tmp/ver_{}.txt", i)),
                relative_path: "test.txt".to_string(),
                timestamp: now - chrono::Duration::hours(i),
                size: 100,
            })
            .collect();

        let plan = apply_simple_retention(&versions, 3);
        assert_eq!(plan.keep.len(), 3);
        assert_eq!(plan.remove.len(), 2);

        // Keep 3 newest (hours 0, 1, 2)
        assert_eq!(plan.keep[0].timestamp, now);
        assert_eq!(plan.keep[1].timestamp, now - chrono::Duration::hours(1));
        assert_eq!(plan.keep[2].timestamp, now - chrono::Duration::hours(2));
    }

    #[test]
    fn test_trashcan_retention() {
        let now = Utc::now();
        let v1 = FileVersion::new(PathBuf::from("/v1"), "a.txt", now - chrono::Duration::days(5), 50);
        let v2 = FileVersion::new(PathBuf::from("/v2"), "a.txt", now - chrono::Duration::days(40), 50);

        let plan = apply_trashcan_retention(&[v1.clone(), v2.clone()], now, 30 * ONE_DAY_SECS);
        assert_eq!(plan.keep, vec![v1]);
        assert_eq!(plan.remove, vec![v2]);
    }

    #[test]
    fn test_cleanup_expired_versions_garbage_collection() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_cleanup_test_{}", uuid::Uuid::new_v4()));
        let versions_dir = temp_dir.join(".synapse").join("versions");
        fs::create_dir_all(&versions_dir).unwrap();

        let now = Utc::now();

        // 1. Version within last hour
        let ts1 = (now - chrono::Duration::minutes(10)).format("%Y%m%d-%H%M%S").to_string();
        let v1_dir = versions_dir.join(&ts1);
        fs::create_dir_all(&v1_dir).unwrap();
        let v1_path = v1_dir.join("doc.txt");
        fs::write(&v1_path, b"recent content").unwrap();

        // 2. Duplicate version within last hour (should be removed by staggered retention)
        let ts2 = (now - chrono::Duration::minutes(40)).format("%Y%m%d-%H%M%S").to_string();
        let v2_dir = versions_dir.join(&ts2);
        fs::create_dir_all(&v2_dir).unwrap();
        let v2_path = v2_dir.join("doc.txt");
        fs::write(&v2_path, b"older content in same hour").unwrap();

        // 3. Version past max_age (e.g. 100 days old with max_age = 60 days)
        let ts3 = (now - chrono::Duration::days(100)).format("%Y%m%d-%H%M%S").to_string();
        let v3_dir = versions_dir.join(&ts3);
        fs::create_dir_all(&v3_dir).unwrap();
        let v3_path = v3_dir.join("doc.txt");
        fs::write(&v3_path, b"expired content").unwrap();

        let policy = VersioningPolicy::Staggered(3600, 60 * ONE_DAY_SECS);
        let report = cleanup_expired_versions_at(&temp_dir, &policy, now).unwrap();

        assert_eq!(report.deleted_files_count, 2);
        assert!(v1_path.exists());
        assert!(!v2_path.exists());
        assert!(!v3_path.exists());

        // Empty directory v2_dir and v3_dir should be pruned
        assert!(!v2_dir.exists());
        assert!(!v3_dir.exists());
        assert!(v1_dir.exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
