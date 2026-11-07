//! Filesystem Safety, Mount Protection, Atomic Staging, and Platform Sanitization.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use filetime::{set_file_times, FileTime};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[derive(Debug)]
pub enum FsSafetyError {
    MarkerMissing(String),
    DirectoryNotFound(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for FsSafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MarkerMissing(m) => write!(f, "Safety marker '{}' missing! Folder unmounted or corrupted; aborting sync", m),
            Self::DirectoryNotFound(d) => write!(f, "Directory does not exist: {}", d),
            Self::IoError(e) => write!(f, "Filesystem I/O error: {}", e),
        }
    }
}

impl std::error::Error for FsSafetyError {}

impl From<std::io::Error> for FsSafetyError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

/// Verifies that the folder safety marker exists (default `.synapse-folder` or `.stfolder`).
/// Prevents deleting remote files if an external USB drive, NFS share, or encrypted partition unmounts.
pub fn verify_folder_marker(folder_root: &Path, marker_name: &str) -> Result<(), FsSafetyError> {
    if !folder_root.exists() {
        return Err(FsSafetyError::DirectoryNotFound(folder_root.display().to_string()));
    }

    let primary_marker = folder_root.join(marker_name);
    let fallback_marker = folder_root.join(".stfolder");

    if primary_marker.exists() || fallback_marker.exists() {
        Ok(())
    } else {
        Err(FsSafetyError::MarkerMissing(marker_name.to_string()))
    }
}

/// Creates the folder marker if it doesn't already exist.
pub fn ensure_folder_marker(folder_root: &Path, marker_name: &str) -> std::io::Result<()> {
    let marker_path = folder_root.join(marker_name);
    if !marker_path.exists() {
        if let Some(parent) = marker_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Create marker as a hidden directory or empty file
        fs::create_dir_all(&marker_path)?;
    }
    Ok(())
}

/// Writes incoming payload to a temporary file (`.synapse.tmp.XXXXX`) and renames atomically.
/// Preserves POSIX file permissions and sub-millisecond modification timestamps (`mtime_nanos`).
pub fn atomic_write_file(
    target_path: &Path,
    data: &[u8],
    mtime_nanos: Option<i64>,
    _permissions: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let temp_name = format!(".synapse.tmp.{}", uuid::Uuid::new_v4());
    let temp_path = parent.join(temp_name);

    // 1. Write to temp file
    {
        let mut file = File::create(&temp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    // 2. Set POSIX permissions on Unix
    #[cfg(unix)]
    if let Some(mode) = _permissions {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode));
    }

    // 3. Set modification timestamp if specified
    if let Some(nanos) = mtime_nanos {
        let secs = nanos / 1_000_000_000;
        let nsecs = (nanos % 1_000_000_000) as u32;
        let mtime = FileTime::from_unix_time(secs, nsecs);
        let _ = set_file_times(&temp_path, mtime, mtime);
    }

    // 4. Atomic rename replaces destination in one atomic filesystem operation
    fs::rename(&temp_path, target_path)?;
    Ok(())
}

/// Archives an existing file to `.synapse/versions/` before overwriting or deleting it.
pub fn archive_file_version(
    folder_root: &Path,
    relative_path: &str,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    let source_path = folder_root.join(relative_path);
    if !source_path.exists() {
        return Ok(None);
    }

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let versions_dir = folder_root.join(".synapse").join("versions").join(&timestamp);
    let archive_path = versions_dir.join(relative_path);

    if let Some(parent) = archive_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::copy(&source_path, &archive_path)?;
    Ok(Some(archive_path))
}

/// Sanitizes relative path to prevent directory traversal and strip Windows illegal characters.
pub fn sanitize_relative_path(path_str: &str) -> String {
    let normalized = path_str.replace('\\', "/");
    let mut parts = Vec::new();

    for seg in normalized.split('/') {
        let trimmed = seg.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            // Prevent directory traversal
            parts.pop();
            continue;
        }
        // Strip illegal Windows characters: < > : " / \ | ? *
        let clean: String = trimmed
            .chars()
            .map(|c| match c {
                '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
                other => other,
            })
            .collect();

        parts.push(clean);
    }

    parts.join("/")
}

/// Checks if an existing file or directory under `folder_root` matches `rel_path`
/// case-insensitively, but differs in letter case (e.g. `README.md` vs `readme.md`).
///
/// Prevents silent overwrites, data loss, and divergent states when synchronizing
/// between case-insensitive filesystems (NTFS, APFS) and case-sensitive ones (ext4).
/// Returns `Some(existing_path)` with the on-disk relative path if a case collision is detected.
pub fn detect_case_collision(folder_root: &Path, rel_path: &str) -> Option<PathBuf> {
    let clean = sanitize_relative_path(rel_path);
    if clean.is_empty() {
        return None;
    }

    let components: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
    if components.is_empty() {
        return None;
    }

    find_case_collision(folder_root, &components, 0, PathBuf::new(), &clean)
}

fn find_case_collision(
    current_dir: &Path,
    components: &[&str],
    idx: usize,
    accumulated: PathBuf,
    target_clean: &str,
) -> Option<PathBuf> {
    if !current_dir.exists() {
        return None;
    }

    let target_component = components[idx];
    let entries = fs::read_dir(current_dir).ok()?;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if name_str.to_lowercase() == target_component.to_lowercase() {
            let next_accumulated = accumulated.join(&*name_str);
            let next_dir = current_dir.join(&*name_str);

            if idx + 1 == components.len() {
                // Leaf level reached: check if the accumulated relative path differs by case from target
                let acc_normalized = next_accumulated.to_string_lossy().replace('\\', "/");
                if acc_normalized != target_clean {
                    return Some(next_accumulated);
                }
            } else if entry.path().is_dir() {
                // Recurse into subdirectory
                if let Some(collision) = find_case_collision(
                    &next_dir,
                    components,
                    idx + 1,
                    next_accumulated,
                    target_clean,
                ) {
                    return Some(collision);
                }
            }
        }
    }

    None
}

/// CAS magic prefix identifying serialized special file payloads.
pub const SPECIAL_CAS_PREFIX: &[u8] = b"SYNAPSE_SPECIAL_V1:";

/// Representation of special files (symlinks and hardlinks) in CAS revisions and filesystem operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "target")]
pub enum SpecialFileType {
    /// Standard regular file.
    Regular,
    /// Symbolic link pointing to `target`.
    Symlink { target: String },
    /// Hard link pointing to a shared file target.
    Hardlink { target: String },
}

/// Type alias for `SpecialFileType`.
pub type SpecialFile = SpecialFileType;

impl SpecialFileType {
    /// Checks if this special file is a symlink.
    pub fn is_symlink(&self) -> bool {
        matches!(self, Self::Symlink { .. })
    }

    /// Checks if this special file is a hardlink.
    pub fn is_hardlink(&self) -> bool {
        matches!(self, Self::Hardlink { .. })
    }

    /// Checks if this is a standard regular file.
    pub fn is_regular(&self) -> bool {
        matches!(self, Self::Regular)
    }

    /// Returns the link target, if any.
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::Symlink { target } | Self::Hardlink { target } => Some(target.as_str()),
            Self::Regular => None,
        }
    }

    /// Serializes this special file metadata into a CAS payload byte buffer with header prefix.
    pub fn to_cas_payload(&self) -> Vec<u8> {
        let mut buf = Vec::from(SPECIAL_CAS_PREFIX);
        if let Ok(json) = serde_json::to_vec(self) {
            buf.extend_from_slice(&json);
        }
        buf
    }

    /// Deserializes a CAS payload byte buffer if it begins with `SPECIAL_CAS_PREFIX`.
    pub fn from_cas_payload(data: &[u8]) -> Option<Self> {
        if data.starts_with(SPECIAL_CAS_PREFIX) {
            let json = &data[SPECIAL_CAS_PREFIX.len()..];
            serde_json::from_slice(json).ok()
        } else {
            None
        }
    }
}

/// Checks whether raw CAS chunk data represents a special file (symlink or hardlink).
pub fn is_special_file_payload(data: &[u8]) -> bool {
    data.starts_with(SPECIAL_CAS_PREFIX)
}

/// Creates a CAS payload for a symbolic link.
pub fn symlink_cas_payload(target: &str) -> Vec<u8> {
    SpecialFileType::Symlink {
        target: target.to_string(),
    }
    .to_cas_payload()
}

/// Creates a CAS payload for a hard link.
pub fn hardlink_cas_payload(target: &str) -> Vec<u8> {
    SpecialFileType::Hardlink {
        target: target.to_string(),
    }
    .to_cas_payload()
}

/// Parses a special file representation from CAS chunk data.
pub fn parse_special_cas_payload(data: &[u8]) -> Option<SpecialFileType> {
    SpecialFileType::from_cas_payload(data)
}

/// Returns true if the filesystem entry at `path` is a symbolic link.
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Reads the raw target path of a symbolic link on disk.
pub fn read_symlink_target(path: &Path) -> std::io::Result<PathBuf> {
    fs::read_link(path)
}

/// Reads the target path of a symbolic link as a UTF-8 String.
pub fn read_symlink_target_string(path: &Path) -> std::io::Result<String> {
    fs::read_link(path).map(|p| p.to_string_lossy().to_string())
}

/// Creates a symbolic link pointing to `target` at `link_path` (cross-platform).
#[cfg(unix)]
pub fn create_symlink(target: &Path, link_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(target, link_path)
}

/// Creates a symbolic link pointing to `target` at `link_path` on Windows.
#[cfg(windows)]
pub fn create_symlink(target: &Path, link_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link_path)
    } else {
        std::os::windows::fs::symlink_file(target, link_path)
    }
}

/// Fallback for non-Unix, non-Windows platforms.
#[cfg(not(any(unix, windows)))]
pub fn create_symlink(_target: &Path, _link_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Symlinks not supported on this platform",
    ))
}

/// Creates a hard link pointing to `original` at `link_path`.
pub fn create_hardlink(original: &Path, link_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::hard_link(original, link_path)
}

/// Retrieves the number of hard links pointing to the filesystem inode at `path`.
#[cfg(unix)]
pub fn get_hardlink_count(path: &Path) -> std::io::Result<u64> {
    let meta = fs::symlink_metadata(path)?;
    Ok(meta.nlink())
}

/// Retrieves the number of hard links pointing to `path` on non-Unix platforms.
#[cfg(not(unix))]
pub fn get_hardlink_count(_path: &Path) -> std::io::Result<u64> {
    Ok(1)
}

/// Retrieves the filesystem inode number for `path` on Unix platforms.
#[cfg(unix)]
pub fn get_file_inode(path: &Path) -> std::io::Result<u64> {
    let meta = fs::metadata(path)?;
    Ok(meta.ino())
}

/// Inode fallback for non-Unix platforms.
#[cfg(not(unix))]
pub fn get_file_inode(_path: &Path) -> std::io::Result<u64> {
    Ok(0)
}

/// Checks if a file has multiple hard links referencing the same inode.
pub fn is_hardlink(path: &Path) -> bool {
    get_hardlink_count(path).map(|c| c > 1).unwrap_or(false)
}

/// Inspects a filesystem path and determines its `SpecialFileType`.
pub fn inspect_special_file(path: &Path) -> std::io::Result<SpecialFileType> {
    if is_symlink(path) {
        let target = read_symlink_target_string(path)?;
        Ok(SpecialFileType::Symlink { target })
    } else {
        Ok(SpecialFileType::Regular)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_collision_detection() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_case_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let readme = temp_dir.join("ReadMe.md");
        fs::write(&readme, b"Hello").unwrap();

        // Differing letter case (e.g. ReadMe.md vs readme.md) -> collision detected!
        let collision = detect_case_collision(&temp_dir, "readme.md");
        assert!(collision.is_some());
        assert_eq!(collision.unwrap().to_string_lossy().replace('\\', "/"), "ReadMe.md");

        let collision_upper = detect_case_collision(&temp_dir, "README.MD");
        assert!(collision_upper.is_some());
        assert_eq!(collision_upper.unwrap().to_string_lossy().replace('\\', "/"), "ReadMe.md");

        let collision_all_caps = detect_case_collision(&temp_dir, "README.md");
        assert!(collision_all_caps.is_some());

        // Identical case -> not a collision
        let exact = detect_case_collision(&temp_dir, "ReadMe.md");
        assert!(exact.is_none());

        // Non-existent file -> not a collision
        let non_existent = detect_case_collision(&temp_dir, "other.txt");
        assert!(non_existent.is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_case_collision_nested_directories() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_case_nested_{}", uuid::Uuid::new_v4()));
        let sub = temp_dir.join("Docs").join("SubFolder");
        fs::create_dir_all(&sub).unwrap();
        let target = sub.join("ReadMe.md");
        fs::write(&target, b"Doc bytes").unwrap();

        // Differing case across all nested directories and filename
        let collision = detect_case_collision(&temp_dir, "docs/subfolder/readme.md");
        assert!(collision.is_some());
        assert_eq!(collision.unwrap().to_string_lossy().replace('\\', "/"), "Docs/SubFolder/ReadMe.md");

        // Windows backslash path
        let collision_win = detect_case_collision(&temp_dir, "docs\\subfolder\\readme.md");
        assert!(collision_win.is_some());
        assert_eq!(collision_win.unwrap().to_string_lossy().replace('\\', "/"), "Docs/SubFolder/ReadMe.md");

        // All uppercase
        let collision_caps = detect_case_collision(&temp_dir, "DOCS/SUBFOLDER/README.MD");
        assert!(collision_caps.is_some());

        // Differing case only in directory segment
        let collision_dir = detect_case_collision(&temp_dir, "docs/subfolder/ReadMe.md");
        assert!(collision_dir.is_some());
        assert_eq!(collision_dir.unwrap().to_string_lossy().replace('\\', "/"), "Docs/SubFolder/ReadMe.md");

        // Differing case only in filename
        let collision_file = detect_case_collision(&temp_dir, "Docs/SubFolder/readme.md");
        assert!(collision_file.is_some());
        assert_eq!(collision_file.unwrap().to_string_lossy().replace('\\', "/"), "Docs/SubFolder/ReadMe.md");

        // Exact match
        let exact = detect_case_collision(&temp_dir, "Docs/SubFolder/ReadMe.md");
        assert!(exact.is_none());

        // Nonexistent file in same directory
        let nonexistent = detect_case_collision(&temp_dir, "Docs/SubFolder/NonExistent.md");
        assert!(nonexistent.is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_special_file_symlink_helpers() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_symlink_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let target_file = temp_dir.join("original.txt");
        fs::write(&target_file, b"Original file content").unwrap();

        let link_path = temp_dir.join("link_to_original.txt");
        create_symlink(&target_file, &link_path).unwrap();

        assert!(is_symlink(&link_path));
        let read_target = read_symlink_target_string(&link_path).unwrap();
        assert_eq!(read_target, target_file.to_string_lossy());

        // CAS payload round-trip
        let payload = symlink_cas_payload("original.txt");
        assert!(is_special_file_payload(&payload));
        let parsed = parse_special_cas_payload(&payload).unwrap();
        assert_eq!(parsed, SpecialFileType::Symlink { target: "original.txt".to_string() });

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_special_file_hardlink_helpers() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_hardlink_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let orig = temp_dir.join("file.txt");
        fs::write(&orig, b"Hardlink content").unwrap();

        let hardlink_path = temp_dir.join("file_hl.txt");
        create_hardlink(&orig, &hardlink_path).unwrap();

        assert!(hardlink_path.exists());
        #[cfg(unix)]
        {
            assert_eq!(get_hardlink_count(&orig).unwrap(), 2);
            assert_eq!(get_hardlink_count(&hardlink_path).unwrap(), 2);
            assert!(is_hardlink(&orig));
            assert_eq!(get_file_inode(&orig).unwrap(), get_file_inode(&hardlink_path).unwrap());
        }

        // CAS payload round-trip
        let payload = hardlink_cas_payload("file.txt");
        assert!(is_special_file_payload(&payload));
        let parsed = parse_special_cas_payload(&payload).unwrap();
        assert_eq!(parsed, SpecialFileType::Hardlink { target: "file.txt".to_string() });

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mount_marker_verification() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_marker_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. Marker missing initially
        let res_missing = verify_folder_marker(&temp_dir, ".synapse-folder");
        assert!(res_missing.is_err());
        match res_missing {
            Err(FsSafetyError::MarkerMissing(name)) => assert_eq!(name, ".synapse-folder"),
            other => panic!("Expected MarkerMissing, got {:?}", other),
        }

        // 2. Ensure / create marker
        ensure_folder_marker(&temp_dir, ".synapse-folder").unwrap();
        assert!(verify_folder_marker(&temp_dir, ".synapse-folder").is_ok());

        // 3. Delete marker -> verify detection of missing/deleted marker
        let marker_path = temp_dir.join(".synapse-folder");
        fs::remove_dir_all(&marker_path).unwrap();
        let res_deleted = verify_folder_marker(&temp_dir, ".synapse-folder");
        assert!(res_deleted.is_err());
        match res_deleted {
            Err(FsSafetyError::MarkerMissing(name)) => assert_eq!(name, ".synapse-folder"),
            other => panic!("Expected MarkerMissing after deletion, got {:?}", other),
        }

        // 4. Verify fallback marker (.stfolder)
        let fallback_marker = temp_dir.join(".stfolder");
        fs::create_dir_all(&fallback_marker).unwrap();
        assert!(verify_folder_marker(&temp_dir, ".synapse-folder").is_ok());

        // Delete fallback marker
        fs::remove_dir_all(&fallback_marker).unwrap();
        assert!(verify_folder_marker(&temp_dir, ".synapse-folder").is_err());

        // 5. Verify unmounted / nonexistent directory
        let unmounted = temp_dir.join("nonexistent_mount");
        let res_unmounted = verify_folder_marker(&unmounted, ".synapse-folder");
        assert!(res_unmounted.is_err());
        match res_unmounted {
            Err(FsSafetyError::DirectoryNotFound(_)) => {},
            other => panic!("Expected DirectoryNotFound, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_write() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_atomic_{}", uuid::Uuid::new_v4()));
        let parent_dir = temp_dir.join("sub");
        let file_path = parent_dir.join("test.txt");

        let target_nanos = 1_700_000_123_000_000_000i64;
        let target_mode = 0o755u32;

        // 1. Initial write
        atomic_write_file(&file_path, b"Atomic Payload Content", Some(target_nanos), Some(target_mode)).unwrap();
        assert!(file_path.exists());
        assert_eq!(fs::read(&file_path).unwrap(), b"Atomic Payload Content");

        // Verify temporary files are cleaned up
        let temp_files: Vec<_> = fs::read_dir(&parent_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".synapse.tmp."))
            .collect();
        assert!(temp_files.is_empty(), "Temporary files must be cleaned up");

        // Verify timestamp preservation
        let meta = fs::metadata(&file_path).unwrap();
        let mtime = FileTime::from_last_modification_time(&meta);
        assert_eq!(mtime.unix_seconds(), 1_700_000_123);

        // Verify POSIX permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, target_mode);
        }

        // 2. Atomic overwrite of existing file
        let update_nanos = 1_705_000_456_000_000_000i64;
        let update_mode = 0o644u32;
        atomic_write_file(&file_path, b"Updated Atomic Payload", Some(update_nanos), Some(update_mode)).unwrap();

        assert_eq!(fs::read(&file_path).unwrap(), b"Updated Atomic Payload");

        let updated_meta = fs::metadata(&file_path).unwrap();
        let updated_mtime = FileTime::from_last_modification_time(&updated_meta);
        assert_eq!(updated_mtime.unix_seconds(), 1_705_000_456);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(updated_meta.permissions().mode() & 0o777, update_mode);
        }

        // Verify no leftover temporary files after overwrite
        let temp_files_after: Vec<_> = fs::read_dir(&parent_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".synapse.tmp."))
            .collect();
        assert!(temp_files_after.is_empty(), "No temporary files should remain after overwrite");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_sanitization() {
        // Standard path
        assert_eq!(sanitize_relative_path("foo/bar/test.txt"), "foo/bar/test.txt");

        // Directory traversal with ..
        assert_eq!(sanitize_relative_path("foo/../bar/test.txt"), "bar/test.txt");
        assert_eq!(sanitize_relative_path("a/b/../../c/d/../e/file.txt"), "c/e/file.txt");
        assert_eq!(sanitize_relative_path("../../../../etc/passwd"), "etc/passwd");
        assert_eq!(sanitize_relative_path("foo/bar/baz/../../qux"), "foo/qux");

        // Current directory components and redundant slashes
        assert_eq!(sanitize_relative_path("./foo/./bar/./test.txt"), "foo/bar/test.txt");
        assert_eq!(sanitize_relative_path("foo///bar//file.txt"), "foo/bar/file.txt");

        // Windows backslash normalization
        assert_eq!(sanitize_relative_path("nested\\folder/sub\\file.txt"), "nested/folder/sub/file.txt");

        // Windows illegal characters replacement
        assert_eq!(sanitize_relative_path("illegal:name*file?.txt"), "illegal_name_file_.txt");
        assert_eq!(sanitize_relative_path("folder<1>/file:name?version*\"test\"|pipe.txt"), "folder_1_/file_name_version__test__pipe.txt");

        // Whitespace trimming in path segments
        assert_eq!(sanitize_relative_path(" foo / bar / file.txt "), "foo/bar/file.txt");
    }
}
