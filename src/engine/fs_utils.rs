//! Filesystem Safety, Mount Protection, Atomic Staging, and Platform Sanitization.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use filetime::{set_file_times, FileTime};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_marker_verification() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_marker_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        // Marker missing initially
        assert!(verify_folder_marker(&temp_dir, ".synapse-folder").is_err());

        // Create marker
        ensure_folder_marker(&temp_dir, ".synapse-folder").unwrap();
        assert!(verify_folder_marker(&temp_dir, ".synapse-folder").is_ok());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_write() {
        let temp_dir = std::env::temp_dir().join(format!("synapse_atomic_{}", uuid::Uuid::new_v4()));
        let file_path = temp_dir.join("sub/test.txt");

        atomic_write_file(&file_path, b"Atomic Payload Content", Some(1_700_000_000_000_000_000), None).unwrap();
        assert!(file_path.exists());
        assert_eq!(fs::read(&file_path).unwrap(), b"Atomic Payload Content");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_sanitization() {
        assert_eq!(sanitize_relative_path("foo/bar/test.txt"), "foo/bar/test.txt");
        assert_eq!(sanitize_relative_path("foo/../bar/test.txt"), "bar/test.txt");
        assert_eq!(sanitize_relative_path("illegal:name*file?.txt"), "illegal_name_file_.txt");
    }
}
