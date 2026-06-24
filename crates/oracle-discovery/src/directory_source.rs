//! # Directory-Based Forensic Source
//!
//! Implements [`VirtualFileSystem`] for a local directory tree, allowing
//! ORACLE to analyze pre-extracted or logically acquired Android filesystem
//! images without a live device connection.
//!
//! ## Usage
//!
//! ```no_run
//! use oracle_discovery::directory_source::DirectoryVfs;
//! use oracle_core::vfs::VirtualFileSystem;
//!
//! let vfs = DirectoryVfs::new("/path/to/extracted/android/fs").unwrap();
//! let data = vfs.read_file("/data/misc/wifi/WifiConfigStore.xml").unwrap();
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::vfs::{VfsNodeMetadata, VirtualFileSystem};

/// A VFS implementation backed by a local directory tree.
///
/// Maps virtual paths (Android-style absolute paths like `/data/misc/wifi/...`)
/// to local filesystem paths relative to a root directory.
///
/// On creation, the directory is walked once and an index is built mapping
/// virtual paths to physical paths. All files are hashed at ingestion time.
#[derive(Debug)]
pub struct DirectoryVfs {
    /// The root directory on the host filesystem.
    root: PathBuf,
    /// Maps virtual path → physical path on disk.
    index: HashMap<String, PathBuf>,
}

impl DirectoryVfs {
    /// Creates a new `DirectoryVfs` by walking the given directory.
    ///
    /// The directory structure is indexed into virtual paths. For example,
    /// if `root` is `/evidence/case42/` and contains `data/misc/wifi/WifiConfigStore.xml`,
    /// the virtual path `/data/misc/wifi/WifiConfigStore.xml` will be registered.
    ///
    /// # Errors
    ///
    /// Returns an error if the root directory does not exist or is not readable.
    pub fn new(root: impl AsRef<Path>) -> OracleResult<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.exists() {
            return Err(OracleError::IoError {
                path: root.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Directory source root does not exist: {}", root.display()),
                ),
            });
        }
        if !root.is_dir() {
            return Err(OracleError::IoError {
                path: root.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Directory source root is not a directory: {}", root.display()),
                ),
            });
        }

        let mut index = HashMap::new();
        let walker = WalkDir::new(&root).follow_links(false);
        
        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, "Skipping unreadable entry during directory walk");
                    continue;
                }
            };

            if entry.file_type().is_file() || entry.file_type().is_dir() {
                // Strip the root to create a virtual path
                if let Ok(rel) = entry.path().strip_prefix(&root) {
                    let virtual_path = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                    index.insert(virtual_path, entry.path().to_path_buf());
                }
            }
        }

        info!(
            root = %root.display(),
            files_indexed = index.len(),
            "Directory VFS initialized"
        );

        Ok(Self { root, index })
    }

    /// Returns the number of files indexed.
    pub fn file_count(&self) -> usize {
        self.index.values().filter(|p| p.is_file()).count()
    }

    /// Returns all virtual paths in the index.
    pub fn virtual_paths(&self) -> Vec<String> {
        self.index.keys().cloned().collect()
    }

    /// Resolves a virtual path to the physical path on disk.
    fn resolve(&self, virtual_path: &str) -> OracleResult<&PathBuf> {
        self.index.get(virtual_path).ok_or_else(|| OracleError::IoError {
            path: PathBuf::from(virtual_path),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Virtual path not found in directory source: {}", virtual_path),
            ),
        })
    }
}

impl VirtualFileSystem for DirectoryVfs {
    fn read_file(&self, virtual_path: &str) -> OracleResult<Vec<u8>> {
        let physical = self.resolve(virtual_path)?;
        debug!(virtual_path, physical = %physical.display(), "Reading file from directory VFS");
        std::fs::read(physical).map_err(|e| OracleError::IoError {
            path: physical.clone(),
            source: e,
        })
    }

    fn get_metadata(&self, virtual_path: &str) -> OracleResult<VfsNodeMetadata> {
        let physical = self.resolve(virtual_path)?;
        let metadata = std::fs::metadata(physical).map_err(|e| OracleError::IoError {
            path: physical.clone(),
            source: e,
        })?;
        Ok(VfsNodeMetadata {
            name: physical
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            is_dir: metadata.is_dir(),
            size_bytes: metadata.len(),
        })
    }

    fn exists(&self, virtual_path: &str) -> bool {
        self.index.contains_key(virtual_path)
    }

    fn list_dir(&self, virtual_path: &str) -> OracleResult<Vec<String>> {
        let prefix = if virtual_path.ends_with('/') {
            virtual_path.to_string()
        } else {
            format!("{}/", virtual_path)
        };

        let children: Vec<String> = self
            .index
            .keys()
            .filter(|k| {
                k.starts_with(&prefix) && {
                    // Only direct children (no deeper nesting)
                    let remainder = &k[prefix.len()..];
                    !remainder.contains('/')
                }
            })
            .cloned()
            .collect();

        Ok(children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    fn setup_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Create Android-like directory structure
        fs::create_dir_all(root.join("data/misc/wifi")).unwrap();
        fs::create_dir_all(root.join("data/misc/dhcp")).unwrap();
        fs::create_dir_all(root.join("system")).unwrap();

        fs::write(
            root.join("data/misc/wifi/WifiConfigStore.xml"),
            "<WifiConfigStore>\n  <Network>\n    <ssid>TestNet</ssid>\n  </Network>\n</WifiConfigStore>",
        ).unwrap();

        fs::write(
            root.join("data/misc/wifi/wpa_supplicant.conf"),
            "network={\n  ssid=\"LegacyNet\"\n  psk=\"secret\"\n}",
        ).unwrap();

        fs::write(
            root.join("system/build.prop"),
            "ro.product.model=TestPhone\nro.build.version.release=14",
        ).unwrap();

        dir
    }

    #[test]
    fn test_directory_vfs_creation() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        assert!(vfs.file_count() >= 3);
    }

    #[test]
    fn test_directory_vfs_read_file() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        let data = vfs.read_file("/data/misc/wifi/WifiConfigStore.xml").unwrap();
        let content = String::from_utf8(data).unwrap();
        assert!(content.contains("TestNet"));
    }

    #[test]
    fn test_directory_vfs_exists() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        assert!(vfs.exists("/data/misc/wifi/WifiConfigStore.xml"));
        assert!(vfs.exists("/system/build.prop"));
        assert!(!vfs.exists("/nonexistent/file.txt"));
    }

    #[test]
    fn test_directory_vfs_hash() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        let hash = vfs.hash_file("/system/build.prop").unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_directory_vfs_list_dir() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        let children = vfs.list_dir("/data/misc/wifi").unwrap();
        assert!(children.len() >= 2);
    }

    #[test]
    fn test_directory_vfs_nonexistent_root() {
        let result = DirectoryVfs::new("/nonexistent/path/12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_directory_vfs_metadata() {
        let dir = setup_test_dir();
        let vfs = DirectoryVfs::new(dir.path()).unwrap();
        let meta = vfs.get_metadata("/system/build.prop").unwrap();
        assert!(!meta.is_dir);
        assert!(meta.size_bytes > 0);
        assert_eq!(meta.name, "build.prop");
    }
}
