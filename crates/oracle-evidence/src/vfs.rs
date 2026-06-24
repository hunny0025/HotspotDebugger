//! # Virtual Forensic Filesystem (VFS)
//!
//! Provides the [`VirtualFileSystem`] trait and default mount providers
//! to decouple downstream parsing engines from physical storage.

use std::path::PathBuf;
use oracle_core::error::{OracleError, OracleResult};
pub use oracle_core::vfs::{VfsNodeMetadata, VirtualFileSystem};

/// VFS provider mapping directly to a local directory tree.
pub struct DirectoryVfs {
    root_path: PathBuf,
}

impl DirectoryVfs {
    pub fn new(root_path: PathBuf) -> Self {
        Self { root_path }
    }

    fn resolve_path(&self, virtual_path: &str) -> OracleResult<PathBuf> {
        let cleaned = virtual_path.replace("..", "");
        let cleaned = cleaned.trim_start_matches('/');
        Ok(self.root_path.join(cleaned))
    }
}

impl VirtualFileSystem for DirectoryVfs {
    fn read_file(&self, virtual_path: &str) -> OracleResult<Vec<u8>> {
        let path = self.resolve_path(virtual_path)?;
        std::fs::read(&path).map_err(|e| OracleError::IoError {
            path: path.clone(),
            source: e,
        })
    }

    fn get_metadata(&self, virtual_path: &str) -> OracleResult<VfsNodeMetadata> {
        let path = self.resolve_path(virtual_path)?;
        let meta = std::fs::metadata(&path).map_err(|e| OracleError::IoError {
            path: path.clone(),
            source: e,
        })?;
        Ok(VfsNodeMetadata {
            name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            is_dir: meta.is_dir(),
            size_bytes: meta.len(),
        })
    }

    fn exists(&self, virtual_path: &str) -> bool {
        self.resolve_path(virtual_path).map(|p| p.exists()).unwrap_or(false)
    }

    fn list_dir(&self, virtual_path: &str) -> OracleResult<Vec<String>> {
        let path = self.resolve_path(virtual_path)?;
        let mut entries = Vec::new();
        let read_dir = std::fs::read_dir(&path).map_err(|e| OracleError::IoError {
            path: path.clone(),
            source: e,
        })?;
        for entry in read_dir {
            let entry = entry.map_err(|e| OracleError::IoError {
                path: path.clone(),
                source: e,
            })?;
            let relative_path = entry.path()
                .strip_prefix(&self.root_path)
                .map(|p| p.to_string_lossy().to_string().replace('\\', "/"))
                .unwrap_or_default();
            entries.push(relative_path);
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_directory_vfs() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"hello vfs").unwrap();

        let vfs = DirectoryVfs::new(dir.path().to_path_buf());
        assert!(vfs.exists("test.txt"));
        assert!(!vfs.exists("nonexistent.txt"));

        let content = vfs.read_file("test.txt").unwrap();
        assert_eq!(content, b"hello vfs");

        let meta = vfs.get_metadata("test.txt").unwrap();
        assert_eq!(meta.name, "test.txt");
        assert!(!meta.is_dir);
        assert_eq!(meta.size_bytes, 9);

        let list = vfs.list_dir("").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], "test.txt");

        let hash = vfs.hash_file("test.txt").unwrap();
        // sha256 of "hello vfs"
        assert_eq!(hash, "ff528fe3232b43986081db081838bf45a08f83f0009bfdd82702a23ffe2ce7f5");
    }
}
