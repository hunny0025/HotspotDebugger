//! # Virtual Forensic Filesystem (VFS) Traits
//!
//! Defines the core traits and metadata structures for the Virtual Forensic Filesystem,
//! allowing downstream analysis engines to query forensic sources without circular dependencies.

use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::error::OracleResult;

/// The type of forensic input source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputSourceType {
    /// Live Android device connected via ADB.
    LiveDevice,
    /// Pre-extracted directory tree on the host filesystem.
    DirectoryExtraction,
    /// ZIP archive containing an extracted filesystem.
    ZipExtraction,
    /// A single artifact file with an explicit type override.
    SingleArtifact,
}

impl std::fmt::Display for InputSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputSourceType::LiveDevice => write!(f, "Live Device (ADB)"),
            InputSourceType::DirectoryExtraction => write!(f, "Directory Extraction"),
            InputSourceType::ZipExtraction => write!(f, "ZIP Archive"),
            InputSourceType::SingleArtifact => write!(f, "Single Artifact"),
        }
    }
}

/// Metadata about the forensic input source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSourceMetadata {
    /// The type of input source.
    pub source_type: InputSourceType,
    /// Identifier (serial number, directory path, ZIP path, or file path).
    pub identifier: String,
    /// Whether the source integrity was verified (e.g., hash match for ZIP/directory).
    pub integrity_verified: bool,
    /// When the source was ingested.
    pub ingested_at: DateTime<Utc>,
}

/// Metadata for a node in the Virtual Forensic Filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VfsNodeMetadata {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u64,
}

/// Unified interface for accessing static forensic evidence.
pub trait VirtualFileSystem: Send + Sync {
    /// Read the complete byte contents of a virtual file path.
    fn read_file(&self, virtual_path: &str) -> OracleResult<Vec<u8>>;

    /// Returns metadata for a node at the virtual path.
    fn get_metadata(&self, virtual_path: &str) -> OracleResult<VfsNodeMetadata>;

    /// Check if a path exists in the VFS.
    fn exists(&self, virtual_path: &str) -> bool;

    /// List directory children (returns relative virtual paths).
    fn list_dir(&self, virtual_path: &str) -> OracleResult<Vec<String>>;

    /// Calculates the SHA-256 hash of a file.
    fn hash_file(&self, virtual_path: &str) -> OracleResult<String> {
        let content = self.read_file(virtual_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(hex::encode(hasher.finalize()))
    }
}
