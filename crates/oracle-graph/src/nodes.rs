//! # Evidence Graph — Node Types
//!
//! Every entity in the forensic evidence graph is represented as a typed node.
//! Nodes carry their own identity, provenance metadata, and domain-specific
//! payload. The graph engine is agnostic to node internals — it only cares
//! about [`NodeId`] and [`GraphNode`] for indexing and traversal.

use chrono::{DateTime, Utc};
use oracle_core::types::{
    ArtifactClass, ArtifactId, ConfidenceClassification, InvestigationId, RecordId,
    SecurityProtocol,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Node Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for any node in the evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Uuid);

impl NodeId {
    pub fn new() -> Self {
        NodeId(Uuid::new_v4())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Node Type Discriminant
// ──────────────────────────────────────────────────────────────────────────────

/// Discriminant for the kind of node in the evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Artifact,
    ParsedRecord,
    NetworkIdentity,
    Event,
    Device,
    Finding,
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeKind::Artifact => write!(f, "ARTIFACT"),
            NodeKind::ParsedRecord => write!(f, "PARSED_RECORD"),
            NodeKind::NetworkIdentity => write!(f, "NETWORK_IDENTITY"),
            NodeKind::Event => write!(f, "EVENT"),
            NodeKind::Device => write!(f, "DEVICE"),
            NodeKind::Finding => write!(f, "FINDING"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Typed Node Payloads
// ──────────────────────────────────────────────────────────────────────────────

/// Raw forensic artifact node — a file with hashes and provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactNode {
    /// The ORACLE artifact ID assigned at ingestion.
    pub artifact_id: ArtifactId,
    /// Original filesystem path where the artifact was found.
    pub source_path: String,
    /// SHA-256 hash of the raw artifact bytes.
    pub sha256_hash: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// The artifact classification.
    pub artifact_class: ArtifactClass,
    /// When the artifact was ingested into the evidence store.
    pub ingested_at: DateTime<Utc>,
}

/// Structured data extracted from an artifact by a parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedRecordNode {
    /// The ORACLE record ID.
    pub record_id: RecordId,
    /// Which parser produced this record.
    pub parser_id: String,
    /// Parser version string.
    pub parser_version: String,
    /// The artifact this record was derived from.
    pub source_artifact_id: ArtifactId,
    /// Human-readable description of the record content.
    pub description: String,
    /// When this record was created.
    pub parsed_at: DateTime<Utc>,
}

/// A resolved network entity (SSID + BSSID combination).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdentityNode {
    /// The SSID (network name), normalized.
    pub ssid: String,
    /// The BSSID (access point MAC), normalized. May be absent.
    pub bssid: Option<String>,
    /// Security protocol observed.
    pub security: SecurityProtocol,
    /// Number of distinct artifact sources that reference this network.
    pub source_count: usize,
}

/// A connection event placed on the timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNode {
    /// Human-readable event description.
    pub description: String,
    /// Start timestamp (if known).
    pub start_time: Option<DateTime<Utc>>,
    /// End timestamp (if known).
    pub end_time: Option<DateTime<Utc>>,
    /// Whether the device was a client or hotspot during this event.
    pub role: String,
    /// Confidence in the event's existence.
    pub confidence: f64,
}

/// The subject device under investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceNode {
    /// Investigation this device belongs to.
    pub investigation_id: InvestigationId,
    /// Device manufacturer.
    pub manufacturer: String,
    /// Device model.
    pub model: String,
    /// Android version.
    pub android_version: String,
    /// Device serial number.
    pub serial: String,
}

/// A conclusion drawn by the system or examiner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingNode {
    /// Human-readable finding statement.
    pub statement: String,
    /// The confidence classification.
    pub classification: ConfidenceClassification,
    /// The numeric confidence score.
    pub confidence_score: f64,
    /// Whether an examiner has reviewed and approved this finding.
    pub examiner_approved: bool,
    /// Optional examiner notes.
    pub examiner_notes: Option<String>,
    /// When this finding was generated.
    pub generated_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Unified Graph Node
// ──────────────────────────────────────────────────────────────────────────────

/// The payload of a graph node — one of the typed node variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodePayload {
    Artifact(ArtifactNode),
    ParsedRecord(ParsedRecordNode),
    NetworkIdentity(NetworkIdentityNode),
    Event(EventNode),
    Device(DeviceNode),
    Finding(FindingNode),
}

/// A node in the evidence graph, combining identity with typed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Unique node identifier.
    pub id: NodeId,
    /// The kind of node (for fast filtering without matching the payload).
    pub kind: NodeKind,
    /// The typed payload.
    pub payload: NodePayload,
    /// When this node was added to the graph.
    pub added_at: DateTime<Utc>,
}

impl GraphNode {
    /// Create a new graph node with the given payload.
    pub fn new(kind: NodeKind, payload: NodePayload) -> Self {
        GraphNode {
            id: NodeId::new(),
            kind,
            payload,
            added_at: Utc::now(),
        }
    }

    /// Create an Artifact node.
    pub fn artifact(data: ArtifactNode) -> Self {
        Self::new(NodeKind::Artifact, NodePayload::Artifact(data))
    }

    /// Create a ParsedRecord node.
    pub fn parsed_record(data: ParsedRecordNode) -> Self {
        Self::new(NodeKind::ParsedRecord, NodePayload::ParsedRecord(data))
    }

    /// Create a NetworkIdentity node.
    pub fn network_identity(data: NetworkIdentityNode) -> Self {
        Self::new(NodeKind::NetworkIdentity, NodePayload::NetworkIdentity(data))
    }

    /// Create an Event node.
    pub fn event(data: EventNode) -> Self {
        Self::new(NodeKind::Event, NodePayload::Event(data))
    }

    /// Create a Device node.
    pub fn device(data: DeviceNode) -> Self {
        Self::new(NodeKind::Device, NodePayload::Device(data))
    }

    /// Create a Finding node.
    pub fn finding(data: FindingNode) -> Self {
        Self::new(NodeKind::Finding, NodePayload::Finding(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::ArtifactId;

    #[test]
    fn test_node_id_uniqueness() {
        let a = NodeId::new();
        let b = NodeId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_artifact_node_creation() {
        let node = GraphNode::artifact(ArtifactNode {
            artifact_id: ArtifactId::new(),
            source_path: "/data/misc/wifi/WifiConfigStore.xml".to_string(),
            sha256_hash: "abcdef1234567890".to_string(),
            size_bytes: 4096,
            artifact_class: ArtifactClass::WifiConfigStore,
            ingested_at: Utc::now(),
        });
        assert_eq!(node.kind, NodeKind::Artifact);
        assert!(matches!(node.payload, NodePayload::Artifact(_)));
    }

    #[test]
    fn test_finding_node_creation() {
        let node = GraphNode::finding(FindingNode {
            statement: "Device connected to HomeNetwork at 10:00 UTC".to_string(),
            classification: ConfidenceClassification::High,
            confidence_score: 0.88,
            examiner_approved: false,
            examiner_notes: None,
            generated_at: Utc::now(),
        });
        assert_eq!(node.kind, NodeKind::Finding);
    }

    #[test]
    fn test_node_kind_display() {
        assert_eq!(format!("{}", NodeKind::Artifact), "ARTIFACT");
        assert_eq!(format!("{}", NodeKind::Finding), "FINDING");
        assert_eq!(format!("{}", NodeKind::Event), "EVENT");
    }
}
