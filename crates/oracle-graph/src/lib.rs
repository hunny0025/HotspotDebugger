//! # ORACLE Evidence Graph
//!
//! The central analytical model for ORACLE V2. The evidence graph represents
//! all forensic entities (artifacts, records, networks, events, findings) as
//! typed nodes connected by typed edges representing forensic relationships.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        EvidenceGraph                           │
//! │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  │
//! │  │   Nodes   │  │   Edges   │  │ Traversal │  │  Builder  │  │
//! │  │ (6 types) │  │ (7 types) │  │ (5 query) │  │           │  │
//! │  └───────────┘  └───────────┘  └───────────┘  └───────────┘  │
//! │                                                               │
//! │  ┌───────────────────────────────────────────────────────────┐│
//! │  │                 Temporal Reasoning Engine                  ││
//! │  │  Cases 1-6: Conflicts, Missing, Manipulation, Gaps, etc.  ││
//! │  └───────────────────────────────────────────────────────────┘│
//! │                                                               │
//! │  ┌──────────────┐  ┌──────────────────┐  ┌────────────────┐  │
//! │  │ Multi-Device │  │   Completeness   │  │ Artifact Health│  │
//! │  │  Comparison  │  │     Scorer       │  │    Scorer      │  │
//! │  └──────────────┘  └──────────────────┘  └────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`nodes`] — Typed graph node definitions (Artifact, Record, Network, Event, Device, Finding).
//! - [`edges`] — Typed edge definitions (DerivedFrom, Corroborates, Contradicts, etc.).
//! - [`traversal`] — Core graph structure and forensic query algorithms.
//! - [`builder`] — Incremental graph construction from pipeline output.
//! - [`temporal`] — Temporal Reasoning Engine (6 ambiguous temporal cases).
//! - [`multi_device`] — Multi-device comparison for co-location analysis.
//! - [`completeness`] — Evidence completeness scoring against device baselines.
//! - [`health`] — Artifact health scoring before parsing.

pub mod nodes;
pub mod edges;
pub mod traversal;
pub mod builder;
pub mod temporal;
pub mod multi_device;
pub mod completeness;
pub mod health;

// Re-export primary types.
pub use nodes::{GraphNode, NodeId, NodeKind, NodePayload};
pub use nodes::{ArtifactNode, ParsedRecordNode, NetworkIdentityNode, EventNode, DeviceNode, FindingNode};
pub use edges::{GraphEdge, EdgeId, EdgeType};
pub use traversal::{EvidenceGraph, EvidenceChain, Contradiction, CorroborationResult};
pub use builder::EvidenceGraphBuilder;
pub use temporal::{TemporalReasoningEngine, TemporalIssue, TemporalCase, TemporalResolution, TemporalSeverity};
pub use multi_device::{MultiDeviceComparator, ComparisonResult, SharedNetwork, DeviceNetworkSummary, NetworkPresence};
pub use completeness::{CompletenessScorer, CompletenessResult};
pub use health::{ArtifactHealthScorer, ArtifactHealthReport, HealthStatus};
