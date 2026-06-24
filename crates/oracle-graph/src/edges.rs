//! # Evidence Graph — Edge Types
//!
//! Edges represent forensic relationships between nodes in the evidence graph.
//! Every edge is typed, directional, and carries metadata about when and why
//! the relationship was established.
//!
//! # Edge Type Semantics
//!
//! | Edge Type           | From → To                       | Meaning                                    |
//! |---------------------|----------------------------------|--------------------------------------------|
//! | `DERIVED_FROM`      | ParsedRecord → Artifact          | Record was parsed from this artifact       |
//! | `NORMALIZED_TO`     | NormalizedRecord → ParsedRecord  | Normalization produced from parsed record  |
//! | `CORROBORATES`      | Any → Any                        | Source supports target                     |
//! | `CONTRADICTS`       | Any → Any                        | Source conflicts with target               |
//! | `PART_OF`           | Event → Timeline                 | Event belongs to this timeline             |
//! | `IDENTIFIED_AS`     | Artifact → NetworkIdentity       | Artifact identifies a network entity       |
//! | `CONFIDENCE_SCORED` | Finding → ConfidenceScore        | Finding scored by confidence engine        |

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::nodes::NodeId;

// ──────────────────────────────────────────────────────────────────────────────
// Edge Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for an edge in the evidence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub Uuid);

impl EdgeId {
    pub fn new() -> Self {
        EdgeId(Uuid::new_v4())
    }
}

impl Default for EdgeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EdgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Edge Types
// ──────────────────────────────────────────────────────────────────────────────

/// The type of relationship between two graph nodes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    /// A parsed record was derived from a raw artifact.
    /// Direction: ParsedRecord → Artifact
    DerivedFrom,

    /// A normalized record was produced from a parsed record.
    /// Direction: NormalizedRecord → ParsedRecord
    NormalizedTo,

    /// One evidence record supports / confirms another.
    /// Direction: Supporting → Supported
    Corroborates,

    /// One evidence record conflicts with another.
    /// Direction: Contradicting → Contradicted
    Contradicts,

    /// An event is part of a reconstructed timeline.
    /// Direction: Event → Timeline
    PartOf,

    /// An artifact identifies or belongs to a network entity.
    /// Direction: Artifact/Record → NetworkIdentity
    IdentifiedAs,

    /// A finding has been scored by the confidence engine.
    /// Direction: Finding → ConfidenceScore
    ConfidenceScored,
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeType::DerivedFrom => write!(f, "DERIVED_FROM"),
            EdgeType::NormalizedTo => write!(f, "NORMALIZED_TO"),
            EdgeType::Corroborates => write!(f, "CORROBORATES"),
            EdgeType::Contradicts => write!(f, "CONTRADICTS"),
            EdgeType::PartOf => write!(f, "PART_OF"),
            EdgeType::IdentifiedAs => write!(f, "IDENTIFIED_AS"),
            EdgeType::ConfidenceScored => write!(f, "CONFIDENCE_SCORED"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Graph Edge
// ──────────────────────────────────────────────────────────────────────────────

/// A directed edge in the evidence graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Unique edge identifier.
    pub id: EdgeId,
    /// The source node (origin of the relationship).
    pub from: NodeId,
    /// The target node (destination of the relationship).
    pub to: NodeId,
    /// The type of relationship.
    pub edge_type: EdgeType,
    /// Optional weight or strength of the relationship (0.0–1.0).
    pub weight: Option<f64>,
    /// Optional human-readable rationale for this edge.
    pub rationale: Option<String>,
    /// When this edge was created.
    pub created_at: DateTime<Utc>,
}

impl GraphEdge {
    /// Create a new edge between two nodes.
    pub fn new(from: NodeId, to: NodeId, edge_type: EdgeType) -> Self {
        GraphEdge {
            id: EdgeId::new(),
            from,
            to,
            edge_type,
            weight: None,
            rationale: None,
            created_at: Utc::now(),
        }
    }

    /// Create an edge with a weight.
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = Some(weight.clamp(0.0, 1.0));
        self
    }

    /// Create an edge with a rationale.
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = Some(rationale.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_id_uniqueness() {
        let a = EdgeId::new();
        let b = EdgeId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn test_edge_creation() {
        let from = NodeId::new();
        let to = NodeId::new();
        let edge = GraphEdge::new(from, to, EdgeType::DerivedFrom);
        assert_eq!(edge.from, from);
        assert_eq!(edge.to, to);
        assert_eq!(edge.edge_type, EdgeType::DerivedFrom);
        assert!(edge.weight.is_none());
    }

    #[test]
    fn test_edge_with_weight() {
        let edge = GraphEdge::new(NodeId::new(), NodeId::new(), EdgeType::Corroborates)
            .with_weight(0.85);
        assert_eq!(edge.weight, Some(0.85));
    }

    #[test]
    fn test_edge_weight_clamped() {
        let edge = GraphEdge::new(NodeId::new(), NodeId::new(), EdgeType::Corroborates)
            .with_weight(1.5);
        assert_eq!(edge.weight, Some(1.0));
    }

    #[test]
    fn test_edge_type_display() {
        assert_eq!(format!("{}", EdgeType::DerivedFrom), "DERIVED_FROM");
        assert_eq!(format!("{}", EdgeType::Corroborates), "CORROBORATES");
        assert_eq!(format!("{}", EdgeType::Contradicts), "CONTRADICTS");
    }
}
