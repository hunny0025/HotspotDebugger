//! # Evidence Graph — Traversal Queries
//!
//! Provides the core graph traversal algorithms needed for forensic analysis.
//! Every query is designed to answer a specific forensic question and produces
//! an audit-ready result that can be included in court reports.
//!
//! # Supported Queries
//!
//! 1. **Evidence chain reconstruction** — trace any finding back to raw artifacts
//! 2. **Artifact support query** — find all artifacts supporting a network connection
//! 3. **Contradiction query** — find all contradictions affecting a finding
//! 4. **Corroboration score** — count independent corroborating sources for an event
//! 5. **Evidence island detection** — find disconnected subgraphs

use crate::edges::{EdgeType, GraphEdge};
use crate::nodes::{GraphNode, NodeId, NodeKind};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ──────────────────────────────────────────────────────────────────────────────
// Evidence Graph Core
// ──────────────────────────────────────────────────────────────────────────────

/// The central evidence graph containing all nodes and edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceGraph {
    /// All nodes in the graph, indexed by NodeId.
    nodes: HashMap<NodeId, GraphNode>,
    /// All edges in the graph.
    edges: Vec<GraphEdge>,
    /// Forward adjacency: from-node → list of edge indices.
    forward_adj: HashMap<NodeId, Vec<usize>>,
    /// Reverse adjacency: to-node → list of edge indices.
    reverse_adj: HashMap<NodeId, Vec<usize>>,
}

impl EvidenceGraph {
    /// Create a new empty evidence graph.
    pub fn new() -> Self {
        EvidenceGraph {
            nodes: HashMap::new(),
            edges: Vec::new(),
            forward_adj: HashMap::new(),
            reverse_adj: HashMap::new(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: GraphNode) -> NodeId {
        let id = node.id;
        self.nodes.insert(id, node);
        id
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: GraphEdge) {
        let idx = self.edges.len();
        self.forward_adj
            .entry(edge.from)
            .or_default()
            .push(idx);
        self.reverse_adj
            .entry(edge.to)
            .or_default()
            .push(idx);
        self.edges.push(edge);
    }

    /// Get a node by its ID.
    pub fn get_node(&self, id: &NodeId) -> Option<&GraphNode> {
        self.nodes.get(id)
    }

    /// Get all nodes of a specific kind.
    pub fn nodes_by_kind(&self, kind: NodeKind) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| n.kind == kind)
            .collect()
    }

    /// Get outgoing edges from a node.
    pub fn outgoing_edges(&self, node_id: &NodeId) -> Vec<&GraphEdge> {
        self.forward_adj
            .get(node_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Get incoming edges to a node.
    pub fn incoming_edges(&self, node_id: &NodeId) -> Vec<&GraphEdge> {
        self.reverse_adj
            .get(node_id)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// Total number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    // ── Query 1: Evidence Chain Reconstruction ──────────────────────────

    /// Reconstruct the complete evidence chain for a finding node.
    ///
    /// Traverses backward from the finding through all `DERIVED_FROM`,
    /// `NORMALIZED_TO`, and `CORROBORATES` edges to reach the raw
    /// artifacts that ultimately support this finding.
    ///
    /// Returns the ordered chain of node IDs from finding → raw artifacts.
    pub fn evidence_chain(&self, finding_id: &NodeId) -> EvidenceChain {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(*finding_id);
        visited.insert(*finding_id);

        while let Some(current) = queue.pop_front() {
            if self.get_node(&current).is_some() {
                chain.push(current);
            }

            // Follow reverse edges (incoming edges to current)
            for edge in self.incoming_edges(&current) {
                if !visited.contains(&edge.from) {
                    match edge.edge_type {
                        EdgeType::DerivedFrom
                        | EdgeType::NormalizedTo
                        | EdgeType::Corroborates
                        | EdgeType::ConfidenceScored => {
                            visited.insert(edge.from);
                            queue.push_back(edge.from);
                        }
                        _ => {}
                    }
                }
            }

            // Also follow forward DerivedFrom edges (record → artifact direction)
            for edge in self.outgoing_edges(&current) {
                if !visited.contains(&edge.to) {
                    if edge.edge_type == EdgeType::DerivedFrom {
                        visited.insert(edge.to);
                        queue.push_back(edge.to);
                    }
                }
            }
        }

        let artifact_count = chain
            .iter()
            .filter(|id| {
                self.get_node(id)
                    .map(|n| n.kind == NodeKind::Artifact)
                    .unwrap_or(false)
            })
            .count();

        EvidenceChain {
            finding_id: *finding_id,
            node_ids: chain,
            artifact_count,
        }
    }

    // ── Query 2: Artifacts Supporting a Network Connection ──────────────

    /// Find all artifact nodes that support a specific network identity node.
    ///
    /// Traverses through `IDENTIFIED_AS` edges and their provenance chains.
    pub fn artifacts_supporting_network(&self, network_id: &NodeId) -> Vec<NodeId> {
        let mut artifacts = Vec::new();
        let mut visited = HashSet::new();

        // Find all nodes that have an IDENTIFIED_AS edge pointing to this network
        for edge in self.incoming_edges(network_id) {
            if edge.edge_type == EdgeType::IdentifiedAs && !visited.contains(&edge.from) {
                visited.insert(edge.from);

                // If it's an artifact directly, add it
                if let Some(node) = self.get_node(&edge.from) {
                    if node.kind == NodeKind::Artifact {
                        artifacts.push(edge.from);
                    } else {
                        // Trace back through DerivedFrom to find artifacts
                        self.trace_to_artifacts(edge.from, &mut artifacts, &mut visited);
                    }
                }
            }
        }

        artifacts
    }

    /// Recursively trace a node back to its source artifacts via DerivedFrom edges.
    fn trace_to_artifacts(
        &self,
        node_id: NodeId,
        artifacts: &mut Vec<NodeId>,
        visited: &mut HashSet<NodeId>,
    ) {
        for edge in self.outgoing_edges(&node_id) {
            if edge.edge_type == EdgeType::DerivedFrom && !visited.contains(&edge.to) {
                visited.insert(edge.to);
                if let Some(node) = self.get_node(&edge.to) {
                    if node.kind == NodeKind::Artifact {
                        artifacts.push(edge.to);
                    } else {
                        self.trace_to_artifacts(edge.to, artifacts, visited);
                    }
                }
            }
        }
    }

    // ── Query 3: Contradictions Affecting a Finding ─────────────────────

    /// Find all contradictions (CONTRADICTS edges) that affect a finding
    /// or any node in its evidence chain.
    pub fn contradictions_for_finding(&self, finding_id: &NodeId) -> Vec<Contradiction> {
        let chain = self.evidence_chain(finding_id);
        let chain_set: HashSet<NodeId> = chain.node_ids.iter().copied().collect();
        let mut contradictions = Vec::new();

        for edge in &self.edges {
            if edge.edge_type == EdgeType::Contradicts {
                let affects_chain = chain_set.contains(&edge.from)
                    || chain_set.contains(&edge.to);
                if affects_chain {
                    contradictions.push(Contradiction {
                        edge_id: edge.id,
                        contradicting_node: edge.from,
                        contradicted_node: edge.to,
                        weight: edge.weight,
                        rationale: edge.rationale.clone(),
                    });
                }
            }
        }

        contradictions
    }

    // ── Query 4: Corroboration Score ────────────────────────────────────

    /// Compute the corroboration score for an event node.
    ///
    /// The score is the count of independent CORROBORATES edges pointing
    /// to this event, weighted by the reliability of the corroborating sources.
    pub fn corroboration_score(&self, event_id: &NodeId) -> CorroborationResult {
        let corroborating: Vec<&GraphEdge> = self
            .incoming_edges(event_id)
            .into_iter()
            .filter(|e| e.edge_type == EdgeType::Corroborates)
            .collect();

        let source_count = corroborating.len();
        let weighted_sum: f64 = corroborating
            .iter()
            .map(|e| e.weight.unwrap_or(1.0))
            .sum();

        // Normalized score: log curve capped at 1.0 (matches confidence model)
        let raw_score = if source_count <= 1 {
            0.0
        } else {
            ((source_count as f64 - 1.0) / 3.0).min(1.0)
        };

        CorroborationResult {
            event_id: *event_id,
            source_count,
            weighted_sum,
            normalized_score: raw_score,
        }
    }

    // ── Query 5: Evidence Island Detection ──────────────────────────────

    /// Detect evidence islands — nodes that have no connections to the main
    /// graph. These represent artifacts that couldn't be correlated with
    /// any other evidence, which is forensically significant.
    pub fn detect_islands(&self) -> Vec<Vec<NodeId>> {
        let mut visited = HashSet::new();
        let mut components = Vec::new();

        for &node_id in self.nodes.keys() {
            if visited.contains(&node_id) {
                continue;
            }

            let mut component = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(node_id);
            visited.insert(node_id);

            while let Some(current) = queue.pop_front() {
                component.push(current);

                // Follow all edges in both directions (undirected connectivity)
                for edge in self.outgoing_edges(&current) {
                    if !visited.contains(&edge.to) {
                        visited.insert(edge.to);
                        queue.push_back(edge.to);
                    }
                }
                for edge in self.incoming_edges(&current) {
                    if !visited.contains(&edge.from) {
                        visited.insert(edge.from);
                        queue.push_back(edge.from);
                    }
                }
            }

            components.push(component);
        }

        // Sort by size ascending — small components are the "islands"
        components.sort_by_key(|c| c.len());
        components
    }

    /// Returns only true islands (components with fewer nodes than the largest component).
    pub fn isolated_islands(&self) -> Vec<Vec<NodeId>> {
        let components = self.detect_islands();
        if components.len() <= 1 {
            return Vec::new();
        }

        let max_size = components.iter().map(|c| c.len()).max().unwrap_or(0);
        components
            .into_iter()
            .filter(|c| c.len() < max_size)
            .collect()
    }
}

impl Default for EvidenceGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Query Result Types
// ──────────────────────────────────────────────────────────────────────────────

/// The result of an evidence chain reconstruction query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    /// The finding that was traced.
    pub finding_id: NodeId,
    /// All node IDs in the chain, from finding to raw artifacts.
    pub node_ids: Vec<NodeId>,
    /// How many raw artifact nodes are in the chain.
    pub artifact_count: usize,
}

/// A detected contradiction in the evidence graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    /// The edge representing this contradiction.
    pub edge_id: crate::edges::EdgeId,
    /// The node making the contradicting claim.
    pub contradicting_node: NodeId,
    /// The node being contradicted.
    pub contradicted_node: NodeId,
    /// Optional weight of the contradiction.
    pub weight: Option<f64>,
    /// Optional rationale for the contradiction.
    pub rationale: Option<String>,
}

/// The result of a corroboration score computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorroborationResult {
    /// The event that was scored.
    pub event_id: NodeId,
    /// Number of independent corroborating sources.
    pub source_count: usize,
    /// Sum of weights from corroborating edges.
    pub weighted_sum: f64,
    /// Normalized score (0.0–1.0) using the confidence model curve.
    pub normalized_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nodes::*;
    use chrono::Utc;
    use oracle_core::types::{ArtifactClass, ArtifactId, ConfidenceClassification, RecordId};

    fn make_artifact_node() -> GraphNode {
        GraphNode::artifact(ArtifactNode {
            artifact_id: ArtifactId::new(),
            source_path: "/data/misc/wifi/WifiConfigStore.xml".to_string(),
            sha256_hash: "abc123".to_string(),
            size_bytes: 4096,
            artifact_class: ArtifactClass::WifiConfigStore,
            ingested_at: Utc::now(),
        })
    }

    fn make_record_node(artifact_id: ArtifactId) -> GraphNode {
        GraphNode::parsed_record(ParsedRecordNode {
            record_id: RecordId::new(),
            parser_id: "wifi_config_parser".to_string(),
            parser_version: "1.0.0".to_string(),
            source_artifact_id: artifact_id,
            description: "Parsed WiFi config".to_string(),
            parsed_at: Utc::now(),
        })
    }

    fn make_finding_node() -> GraphNode {
        GraphNode::finding(FindingNode {
            statement: "Device connected to HomeNetwork".to_string(),
            classification: ConfidenceClassification::High,
            confidence_score: 0.88,
            examiner_approved: false,
            examiner_notes: None,
            generated_at: Utc::now(),
        })
    }

    #[test]
    fn test_empty_graph() {
        let graph = EvidenceGraph::new();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_add_node_and_edge() {
        let mut graph = EvidenceGraph::new();
        let artifact = make_artifact_node();
        let artifact_id_core = match &artifact.payload {
            NodePayload::Artifact(a) => a.artifact_id,
            _ => unreachable!(),
        };
        let artifact_nid = graph.add_node(artifact);

        let record = make_record_node(artifact_id_core);
        let record_nid = graph.add_node(record);

        graph.add_edge(GraphEdge::new(
            record_nid,
            artifact_nid,
            EdgeType::DerivedFrom,
        ));

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert_eq!(graph.outgoing_edges(&record_nid).len(), 1);
        assert_eq!(graph.incoming_edges(&artifact_nid).len(), 1);
    }

    #[test]
    fn test_evidence_chain() {
        let mut graph = EvidenceGraph::new();

        // Build: Finding ← Record → Artifact
        let artifact = make_artifact_node();
        let a_id = match &artifact.payload {
            NodePayload::Artifact(a) => a.artifact_id,
            _ => unreachable!(),
        };
        let artifact_nid = graph.add_node(artifact);
        let record = make_record_node(a_id);
        let record_nid = graph.add_node(record);
        let finding = make_finding_node();
        let finding_nid = graph.add_node(finding);

        // Record derived from artifact
        graph.add_edge(GraphEdge::new(record_nid, artifact_nid, EdgeType::DerivedFrom));
        // Record corroborates finding
        graph.add_edge(GraphEdge::new(record_nid, finding_nid, EdgeType::Corroborates));

        let chain = graph.evidence_chain(&finding_nid);
        assert!(chain.node_ids.contains(&finding_nid));
        assert!(chain.artifact_count >= 1);
    }

    #[test]
    fn test_corroboration_score() {
        let mut graph = EvidenceGraph::new();
        let event = GraphNode::event(EventNode {
            description: "WiFi connection".to_string(),
            start_time: Some(Utc::now()),
            end_time: None,
            role: "client".to_string(),
            confidence: 0.9,
        });
        let event_nid = graph.add_node(event);

        // Add 3 corroborating sources
        for _ in 0..3 {
            let source = make_artifact_node();
            let source_nid = graph.add_node(source);
            graph.add_edge(
                GraphEdge::new(source_nid, event_nid, EdgeType::Corroborates)
                    .with_weight(0.9),
            );
        }

        let result = graph.corroboration_score(&event_nid);
        assert_eq!(result.source_count, 3);
        assert!(result.normalized_score > 0.0);
    }

    #[test]
    fn test_island_detection() {
        let mut graph = EvidenceGraph::new();

        // Create a connected pair
        let a = graph.add_node(make_artifact_node());
        let b = graph.add_node(make_finding_node());
        graph.add_edge(GraphEdge::new(a, b, EdgeType::Corroborates));

        // Create an isolated node (island)
        let _island = graph.add_node(make_artifact_node());

        let islands = graph.isolated_islands();
        assert_eq!(islands.len(), 1);
        assert_eq!(islands[0].len(), 1);
    }

    #[test]
    fn test_contradiction_detection() {
        let mut graph = EvidenceGraph::new();
        let finding = make_finding_node();
        let finding_nid = graph.add_node(finding);

        let supporter = make_artifact_node();
        let supporter_nid = graph.add_node(supporter);
        graph.add_edge(GraphEdge::new(supporter_nid, finding_nid, EdgeType::Corroborates));

        let contradicting = make_artifact_node();
        let contradicting_nid = graph.add_node(contradicting);
        graph.add_edge(
            GraphEdge::new(contradicting_nid, finding_nid, EdgeType::Contradicts)
                .with_rationale("Timestamp mismatch exceeds 2 hours"),
        );

        let contradictions = graph.contradictions_for_finding(&finding_nid);
        assert_eq!(contradictions.len(), 1);
        assert_eq!(contradictions[0].contradicting_node, contradicting_nid);
    }
}
