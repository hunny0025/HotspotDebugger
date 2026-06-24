//! # Evidence Graph — Builder
//!
//! Constructs the evidence graph from parsed, normalized, and correlated records.
//! The builder is the entry point for populating the graph from the forensic
//! analysis pipeline output.

use chrono::Utc;
use oracle_core::types::{ArtifactClass, ArtifactId, ConfidenceClassification, InvestigationId, RecordId};

use crate::edges::{EdgeType, GraphEdge};
use crate::nodes::*;
use crate::traversal::EvidenceGraph;

/// Builder that incrementally constructs an evidence graph.
pub struct EvidenceGraphBuilder {
    graph: EvidenceGraph,
}

impl EvidenceGraphBuilder {
    /// Create a new builder with an empty graph.
    pub fn new() -> Self {
        EvidenceGraphBuilder {
            graph: EvidenceGraph::new(),
        }
    }

    /// Add a device node as the root of the investigation.
    pub fn add_device(
        &mut self,
        investigation_id: InvestigationId,
        manufacturer: &str,
        model: &str,
        android_version: &str,
        serial: &str,
    ) -> NodeId {
        let node = GraphNode::device(DeviceNode {
            investigation_id,
            manufacturer: manufacturer.to_string(),
            model: model.to_string(),
            android_version: android_version.to_string(),
            serial: serial.to_string(),
        });
        self.graph.add_node(node)
    }

    /// Add a raw artifact node and return its graph node ID.
    pub fn add_artifact(
        &mut self,
        artifact_id: ArtifactId,
        source_path: &str,
        sha256_hash: &str,
        size_bytes: u64,
        artifact_class: ArtifactClass,
    ) -> NodeId {
        let node = GraphNode::artifact(ArtifactNode {
            artifact_id,
            source_path: source_path.to_string(),
            sha256_hash: sha256_hash.to_string(),
            size_bytes,
            artifact_class,
            ingested_at: Utc::now(),
        });
        self.graph.add_node(node)
    }

    /// Add a parsed record node linked to its source artifact via DERIVED_FROM.
    pub fn add_parsed_record(
        &mut self,
        record_id: RecordId,
        parser_id: &str,
        parser_version: &str,
        source_artifact_id: ArtifactId,
        source_artifact_nid: NodeId,
        description: &str,
    ) -> NodeId {
        let node = GraphNode::parsed_record(ParsedRecordNode {
            record_id,
            parser_id: parser_id.to_string(),
            parser_version: parser_version.to_string(),
            source_artifact_id,
            description: description.to_string(),
            parsed_at: Utc::now(),
        });
        let nid = self.graph.add_node(node);

        // Add DERIVED_FROM edge: record → artifact
        self.graph.add_edge(GraphEdge::new(
            nid,
            source_artifact_nid,
            EdgeType::DerivedFrom,
        ));

        nid
    }

    /// Add a network identity node.
    pub fn add_network_identity(
        &mut self,
        ssid: &str,
        bssid: Option<&str>,
        security: oracle_core::types::SecurityProtocol,
        source_count: usize,
    ) -> NodeId {
        let node = GraphNode::network_identity(NetworkIdentityNode {
            ssid: ssid.to_string(),
            bssid: bssid.map(|s| s.to_string()),
            security,
            source_count,
        });
        self.graph.add_node(node)
    }

    /// Add an event node.
    pub fn add_event(
        &mut self,
        description: &str,
        start_time: Option<chrono::DateTime<chrono::Utc>>,
        end_time: Option<chrono::DateTime<chrono::Utc>>,
        role: &str,
        confidence: f64,
    ) -> NodeId {
        let node = GraphNode::event(EventNode {
            description: description.to_string(),
            start_time,
            end_time,
            role: role.to_string(),
            confidence,
        });
        self.graph.add_node(node)
    }

    /// Add a finding node.
    pub fn add_finding(
        &mut self,
        statement: &str,
        classification: ConfidenceClassification,
        confidence_score: f64,
    ) -> NodeId {
        let node = GraphNode::finding(FindingNode {
            statement: statement.to_string(),
            classification,
            confidence_score,
            examiner_approved: false,
            examiner_notes: None,
            generated_at: Utc::now(),
        });
        self.graph.add_node(node)
    }

    /// Link a record/artifact to a network identity via IDENTIFIED_AS.
    pub fn link_identified_as(&mut self, source: NodeId, network: NodeId) {
        self.graph.add_edge(GraphEdge::new(
            source,
            network,
            EdgeType::IdentifiedAs,
        ));
    }

    /// Link two nodes with a CORROBORATES edge.
    pub fn link_corroborates(&mut self, supporter: NodeId, supported: NodeId, weight: f64) {
        self.graph.add_edge(
            GraphEdge::new(supporter, supported, EdgeType::Corroborates)
                .with_weight(weight),
        );
    }

    /// Link two nodes with a CONTRADICTS edge.
    pub fn link_contradicts(
        &mut self,
        contradicting: NodeId,
        contradicted: NodeId,
        rationale: &str,
    ) {
        self.graph.add_edge(
            GraphEdge::new(contradicting, contradicted, EdgeType::Contradicts)
                .with_rationale(rationale),
        );
    }

    /// Link an event to a timeline via PART_OF.
    pub fn link_part_of(&mut self, event: NodeId, timeline: NodeId) {
        self.graph.add_edge(GraphEdge::new(
            event,
            timeline,
            EdgeType::PartOf,
        ));
    }

    /// Consume the builder and return the finalized graph.
    pub fn build(self) -> EvidenceGraph {
        self.graph
    }
}

impl Default for EvidenceGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle_core::types::SecurityProtocol;

    #[test]
    fn test_builder_full_chain() {
        let mut builder = EvidenceGraphBuilder::new();

        // Add device
        let _device = builder.add_device(
            InvestigationId::new(),
            "samsung",
            "SM-S928B",
            "14",
            "R5CR30ABCDE",
        );

        // Add artifact
        let artifact_id = ArtifactId::new();
        let artifact = builder.add_artifact(
            artifact_id,
            "/data/misc/wifi/WifiConfigStore.xml",
            "abcdef",
            4096,
            ArtifactClass::WifiConfigStore,
        );

        // Add parsed record linked to artifact
        let record = builder.add_parsed_record(
            RecordId::new(),
            "wifi_config_parser",
            "1.0.0",
            artifact_id,
            artifact,
            "HomeNetwork configuration",
        );

        // Add network identity
        let network = builder.add_network_identity(
            "HomeNetwork",
            Some("AA:BB:CC:DD:EE:FF"),
            SecurityProtocol::Wpa2Psk,
            2,
        );

        // Link record to network
        builder.link_identified_as(record, network);

        // Add finding
        let finding = builder.add_finding(
            "Device was configured to connect to HomeNetwork",
            ConfidenceClassification::High,
            0.88,
        );

        // Corroborate finding
        builder.link_corroborates(record, finding, 0.9);

        let graph = builder.build();
        assert_eq!(graph.node_count(), 5);
        assert!(graph.edge_count() >= 3); // DerivedFrom + IdentifiedAs + Corroborates
    }
}
