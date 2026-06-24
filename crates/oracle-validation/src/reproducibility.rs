//! # Investigation Reproducibility Certificate
//!
//! Generates cryptographically verifiable proofs of analysis determinism.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityCertificate {
    pub investigation_id: String,
    pub generated_at: DateTime<Utc>,
    pub oracle_version: String,
    pub initial_evidence_hash: String,
    pub final_graph_hash: String,
    pub certificate_hash: String,
}

pub struct CertificateGenerator;

impl CertificateGenerator {
    pub fn generate(
        investigation_id: &str,
        oracle_version: &str,
        evidence_hash: &str,
        graph_hash: &str,
    ) -> ReproducibilityCertificate {
        let mut hasher = Sha256::new();
        hasher.update(investigation_id.as_bytes());
        hasher.update(evidence_hash.as_bytes());
        hasher.update(graph_hash.as_bytes());
        let result = hasher.finalize();
        let cert_hash = hex::encode(result);

        ReproducibilityCertificate {
            investigation_id: investigation_id.to_string(),
            generated_at: Utc::now(),
            oracle_version: oracle_version.to_string(),
            initial_evidence_hash: evidence_hash.to_string(),
            final_graph_hash: graph_hash.to_string(),
            certificate_hash: cert_hash,
        }
    }
}
