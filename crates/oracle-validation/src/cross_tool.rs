//! # Cross-Tool Validation
//!
//! Comparison protocol for ORACLE vs other forensic tools (UFED, Oxygen, Magnet).

use serde::{Deserialize, Serialize};

/// Represents findings from an external tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalToolFindings {
    pub tool_name: String,
    pub tool_version: String,
    pub findings: Vec<String>,
}

/// Compares ORACLE findings with an external tool.
pub struct CrossToolValidator;

impl CrossToolValidator {
    pub fn compare(
        _oracle_findings: &[String],
        _external_findings: &ExternalToolFindings,
    ) -> CrossToolComparisonResult {
        // Mock comparison
        CrossToolComparisonResult {
            tool_name: _external_findings.tool_name.clone(),
            concordant_findings_count: 0,
            oracle_unique_count: 0,
            external_unique_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossToolComparisonResult {
    pub tool_name: String,
    pub concordant_findings_count: usize,
    pub oracle_unique_count: usize,
    pub external_unique_count: usize,
}
