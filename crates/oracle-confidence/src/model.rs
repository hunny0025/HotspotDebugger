//! # Confidence Model v2.0 Documentation
//!
//! Formal definition of the ORACLE Confidence Scoring Model V2. This module
//! serves as both executable documentation and the authoritative source
//! of truth for all scoring parameters.
//!
//! # Model Overview
//!
//! The confidence score quantifies how much weight a forensic examiner or
//! court should assign to a particular finding. It is a deterministic value
//! in the range `[0.0, 1.0]` computed from the formula:
//!
//! ```text
//! C_final = max(0.0, min(1.0, ((W_SR * S_R + W_CS * C_S) * T_T * A_V * C_V * (1.0 - A_F)) - C_P))
//! ```
//!
//! # Determinism Guarantee
//!
//! Given identical inputs, the scoring engine MUST produce bit-identical
//! output. No randomness, no floating-point non-determinism (all operations
//! use ordered comparisons), no external state.

use serde::{Deserialize, Serialize};

/// The current model version string. Embedded in every score output.
pub const MODEL_VERSION: &str = "2.0.0";

/// Factor weights.
pub const WEIGHT_SOURCE_RELIABILITY: f64 = 0.60;
pub const WEIGHT_CORROBORATION: f64 = 0.40;

/// Formal model documentation for inclusion in forensic reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDocumentation {
    pub version: String,
    pub factor_weights: Vec<FactorWeight>,
    pub methodology_summary: String,
}

/// A single factor weight entry for documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorWeight {
    pub factor_name: String,
    pub weight: f64,
    pub description: String,
}

impl ModelDocumentation {
    /// Generate the v2.0 model documentation.
    pub fn v2() -> Self {
        ModelDocumentation {
            version: MODEL_VERSION.to_string(),
            factor_weights: vec![
                FactorWeight {
                    factor_name: "Source Reliability (W_SR)".to_string(),
                    weight: WEIGHT_SOURCE_RELIABILITY,
                    description: "Baseline reliability of the primary artifact class (e.g., SQLite configs = 1.00, XML configs = 0.95, kernel logs = 0.85, logs = 0.70)."
                        .to_string(),
                },
                FactorWeight {
                    factor_name: "Corroboration (W_CS)".to_string(),
                    weight: WEIGHT_CORROBORATION,
                    description: "Number of independent confirming sources. Calculated as min(1.0, (N - 1) / 3)."
                        .to_string(),
                },
            ],
            methodology_summary: "The ORACLE Confidence Model v2.0 calculates a base score using \
                Source Reliability (60%) and Corroboration (40%). This base is scaled by: \
                Timestamp Trust Factor (T_T: 1.0, 0.8, or 0.3), Volatility Factor (A_V: 1.0, 0.8, or 0.5), \
                Capability Validation (C_V: 1.0 or 0.0), and (1.0 - Anti-Forensics Penalty). Finally, \
                Contradiction Penalties (C_P) are subtracted directly. The score is clamped to [0.0, 1.0]."
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weights_sum_to_one() {
        let sum = WEIGHT_SOURCE_RELIABILITY + WEIGHT_CORROBORATION;
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Factor weights must sum to 1.0, got {}",
            sum
        );
    }

    #[test]
    fn test_model_version() {
        assert_eq!(MODEL_VERSION, "2.0.0");
    }

    #[test]
    fn test_documentation_generation() {
        let doc = ModelDocumentation::v2();
        assert_eq!(doc.version, "2.0.0");
        assert_eq!(doc.factor_weights.len(), 2);
        assert!(!doc.methodology_summary.is_empty());
    }
}
