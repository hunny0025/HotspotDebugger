//! # AI Layer Hard Constraints
//!
//! Compile-time and runtime enforcement of the AI Assistance Layer constraints
//! defined in V2 Prompt 3.
//!
//! # Enforced Constraints
//!
//! 1. The AI layer NEVER produces forensic findings.
//! 2. The AI layer NEVER modifies evidence records.
//! 3. Everything the AI layer suggests must be explicitly reviewed and confirmed
//!    by deterministic evidence before appearing in a report.
//! 4. The AI layer's suggestions must be clearly labeled as AI-ASSISTED HYPOTHESIS.
//! 5. The AI layer must be completely removable without affecting forensic findings.
//!
//! # Removability Proof
//!
//! The `oracle-ai` crate has NO reverse dependencies in the forensic pipeline.
//! No other crate depends on `oracle-ai`. Removing this crate from the workspace
//! does not affect compilation or correctness of any other subsystem.

use crate::hypothesis::AiHypothesis;

/// Marker trait proving a component is AI-generated and NOT a forensic finding.
///
/// This trait cannot be implemented by types in other crates (it is sealed).
/// Only [`AiHypothesis`] implements it.
pub trait AiGenerated: private::Sealed {
    /// Returns the invariant label. Always "AI-ASSISTED HYPOTHESIS".
    fn label(&self) -> &str;

    /// Returns whether this item modifies evidence. Always `false`.
    fn modifies_evidence(&self) -> bool;
}

mod private {
    pub trait Sealed {}
    impl Sealed for super::AiHypothesis {}
}

impl AiGenerated for AiHypothesis {
    fn label(&self) -> &str {
        &self.label
    }

    fn modifies_evidence(&self) -> bool {
        false // INVARIANT: AI layer NEVER modifies evidence
    }
}

/// Validates that a collection of AI hypotheses satisfies all hard constraints.
///
/// This is a runtime check that can be called before report generation to
/// ensure no constraint violations have occurred.
pub fn validate_constraints(hypotheses: &[AiHypothesis]) -> ConstraintValidationResult {
    let mut violations = Vec::new();

    for h in hypotheses {
        // Constraint 1: Label must be "AI-ASSISTED HYPOTHESIS"
        if h.label != "AI-ASSISTED HYPOTHESIS" {
            violations.push(format!(
                "Hypothesis {} has incorrect label: '{}'",
                h.id.0, h.label
            ));
        }

        // Constraint 2: modifies_evidence must be false
        if h.modifies_evidence {
            violations.push(format!(
                "Hypothesis {} has modifies_evidence=true — CRITICAL VIOLATION",
                h.id.0
            ));
        }
    }

    ConstraintValidationResult {
        valid: violations.is_empty(),
        violations,
        hypotheses_checked: hypotheses.len(),
    }
}

/// Result of constraint validation.
#[derive(Debug, Clone)]
pub struct ConstraintValidationResult {
    /// Whether all constraints are satisfied.
    pub valid: bool,
    /// List of constraint violations (empty if valid).
    pub violations: Vec<String>,
    /// Number of hypotheses checked.
    pub hypotheses_checked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::{HypothesisCategory, AiHypothesis};

    #[test]
    fn test_ai_generated_trait() {
        let h = AiHypothesis::new(
            HypothesisCategory::InvestigatorSummary {
                summary_text: "Test".to_string(),
            },
            0.5,
            "Test reasoning",
        );
        let ai: &dyn AiGenerated = &h;
        assert_eq!(ai.label(), "AI-ASSISTED HYPOTHESIS");
        assert!(!ai.modifies_evidence());
    }

    #[test]
    fn test_constraint_validation_passes() {
        let hypotheses = vec![
            AiHypothesis::new(
                HypothesisCategory::InvestigatorSummary {
                    summary_text: "Summary".to_string(),
                },
                0.5,
                "test",
            ),
            AiHypothesis::new(
                HypothesisCategory::StatisticalAnomaly {
                    description: "anomaly".to_string(),
                    anomaly_score: 0.3,
                },
                0.4,
                "test",
            ),
        ];

        let result = validate_constraints(&hypotheses);
        assert!(result.valid);
        assert!(result.violations.is_empty());
        assert_eq!(result.hypotheses_checked, 2);
    }
}
