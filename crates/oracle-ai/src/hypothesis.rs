//! # AI-Assisted Hypothesis System
//!
//! All AI layer outputs are wrapped in [`AiHypothesis`] which is explicitly
//! labeled as `AI-ASSISTED HYPOTHESIS` in all serialized outputs.
//!
//! # Hard Constraints (enforced by type system)
//!
//! - AI hypotheses have NO path to become forensic findings without examiner review
//! - AI hypotheses carry a `promoted` field that defaults to `false`
//! - Promotion requires an examiner identity and written justification
//! - Reports MUST render AI hypotheses with the `AI-ASSISTED HYPOTHESIS` prefix

use chrono::{DateTime, Utc};
use oracle_core::types::ArtifactClass;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for an AI hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HypothesisId(pub Uuid);

impl HypothesisId {
    pub fn new() -> Self {
        HypothesisId(Uuid::new_v4())
    }
}

impl Default for HypothesisId {
    fn default() -> Self {
        Self::new()
    }
}

/// The category of AI-generated hypothesis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HypothesisCategory {
    /// A previously unknown artifact pattern was detected.
    UnknownArtifactPattern {
        detected_path: String,
        suspected_class: Option<ArtifactClass>,
    },
    /// An anomaly that rule-based systems would miss.
    StatisticalAnomaly {
        description: String,
        anomaly_score: f64,
    },
    /// A suggested correlation between evidence items.
    SuggestedCorrelation {
        item_a_description: String,
        item_b_description: String,
        correlation_basis: String,
    },
    /// An identified OEM-specific variation not in the known registry.
    OemVariationDetected {
        manufacturer: String,
        variation_description: String,
    },
    /// A natural-language summary generated for investigator review.
    InvestigatorSummary {
        summary_text: String,
    },
}

/// The promotion status of an AI hypothesis.
///
/// This is the boundary protocol between Layer 3 (AI) and Layer 2 (Probabilistic).
/// A hypothesis CANNOT become a finding without passing through this gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionStatus {
    /// Default: The hypothesis has not been reviewed.
    Pending,
    /// An examiner reviewed and approved promotion to probabilistic candidate.
    PromotedToProbabilistic {
        examiner_name: String,
        justification: String,
        promoted_at: DateTime<Utc>,
    },
    /// An examiner reviewed and rejected the hypothesis.
    Rejected {
        examiner_name: String,
        reason: String,
        rejected_at: DateTime<Utc>,
    },
    /// The hypothesis was confirmed by deterministic evidence and promoted
    /// to a forensic finding. This requires BOTH examiner approval AND
    /// deterministic corroboration.
    ConfirmedByDeterministicEvidence {
        examiner_name: String,
        corroborating_evidence_description: String,
        confirmed_at: DateTime<Utc>,
    },
}

/// An AI-generated hypothesis. Every instance is explicitly labeled as
/// `AI-ASSISTED HYPOTHESIS` in its display representation.
///
/// # Invariants
///
/// - The `label` field is always `"AI-ASSISTED HYPOTHESIS"` — it cannot be
///   constructed with any other value.
/// - The `promotion` field defaults to `Pending`.
/// - The `modifies_evidence` field is always `false` — the AI layer NEVER
///   modifies evidence records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiHypothesis {
    /// Unique identifier.
    pub id: HypothesisId,
    /// Invariant label — always "AI-ASSISTED HYPOTHESIS".
    pub label: String,
    /// The hypothesis category and details.
    pub category: HypothesisCategory,
    /// Confidence in the hypothesis (0.0–1.0). NOT a forensic confidence score.
    pub ai_confidence: f64,
    /// The promotion status (boundary protocol).
    pub promotion: PromotionStatus,
    /// This is always `false`. AI NEVER modifies evidence records.
    pub modifies_evidence: bool,
    /// When this hypothesis was generated.
    pub generated_at: DateTime<Utc>,
    /// Human-readable explanation of how this hypothesis was derived.
    pub reasoning: String,
}

impl AiHypothesis {
    /// Create a new AI hypothesis. The label is automatically set to
    /// "AI-ASSISTED HYPOTHESIS" and `modifies_evidence` is always `false`.
    pub fn new(
        category: HypothesisCategory,
        ai_confidence: f64,
        reasoning: &str,
    ) -> Self {
        AiHypothesis {
            id: HypothesisId::new(),
            label: "AI-ASSISTED HYPOTHESIS".to_string(),
            category,
            ai_confidence: ai_confidence.clamp(0.0, 1.0),
            promotion: PromotionStatus::Pending,
            modifies_evidence: false, // INVARIANT: always false
            generated_at: Utc::now(),
            reasoning: reasoning.to_string(),
        }
    }

    /// Promote this hypothesis to probabilistic candidate status.
    /// Requires examiner identity and written justification.
    pub fn promote_to_probabilistic(
        &mut self,
        examiner_name: &str,
        justification: &str,
    ) {
        self.promotion = PromotionStatus::PromotedToProbabilistic {
            examiner_name: examiner_name.to_string(),
            justification: justification.to_string(),
            promoted_at: Utc::now(),
        };
    }

    /// Reject this hypothesis after examiner review.
    pub fn reject(&mut self, examiner_name: &str, reason: &str) {
        self.promotion = PromotionStatus::Rejected {
            examiner_name: examiner_name.to_string(),
            reason: reason.to_string(),
            rejected_at: Utc::now(),
        };
    }

    /// Confirm this hypothesis with deterministic evidence.
    /// This is the FINAL promotion gate — requires both examiner approval
    /// AND a description of the deterministic evidence that confirms it.
    pub fn confirm_with_evidence(
        &mut self,
        examiner_name: &str,
        evidence_description: &str,
    ) {
        self.promotion = PromotionStatus::ConfirmedByDeterministicEvidence {
            examiner_name: examiner_name.to_string(),
            corroborating_evidence_description: evidence_description.to_string(),
            confirmed_at: Utc::now(),
        };
    }

    /// Check if this hypothesis has been promoted past pending status.
    pub fn is_reviewed(&self) -> bool {
        !matches!(self.promotion, PromotionStatus::Pending)
    }

    /// Check if this hypothesis has been confirmed by deterministic evidence.
    pub fn is_confirmed(&self) -> bool {
        matches!(self.promotion, PromotionStatus::ConfirmedByDeterministicEvidence { .. })
    }
}

impl std::fmt::Display for AiHypothesis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[AI-ASSISTED HYPOTHESIS] (confidence: {:.0}%) {}",
            self.ai_confidence * 100.0,
            self.reasoning
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypothesis_label_invariant() {
        let h = AiHypothesis::new(
            HypothesisCategory::StatisticalAnomaly {
                description: "Unusual pattern".to_string(),
                anomaly_score: 0.8,
            },
            0.7,
            "Pattern detected in battery stats",
        );
        assert_eq!(h.label, "AI-ASSISTED HYPOTHESIS");
        assert!(!h.modifies_evidence);
        assert!(matches!(h.promotion, PromotionStatus::Pending));
    }

    #[test]
    fn test_hypothesis_promotion_flow() {
        let mut h = AiHypothesis::new(
            HypothesisCategory::SuggestedCorrelation {
                item_a_description: "WiFi log entry".to_string(),
                item_b_description: "Battery drain spike".to_string(),
                correlation_basis: "Temporal proximity".to_string(),
            },
            0.6,
            "Battery drain coincides with WiFi radio activation",
        );

        assert!(!h.is_reviewed());
        assert!(!h.is_confirmed());

        // Examiner promotes to probabilistic
        h.promote_to_probabilistic("Dr. Smith", "Temporal correlation is plausible");
        assert!(h.is_reviewed());
        assert!(!h.is_confirmed());

        // Examiner confirms with deterministic evidence
        h.confirm_with_evidence(
            "Dr. Smith",
            "DHCP lease record confirms WiFi connection at same timestamp",
        );
        assert!(h.is_confirmed());
        // modifies_evidence must STILL be false
        assert!(!h.modifies_evidence);
    }

    #[test]
    fn test_hypothesis_rejection() {
        let mut h = AiHypothesis::new(
            HypothesisCategory::UnknownArtifactPattern {
                detected_path: "/data/misc/wifi/unknown.db".to_string(),
                suspected_class: None,
            },
            0.3,
            "Unrecognized database file in WiFi directory",
        );

        h.reject("Dr. Jones", "File is a standard Android system cache, not forensically relevant");
        assert!(h.is_reviewed());
        assert!(!h.is_confirmed());
    }

    #[test]
    fn test_display_format() {
        let h = AiHypothesis::new(
            HypothesisCategory::InvestigatorSummary {
                summary_text: "Device connected to 5 networks".to_string(),
            },
            0.9,
            "Summarized from 12 artifact records",
        );
        let display = format!("{}", h);
        assert!(display.starts_with("[AI-ASSISTED HYPOTHESIS]"));
    }

    #[test]
    fn test_confidence_clamped() {
        let h = AiHypothesis::new(
            HypothesisCategory::StatisticalAnomaly {
                description: "test".to_string(),
                anomaly_score: 1.5,
            },
            1.5, // Should be clamped to 1.0
            "test",
        );
        assert_eq!(h.ai_confidence, 1.0);
    }
}
