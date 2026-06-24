//! # Confidence Score Computation Engine V2
//!
//! Deterministic computation of confidence scores based on the Confidence
//! Model v2.0. Given a set of scoring inputs, produces a versioned,
//! reproducible score with full factor breakdown.

use chrono::{DateTime, Utc};
use oracle_core::types::{ArtifactClass, ConfidenceClassification};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{MODEL_VERSION, WEIGHT_CORROBORATION, WEIGHT_SOURCE_RELIABILITY};

// ──────────────────────────────────────────────────────────────────────────────
// Score Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a computed confidence score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScoreId(pub Uuid);

impl ScoreId {
    pub fn new() -> Self {
        ScoreId(Uuid::new_v4())
    }
}

impl Default for ScoreId {
    fn default() -> Self {
        Self::new()
    }
}

/// Timestamp trust classifications for SCM / Confidence Scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampTrust {
    VerifiedNtp,
    UnverifiedLocal,
    Manipulated,
}

impl TimestampTrust {
    pub fn factor_value(&self) -> f64 {
        match self {
            TimestampTrust::VerifiedNtp => 1.0,
            TimestampTrust::UnverifiedLocal => 0.8,
            TimestampTrust::Manipulated => 0.3,
        }
    }
}

/// Volatility classification of evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactVolatility {
    Persistent,
    SemiVolatile,
    Volatile,
}

impl ArtifactVolatility {
    pub fn factor_value(&self) -> f64 {
        match self {
            ArtifactVolatility::Persistent => 1.0,
            ArtifactVolatility::SemiVolatile => 0.8,
            ArtifactVolatility::Volatile => 0.5,
        }
    }
}

/// Inputs to the confidence scoring engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringInput {
    /// The artifact class of the primary evidence source.
    pub primary_artifact_class: ArtifactClass,
    /// Number of independent sources corroborating the finding.
    pub corroboration_count: usize,
    /// Clock state trust level.
    pub timestamp_trust: TimestampTrust,
    /// File persistence/volatility level.
    pub volatility: ArtifactVolatility,
    /// Whether hardware capabilities match this record.
    pub hardware_validated: bool,
    /// Anti-forensics indicators penalty score (0.0 to 1.0).
    pub anti_forensics_penalty: f64,
    /// Contradictions direct penalty score.
    pub contradiction_penalty: f64,
}

/// The breakdown of individual factor scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorBreakdown {
    pub source_reliability: f64,
    pub corroboration: f64,
    pub timestamp_trust: f64,
    pub volatility: f64,
    pub hardware_validated: f64,
    pub anti_forensics: f64,
    pub contradiction: f64,
}

/// A fully computed, versioned confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceScore {
    /// Unique identifier.
    pub id: ScoreId,
    /// The model version that produced this score.
    pub model_version: String,
    /// The final composite score (0.0–1.0).
    pub score: f64,
    /// The court-facing classification derived from the score.
    pub classification: ConfidenceClassification,
    /// Full factor breakdown.
    pub factors: FactorBreakdown,
    /// Raw base score (weighted reliability + corroboration) before scaling.
    pub raw_base_score: f64,
    /// When this score was computed.
    pub computed_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Score History
// ──────────────────────────────────────────────────────────────────────────────

/// Tracks historical score versions when a finding is re-scored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreHistory {
    pub versions: Vec<ConfidenceScore>,
}

impl ScoreHistory {
    pub fn new(initial: ConfidenceScore) -> Self {
        ScoreHistory {
            versions: vec![initial],
        }
    }

    pub fn add_version(&mut self, score: ConfidenceScore) {
        self.versions.insert(0, score);
    }

    pub fn current(&self) -> Option<&ConfidenceScore> {
        self.versions.first()
    }

    pub fn revision_count(&self) -> usize {
        self.versions.len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Examiner Override
// ──────────────────────────────────────────────────────────────────────────────

/// An examiner override that adjusts a confidence score with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExaminerOverride {
    pub original_score: f64,
    pub adjusted_score: f64,
    pub justification: String,
    pub examiner_name: String,
    pub applied_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Scoring Engine
// ──────────────────────────────────────────────────────────────────────────────

/// Deterministic confidence scoring engine V2.
pub struct ScoringEngine;

impl ScoringEngine {
    /// Compute a confidence score from the given inputs.
    pub fn compute(input: &ScoringInput) -> ConfidenceScore {
        let source_reliability = Self::compute_source_reliability(input.primary_artifact_class);
        let corroboration = Self::compute_corroboration(input.corroboration_count);
        let t_t = input.timestamp_trust.factor_value();
        let a_v = input.volatility.factor_value();
        let c_v = if input.hardware_validated { 1.0 } else { 0.0 };
        let a_f = input.anti_forensics_penalty.clamp(0.0, 1.0);
        let c_p = input.contradiction_penalty.clamp(0.0, 1.0);

        let raw_base_score = (source_reliability * WEIGHT_SOURCE_RELIABILITY)
            + (corroboration * WEIGHT_CORROBORATION);

        let scaled = raw_base_score * t_t * a_v * c_v * (1.0 - a_f);
        let final_score = (scaled - c_p).clamp(0.0, 1.0);

        let classification = if c_p >= 0.40 && final_score < 0.50 {
            ConfidenceClassification::Contradicted
        } else {
            ConfidenceClassification::from_score(final_score)
        };

        ConfidenceScore {
            id: ScoreId::new(),
            model_version: MODEL_VERSION.to_string(),
            score: final_score,
            classification,
            factors: FactorBreakdown {
                source_reliability,
                corroboration,
                timestamp_trust: t_t,
                volatility: a_v,
                hardware_validated: c_v,
                anti_forensics: a_f,
                contradiction: c_p,
            },
            raw_base_score,
            computed_at: Utc::now(),
        }
    }

    /// Apply an examiner override to an existing score.
    pub fn apply_override(
        original: &ConfidenceScore,
        adjusted_score: f64,
        justification: &str,
        examiner_name: &str,
    ) -> (ConfidenceScore, ExaminerOverride) {
        let clamped = adjusted_score.clamp(0.0, 1.0);

        let override_record = ExaminerOverride {
            original_score: original.score,
            adjusted_score: clamped,
            justification: justification.to_string(),
            examiner_name: examiner_name.to_string(),
            applied_at: Utc::now(),
        };

        let new_score = ConfidenceScore {
            id: ScoreId::new(),
            model_version: original.model_version.clone(),
            score: clamped,
            classification: ConfidenceClassification::from_score(clamped),
            factors: original.factors.clone(),
            raw_base_score: original.raw_base_score,
            computed_at: Utc::now(),
        };

        (new_score, override_record)
    }

    // ── Factor Computations ─────────────────────────────────────────────

    /// Source reliability: baseline reliability from the artifact class taxonomy.
    fn compute_source_reliability(class: ArtifactClass) -> f64 {
        class.baseline_reliability()
    }

    /// Corroboration: logarithmic curve based on independent source count.
    fn compute_corroboration(source_count: usize) -> f64 {
        if source_count <= 1 {
            0.0
        } else {
            let n = source_count as f64;
            ((n - 1.0) / 3.0).min(1.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(
        class: ArtifactClass,
        sources: usize,
        contradiction_penalty: f64,
    ) -> ScoringInput {
        ScoringInput {
            primary_artifact_class: class,
            corroboration_count: sources,
            timestamp_trust: TimestampTrust::VerifiedNtp,
            volatility: ArtifactVolatility::Persistent,
            hardware_validated: true,
            anti_forensics_penalty: 0.0,
            contradiction_penalty,
        }
    }

    #[test]
    fn test_v2_high_confidence_scenario() {
        let input = make_input(ArtifactClass::WifiConfigStore, 4, 0.0);
        let score = ScoringEngine::compute(&input);

        assert!(score.score >= 0.95, "high-quality evidence should score >= 0.95, got {}", score.score);
        assert_eq!(score.classification, ConfidenceClassification::Definitive);
    }

    #[test]
    fn test_v2_unreliable_scenario_unrooted_single_source() {
        let mut input = make_input(ArtifactClass::Unknown, 1, 0.0);
        input.volatility = ArtifactVolatility::Volatile;
        let score = ScoringEngine::compute(&input);

        // Volatile and unknown reliability should scale down heavily
        assert!(score.score < 0.50, "should score < 0.50, got {}", score.score);
        assert_eq!(score.classification, ConfidenceClassification::Low);
    }

    #[test]
    fn test_v2_contradiction_applied() {
        let input_clean = make_input(ArtifactClass::WifiConfigStore, 3, 0.0);
        let input_contradicted = make_input(ArtifactClass::WifiConfigStore, 3, 0.5);

        let score_clean = ScoringEngine::compute(&input_clean);
        let score_contradicted = ScoringEngine::compute(&input_contradicted);

        assert!(score_contradicted.score < score_clean.score);
        assert_eq!(score_contradicted.classification, ConfidenceClassification::Contradicted);
    }
}
