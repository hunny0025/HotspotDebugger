//! # Evidence Completeness Score
//!
//! Rates how complete the recovered evidence is relative to what would
//! normally exist on a healthy, unmodified device of this type.
//! A low completeness score may indicate anti-forensics activity,
//! data loss, or acquisition limitations.

use oracle_core::types::ArtifactClass;
use serde::{Deserialize, Serialize};

/// Expected artifact presence on a standard Android device by API level range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedArtifact {
    /// The artifact class.
    pub artifact_class: ArtifactClass,
    /// Minimum Android API level where this artifact is expected.
    pub min_api: u32,
    /// Maximum Android API level where this artifact is expected (inclusive).
    /// Use `u32::MAX` for "still present in current versions".
    pub max_api: u32,
    /// Relative importance weight (0.0–1.0). Critical artifacts weigh more.
    pub importance: f64,
    /// Whether this artifact is always present or only sometimes.
    pub mandatory: bool,
}

/// The result of an evidence completeness assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletenessResult {
    /// The overall completeness score (0.0–1.0).
    pub score: f64,
    /// Number of expected artifacts that were found.
    pub found_count: usize,
    /// Number of expected artifacts that were missing.
    pub missing_count: usize,
    /// Number of expected artifacts that were inaccessible.
    pub inaccessible_count: usize,
    /// Total number of artifacts expected for this device type.
    pub expected_count: usize,
    /// Details of missing artifacts and their forensic significance.
    pub missing_artifacts: Vec<MissingArtifactDetail>,
    /// Human-readable assessment for the report.
    pub report_language: String,
}

/// Detail about a missing artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingArtifactDetail {
    pub artifact_class: ArtifactClass,
    pub importance: f64,
    pub mandatory: bool,
    pub possible_reasons: Vec<String>,
}

/// Computes evidence completeness against a device-specific baseline.
pub struct CompletenessScorer;

impl CompletenessScorer {
    /// Get the default expected artifacts for a standard Android device.
    pub fn default_expectations() -> Vec<ExpectedArtifact> {
        vec![
            ExpectedArtifact {
                artifact_class: ArtifactClass::BuildProp,
                min_api: 1, max_api: u32::MAX,
                importance: 1.0, mandatory: true,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::WifiConfigStore,
                min_api: 26, max_api: u32::MAX,
                importance: 0.95, mandatory: true,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::WpaSupplicant,
                min_api: 1, max_api: 29,
                importance: 0.90, mandatory: true,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::DhcpLeases,
                min_api: 1, max_api: u32::MAX,
                importance: 0.80, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::ConnectivityLogs,
                min_api: 21, max_api: u32::MAX,
                importance: 0.75, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::BatteryStats,
                min_api: 21, max_api: u32::MAX,
                importance: 0.60, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::KernelLogs,
                min_api: 1, max_api: u32::MAX,
                importance: 0.50, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::NetworkPolicy,
                min_api: 23, max_api: u32::MAX,
                importance: 0.40, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::HostapdLogs,
                min_api: 1, max_api: u32::MAX,
                importance: 0.30, mandatory: false,
            },
            ExpectedArtifact {
                artifact_class: ArtifactClass::DnsCache,
                min_api: 1, max_api: u32::MAX,
                importance: 0.20, mandatory: false,
            },
        ]
    }

    /// Compute the completeness score.
    ///
    /// # Arguments
    /// * `api_level` — The device's Android API level.
    /// * `found` — Artifact classes that were successfully recovered.
    /// * `inaccessible` — Artifact classes that exist but couldn't be read.
    pub fn compute(
        api_level: u32,
        found: &[ArtifactClass],
        inaccessible: &[ArtifactClass],
    ) -> CompletenessResult {
        let expectations = Self::default_expectations();

        let applicable: Vec<&ExpectedArtifact> = expectations
            .iter()
            .filter(|e| api_level >= e.min_api && api_level <= e.max_api)
            .collect();

        let expected_count = applicable.len();
        let mut found_count = 0;
        let mut inaccessible_count = 0;
        let mut missing_artifacts = Vec::new();
        let mut weighted_found = 0.0;
        let mut total_weight = 0.0;

        for expected in &applicable {
            total_weight += expected.importance;

            if found.contains(&expected.artifact_class) {
                found_count += 1;
                weighted_found += expected.importance;
            } else if inaccessible.contains(&expected.artifact_class) {
                inaccessible_count += 1;
                // Inaccessible counts as partial — the artifact exists but we couldn't read it
                weighted_found += expected.importance * 0.3;
            } else {
                let reasons = Self::possible_missing_reasons(&expected.artifact_class, api_level);
                missing_artifacts.push(MissingArtifactDetail {
                    artifact_class: expected.artifact_class,
                    importance: expected.importance,
                    mandatory: expected.mandatory,
                    possible_reasons: reasons,
                });
            }
        }

        let score = if total_weight > 0.0 {
            (weighted_found / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let missing_count = missing_artifacts.len();

        let report_language = Self::generate_report_language(
            score, found_count, missing_count, inaccessible_count, expected_count, &missing_artifacts,
        );

        CompletenessResult {
            score,
            found_count,
            missing_count,
            inaccessible_count,
            expected_count,
            missing_artifacts,
            report_language,
        }
    }

    fn possible_missing_reasons(class: &ArtifactClass, api_level: u32) -> Vec<String> {
        let mut reasons = Vec::new();
        match class {
            ArtifactClass::WpaSupplicant if api_level >= 30 => {
                reasons.push("wpa_supplicant.conf deprecated in Android 11+".to_string());
            }
            ArtifactClass::KernelLogs => {
                reasons.push("Kernel ring buffer is volatile; lost on reboot".to_string());
                reasons.push("SELinux may block access without root".to_string());
            }
            ArtifactClass::DhcpLeases => {
                reasons.push("Device may not have connected to any DHCP networks".to_string());
            }
            ArtifactClass::HostapdLogs => {
                reasons.push("Hotspot may never have been activated".to_string());
            }
            ArtifactClass::DnsCache => {
                reasons.push("DNS cache is volatile and cleared frequently".to_string());
            }
            _ => {
                reasons.push("Artifact may have been deleted or is inaccessible".to_string());
            }
        }
        reasons
    }

    fn generate_report_language(
        score: f64,
        found: usize,
        missing: usize,
        inaccessible: usize,
        expected: usize,
        missing_details: &[MissingArtifactDetail],
    ) -> String {
        let assessment = if score >= 0.90 {
            "Excellent — the evidence set is substantially complete"
        } else if score >= 0.70 {
            "Good — most expected artifacts were recovered"
        } else if score >= 0.50 {
            "Partial — significant artifacts are missing"
        } else {
            "Poor — the majority of expected artifacts are missing, which may \
             indicate anti-forensics activity, severe acquisition limitations, \
             or device reset"
        };

        let mandatory_missing: Vec<_> = missing_details.iter()
            .filter(|m| m.mandatory)
            .collect();

        let mut report = format!(
            "Evidence Completeness Assessment: {:.0}% ({}/{}). {}. \
             {} artifacts found, {} missing, {} inaccessible.",
            score * 100.0, found, expected, assessment,
            found, missing, inaccessible
        );

        if !mandatory_missing.is_empty() {
            report.push_str(&format!(
                " WARNING: {} mandatory artifact(s) are missing, which is forensically significant.",
                mandatory_missing.len()
            ));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_completeness() {
        let found = vec![
            ArtifactClass::BuildProp,
            ArtifactClass::WifiConfigStore,
            ArtifactClass::DhcpLeases,
            ArtifactClass::ConnectivityLogs,
            ArtifactClass::BatteryStats,
            ArtifactClass::KernelLogs,
            ArtifactClass::NetworkPolicy,
            ArtifactClass::HostapdLogs,
            ArtifactClass::DnsCache,
        ];
        let result = CompletenessScorer::compute(34, &found, &[]);
        assert!(result.score > 0.90);
        assert!(result.missing_artifacts.is_empty());
    }

    #[test]
    fn test_partial_completeness() {
        let found = vec![
            ArtifactClass::BuildProp,
            ArtifactClass::WifiConfigStore,
        ];
        let result = CompletenessScorer::compute(34, &found, &[]);
        assert!(result.score > 0.0 && result.score < 1.0);
        assert!(!result.missing_artifacts.is_empty());
    }

    #[test]
    fn test_empty_completeness() {
        let result = CompletenessScorer::compute(34, &[], &[]);
        assert!(result.score < 0.1);
        assert!(result.report_language.contains("Poor"));
    }

    #[test]
    fn test_inaccessible_partial_credit() {
        let inaccessible = vec![ArtifactClass::WifiConfigStore];
        let result_without = CompletenessScorer::compute(34, &[], &[]);
        let result_with = CompletenessScorer::compute(34, &[], &inaccessible);
        // Inaccessible should give partial credit
        assert!(result_with.score > result_without.score);
    }
}
