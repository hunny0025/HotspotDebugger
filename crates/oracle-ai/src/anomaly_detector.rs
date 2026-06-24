//! # AI Anomaly Detector
//!
//! Pattern-based anomaly detection for discovering unknown artifact patterns,
//! OEM variations, and suspicious data that rule-based systems would miss.
//! All outputs are wrapped as [`AiHypothesis`] and NEVER treated as findings.

use oracle_core::types::ArtifactClass;
use serde::{Deserialize, Serialize};

use crate::hypothesis::{AiHypothesis, HypothesisCategory};

/// Statistics about a scanned filesystem for anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemStats {
    /// Paths that contain potentially forensic data but are not in the known registry.
    pub unknown_paths: Vec<UnknownPath>,
    /// Artifact files whose size deviates significantly from the norm.
    pub size_anomalies: Vec<SizeAnomaly>,
    /// Files whose modification timestamps are inconsistent with surrounding files.
    pub timestamp_anomalies: Vec<TimestampAnomalyRecord>,
}

/// An unknown path discovered during filesystem scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownPath {
    pub path: String,
    pub size_bytes: u64,
    pub looks_like_database: bool,
    pub looks_like_config: bool,
    pub looks_like_log: bool,
}

/// A file whose size is anomalous for its type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeAnomaly {
    pub path: String,
    pub artifact_class: ArtifactClass,
    pub actual_size: u64,
    pub expected_range: (u64, u64),
}

/// A file whose modification timestamp is anomalous.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampAnomalyRecord {
    pub path: String,
    pub file_mtime: String,
    pub anomaly_reason: String,
}

/// The AI Anomaly Detector scans filesystem statistics and generates hypotheses.
pub struct AnomalyDetector;

impl AnomalyDetector {
    /// Analyze filesystem statistics and generate AI hypotheses for anomalies.
    pub fn analyze(stats: &FilesystemStats) -> Vec<AiHypothesis> {
        let mut hypotheses = Vec::new();

        // Detect unknown artifact patterns
        for unknown in &stats.unknown_paths {
            if unknown.looks_like_database || unknown.looks_like_config || unknown.looks_like_log {
                let suspected_class = if unknown.looks_like_database {
                    Some(ArtifactClass::Unknown)
                } else {
                    None
                };

                let file_type = if unknown.looks_like_database {
                    "database"
                } else if unknown.looks_like_config {
                    "configuration"
                } else {
                    "log"
                };

                hypotheses.push(AiHypothesis::new(
                    HypothesisCategory::UnknownArtifactPattern {
                        detected_path: unknown.path.clone(),
                        suspected_class,
                    },
                    0.4,
                    &format!(
                        "Unknown {} file detected at '{}' ({} bytes). This may be an \
                         OEM-specific artifact not in the known path registry.",
                        file_type, unknown.path, unknown.size_bytes
                    ),
                ));
            }
        }

        // Detect size anomalies
        for anomaly in &stats.size_anomalies {
            let ratio = if anomaly.expected_range.1 > 0 {
                anomaly.actual_size as f64 / anomaly.expected_range.1 as f64
            } else {
                0.0
            };

            hypotheses.push(AiHypothesis::new(
                HypothesisCategory::StatisticalAnomaly {
                    description: format!(
                        "Artifact at '{}' is {:.1}x the expected maximum size",
                        anomaly.path, ratio
                    ),
                    anomaly_score: (ratio - 1.0).min(1.0).max(0.0),
                },
                0.3,
                &format!(
                    "File '{}' ({:?}) is {} bytes, but expected range is {}-{} bytes. \
                     This may indicate data accumulation, corruption, or tampering.",
                    anomaly.path,
                    anomaly.artifact_class,
                    anomaly.actual_size,
                    anomaly.expected_range.0,
                    anomaly.expected_range.1
                ),
            ));
        }

        // Detect timestamp anomalies
        for ts_anomaly in &stats.timestamp_anomalies {
            hypotheses.push(AiHypothesis::new(
                HypothesisCategory::StatisticalAnomaly {
                    description: format!(
                        "Timestamp anomaly on '{}': {}",
                        ts_anomaly.path, ts_anomaly.anomaly_reason
                    ),
                    anomaly_score: 0.5,
                },
                0.35,
                &format!(
                    "File '{}' has modification time {} which is anomalous: {}",
                    ts_anomaly.path, ts_anomaly.file_mtime, ts_anomaly.anomaly_reason
                ),
            ));
        }

        hypotheses
    }

    /// Detect potential OEM variations by comparing discovered paths
    /// against AOSP expected paths.
    pub fn detect_oem_variations(
        manufacturer: &str,
        discovered_paths: &[String],
        aosp_expected_paths: &[String],
    ) -> Vec<AiHypothesis> {
        let mut hypotheses = Vec::new();

        // Find paths that exist but are not in the AOSP expected set
        let unexpected: Vec<&String> = discovered_paths
            .iter()
            .filter(|p| !aosp_expected_paths.contains(p))
            .collect();

        if !unexpected.is_empty() {
            hypotheses.push(AiHypothesis::new(
                HypothesisCategory::OemVariationDetected {
                    manufacturer: manufacturer.to_string(),
                    variation_description: format!(
                        "{} non-AOSP paths found: {}",
                        unexpected.len(),
                        unexpected.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                },
                0.5,
                &format!(
                    "Device from manufacturer '{}' contains {} filesystem paths not present \
                     in the standard AOSP layout. These may be OEM-specific artifact locations \
                     that require custom parsing.",
                    manufacturer,
                    unexpected.len()
                ),
            ));
        }

        hypotheses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_path_hypothesis() {
        let stats = FilesystemStats {
            unknown_paths: vec![UnknownPath {
                path: "/data/misc/wifi/oem_config.db".to_string(),
                size_bytes: 8192,
                looks_like_database: true,
                looks_like_config: false,
                looks_like_log: false,
            }],
            size_anomalies: Vec::new(),
            timestamp_anomalies: Vec::new(),
        };

        let hypotheses = AnomalyDetector::analyze(&stats);
        assert_eq!(hypotheses.len(), 1);
        assert_eq!(hypotheses[0].label, "AI-ASSISTED HYPOTHESIS");
        assert!(!hypotheses[0].modifies_evidence);
    }

    #[test]
    fn test_oem_variation_detection() {
        let discovered = vec![
            "/data/misc/wifi/WifiConfigStore.xml".to_string(),
            "/data/misc/wifi/softap_config.xml".to_string(),
            "/data/misc/wifi/samsung_wifi_debug.log".to_string(),
        ];
        let aosp = vec![
            "/data/misc/wifi/WifiConfigStore.xml".to_string(),
            "/data/misc/wifi/softap_config.xml".to_string(),
        ];

        let hypotheses = AnomalyDetector::detect_oem_variations("samsung", &discovered, &aosp);
        assert_eq!(hypotheses.len(), 1);
        assert!(matches!(
            hypotheses[0].category,
            HypothesisCategory::OemVariationDetected { .. }
        ));
    }

    #[test]
    fn test_empty_stats_no_hypotheses() {
        let stats = FilesystemStats {
            unknown_paths: Vec::new(),
            size_anomalies: Vec::new(),
            timestamp_anomalies: Vec::new(),
        };
        let hypotheses = AnomalyDetector::analyze(&stats);
        assert!(hypotheses.is_empty());
    }
}
