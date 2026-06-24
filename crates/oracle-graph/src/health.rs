//! # Artifact Health Scoring
//!
//! Rates each artifact's integrity before it enters the parsing pipeline.
//! An artifact can be: Complete, Partial, Corrupted, or SuspiciouslyModified.
//! This pre-parse assessment affects downstream confidence scoring.

use oracle_core::types::ArtifactClass;
use serde::{Deserialize, Serialize};

/// Health classification of an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Artifact passes all integrity checks.
    Complete,
    /// Artifact is truncated or missing expected sections but is partially parseable.
    Partial,
    /// Artifact has structural corruption (invalid headers, broken encoding).
    Corrupted,
    /// Artifact shows patterns consistent with deliberate modification.
    SuspiciouslyModified,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Complete => write!(f, "COMPLETE"),
            HealthStatus::Partial => write!(f, "PARTIAL"),
            HealthStatus::Corrupted => write!(f, "CORRUPTED"),
            HealthStatus::SuspiciouslyModified => write!(f, "SUSPICIOUSLY_MODIFIED"),
        }
    }
}

/// A specific health check that was performed on an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Name of the check.
    pub check_name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Details about the check result.
    pub detail: String,
}

/// Complete health assessment of a single artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHealthReport {
    /// The artifact class being assessed.
    pub artifact_class: ArtifactClass,
    /// Overall health status.
    pub status: HealthStatus,
    /// Numeric health score (0.0–1.0).
    pub score: f64,
    /// Individual checks performed.
    pub checks: Vec<HealthCheck>,
    /// Confidence modifier this health status applies to downstream scoring.
    /// A corrupted artifact should reduce finding confidence.
    pub confidence_modifier: f64,
    /// Human-readable summary for reports.
    pub summary: String,
}

/// Performs health assessment on raw artifact bytes before parsing.
pub struct ArtifactHealthScorer;

impl ArtifactHealthScorer {
    /// Assess the health of an artifact.
    ///
    /// # Arguments
    /// * `artifact_class` — The classified type of artifact.
    /// * `raw_bytes` — The raw bytes of the artifact.
    /// * `expected_min_size` — Optional minimum expected file size in bytes.
    pub fn assess(
        artifact_class: ArtifactClass,
        raw_bytes: &[u8],
        expected_min_size: Option<u64>,
    ) -> ArtifactHealthReport {
        let mut checks = Vec::new();

        // Check 1: Non-empty
        let non_empty = !raw_bytes.is_empty();
        checks.push(HealthCheck {
            check_name: "Non-Empty".to_string(),
            passed: non_empty,
            detail: if non_empty {
                format!("{} bytes", raw_bytes.len())
            } else {
                "Artifact is empty (0 bytes)".to_string()
            },
        });

        // Check 2: Minimum size
        let min_size_ok = if let Some(min) = expected_min_size {
            let ok = raw_bytes.len() as u64 >= min;
            checks.push(HealthCheck {
                check_name: "Minimum Size".to_string(),
                passed: ok,
                detail: if ok {
                    format!("{} bytes >= {} minimum", raw_bytes.len(), min)
                } else {
                    format!("{} bytes < {} minimum — possible truncation", raw_bytes.len(), min)
                },
            });
            ok
        } else {
            true
        };

        // Check 3: Format-specific header validation
        let header_ok = Self::check_header(artifact_class, raw_bytes);
        checks.push(HealthCheck {
            check_name: "Header Validation".to_string(),
            passed: header_ok,
            detail: if header_ok {
                "File header matches expected format".to_string()
            } else {
                "File header does not match expected format".to_string()
            },
        });

        // Check 4: Null byte ratio (high ratio may indicate corruption)
        let null_ratio = Self::null_byte_ratio(raw_bytes);
        let null_ok = null_ratio < 0.5;
        checks.push(HealthCheck {
            check_name: "Null Byte Ratio".to_string(),
            passed: null_ok,
            detail: format!("{:.1}% null bytes", null_ratio * 100.0),
        });

        // Check 5: Suspicious patterns (all-zeros sections, repeated patterns)
        let suspicious_patterns = Self::detect_suspicious_patterns(raw_bytes);
        let no_suspicious = suspicious_patterns.is_empty();
        if !no_suspicious {
            for pattern in &suspicious_patterns {
                checks.push(HealthCheck {
                    check_name: "Suspicious Pattern".to_string(),
                    passed: false,
                    detail: pattern.clone(),
                });
            }
        }

        // Determine overall status
        let passed_count = checks.iter().filter(|c| c.passed).count();
        let total_checks = checks.len();

        let (status, score) = if !non_empty {
            (HealthStatus::Corrupted, 0.0)
        } else if !no_suspicious {
            (HealthStatus::SuspiciouslyModified, 0.3)
        } else if !header_ok || !null_ok {
            (HealthStatus::Corrupted, 0.2)
        } else if !min_size_ok {
            (HealthStatus::Partial, 0.6)
        } else {
            let ratio = passed_count as f64 / total_checks as f64;
            if ratio >= 0.9 {
                (HealthStatus::Complete, ratio)
            } else {
                (HealthStatus::Partial, ratio)
            }
        };

        let confidence_modifier = match status {
            HealthStatus::Complete => 1.0,
            HealthStatus::Partial => 0.7,
            HealthStatus::Corrupted => 0.3,
            HealthStatus::SuspiciouslyModified => 0.2,
        };

        let summary = format!(
            "Artifact health: {} (score: {:.2}, {}/{} checks passed). {}",
            status,
            score,
            passed_count,
            total_checks,
            match status {
                HealthStatus::Complete => "Artifact is suitable for full forensic analysis.",
                HealthStatus::Partial => "Artifact is partially intact; extracted data may be incomplete.",
                HealthStatus::Corrupted => "Artifact has structural damage; parsing may fail or produce unreliable results.",
                HealthStatus::SuspiciouslyModified => "Artifact exhibits patterns consistent with deliberate modification. Findings should be treated with caution.",
            }
        );

        ArtifactHealthReport {
            artifact_class,
            status,
            score,
            checks,
            confidence_modifier,
            summary,
        }
    }

    /// Check if the file has an expected header for its artifact class.
    fn check_header(class: ArtifactClass, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }

        match class {
            ArtifactClass::WifiConfigStore => {
                // XML file should start with <?xml or <
                data.starts_with(b"<?xml") || data.starts_with(b"<")
            }
            ArtifactClass::WpaSupplicant => {
                // wpa_supplicant.conf starts with text content
                let start = String::from_utf8_lossy(&data[..data.len().min(100)]);
                start.contains("network=") || start.contains("ctrl_interface=") || start.contains('#')
            }
            ArtifactClass::BuildProp => {
                // build.prop is a properties file
                let start = String::from_utf8_lossy(&data[..data.len().min(100)]);
                start.contains('=') || start.starts_with('#')
            }
            // For other types, accept any non-empty data
            _ => true,
        }
    }

    /// Calculate the ratio of null bytes in the data.
    fn null_byte_ratio(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let null_count = data.iter().filter(|&&b| b == 0).count();
        null_count as f64 / data.len() as f64
    }

    /// Detect patterns consistent with deliberate modification.
    fn detect_suspicious_patterns(data: &[u8]) -> Vec<String> {
        let mut patterns = Vec::new();

        if data.len() < 16 {
            return patterns;
        }

        // Check for large runs of repeated bytes (excluding nulls)
        let mut run_start = 0;
        while run_start < data.len() {
            let byte = data[run_start];
            if byte == 0 {
                run_start += 1;
                continue;
            }
            let run_end = data[run_start..]
                .iter()
                .take_while(|&&b| b == byte)
                .count();
            if run_end > 1024 {
                patterns.push(format!(
                    "Repeated byte 0x{:02X} for {} bytes at offset {}",
                    byte, run_end, run_start
                ));
            }
            run_start += run_end.max(1);
        }

        patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_xml_artifact() {
        let data = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<WifiConfigStore>\n  <network>\n  </network>\n</WifiConfigStore>";
        let report = ArtifactHealthScorer::assess(
            ArtifactClass::WifiConfigStore,
            data,
            Some(10),
        );
        assert_eq!(report.status, HealthStatus::Complete);
        assert!(report.score > 0.8);
        assert_eq!(report.confidence_modifier, 1.0);
    }

    #[test]
    fn test_empty_artifact_is_corrupted() {
        let report = ArtifactHealthScorer::assess(
            ArtifactClass::WifiConfigStore,
            &[],
            None,
        );
        assert_eq!(report.status, HealthStatus::Corrupted);
        assert_eq!(report.score, 0.0);
        assert_eq!(report.confidence_modifier, 0.3);
    }

    #[test]
    fn test_truncated_artifact_is_partial() {
        let data = b"<?xml";
        let report = ArtifactHealthScorer::assess(
            ArtifactClass::WifiConfigStore,
            data,
            Some(100), // Minimum 100 bytes, but only 5 provided
        );
        assert_eq!(report.status, HealthStatus::Partial);
    }

    #[test]
    fn test_suspicious_repeated_bytes() {
        let mut data = vec![b'A'; 2048]; // 2KB of repeated 'A'
        data.extend_from_slice(b"<?xml version=\"1.0\"?>");
        let report = ArtifactHealthScorer::assess(
            ArtifactClass::WifiConfigStore,
            &data,
            None,
        );
        assert_eq!(report.status, HealthStatus::SuspiciouslyModified);
        assert_eq!(report.confidence_modifier, 0.2);
    }
}
