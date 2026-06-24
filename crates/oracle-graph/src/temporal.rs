//! # Temporal Reasoning Engine
//!
//! Handles every ambiguous temporal case defined in V2 Prompt 4, Part 2.
//! Each case has explicit: detection method, handling algorithm, audit trail
//! requirement, and report language.
//!
//! # Cases Handled
//!
//! | Case | Scenario                                     | Severity |
//! |------|----------------------------------------------|----------|
//! | 1    | Two artifacts, same event, different timestamps | Critical |
//! | 2    | Start time known, end time unknown            | Warning  |
//! | 3    | All timestamps suspicious (clock manipulation)| Critical |
//! | 4    | Log gap consistent with deliberate clearing   | Critical |
//! | 5    | Forensically impossible timestamp             | Critical |
//! | 6    | Indirect evidence without direct logs         | Info     |

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Temporal Issue Types
// ──────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a temporal issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TemporalIssueId(pub Uuid);

impl TemporalIssueId {
    pub fn new() -> Self {
        TemporalIssueId(Uuid::new_v4())
    }
}

impl Default for TemporalIssueId {
    fn default() -> Self {
        Self::new()
    }
}

/// The case number from the V2 architecture specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TemporalCase {
    /// Case 1: Two artifacts report the same event with different timestamps.
    ConflictingTimestamps,
    /// Case 2: A connection event has a start time but no end time.
    MissingEndTime,
    /// Case 3: All timestamps on a device are suspicious (possible clock manipulation).
    ClockManipulation,
    /// Case 4: A log file shows a gap consistent with deliberate clearing.
    LogGapClearing,
    /// Case 5: An artifact contains a forensically impossible timestamp.
    ImpossibleTimestamp,
    /// Case 6: Indirect evidence suggests activity without direct logs.
    IndirectTemporalEvidence,
}

impl std::fmt::Display for TemporalCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemporalCase::ConflictingTimestamps => write!(f, "CASE_1_CONFLICTING_TIMESTAMPS"),
            TemporalCase::MissingEndTime => write!(f, "CASE_2_MISSING_END_TIME"),
            TemporalCase::ClockManipulation => write!(f, "CASE_3_CLOCK_MANIPULATION"),
            TemporalCase::LogGapClearing => write!(f, "CASE_4_LOG_GAP_CLEARING"),
            TemporalCase::ImpossibleTimestamp => write!(f, "CASE_5_IMPOSSIBLE_TIMESTAMP"),
            TemporalCase::IndirectTemporalEvidence => write!(f, "CASE_6_INDIRECT_EVIDENCE"),
        }
    }
}

/// Severity of a temporal issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TemporalSeverity {
    Info,
    Warning,
    Critical,
}

/// The resolution applied to a temporal issue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalResolution {
    /// One source was preferred over the other based on source priority.
    SourcePriorityApplied {
        preferred_source: String,
        reason: String,
    },
    /// An estimated bound was computed for an unknown value.
    BoundEstimated {
        estimated_value: DateTime<Utc>,
        method: String,
        confidence: f64,
    },
    /// The issue was flagged for mandatory examiner review.
    ExaminerEscalation {
        reason: String,
    },
    /// A forensic finding was generated from the absence of evidence.
    AbsenceFinding {
        finding_statement: String,
    },
    /// The timestamp was retained but marked as untrusted.
    RetainedUntrusted {
        original_value: DateTime<Utc>,
        trust_factor: f64,
    },
    /// Indirect evidence was weighted and represented alongside direct evidence.
    IndirectWeighted {
        inferred_window_start: DateTime<Utc>,
        inferred_window_end: DateTime<Utc>,
        weight: f64,
    },
}

/// A complete temporal issue record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalIssue {
    pub id: TemporalIssueId,
    pub case: TemporalCase,
    pub severity: TemporalSeverity,
    pub description: String,
    pub resolution: TemporalResolution,
    pub report_language: String,
    pub audit_note: String,
    pub detected_at: DateTime<Utc>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Source Priority for Case 1
// ──────────────────────────────────────────────────────────────────────────────

/// Source priority ranking for timestamp conflict resolution.
/// Lower number = higher priority. Kernel logs are most trusted
/// because they use monotonic clocks with minimal userspace interference.
const SOURCE_PRIORITY: &[(&str, u8)] = &[
    ("kernel_dmesg", 1),
    ("battery_stats", 2),
    ("wifi_config_store", 3),
    ("connectivity_log", 4),
    ("wpa_supplicant", 5),
    ("dhcp_lease", 6),
    ("logcat", 7),
    ("unknown", 99),
];

fn source_priority(source: &str) -> u8 {
    SOURCE_PRIORITY
        .iter()
        .find(|(s, _)| *s == source)
        .map(|(_, p)| *p)
        .unwrap_or(99)
}

// ──────────────────────────────────────────────────────────────────────────────
// Temporal Reasoning Engine
// ──────────────────────────────────────────────────────────────────────────────

/// The Temporal Reasoning Engine processes all ambiguous temporal cases.
pub struct TemporalReasoningEngine {
    issues: Vec<TemporalIssue>,
    /// The Android epoch: timestamps before this are impossible.
    android_epoch: DateTime<Utc>,
    /// The acquisition timestamp: timestamps after this are suspicious.
    acquisition_time: DateTime<Utc>,
}

impl TemporalReasoningEngine {
    /// Create a new engine with the acquisition timestamp.
    pub fn new(acquisition_time: DateTime<Utc>) -> Self {
        // Android 1.0 released September 23, 2008
        let android_epoch = DateTime::parse_from_rfc3339("2008-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        TemporalReasoningEngine {
            issues: Vec::new(),
            android_epoch,
            acquisition_time,
        }
    }

    /// Return all detected temporal issues.
    pub fn issues(&self) -> &[TemporalIssue] {
        &self.issues
    }

    // ── CASE 1: Conflicting Timestamps ──────────────────────────────────

    /// Case 1: Two artifacts report the same event with different timestamps.
    ///
    /// **Detection:** Delta exceeds threshold (120 seconds).
    /// **Resolution:** The source with higher priority wins. If priorities are
    /// equal, the earlier timestamp is preferred (forensic conservatism).
    /// **If neither can be trusted:** Both are retained with reduced trust.
    pub fn resolve_conflicting_timestamps(
        &mut self,
        event_description: &str,
        ts_a: DateTime<Utc>,
        source_a: &str,
        ts_b: DateTime<Utc>,
        source_b: &str,
        threshold_secs: f64,
    ) -> TemporalResolution {
        let delta_secs = (ts_a - ts_b).num_milliseconds().unsigned_abs() as f64 / 1000.0;

        if delta_secs <= threshold_secs {
            // Not a conflict — within tolerance
            let resolution = TemporalResolution::SourcePriorityApplied {
                preferred_source: source_a.to_string(),
                reason: format!("Delta {:.1}s is within {:.0}s tolerance", delta_secs, threshold_secs),
            };
            return resolution;
        }

        let prio_a = source_priority(source_a);
        let prio_b = source_priority(source_b);

        let resolution = if prio_a < prio_b {
            TemporalResolution::SourcePriorityApplied {
                preferred_source: source_a.to_string(),
                reason: format!(
                    "{} (priority {}) preferred over {} (priority {}) for event '{}'",
                    source_a, prio_a, source_b, prio_b, event_description
                ),
            }
        } else if prio_b < prio_a {
            TemporalResolution::SourcePriorityApplied {
                preferred_source: source_b.to_string(),
                reason: format!(
                    "{} (priority {}) preferred over {} (priority {}) for event '{}'",
                    source_b, prio_b, source_a, prio_a, event_description
                ),
            }
        } else {
            // Equal priority — escalate to examiner
            TemporalResolution::ExaminerEscalation {
                reason: format!(
                    "Two equally trusted sources ({}, {}) report event '{}' with a {:.1}s \
                     discrepancy. Examiner must determine which is authoritative.",
                    source_a, source_b, event_description, delta_secs
                ),
            }
        };

        let issue = TemporalIssue {
            id: TemporalIssueId::new(),
            case: TemporalCase::ConflictingTimestamps,
            severity: if delta_secs > 3600.0 {
                TemporalSeverity::Critical
            } else {
                TemporalSeverity::Warning
            },
            description: format!(
                "Event '{}' has conflicting timestamps: {} ({}) vs {} ({}), delta={:.1}s",
                event_description,
                ts_a.format("%Y-%m-%dT%H:%M:%SZ"),
                source_a,
                ts_b.format("%Y-%m-%dT%H:%M:%SZ"),
                source_b,
                delta_secs
            ),
            resolution: resolution.clone(),
            report_language: format!(
                "Two forensic sources provided different timestamps for the event '{}'. \
                 Source '{}' recorded {} while source '{}' recorded {}, a difference of \
                 {:.1} seconds. {}",
                event_description,
                source_a,
                ts_a.format("%Y-%m-%dT%H:%M:%S UTC"),
                source_b,
                ts_b.format("%Y-%m-%dT%H:%M:%S UTC"),
                delta_secs,
                match &resolution {
                    TemporalResolution::SourcePriorityApplied { preferred_source, reason } =>
                        format!("The timestamp from '{}' was preferred: {}", preferred_source, reason),
                    TemporalResolution::ExaminerEscalation { reason } =>
                        format!("This conflict requires examiner review: {}", reason),
                    _ => String::new(),
                }
            ),
            audit_note: format!(
                "TEMPORAL_CASE_1: conflicting_timestamps event='{}' delta={:.1}s",
                event_description, delta_secs
            ),
            detected_at: Utc::now(),
        };

        self.issues.push(issue);
        resolution
    }

    // ── CASE 2: Missing End Time ────────────────────────────────────────

    /// Case 2: A connection event has a start time but no end time.
    ///
    /// **Detection:** Event record has `start_time` but `end_time` is None.
    /// **Resolution:** Estimate the upper bound using:
    ///   1. Next connection event start time (if available)
    ///   2. Device shutdown/reboot timestamp (if available)
    ///   3. DHCP lease duration (if available)
    ///   4. Default maximum session duration (24 hours)
    pub fn estimate_missing_end_time(
        &mut self,
        event_description: &str,
        start_time: DateTime<Utc>,
        next_event_start: Option<DateTime<Utc>>,
        device_shutdown: Option<DateTime<Utc>>,
        dhcp_lease_duration_secs: Option<i64>,
    ) -> TemporalResolution {
        // Apply bounding evidence in priority order
        let (estimated_end, method, confidence) = if let Some(next_start) = next_event_start {
            (next_start, "Next connection event start time".to_string(), 0.75)
        } else if let Some(shutdown) = device_shutdown {
            (shutdown, "Device shutdown timestamp".to_string(), 0.60)
        } else if let Some(lease_secs) = dhcp_lease_duration_secs {
            let estimated = start_time + Duration::seconds(lease_secs);
            (estimated, format!("DHCP lease duration ({}s)", lease_secs), 0.50)
        } else {
            let estimated = start_time + Duration::hours(24);
            ("Default maximum session bound (24h)".to_string(), estimated, 0.25);
            (start_time + Duration::hours(24), "Default 24-hour maximum session bound".to_string(), 0.25)
        };

        let resolution = TemporalResolution::BoundEstimated {
            estimated_value: estimated_end,
            method: method.clone(),
            confidence,
        };

        let issue = TemporalIssue {
            id: TemporalIssueId::new(),
            case: TemporalCase::MissingEndTime,
            severity: TemporalSeverity::Warning,
            description: format!(
                "Event '{}' starting at {} has no recorded end time",
                event_description,
                start_time.format("%Y-%m-%dT%H:%M:%SZ")
            ),
            resolution: resolution.clone(),
            report_language: format!(
                "The connection event '{}' starting at {} has no recorded disconnection time. \
                 An upper bound of {} was estimated using: {}. This estimate has a confidence \
                 of {:.0}%.",
                event_description,
                start_time.format("%Y-%m-%dT%H:%M:%S UTC"),
                estimated_end.format("%Y-%m-%dT%H:%M:%S UTC"),
                method,
                confidence * 100.0
            ),
            audit_note: format!(
                "TEMPORAL_CASE_2: missing_end_time event='{}' estimated_end={} method='{}' confidence={:.2}",
                event_description,
                estimated_end.format("%Y-%m-%dT%H:%M:%SZ"),
                method,
                confidence
            ),
            detected_at: Utc::now(),
        };

        self.issues.push(issue);
        resolution
    }

    // ── CASE 3: Clock Manipulation ──────────────────────────────────────

    /// Case 3: All timestamps on a device are suspicious.
    ///
    /// **Detection:** Multiple indicators:
    ///   - Device clock differs from acquisition workstation by > 5 minutes
    ///   - Multiple timestamps are Unix epoch (1970-01-01)
    ///   - Timestamps are in the future relative to acquisition
    ///   - Non-monotonic sequence in sequential log entries
    ///
    /// **Handling:** Flag all timestamps as untrusted. Continue analysis
    /// using relative ordering only. Report must explicitly state the finding.
    pub fn flag_clock_manipulation(
        &mut self,
        device_clock_offset_secs: f64,
        epoch_timestamp_count: usize,
        future_timestamp_count: usize,
        non_monotonic_count: usize,
    ) -> TemporalResolution {
        let indicators: Vec<String> = [
            if device_clock_offset_secs.abs() > 300.0 {
                Some(format!("Device clock offset: {:.0}s from acquisition workstation", device_clock_offset_secs))
            } else { None },
            if epoch_timestamp_count > 0 {
                Some(format!("{} timestamps at Unix epoch (1970-01-01)", epoch_timestamp_count))
            } else { None },
            if future_timestamp_count > 0 {
                Some(format!("{} timestamps in the future relative to acquisition", future_timestamp_count))
            } else { None },
            if non_monotonic_count > 0 {
                Some(format!("{} non-monotonic sequences in sequential logs", non_monotonic_count))
            } else { None },
        ].into_iter().flatten().collect();

        let total_indicators = indicators.len();

        let resolution = TemporalResolution::ExaminerEscalation {
            reason: format!(
                "Clock manipulation suspected. {} indicators detected: {}",
                total_indicators,
                indicators.join("; ")
            ),
        };

        let issue = TemporalIssue {
            id: TemporalIssueId::new(),
            case: TemporalCase::ClockManipulation,
            severity: TemporalSeverity::Critical,
            description: format!(
                "Device clock integrity compromised: {} manipulation indicators detected",
                total_indicators
            ),
            resolution: resolution.clone(),
            report_language: format!(
                "FORENSIC NOTICE: The device's system clock shows evidence of possible \
                 manipulation or malfunction. {} indicators were detected: {}. All absolute \
                 timestamps from this device should be treated as unreliable. Relative \
                 event ordering may still be forensically valid. This finding is reported \
                 as an observation and does not constitute an accusation of tampering.",
                total_indicators,
                indicators.join("; ")
            ),
            audit_note: format!(
                "TEMPORAL_CASE_3: clock_manipulation indicators={} offset={:.0}s epoch_count={} future_count={} non_monotonic={}",
                total_indicators, device_clock_offset_secs, epoch_timestamp_count, future_timestamp_count, non_monotonic_count
            ),
            detected_at: Utc::now(),
        };

        self.issues.push(issue);
        resolution
    }

    // ── CASE 4: Log Gap / Deliberate Clearing ───────────────────────────

    /// Case 4: A log file shows a gap consistent with deliberate clearing.
    ///
    /// **Detection:** Expected continuous data has an unexplained gap.
    /// The gap duration exceeds what is normal for log rotation.
    ///
    /// **Handling:** Generate a forensic finding from the *absence* of evidence.
    /// The gap itself is evidence.
    pub fn detect_log_gap(
        &mut self,
        log_source: &str,
        last_entry_before_gap: DateTime<Utc>,
        first_entry_after_gap: DateTime<Utc>,
        expected_max_gap_secs: i64,
    ) -> TemporalResolution {
        let actual_gap_secs = (first_entry_after_gap - last_entry_before_gap).num_seconds();

        if actual_gap_secs <= expected_max_gap_secs {
            // Not suspicious
            return TemporalResolution::RetainedUntrusted {
                original_value: last_entry_before_gap,
                trust_factor: 1.0,
            };
        }

        let gap_ratio = actual_gap_secs as f64 / expected_max_gap_secs.max(1) as f64;

        let resolution = TemporalResolution::AbsenceFinding {
            finding_statement: format!(
                "Log source '{}' contains a gap of {} seconds ({:.1} hours) between {} and {}. \
                 The expected maximum gap for this source is {} seconds. This gap is {:.1}x \
                 larger than expected and is consistent with deliberate log clearing.",
                log_source,
                actual_gap_secs,
                actual_gap_secs as f64 / 3600.0,
                last_entry_before_gap.format("%Y-%m-%dT%H:%M:%S UTC"),
                first_entry_after_gap.format("%Y-%m-%dT%H:%M:%S UTC"),
                expected_max_gap_secs,
                gap_ratio
            ),
        };

        let issue = TemporalIssue {
            id: TemporalIssueId::new(),
            case: TemporalCase::LogGapClearing,
            severity: TemporalSeverity::Critical,
            description: format!(
                "Suspicious gap in '{}': {}s (expected max {}s, ratio {:.1}x)",
                log_source, actual_gap_secs, expected_max_gap_secs, gap_ratio
            ),
            resolution: resolution.clone(),
            report_language: format!(
                "The log source '{}' exhibits an unexplained gap of approximately {:.1} hours \
                 (from {} to {}). For this source type, gaps exceeding {} seconds are abnormal. \
                 The observed gap is {:.1} times the expected maximum. This pattern is consistent \
                 with, but does not conclusively prove, deliberate log clearing. No network \
                 activity data is available for this period.",
                log_source,
                actual_gap_secs as f64 / 3600.0,
                last_entry_before_gap.format("%Y-%m-%dT%H:%M:%S UTC"),
                first_entry_after_gap.format("%Y-%m-%dT%H:%M:%S UTC"),
                expected_max_gap_secs,
                gap_ratio
            ),
            audit_note: format!(
                "TEMPORAL_CASE_4: log_gap source='{}' gap_secs={} expected_max={} ratio={:.1}",
                log_source, actual_gap_secs, expected_max_gap_secs, gap_ratio
            ),
            detected_at: Utc::now(),
        };

        self.issues.push(issue);
        resolution
    }

    // ── CASE 5: Impossible Timestamp ────────────────────────────────────

    /// Case 5: An artifact contains a forensically impossible timestamp.
    ///
    /// **Validation rules for impossibility:**
    ///   - Before the Android epoch (2008-01-01)
    ///   - After the acquisition time (future)
    ///   - Unix epoch zero (1970-01-01T00:00:00Z)
    ///   - Year > 2100 (clearly incorrect)
    ///
    /// **Handling:** Retain the artifact but mark the timestamp as untrusted.
    /// The artifact's non-temporal data may still be forensically valuable.
    pub fn validate_timestamp(
        &mut self,
        artifact_source: &str,
        timestamp: DateTime<Utc>,
    ) -> TemporalResolution {
        let epoch_zero = DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let far_future = DateTime::parse_from_rfc3339("2100-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let impossibility_reason = if timestamp == epoch_zero {
            Some("Timestamp is Unix epoch zero (uninitialized default)")
        } else if timestamp < self.android_epoch {
            Some("Timestamp predates the Android operating system (before 2008)")
        } else if timestamp > self.acquisition_time {
            Some("Timestamp is in the future relative to acquisition time")
        } else if timestamp > far_future {
            Some("Timestamp is unreasonably far in the future (after year 2100)")
        } else {
            None
        };

        if let Some(reason) = impossibility_reason {
            let resolution = TemporalResolution::RetainedUntrusted {
                original_value: timestamp,
                trust_factor: 0.1,
            };

            let issue = TemporalIssue {
                id: TemporalIssueId::new(),
                case: TemporalCase::ImpossibleTimestamp,
                severity: TemporalSeverity::Critical,
                description: format!(
                    "Impossible timestamp {} in '{}': {}",
                    timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                    artifact_source,
                    reason
                ),
                resolution: resolution.clone(),
                report_language: format!(
                    "The artifact '{}' contains the timestamp {} which is forensically \
                     impossible: {}. The artifact has been retained for analysis of its \
                     non-temporal content, but this timestamp has been assigned a trust \
                     factor of 0.1 (minimal trust) and is excluded from timeline \
                     reconstruction.",
                    artifact_source,
                    timestamp.format("%Y-%m-%dT%H:%M:%S UTC"),
                    reason
                ),
                audit_note: format!(
                    "TEMPORAL_CASE_5: impossible_timestamp source='{}' ts={} reason='{}'",
                    artifact_source,
                    timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                    reason
                ),
                detected_at: Utc::now(),
            };

            self.issues.push(issue);
            resolution
        } else {
            // Timestamp is valid
            TemporalResolution::RetainedUntrusted {
                original_value: timestamp,
                trust_factor: 1.0,
            }
        }
    }

    // ── CASE 6: Indirect Temporal Evidence ──────────────────────────────

    /// Case 6: Battery statistics suggest network activity at a time when
    /// no network logs exist.
    ///
    /// **Detection:** Battery drain pattern consistent with WiFi radio
    /// activity exists in a window with no corresponding network logs.
    ///
    /// **Handling:** Create an inferred activity window weighted lower
    /// than direct evidence. Report it as indirect/circumstantial.
    pub fn record_indirect_evidence(
        &mut self,
        indirect_source: &str,
        inferred_start: DateTime<Utc>,
        inferred_end: DateTime<Utc>,
        confidence: f64,
    ) -> TemporalResolution {
        let weight = (confidence * 0.5).clamp(0.0, 0.5); // Indirect evidence capped at 50% weight

        let resolution = TemporalResolution::IndirectWeighted {
            inferred_window_start: inferred_start,
            inferred_window_end: inferred_end,
            weight,
        };

        let issue = TemporalIssue {
            id: TemporalIssueId::new(),
            case: TemporalCase::IndirectTemporalEvidence,
            severity: TemporalSeverity::Info,
            description: format!(
                "Indirect evidence from '{}' suggests activity between {} and {} \
                 (weight: {:.2})",
                indirect_source,
                inferred_start.format("%Y-%m-%dT%H:%M:%SZ"),
                inferred_end.format("%Y-%m-%dT%H:%M:%SZ"),
                weight
            ),
            resolution: resolution.clone(),
            report_language: format!(
                "Indirect evidence from '{}' (e.g., battery drain patterns, radio wake locks) \
                 suggests possible network activity between {} and {}. No direct network \
                 connection logs exist for this period. This indirect evidence has been \
                 weighted at {:.0}% of direct evidence confidence. It is presented as \
                 circumstantial and should not be treated as conclusive without corroborating \
                 direct evidence.",
                indirect_source,
                inferred_start.format("%Y-%m-%dT%H:%M:%S UTC"),
                inferred_end.format("%Y-%m-%dT%H:%M:%S UTC"),
                weight * 100.0
            ),
            audit_note: format!(
                "TEMPORAL_CASE_6: indirect_evidence source='{}' window={}-{} weight={:.2}",
                indirect_source,
                inferred_start.format("%Y-%m-%dT%H:%M:%SZ"),
                inferred_end.format("%Y-%m-%dT%H:%M:%SZ"),
                weight
            ),
            detected_at: Utc::now(),
        };

        self.issues.push(issue);
        resolution
    }

    /// Generate a summary of all temporal issues for the forensic report.
    pub fn generate_summary(&self) -> TemporalSummary {
        let critical = self.issues.iter().filter(|i| i.severity == TemporalSeverity::Critical).count();
        let warning = self.issues.iter().filter(|i| i.severity == TemporalSeverity::Warning).count();
        let info = self.issues.iter().filter(|i| i.severity == TemporalSeverity::Info).count();

        TemporalSummary {
            total_issues: self.issues.len(),
            critical_count: critical,
            warning_count: warning,
            info_count: info,
            clock_manipulation_detected: self.issues.iter().any(|i| i.case == TemporalCase::ClockManipulation),
            log_gaps_detected: self.issues.iter().filter(|i| i.case == TemporalCase::LogGapClearing).count(),
            impossible_timestamps: self.issues.iter().filter(|i| i.case == TemporalCase::ImpossibleTimestamp).count(),
        }
    }
}

/// Summary of temporal issues for the forensic report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalSummary {
    pub total_issues: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub clock_manipulation_detected: bool,
    pub log_gaps_detected: usize,
    pub impossible_timestamps: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> TemporalReasoningEngine {
        TemporalReasoningEngine::new(Utc::now())
    }

    #[test]
    fn test_case1_conflicting_timestamps_source_priority() {
        let mut engine = make_engine();
        let ts_a = Utc::now() - Duration::hours(2);
        let ts_b = ts_a + Duration::minutes(10); // 600s delta

        let resolution = engine.resolve_conflicting_timestamps(
            "wifi_connect",
            ts_a,
            "kernel_dmesg",
            ts_b,
            "logcat",
            120.0,
        );

        match resolution {
            TemporalResolution::SourcePriorityApplied { preferred_source, .. } => {
                assert_eq!(preferred_source, "kernel_dmesg");
            }
            _ => panic!("Expected SourcePriorityApplied"),
        }
        assert_eq!(engine.issues().len(), 1);
    }

    #[test]
    fn test_case2_missing_end_time_with_next_event() {
        let mut engine = make_engine();
        let start = Utc::now() - Duration::hours(5);
        let next_event = start + Duration::hours(2);

        let resolution = engine.estimate_missing_end_time(
            "wifi_connect",
            start,
            Some(next_event),
            None,
            None,
        );

        match resolution {
            TemporalResolution::BoundEstimated { estimated_value, confidence, .. } => {
                assert_eq!(estimated_value, next_event);
                assert_eq!(confidence, 0.75);
            }
            _ => panic!("Expected BoundEstimated"),
        }
    }

    #[test]
    fn test_case3_clock_manipulation() {
        let mut engine = make_engine();
        let resolution = engine.flag_clock_manipulation(7200.0, 3, 1, 5);

        match resolution {
            TemporalResolution::ExaminerEscalation { reason } => {
                assert!(reason.contains("Clock manipulation"));
            }
            _ => panic!("Expected ExaminerEscalation"),
        }
        assert_eq!(engine.issues()[0].severity, TemporalSeverity::Critical);
    }

    #[test]
    fn test_case4_log_gap_suspicious() {
        let mut engine = make_engine();
        let before = Utc::now() - Duration::hours(48);
        let after = before + Duration::hours(24); // 24-hour gap

        let resolution = engine.detect_log_gap(
            "connectivity_log",
            before,
            after,
            3600, // expected max gap = 1 hour
        );

        match resolution {
            TemporalResolution::AbsenceFinding { finding_statement } => {
                assert!(finding_statement.contains("deliberate log clearing"));
            }
            _ => panic!("Expected AbsenceFinding"),
        }
    }

    #[test]
    fn test_case5_impossible_timestamp_epoch_zero() {
        let mut engine = make_engine();
        let epoch_zero = DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let resolution = engine.validate_timestamp("wpa_supplicant.conf", epoch_zero);

        match resolution {
            TemporalResolution::RetainedUntrusted { trust_factor, .. } => {
                assert_eq!(trust_factor, 0.1);
            }
            _ => panic!("Expected RetainedUntrusted"),
        }
    }

    #[test]
    fn test_case5_valid_timestamp_passes() {
        let mut engine = make_engine();
        let valid_ts = Utc::now() - Duration::hours(1);
        let resolution = engine.validate_timestamp("logcat", valid_ts);

        match resolution {
            TemporalResolution::RetainedUntrusted { trust_factor, .. } => {
                assert_eq!(trust_factor, 1.0);
            }
            _ => panic!("Expected RetainedUntrusted with trust 1.0"),
        }
        // No issue should be recorded for valid timestamps
        assert!(engine.issues().is_empty());
    }

    #[test]
    fn test_case6_indirect_evidence() {
        let mut engine = make_engine();
        let start = Utc::now() - Duration::hours(3);
        let end = start + Duration::hours(1);

        let resolution = engine.record_indirect_evidence("battery_stats", start, end, 0.7);

        match resolution {
            TemporalResolution::IndirectWeighted { weight, .. } => {
                assert!(weight <= 0.5); // Capped at 50%
            }
            _ => panic!("Expected IndirectWeighted"),
        }
    }

    #[test]
    fn test_summary_generation() {
        let mut engine = make_engine();

        // Add one of each severity
        engine.flag_clock_manipulation(7200.0, 3, 1, 5); // Critical
        engine.estimate_missing_end_time("evt", Utc::now(), None, None, None); // Warning
        engine.record_indirect_evidence("battery", Utc::now(), Utc::now(), 0.5); // Info

        let summary = engine.generate_summary();
        assert_eq!(summary.total_issues, 3);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.warning_count, 1);
        assert_eq!(summary.info_count, 1);
        assert!(summary.clock_manipulation_detected);
    }
}
