//! # Report Data Types
//!
//! Core types for the report generation pipeline. These structures represent
//! the complete investigation report data model before rendering to PDF or JSON.

use chrono::{DateTime, Utc};
use oracle_core::types::{
    ConfidenceClassification, ExaminerIdentity, InvestigationId, SecurityProtocol,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a generated report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReportId(pub Uuid);

impl ReportId {
    pub fn new() -> Self {
        ReportId(Uuid::new_v4())
    }
}

impl Default for ReportId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReportId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The type of report being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    /// Executive summary — high-level findings for non-technical audiences.
    Executive,
    /// Technical findings — detailed analysis with full evidence citations.
    Technical,
    /// Evidence appendix — complete artifact inventory with hashes.
    EvidenceAppendix,
    /// Chain of custody — audit trail document.
    ChainOfCustody,
    /// Complete report — all sections combined.
    Complete,
    /// Insufficient evidence — generated when acquisition fails entirely.
    /// Documents the acquisition attempt and explains what could not be determined.
    InsufficientEvidence,
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportType::Executive => write!(f, "Executive Summary"),
            ReportType::Technical => write!(f, "Technical Findings"),
            ReportType::EvidenceAppendix => write!(f, "Evidence Appendix"),
            ReportType::ChainOfCustody => write!(f, "Chain of Custody"),
            ReportType::Complete => write!(f, "Complete Report"),
            ReportType::InsufficientEvidence => write!(f, "Insufficient Evidence Report"),
        }
    }
}

/// A single forensic finding for inclusion in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFinding {
    /// Sequential finding number (F-001, F-002, etc.)
    pub finding_number: String,
    /// One-line summary of the finding.
    pub title: String,
    /// Detailed narrative description.
    pub description: String,
    /// Network SSID involved (if applicable).
    pub network_ssid: Option<String>,
    /// Network BSSID involved (if applicable).
    pub network_bssid: Option<String>,
    /// Security protocol observed.
    pub security_protocol: Option<SecurityProtocol>,
    /// When the event occurred.
    pub event_time: Option<DateTime<Utc>>,
    /// Confidence score for this finding.
    pub confidence_score: f64,
    /// Court-facing classification.
    pub confidence_classification: ConfidenceClassification,
    /// Number of corroborating sources.
    pub corroboration_count: usize,
    /// Names/descriptions of corroborating sources.
    pub corroborating_sources: Vec<String>,
    /// Active contradictions for this finding.
    pub contradictions: Vec<String>,
    /// Whether this finding was overridden by an examiner.
    pub examiner_override: bool,
    /// The logic/reasoning steps taken to arrive at this finding and its confidence score.
    pub reasoning_chain: Vec<String>,
}

/// An evidence artifact entry for the evidence appendix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Sequential evidence number (E-001, E-002, etc.)
    pub evidence_number: String,
    /// Original filename or path on the device.
    pub original_path: String,
    /// SHA-256 hash of the artifact.
    pub sha256_hash: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// When the artifact was acquired.
    pub acquired_at: DateTime<Utc>,
    /// Artifact class description.
    pub artifact_class: String,
    /// How many findings reference this artifact.
    pub referenced_by_findings: Vec<String>,
}

/// Report metadata and investigation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report unique identifier.
    pub report_id: ReportId,
    /// Investigation identifier.
    pub investigation_id: InvestigationId,
    /// Report type.
    pub report_type: ReportType,
    /// Case number or reference.
    pub case_number: String,
    /// The forensic examiner who conducted the investigation.
    pub examiner: ExaminerIdentity,
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
    /// ORACLE platform version.
    pub platform_version: String,
    /// Confidence model version used.
    pub model_version: String,
}

/// The complete investigation summary for the executive report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSummary {
    /// Case number.
    pub case_number: String,
    /// Brief description of the investigation purpose.
    pub purpose: String,
    /// Device examined (manufacturer + model + serial).
    pub device_description: String,
    /// Date range of the investigation window.
    pub investigation_window: String,
    /// Total number of artifacts acquired.
    pub total_artifacts: usize,
    /// Total number of findings.
    pub total_findings: usize,
    /// Number of high-confidence findings.
    pub high_confidence_findings: usize,
    /// Number of contradicted findings.
    pub contradicted_findings: usize,
    /// Number of anomalies detected.
    pub anomalies_detected: usize,
    /// Key findings summary (top 5).
    pub key_findings: Vec<String>,
}

/// A complete forensic report ready for rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    /// Report metadata.
    pub metadata: ReportMetadata,
    /// Investigation summary.
    pub summary: InvestigationSummary,
    /// All findings, ordered by finding number.
    pub findings: Vec<ReportFinding>,
    /// Evidence appendix entries.
    pub evidence_entries: Vec<EvidenceEntry>,
    /// Methodology disclosure text.
    pub methodology_disclosure: String,
    /// Cryptographic signature of the report (SHA-256 of the JSON content).
    pub report_hash: Option<String>,
    /// Evidence acquisition completeness metrics.
    pub acquisition_completeness: Option<AcquisitionCompleteness>,
    /// Limitations on what this investigation could determine.
    pub evidence_limitations: Option<EvidenceLimitations>,
}

/// Tracks what percentage of expected forensic artifacts were acquired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionCompleteness {
    /// Number of artifacts successfully acquired.
    pub acquired_count: usize,
    /// Number of artifacts expected based on capability profile.
    pub expected_count: usize,
    /// Percentage of expected artifacts that were acquired.
    pub completeness_percentage: f64,
    /// Names of artifact classes that could not be acquired.
    pub missing_artifact_classes: Vec<String>,
}

/// Documents what the investigation could NOT determine due to
/// missing evidence, BFU state, or device restrictions.
///
/// This section is MANDATORY in every report — it must never be empty.
/// An honest report states both what it found AND what it could not find.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceLimitations {
    /// Whether the device was in BFU state during acquisition.
    pub bfu_state_impact: bool,
    /// Human-readable description of BFU impact on evidence.
    pub bfu_impact_description: Option<String>,
    /// Artifact classes that were inaccessible.
    pub inaccessible_artifact_classes: Vec<String>,
    /// What questions cannot be answered due to missing evidence.
    pub unanswerable_questions: Vec<String>,
    /// Free-form limitations narrative for the report body.
    pub limitations_narrative: String,
}
