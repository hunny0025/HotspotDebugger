//! # Core Types
//!
//! Canonical data structures shared across all ORACLE subsystems.
//!
//! These types form the forensic ontology of the platform. Every subsystem
//! that stores, transmits, or processes evidence records must use these
//! exact types to ensure provenance traceability and cross-module consistency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// Investigation Identity
// ──────────────────────────────────────────────────────────────────────────────

/// A unique investigation identifier generated at case creation time.
/// Every artifact, record, and audit entry references its parent investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvestigationId(pub Uuid);

impl InvestigationId {
    /// Generate a new unique investigation identifier.
    pub fn new() -> Self {
        InvestigationId(Uuid::new_v4())
    }
}

impl Default for InvestigationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique artifact identifier assigned when an artifact is ingested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub Uuid);

impl ArtifactId {
    pub fn new() -> Self {
        ArtifactId(Uuid::new_v4())
    }
}

impl Default for ArtifactId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique record identifier for any evidence record (parsed, normalized, or correlated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordId(pub Uuid);

impl RecordId {
    pub fn new() -> Self {
        RecordId(Uuid::new_v4())
    }
}

impl Default for RecordId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Examiner Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Identifies the forensic examiner operating the platform.
/// Recorded in every audit log entry and chain of custody record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExaminerIdentity {
    /// Full legal name of the examiner.
    pub name: String,
    /// Badge number or employee identifier within the forensic lab.
    pub badge_id: String,
    /// The forensic laboratory or agency name.
    pub organization: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Device Identity
// ──────────────────────────────────────────────────────────────────────────────

/// Complete identity profile of the target Android device.
/// Populated by the Capability Detection Engine before any acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Device serial number (from `ro.serialno` or ADB).
    pub serial: String,
    /// OEM manufacturer (e.g., "samsung", "Google", "Xiaomi").
    pub manufacturer: String,
    /// Device model (e.g., "SM-S928B", "Pixel 8 Pro").
    pub model: String,
    /// Android version string (e.g., "14").
    pub android_version: String,
    /// API level (e.g., 34).
    pub api_level: u32,
    /// Security patch level (e.g., "2024-12-01").
    pub security_patch_level: String,
    /// Build fingerprint — uniquely identifies the exact firmware build.
    pub build_fingerprint: String,
    /// OEM skin name if detectable (e.g., "One UI", "HyperOS").
    pub oem_skin: Option<String>,
    /// OEM skin version if detectable.
    pub oem_skin_version: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability Profile
// ──────────────────────────────────────────────────────────────────────────────

/// The root access method detected on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootMethod {
    /// No root access available.
    None,
    /// Magisk systemless root detected.
    Magisk,
    /// Traditional system-level su binary detected.
    SystemRoot,
    /// ADB daemon running as root (engineering build or `adb root` success).
    AdbRoot,
    /// KernelSU detected.
    KernelSU,
}

/// SELinux enforcement mode on the target device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
    Disabled,
    Unknown,
}

/// Bootloader lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BootloaderState {
    Locked,
    Unlocked,
    Tampered,
    Unknown,
}

/// File-Based Encryption (FBE) device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionState {
    /// Before First Unlock — CE keys are evicted. Only DE storage is accessible.
    BeforeFirstUnlock,
    /// After First Unlock — CE keys are loaded. Full access if privileged.
    AfterFirstUnlock,
    /// Legacy Full Disk Encryption (pre-Android 10).
    FullDiskEncryption,
    /// Encryption state could not be determined.
    Unknown,
}



/// The acquisition method available for the device given its current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcquisitionMethod {
    /// Full filesystem extraction via rooted ADB shell.
    PrivilegedLogical,
    /// ADB backup-based extraction (limited scope).
    AdbBackup,
    /// Shell-user level extraction via `run-as` or accessible paths.
    UnprivilegedLogical,
    /// Content provider queries via instrumentation.
    ContentProvider,
    /// Static/offline image analysis (no live device required).
    OfflineImage,
}

/// The complete capability profile generated by the Capability Detection Engine.
///
/// Every downstream subsystem receives this profile and adapts its behavior
/// to only request operations that the profile confirms are possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    /// The device identity.
    pub device: DeviceIdentity,
    /// Whether USB debugging is enabled.
    pub usb_debugging_enabled: bool,
    /// Whether ADB is authorized.
    pub adb_authorized: bool,
    /// Root availability and method.
    pub root_method: RootMethod,
    /// SELinux mode.
    pub selinux_mode: SelinuxMode,
    /// Bootloader lock state.
    pub bootloader_state: BootloaderState,
    /// FBE encryption state.
    pub encryption_state: EncryptionState,
    /// Acquisition methods available given the detected state.
    pub available_methods: Vec<AcquisitionMethod>,
    /// Artifact classes accessible under each method.
    pub accessible_artifact_classes: Vec<AccessibleArtifactClass>,
    /// Artifact classes that are inaccessible and the reason why.
    pub inaccessible_artifact_classes: Vec<InaccessibleArtifactClass>,
    /// Timestamp of capability detection.
    pub detected_at: DateTime<Utc>,
    /// Whether the investigator has acknowledged this profile.
    pub acknowledged: bool,
}

/// An artifact class that is accessible under a given acquisition method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessibleArtifactClass {
    pub artifact_class: ArtifactClass,
    pub acquisition_method: AcquisitionMethod,
    pub confidence: f64,
}

/// An artifact class that is inaccessible, with forensic justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InaccessibleArtifactClass {
    pub artifact_class: ArtifactClass,
    pub reason: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Acquisition State Model
// ──────────────────────────────────────────────────────────────────────────────

/// The overall outcome of the forensic acquisition stage.
///
/// The pipeline uses this state to decide how to proceed:
/// - `Complete` → full pipeline execution
/// - `Partial` → proceed with examiner acknowledgment, document gaps
/// - `Failed` → halt pipeline, generate insufficient-evidence report only
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionState {
    /// All expected artifacts for the capability profile were acquired.
    Complete,
    /// Some artifacts acquired, some failed. At least 1 success.
    Partial,
    /// Zero artifacts successfully acquired. Pipeline must halt.
    Failed,
}

impl std::fmt::Display for AcquisitionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquisitionState::Complete => write!(f, "ACQUISITION_COMPLETE"),
            AcquisitionState::Partial => write!(f, "ACQUISITION_PARTIAL"),
            AcquisitionState::Failed => write!(f, "ACQUISITION_FAILED"),
        }
    }
}

/// Granular reason why a specific artifact could not be acquired.
///
/// Each variant maps to a specific Android security mechanism or
/// environmental condition. This classification drives the report's
/// "Evidence Limitations" section and the BFU handling logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactFailureReason {
    /// DAC (Unix permissions) denied access.
    PermissionDenied,
    /// SELinux MAC policy blocked the operation.
    SeLinuxBlocked,
    /// Path does not exist on this device (not a failure — a finding).
    NotFound,
    /// File exists but CE storage is locked (Before First Unlock).
    BfuLocked,
    /// ADB transport lost during pull operation.
    DeviceDisconnected,
    /// ADB command exceeded the 30-second timeout.
    Timeout,
    /// Root access required but not available.
    RootRequired,
    /// Path is a directory, not a regular file.
    IsDirectory,
    /// Failure reason could not be classified. Raw error preserved.
    Unknown(String),
}

impl std::fmt::Display for ArtifactFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactFailureReason::PermissionDenied => write!(f, "PERMISSION_DENIED"),
            ArtifactFailureReason::SeLinuxBlocked => write!(f, "SELINUX_BLOCKED"),
            ArtifactFailureReason::NotFound => write!(f, "NOT_FOUND"),
            ArtifactFailureReason::BfuLocked => write!(f, "BFU_LOCKED"),
            ArtifactFailureReason::DeviceDisconnected => write!(f, "DEVICE_DISCONNECTED"),
            ArtifactFailureReason::Timeout => write!(f, "TIMEOUT"),
            ArtifactFailureReason::RootRequired => write!(f, "ROOT_REQUIRED"),
            ArtifactFailureReason::IsDirectory => write!(f, "IS_DIRECTORY"),
            ArtifactFailureReason::Unknown(s) => write!(f, "UNKNOWN: {}", s),
        }
    }
}

/// Classifies an ADB error string into a structured `ArtifactFailureReason`.
impl ArtifactFailureReason {
    pub fn classify(error_str: &str) -> Self {
        let lower = error_str.to_lowercase();
        if lower.contains("permission denied") {
            ArtifactFailureReason::PermissionDenied
        } else if lower.contains("selinux") || lower.contains("avc:") {
            ArtifactFailureReason::SeLinuxBlocked
        } else if lower.contains("no such file") || lower.contains("does not exist") {
            ArtifactFailureReason::NotFound
        } else if lower.contains("is a directory") || lower.contains("remote object") {
            ArtifactFailureReason::IsDirectory
        } else if lower.contains("device not found") || lower.contains("device offline")
            || lower.contains("closed") {
            ArtifactFailureReason::DeviceDisconnected
        } else if lower.contains("timeout") {
            ArtifactFailureReason::Timeout
        } else {
            ArtifactFailureReason::Unknown(error_str.to_string())
        }
    }
}

/// Encryption zone classification for Android File-Based Encryption (FBE).
///
/// Determines whether an artifact is accessible in BFU (Before First Unlock)
/// state. This classification is version-aware — the same artifact may be
/// in different zones across Android versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionZone {
    /// Device Encrypted (DE) storage — accessible even in BFU state.
    DeviceEncrypted,
    /// Credential Encrypted (CE) storage — requires unlock (AFU).
    CredentialEncrypted,
    /// Has components in both DE and CE storage.
    DeAndCe,
    /// Encryption zone cannot be determined without root access.
    UnknownEncryption,
}

impl std::fmt::Display for EncryptionZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionZone::DeviceEncrypted => write!(f, "DE (Device Encrypted)"),
            EncryptionZone::CredentialEncrypted => write!(f, "CE (Credential Encrypted)"),
            EncryptionZone::DeAndCe => write!(f, "DE+CE (Mixed)"),
            EncryptionZone::UnknownEncryption => write!(f, "UNKNOWN"),
        }
    }
}

/// Complete record of a single artifact acquisition attempt.
///
/// Every acquisition attempt produces one of these, regardless of outcome.
/// These records are written to the audit log and appear in reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionAttemptRecord {
    /// The artifact class being acquired.
    pub artifact_class: ArtifactClass,
    /// The device-side path targeted.
    pub device_path: String,
    /// The exact ADB command that was executed.
    pub command_executed: String,
    /// Whether the attempt succeeded.
    pub success: bool,
    /// Error code or message if failed.
    pub error_detail: Option<String>,
    /// Classified failure reason.
    pub failure_reason: Option<ArtifactFailureReason>,
    /// The Android security mechanism that caused the failure.
    pub security_mechanism: Option<String>,
    /// Whether this failure was expected given the capability profile.
    pub expected_given_profile: bool,
    /// SHA-256 hash of acquired data (only if successful).
    pub sha256_hash: Option<String>,
    /// Size in bytes of acquired data (only if successful).
    pub acquired_bytes: Option<u64>,
    /// Timestamp of the attempt.
    pub attempted_at: DateTime<Utc>,
}

/// The examiner's decision when prompted during BFU or partial acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExaminerDecision {
    /// Examiner chose to unlock the device and retry.
    UnlockDevice,
    /// Examiner chose to proceed with partial acquisition.
    ProceedPartial,
    /// Examiner chose to abort the investigation.
    AbortInvestigation,
}

// ──────────────────────────────────────────────────────────────────────────────
// Artifact Classification
// ──────────────────────────────────────────────────────────────────────────────

/// Classification of forensic artifact types recognized by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactClass {
    /// WPA supplicant configuration (known networks).
    WpaSupplicant,
    /// WifiConfigStore XML (Android 8+).
    WifiConfigStore,
    /// DHCP lease records.
    DhcpLeases,
    /// Battery statistics with network correlation.
    BatteryStats,
    /// System connectivity logs.
    ConnectivityLogs,
    /// Kernel dmesg network events.
    KernelLogs,
    /// Hostapd (hotspot) configuration and logs.
    HostapdLogs,
    /// DNS resolver cache.
    DnsCache,
    /// Network policy data.
    NetworkPolicy,
    /// Build properties (device identity).
    BuildProp,
    /// Unknown or unclassified artifact.
    Unknown,
}

impl ArtifactClass {
    /// Returns the baseline reliability score for this artifact class.
    ///
    /// These values are constants defined by the Confidence Model v1.0
    /// and are documented in the forensic methodology disclosure.
    pub fn baseline_reliability(&self) -> f64 {
        match self {
            ArtifactClass::KernelLogs => 0.99,
            ArtifactClass::WifiConfigStore => 0.95,
            ArtifactClass::WpaSupplicant => 0.90,
            ArtifactClass::DhcpLeases => 0.92,
            ArtifactClass::ConnectivityLogs => 0.85,
            ArtifactClass::BatteryStats => 0.80,
            ArtifactClass::HostapdLogs => 0.88,
            ArtifactClass::DnsCache => 0.70,
            ArtifactClass::NetworkPolicy => 0.85,
            ArtifactClass::BuildProp => 0.99,
            ArtifactClass::Unknown => 0.30,
        }
    }
}

/// The volatility classification of an artifact.
/// Volatile artifacts are cleared on reboot or under memory pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolatilityClass {
    /// Persistent — survives reboot (e.g., configuration files).
    Persistent,
    /// Semi-volatile — survives reboot but may be rotated (e.g., log files).
    SemiVolatile,
    /// Volatile — lost on reboot (e.g., kernel ring buffer, RAM caches).
    Volatile,
}

// ──────────────────────────────────────────────────────────────────────────────
// V2 Input Types & Security Constraint Model (SCM)
// ──────────────────────────────────────────────────────────────────────────────

/// Supported V2 forensic input types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputType {
    /// Physical images (raw NAND/eMMC dumps)
    PhysicalImage,
    /// Full filesystem extractions (tar, zip, directory trees)
    FullFilesystem,
    /// Logical extractions (ADB backups, selected app pulls)
    LogicalExtraction,
    /// Raw partition dumps (dd dumps of individual partitions)
    PartitionDump,
    /// Directory-based forensic extractions
    DirectoryExtraction,
    /// Individual artifact collections (targeted files)
    ArtifactCollection,
    /// UFED output formats
    UfedExport,
    /// Oxygen Forensic output formats
    OxygenExport,
    /// Magnet AXIOM output formats
    MagnetExport,
    /// Live device acquisition (secondary module)
    LiveDevice,
}

/// SCM (Security Constraint Model) privilege levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrivilegeLevel {
    User,
    Shell,
    System,
    Root,
}

/// SCM encryption requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionStateRequirement {
    Unencrypted,
    DeviceEncrypted,
    CredentialEncrypted,
    Any,
}

/// SCM SELinux requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelinuxRequirement {
    Permissive,
    Enforcing,
    Any,
}

/// Security constraint specification for an artifact class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityConstraint {
    pub min_privilege: PrivilegeLevel,
    pub encryption: EncryptionStateRequirement,
    pub selinux: SelinuxRequirement,
}

impl SecurityConstraint {
    /// Check whether a given SCM profile satisfies this security constraint.
    pub fn is_satisfied_by(&self, profile: &SCMProfile) -> Result<(), String> {
        // 1. Check Privilege Level
        if profile.privilege < self.min_privilege {
            return Err(format!(
                "Insufficient privilege: current is {:?}, requires {:?}",
                profile.privilege, self.min_privilege
            ));
        }

        // 2. Check Encryption state
        match self.encryption {
            EncryptionStateRequirement::Unencrypted => {
                if profile.encryption == EncryptionState::BeforeFirstUnlock {
                    return Err("Target partition is encrypted and CE keys are evicted (BFU)".to_string());
                }
            }
            EncryptionStateRequirement::DeviceEncrypted => {
                if profile.encryption == EncryptionState::Unknown {
                    return Err("Encryption state unknown".to_string());
                }
            }
            EncryptionStateRequirement::CredentialEncrypted => {
                if profile.encryption != EncryptionState::AfterFirstUnlock {
                    return Err("Credential encrypted partition requires After First Unlock (AFU)".to_string());
                }
            }
            EncryptionStateRequirement::Any => {}
        }

        // 3. Check SELinux mode
        match self.selinux {
            SelinuxRequirement::Permissive => {
                if profile.selinux == SelinuxMode::Enforcing && profile.privilege != PrivilegeLevel::Root {
                    return Err("SELinux is enforcing and blocks non-root access to this domain".to_string());
                }
            }
            SelinuxRequirement::Enforcing => {}
            SelinuxRequirement::Any => {}
        }

        Ok(())
    }
}

/// The SCM profile of a given analysis context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SCMProfile {
    pub privilege: PrivilegeLevel,
    pub encryption: EncryptionState,
    pub selinux: SelinuxMode,
}

/// Dynamic accessibility status of an artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessibilityStatus {
    Accessible,
    Inaccessible {
        required: SecurityConstraint,
        current_profile: SCMProfile,
        reason: String,
    },
}

// ──────────────────────────────────────────────────────────────────────────────
// Evidence Records
// ──────────────────────────────────────────────────────────────────────────────

/// The provenance of a piece of evidence, linking it back to its
/// exact source bytes in the original artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReference {
    /// The artifact from which this record was extracted.
    pub artifact_id: ArtifactId,
    /// The SHA-256 hash of the source artifact at time of parsing.
    pub artifact_hash: String,
    /// The parser that produced this record.
    pub parser_id: String,
    /// The exact version of the parser.
    pub parser_version: String,
    /// Byte offset within the artifact where this record's source data begins.
    pub byte_offset: Option<u64>,
    /// Byte length of the source data for this record.
    pub byte_length: Option<u64>,
    /// Database row ID if the artifact is a SQLite database.
    pub db_row_id: Option<i64>,
    /// Timestamp when this parsing occurred.
    pub parsed_at: DateTime<Utc>,
}

/// Wi-Fi security protocol taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityProtocol {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
    Owe,
    EapPeap,
    EapTls,
    Unknown,
}

impl std::fmt::Display for SecurityProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProtocol::Open => write!(f, "OPEN"),
            SecurityProtocol::Wep => write!(f, "WEP"),
            SecurityProtocol::WpaPsk => write!(f, "WPA-PSK"),
            SecurityProtocol::Wpa2Psk => write!(f, "WPA2-PSK"),
            SecurityProtocol::Wpa3Sae => write!(f, "WPA3-SAE"),
            SecurityProtocol::Owe => write!(f, "OWE"),
            SecurityProtocol::EapPeap => write!(f, "EAP-PEAP"),
            SecurityProtocol::EapTls => write!(f, "EAP-TLS"),
            SecurityProtocol::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Anomaly flags for timestamps that require forensic attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimestampAnomaly {
    /// No anomaly detected.
    None,
    /// Timestamp is in the future relative to acquisition time.
    Future,
    /// Timestamp is Unix epoch zero (1970-01-01T00:00:00Z).
    EpochDefault,
    /// Timestamp predates the Android OS (before 2008).
    PreAndroidEra,
    /// Timestamp matches a known OEM default date.
    OemDefault,
    /// Clock skew detected between device time and acquisition time.
    ClockSkewDetected,
    /// Timestamp format could not be reliably determined.
    FormatAmbiguous,
}

/// A forensic timestamp carrying both the raw and normalized values
/// along with provenance and anomaly metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicTimestamp {
    /// The raw timestamp value exactly as extracted from the artifact.
    pub raw_value: String,
    /// The format of the raw timestamp (e.g., "unix_epoch_ms", "iso8601").
    pub source_format: String,
    /// The normalized UTC timestamp.
    pub normalized_utc: DateTime<Utc>,
    /// Any detected clock skew compensation applied (in seconds).
    pub clock_skew_compensation_secs: Option<f64>,
    /// Anomaly classification for this timestamp.
    pub anomaly: TimestampAnomaly,
    /// Confidence in this timestamp's accuracy (0.0 to 1.0).
    pub confidence: f64,
}

/// The evidence layer classification, tracking the processing stage of each record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceLayer {
    /// Layer 0: Raw bytes, exactly as acquired.
    Raw,
    /// Layer 1: Parsed records, untransformed structured data.
    Parsed,
    /// Layer 2: Normalized records, cleaned and unified.
    Normalized,
    /// Layer 3: Correlated records, derived conclusions.
    Correlated,
}

/// Whether the device was acting as a Wi-Fi client or a hotspot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkRole {
    /// Device connected to an external Wi-Fi network.
    DeviceAsClient,
    /// Device operating as a mobile hotspot / access point.
    DeviceAsHotspot,
    /// Insufficient evidence to classify.
    Ambiguous,
}

/// Confidence classification for court presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceClassification {
    /// Score ≥ 0.95 — supported by multiple independent sources with no contradictions.
    Definitive,
    /// Score 0.80–0.94 — strong evidence with minor gaps.
    High,
    /// Score 0.50–0.79 — moderate evidence, some uncertainty.
    Moderate,
    /// Score < 0.50 — weak evidence, significant gaps or contradictions.
    Low,
    /// Active contradictions exist for this finding.
    Contradicted,
}

impl ConfidenceClassification {
    /// Derive the classification from a numeric score.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.95 {
            ConfidenceClassification::Definitive
        } else if score >= 0.80 {
            ConfidenceClassification::High
        } else if score >= 0.50 {
            ConfidenceClassification::Moderate
        } else {
            ConfidenceClassification::Low
        }
    }
}

impl std::fmt::Display for ConfidenceClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidenceClassification::Definitive => write!(f, "DEFINITIVE"),
            ConfidenceClassification::High => write!(f, "HIGH"),
            ConfidenceClassification::Moderate => write!(f, "MODERATE"),
            ConfidenceClassification::Low => write!(f, "LOW"),
            ConfidenceClassification::Contradicted => write!(f, "CONTRADICTED"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Audit Types
// ──────────────────────────────────────────────────────────────────────────────

/// Classification of operations recorded in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOperationType {
    // ── Investigation Lifecycle ──
    InvestigationCreated,
    InvestigationOpened,
    InvestigationClosed,

    // ── Device Operations ──
    DeviceConnected,
    DeviceDisconnected,
    CapabilityDetectionStarted,
    CapabilityDetectionCompleted,
    CapabilityProfileAcknowledged,

    // ── Acquisition ──
    ArtifactAcquisitionStarted,
    ArtifactAcquisitionCompleted,
    ArtifactAcquisitionFailed,

    // ── Parsing ──
    ParserExecutionStarted,
    ParserExecutionCompleted,
    ParserExecutionFailed,

    // ── Normalization ──
    NormalizationStarted,
    NormalizationCompleted,

    // ── Correlation ──
    CorrelationStarted,
    CorrelationCompleted,

    // ── Confidence ──
    ConfidenceScoreComputed,

    // ── Examiner Actions ──
    ExaminerOverrideApplied,
    ExaminerNoteAdded,

    // ── Report ──
    ReportGenerationStarted,
    ReportGenerationCompleted,
    ReportExported,

    // ── Evidence Store ──
    EvidenceStoreCreated,
    EvidenceStoreVerified,
    EvidenceIntegrityViolation,

    // ── Plugin ──
    PluginLoaded,
    PluginValidationFailed,

    // ── System Events ──
    SystemStartup,
    SystemShutdown,
    SystemCrashRecovery,
    AuditChainVerified,

    // ── V2 VFS & SCM Events ──
    VfsMounted,
    VfsFileRead,
    VfsIntegrityChecked,
    ScmValidationFailed,

    // ── Catch-all for extensibility ──
    Custom(String),
}

/// The result status of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// The operation completed successfully.
    Success,
    /// The operation failed with an error.
    Failure(String),
    /// The operation was started but not yet completed (intent log).
    Pending,
    /// The operation was skipped (e.g., artifact already exists).
    Skipped(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_classification_boundaries() {
        assert_eq!(ConfidenceClassification::from_score(1.0), ConfidenceClassification::Definitive);
        assert_eq!(ConfidenceClassification::from_score(0.95), ConfidenceClassification::Definitive);
        assert_eq!(ConfidenceClassification::from_score(0.94), ConfidenceClassification::High);
        assert_eq!(ConfidenceClassification::from_score(0.80), ConfidenceClassification::High);
        assert_eq!(ConfidenceClassification::from_score(0.79), ConfidenceClassification::Moderate);
        assert_eq!(ConfidenceClassification::from_score(0.50), ConfidenceClassification::Moderate);
        assert_eq!(ConfidenceClassification::from_score(0.49), ConfidenceClassification::Low);
        assert_eq!(ConfidenceClassification::from_score(0.0), ConfidenceClassification::Low);
    }

    #[test]
    fn test_artifact_class_baseline_reliability() {
        assert_eq!(ArtifactClass::KernelLogs.baseline_reliability(), 0.99);
        assert_eq!(ArtifactClass::Unknown.baseline_reliability(), 0.30);
        // Ensure all classes return a value in [0, 1]
        let all_classes = [
            ArtifactClass::WpaSupplicant, ArtifactClass::WifiConfigStore,
            ArtifactClass::DhcpLeases, ArtifactClass::BatteryStats,
            ArtifactClass::ConnectivityLogs, ArtifactClass::KernelLogs,
            ArtifactClass::HostapdLogs, ArtifactClass::DnsCache,
            ArtifactClass::NetworkPolicy, ArtifactClass::BuildProp,
            ArtifactClass::Unknown,
        ];
        for class in &all_classes {
            let score = class.baseline_reliability();
            assert!(score >= 0.0 && score <= 1.0, "{:?} has invalid baseline: {}", class, score);
        }
    }

    #[test]
    fn test_investigation_id_uniqueness() {
        let id1 = InvestigationId::new();
        let id2 = InvestigationId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_security_protocol_display() {
        assert_eq!(format!("{}", SecurityProtocol::Wpa2Psk), "WPA2-PSK");
        assert_eq!(format!("{}", SecurityProtocol::Open), "OPEN");
    }

    #[test]
    fn test_security_constraint() {
        let constraint = SecurityConstraint {
            min_privilege: PrivilegeLevel::System,
            encryption: EncryptionStateRequirement::CredentialEncrypted,
            selinux: SelinuxRequirement::Any,
        };

        let sat_profile = SCMProfile {
            privilege: PrivilegeLevel::Root,
            encryption: EncryptionState::AfterFirstUnlock,
            selinux: SelinuxMode::Enforcing,
        };
        assert!(constraint.is_satisfied_by(&sat_profile).is_ok());

        let unsat_profile_privilege = SCMProfile {
            privilege: PrivilegeLevel::Shell,
            encryption: EncryptionState::AfterFirstUnlock,
            selinux: SelinuxMode::Enforcing,
        };
        assert!(constraint.is_satisfied_by(&unsat_profile_privilege).is_err());

        let unsat_profile_encryption = SCMProfile {
            privilege: PrivilegeLevel::System,
            encryption: EncryptionState::BeforeFirstUnlock,
            selinux: SelinuxMode::Enforcing,
        };
        assert!(constraint.is_satisfied_by(&unsat_profile_encryption).is_err());
    }
}
