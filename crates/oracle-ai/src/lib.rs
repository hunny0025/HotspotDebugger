//! # ORACLE AI Assistance Layer
//!
//! Advisory-only AI layer for the ORACLE V2 forensic platform.
//!
//! # Hard Constraints
//!
//! 1. **NEVER produces forensic findings** — all outputs are `AiHypothesis`
//! 2. **NEVER modifies evidence records** — enforced by type system
//! 3. **All suggestions labeled** as `AI-ASSISTED HYPOTHESIS`
//! 4. **Requires examiner review** before any output can appear in a report
//! 5. **Completely removable** — no other forensic crate depends on this one
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                   AI Assistance Layer                 │
//! │                                                      │
//! │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
//! │  │  Hypothesis  │  │   Anomaly    │  │ Constraint │ │
//! │  │   System     │  │  Detector    │  │ Enforcer   │ │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬─────┘ │
//! │         │                 │                  │       │
//! │         └─────────────────┼──────────────────┘       │
//! │                           │                          │
//! │              All outputs: AiHypothesis               │
//! │              Label: "AI-ASSISTED HYPOTHESIS"         │
//! └──────────────────────────────────────────────────────┘
//!         │ (advisory only — no reverse dependencies)
//!         ▼
//!   Examiner Review Gate
//! ```
//!
//! # Modules
//!
//! - [`hypothesis`] — Core hypothesis type with promotion boundary protocol.
//! - [`anomaly_detector`] — Pattern-based anomaly detection.
//! - [`constraints`] — Hard constraint enforcement and validation.

pub mod hypothesis;
pub mod anomaly_detector;
pub mod constraints;

// Re-export primary types.
pub use hypothesis::{AiHypothesis, HypothesisId, HypothesisCategory, PromotionStatus};
pub use anomaly_detector::{AnomalyDetector, FilesystemStats, UnknownPath, SizeAnomaly};
pub use constraints::{AiGenerated, validate_constraints, ConstraintValidationResult};
