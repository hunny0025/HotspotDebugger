//! # ORACLE Validation and Testing Infrastructure
//!
//! This crate provides the testing and validation infrastructure to prove ORACLE's
//! correctness, determinism, and reproducibility.

pub mod ground_truth;
pub mod synthetic;
pub mod cross_tool;
pub mod reproducibility;
pub mod regression;

pub use ground_truth::{GroundTruthDataset, GroundTruthEvent, GroundTruthValidator, ValidationResult};
pub use synthetic::SyntheticGenerator;
pub use cross_tool::{CrossToolComparisonResult, CrossToolValidator, ExternalToolFindings};
pub use reproducibility::{CertificateGenerator, ReproducibilityCertificate};
pub use regression::RegressionTester;
