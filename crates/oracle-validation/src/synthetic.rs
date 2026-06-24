//! # Synthetic Dataset Generator
//!
//! Generates synthetic Android forensic artifacts with known content for
//! validation and testing.

use oracle_core::types::ArtifactClass;
use std::path::Path;

/// Generates synthetic data.
pub struct SyntheticGenerator;

impl SyntheticGenerator {
    /// Generates a synthetic WifiConfigStore.xml file.
    pub fn generate_wifi_config_store(path: &Path, ssids: &[&str]) -> std::io::Result<()> {
        let mut xml = String::from("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<WifiConfigStoreData>\n<NetworkList>\n");
        for ssid in ssids {
            xml.push_str(&format!(
                "<Network>\n<WifiConfiguration>\n<string name=\"SSID\">\"{}\"</string>\n</WifiConfiguration>\n</Network>\n",
                ssid
            ));
        }
        xml.push_str("</NetworkList>\n</WifiConfigStoreData>");
        std::fs::write(path, xml)
    }

    /// Generates a generic synthetic artifact.
    pub fn generate_artifact(class: ArtifactClass, path: &Path) -> std::io::Result<()> {
        match class {
            ArtifactClass::WifiConfigStore => Self::generate_wifi_config_store(path, &["SyntheticNetwork1", "SyntheticNetwork2"]),
            _ => std::fs::write(path, b"Synthetic Data"),
        }
    }
}
