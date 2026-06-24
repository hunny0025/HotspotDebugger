//! # Schema Version Registry (SVR)
//!
//! Tracks known schema versions per artifact type per Android version range
//! and resolves them safely, falling back to standard heuristics for unknown schema versions.

use std::collections::HashMap;
use oracle_core::ArtifactClass;

/// Tracks expected schema versions for each artifact class based on Android API level.
#[derive(Debug, Clone)]
pub struct SchemaVersionRegistry {
    version_map: HashMap<(ArtifactClass, u32), String>,
}

impl SchemaVersionRegistry {
    /// Create and pre-populate the registry with known schema versions.
    pub fn new() -> Self {
        let mut version_map = HashMap::new();

        // WifiConfigStore XML format versions
        for api in 26..=34 {
            version_map.insert((ArtifactClass::WifiConfigStore, api), "wifi_config_v1".to_string());
        }

        // WPA Supplicant configuration format versions
        for api in 19..=29 {
            version_map.insert((ArtifactClass::WpaSupplicant, api), "wpa_supplicant_v1".to_string());
        }

        // DHCP leases format versions
        for api in 21..=34 {
            version_map.insert((ArtifactClass::DhcpLeases, api), "dhcp_leases_v1".to_string());
        }

        // Connectivity Logs format versions
        for api in 21..=34 {
            version_map.insert((ArtifactClass::ConnectivityLogs, api), "connectivity_logs_v1".to_string());
        }

        Self { version_map }
    }

    /// Resolve the expected schema version name, falling back safely to a default heuristic version.
    pub fn resolve_version(&self, class: ArtifactClass, api_level: u32) -> String {
        self.version_map
            .get(&(class, api_level))
            .cloned()
            .unwrap_or_else(|| "heuristics_fallback_v1".to_string())
    }
}

impl Default for SchemaVersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_known_schemas() {
        let svr = SchemaVersionRegistry::new();
        assert_eq!(svr.resolve_version(ArtifactClass::WifiConfigStore, 34), "wifi_config_v1");
        assert_eq!(svr.resolve_version(ArtifactClass::WpaSupplicant, 29), "wpa_supplicant_v1");
    }

    #[test]
    fn test_resolve_fallback_schema() {
        let svr = SchemaVersionRegistry::new();
        // API level 99 does not exist yet; should fallback
        assert_eq!(svr.resolve_version(ArtifactClass::WifiConfigStore, 99), "heuristics_fallback_v1");
    }
}
