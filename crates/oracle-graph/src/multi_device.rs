//! # Multi-Device Comparison
//!
//! Compares findings from independently analyzed devices to identify shared
//! networks, establishing that two devices were at the same location at the
//! same time. Evidence isolation is maintained — raw evidence is never shared
//! between investigations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;


/// Unique identifier for a comparison session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ComparisonId(pub Uuid);

impl ComparisonId {
    pub fn new() -> Self {
        ComparisonId(Uuid::new_v4())
    }
}

impl Default for ComparisonId {
    fn default() -> Self {
        Self::new()
    }
}

/// A network that appears in both device histories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedNetwork {
    /// The SSID observed on both devices.
    pub ssid: String,
    /// The BSSID, if available on both devices.
    pub bssid: Option<String>,
    /// Earliest connection time on Device A.
    pub device_a_earliest: DateTime<Utc>,
    /// Latest connection time on Device A.
    pub device_a_latest: DateTime<Utc>,
    /// Earliest connection time on Device B.
    pub device_b_earliest: DateTime<Utc>,
    /// Latest connection time on Device B.
    pub device_b_latest: DateTime<Utc>,
    /// Whether the time windows overlap (both devices present simultaneously).
    pub temporal_overlap: bool,
    /// Duration of the overlap in seconds (0 if no overlap).
    pub overlap_duration_secs: i64,
}

/// Summary of a network event on a single device, used as input to comparison.
/// This is the *only* data shared between investigations — no raw evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceNetworkSummary {
    /// Device identifier (serial or investigation ID — never raw evidence).
    pub device_label: String,
    /// Networks observed on this device.
    pub networks: Vec<NetworkPresence>,
}

/// A single network presence record from one device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPresence {
    pub ssid: String,
    pub bssid: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// The result of comparing two device network histories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub id: ComparisonId,
    /// Shared networks found across both devices.
    pub shared_networks: Vec<SharedNetwork>,
    /// Networks unique to Device A.
    pub device_a_unique_count: usize,
    /// Networks unique to Device B.
    pub device_b_unique_count: usize,
    /// Whether any temporal overlaps were found (co-location indicator).
    pub co_location_indicated: bool,
    /// When this comparison was performed.
    pub compared_at: DateTime<Utc>,
}

/// Performs multi-device comparison without sharing raw evidence.
pub struct MultiDeviceComparator;

impl MultiDeviceComparator {
    /// Compare two device network summaries to find shared networks.
    ///
    /// SSID matching is exact (post-normalization). BSSID matching is
    /// performed when available on both sides — a BSSID match is much
    /// stronger evidence of co-location than SSID alone.
    pub fn compare(
        device_a: &DeviceNetworkSummary,
        device_b: &DeviceNetworkSummary,
    ) -> ComparisonResult {
        let mut shared = Vec::new();
        let mut a_matched = vec![false; device_a.networks.len()];
        let mut b_matched = vec![false; device_b.networks.len()];

        for (i, net_a) in device_a.networks.iter().enumerate() {
            for (j, net_b) in device_b.networks.iter().enumerate() {
                if b_matched[j] {
                    continue;
                }

                let ssid_match = net_a.ssid == net_b.ssid;
                let bssid_match = match (&net_a.bssid, &net_b.bssid) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };

                if ssid_match || bssid_match {
                    // Check temporal overlap
                    let overlap_start = net_a.first_seen.max(net_b.first_seen);
                    let overlap_end = net_a.last_seen.min(net_b.last_seen);
                    let temporal_overlap = overlap_start < overlap_end;
                    let overlap_duration = if temporal_overlap {
                        (overlap_end - overlap_start).num_seconds()
                    } else {
                        0
                    };

                    shared.push(SharedNetwork {
                        ssid: net_a.ssid.clone(),
                        bssid: net_a.bssid.clone().or_else(|| net_b.bssid.clone()),
                        device_a_earliest: net_a.first_seen,
                        device_a_latest: net_a.last_seen,
                        device_b_earliest: net_b.first_seen,
                        device_b_latest: net_b.last_seen,
                        temporal_overlap,
                        overlap_duration_secs: overlap_duration,
                    });

                    a_matched[i] = true;
                    b_matched[j] = true;
                    break;
                }
            }
        }

        let co_location = shared.iter().any(|s| s.temporal_overlap);

        ComparisonResult {
            id: ComparisonId::new(),
            shared_networks: shared,
            device_a_unique_count: a_matched.iter().filter(|m| !*m).count(),
            device_b_unique_count: b_matched.iter().filter(|m| !*m).count(),
            co_location_indicated: co_location,
            compared_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_network_detection() {
        let now = Utc::now();
        let device_a = DeviceNetworkSummary {
            device_label: "Device_A".to_string(),
            networks: vec![
                NetworkPresence {
                    ssid: "HomeNetwork".to_string(),
                    bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
                    first_seen: now - chrono::Duration::hours(10),
                    last_seen: now - chrono::Duration::hours(5),
                },
                NetworkPresence {
                    ssid: "OfficeWifi".to_string(),
                    bssid: None,
                    first_seen: now - chrono::Duration::hours(4),
                    last_seen: now - chrono::Duration::hours(1),
                },
            ],
        };

        let device_b = DeviceNetworkSummary {
            device_label: "Device_B".to_string(),
            networks: vec![
                NetworkPresence {
                    ssid: "HomeNetwork".to_string(),
                    bssid: Some("AA:BB:CC:DD:EE:FF".to_string()),
                    first_seen: now - chrono::Duration::hours(8),
                    last_seen: now - chrono::Duration::hours(6),
                },
                NetworkPresence {
                    ssid: "CafeWifi".to_string(),
                    bssid: None,
                    first_seen: now - chrono::Duration::hours(3),
                    last_seen: now - chrono::Duration::hours(2),
                },
            ],
        };

        let result = MultiDeviceComparator::compare(&device_a, &device_b);
        assert_eq!(result.shared_networks.len(), 1);
        assert_eq!(result.shared_networks[0].ssid, "HomeNetwork");
        assert!(result.shared_networks[0].temporal_overlap);
        assert!(result.co_location_indicated);
        assert_eq!(result.device_a_unique_count, 1); // OfficeWifi
        assert_eq!(result.device_b_unique_count, 1); // CafeWifi
    }

    #[test]
    fn test_no_shared_networks() {
        let now = Utc::now();
        let device_a = DeviceNetworkSummary {
            device_label: "A".to_string(),
            networks: vec![NetworkPresence {
                ssid: "NetworkA".to_string(),
                bssid: None,
                first_seen: now,
                last_seen: now,
            }],
        };
        let device_b = DeviceNetworkSummary {
            device_label: "B".to_string(),
            networks: vec![NetworkPresence {
                ssid: "NetworkB".to_string(),
                bssid: None,
                first_seen: now,
                last_seen: now,
            }],
        };

        let result = MultiDeviceComparator::compare(&device_a, &device_b);
        assert!(result.shared_networks.is_empty());
        assert!(!result.co_location_indicated);
    }
}
