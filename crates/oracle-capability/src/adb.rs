//! # ADB Interface Abstraction
//!
//! Provides a trait-based abstraction over Android Debug Bridge (ADB) commands,
//! allowing the capability detection engine to operate against both live devices
//! and mock environments for testing.
//!
//! ## Architecture
//!
//! ```text
//!              ┌──────────────────┐
//!              │   AdbInterface   │ (trait)
//!              └────────┬─────────┘
//!                       │
//!          ┌────────────┴────────────┐
//!          │                         │
//!  ┌───────┴────────┐   ┌───────────┴──────────┐
//!  │ LiveAdbInterface│   │  MockAdbInterface    │
//!  │ (shells out to  │   │  (configurable test  │
//!  │  adb binary)    │   │   responses)         │
//!  └────────────────┘   └──────────────────────┘
//! ```

use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use regex::Regex;
use tracing::{debug, info, warn};

use oracle_core::error::{OracleError, OracleResult};
use oracle_core::types::ArtifactFailureReason;
use serde::{Deserialize, Serialize};

/// Default timeout for ADB commands in seconds.
const ADB_COMMAND_TIMEOUT_SECS: u64 = 30;

// ──────────────────────────────────────────────────────────────────────────────
// Device State
// ──────────────────────────────────────────────────────────────────────────────

/// The connection state of an ADB device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdbDeviceState {
    /// Device is fully connected and authorized.
    Device,
    /// Device is connected but offline (e.g., recovery or sideload mode).
    Offline,
    /// Device is connected but the host RSA key has not been accepted.
    Unauthorized,
    /// An unrecognized state string from ADB output.
    Unknown(String),
}

impl AdbDeviceState {
    /// Parses a state string from `adb devices` output.
    pub fn from_str_state(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "device" => AdbDeviceState::Device,
            "offline" => AdbDeviceState::Offline,
            "unauthorized" => AdbDeviceState::Unauthorized,
            other => AdbDeviceState::Unknown(other.to_string()),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ADB Device
// ──────────────────────────────────────────────────────────────────────────────

/// Represents a single Android device visible to ADB.
#[derive(Debug, Clone)]
pub struct AdbDevice {
    /// The device serial number (e.g., `RFXXXXXXXX` or an IP:port pair).
    pub serial: String,
    /// The current connection state of the device.
    pub state: AdbDeviceState,
    /// The transport type (e.g., `usb`, `tcp`).
    pub transport_type: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// ADB Interface Trait
// ──────────────────────────────────────────────────────────────────────────────

/// Abstraction over ADB operations required by the Capability Detection Engine.
///
/// All methods accept a device serial number to support multi-device scenarios.
/// Implementations must map failures to appropriate [`OracleError`] variants.
pub trait AdbInterface {
    /// Lists all ADB-visible devices and their connection states.
    fn list_devices(&self) -> OracleResult<Vec<AdbDevice>>;

    /// Executes a shell command on the target device and returns the
    /// trimmed standard output.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::AdbCommandFailed`] if the command exits
    /// with a non-zero status or ADB is unreachable.
    fn shell_command(&self, serial: &str, command: &str) -> OracleResult<String>;

    /// Reads a system property via `getprop` on the target device.
    ///
    /// Returns an empty string if the property is not set.
    fn get_prop(&self, serial: &str, prop_name: &str) -> OracleResult<String>;

    /// Pulls a file from the device to a local filesystem path.
    ///
    /// # Errors
    ///
    /// Returns [`OracleError::AdbCommandFailed`] if the pull fails
    /// (e.g., file not found, permission denied).
    fn pull_file(&self, serial: &str, remote_path: &str, local_path: &str) -> OracleResult<()>;

    /// Checks whether a file or directory exists at the given path on the device.
    fn check_file_exists(&self, serial: &str, path: &str) -> OracleResult<bool>;

    /// Checks whether a file at the given path is readable by the current
    /// ADB user (shell or root).
    fn check_file_readable(&self, serial: &str, path: &str) -> OracleResult<bool>;

    /// Returns file metadata via `stat`: permissions, size, owner, SELinux context.
    ///
    /// Returns a structured `FileStatResult` or an error indicating why
    /// the stat failed (not found, permission denied, etc.).
    fn stat_file(&self, serial: &str, path: &str) -> OracleResult<FileStatResult>;

    /// Pre-flight connection verification.
    ///
    /// Verifies:
    /// 1. ADB binary is reachable
    /// 2. Exactly one device connected (or specified serial matches)
    /// 3. Device is in `device` state (authorized)
    /// 4. Shell echo test succeeds
    ///
    /// Returns the verified serial on success.
    fn verify_connection(&self, expected_serial: &str) -> OracleResult<String>;
}

// ──────────────────────────────────────────────────────────────────────────────
// Live ADB Interface
// ──────────────────────────────────────────────────────────────────────────────

/// Production implementation of [`AdbInterface`] that shells out to the
/// `adb` binary on the host system.
///
/// # Examples
///
/// ```no_run
/// use oracle_capability::adb::{AdbInterface, LiveAdbInterface};
///
/// let adb = LiveAdbInterface::new();
/// let devices = adb.list_devices().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct LiveAdbInterface {
    /// Path to the ADB binary.
    adb_path: String,
}

impl LiveAdbInterface {
    /// Creates a new `LiveAdbInterface` using the default `adb` binary
    /// found on the system PATH.
    pub fn new() -> Self {
        Self {
            adb_path: "adb".to_string(),
        }
    }

    /// Creates a new `LiveAdbInterface` with a custom path to the ADB binary.
    ///
    /// Use this when the ADB binary is not on the system PATH or when
    /// a specific version is required.
    pub fn with_adb_path(path: &str) -> Self {
        Self {
            adb_path: path.to_string(),
        }
    }

    /// Executes an ADB command and returns the raw stdout output.
    ///
    /// Commands are killed after `ADB_COMMAND_TIMEOUT_SECS` seconds to
    /// prevent hung processes from blocking the pipeline.
    fn run_adb_command(&self, args: &[&str]) -> OracleResult<String> {
        self.run_adb_command_with_timeout(args, ADB_COMMAND_TIMEOUT_SECS)
    }

    /// Executes an ADB command with a configurable timeout.
    fn run_adb_command_with_timeout(&self, args: &[&str], timeout_secs: u64) -> OracleResult<String> {
        debug!(adb_path = %self.adb_path, args = ?args, timeout_secs, "Executing ADB command");

        let mut child = Command::new(&self.adb_path)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| OracleError::AdbCommandFailed {
                serial: args.get(1).unwrap_or(&"unknown").to_string(),
                command: args.join(" "),
                reason: format!("Failed to execute adb binary '{}': {}", self.adb_path, e),
            })?;

        // Poll try_wait with 100ms intervals until timeout
        let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Process finished — collect output
                    let output = child.wait_with_output().map_err(|e| OracleError::AdbCommandFailed {
                        serial: args.get(1).unwrap_or(&"unknown").to_string(),
                        command: args.join(" "),
                        reason: format!("Failed to read command output: {}", e),
                    })?;

                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        return Err(OracleError::AdbCommandFailed {
                            serial: args.get(1).unwrap_or(&"unknown").to_string(),
                            command: args.join(" "),
                            reason: format!("Exit code {}: {}", output.status, stderr.trim()),
                        });
                    }

                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    return Ok(stdout);
                }
                Ok(None) => {
                    // Still running — check timeout
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait(); // reap zombie
                        let serial = args.get(1).unwrap_or(&"unknown").to_string();
                        warn!(serial = %serial, timeout_secs, command = args.join(" "), "ADB command timed out, process killed");
                        return Err(OracleError::AcquisitionTimeout {
                            serial,
                            path: args.last().unwrap_or(&"unknown").to_string(),
                            timeout_secs,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(OracleError::AdbCommandFailed {
                        serial: args.get(1).unwrap_or(&"unknown").to_string(),
                        command: args.join(" "),
                        reason: format!("Failed to wait on ADB process: {}", e),
                    });
                }
            }
        }
    }
}

impl Default for LiveAdbInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl AdbInterface for LiveAdbInterface {
    fn list_devices(&self) -> OracleResult<Vec<AdbDevice>> {
        let output = self.run_adb_command(&["devices", "-l"])?;
        let mut devices = Vec::new();

        // Pattern: <serial>\t<state>\s+<transport info>
        // Example: RFXXXXXXXX       device usb:1-1 product:...
        let re = Regex::new(r"^(\S+)\s+(device|offline|unauthorized|[\w]+)\s*(.*)?$")
            .map_err(|e| OracleError::AdbCommandFailed {
                serial: String::new(),
                command: "devices -l".to_string(),
                reason: format!("Failed to compile device list regex: {}", e),
            })?;

        for line in output.lines() {
            // Skip the header line "List of devices attached"
            if line.starts_with("List of") || line.trim().is_empty() {
                continue;
            }

            if let Some(caps) = re.captures(line) {
                let serial = caps.get(1).map_or("", |m| m.as_str()).to_string();
                let state_str = caps.get(2).map_or("", |m| m.as_str());
                let transport_info = caps.get(3).map_or("", |m| m.as_str());

                // Extract transport type from extended info (e.g., "usb:1-1 product:...")
                let transport_type = if transport_info.contains("usb:") {
                    "usb".to_string()
                } else if transport_info.contains("tcp:") || serial.contains(':') {
                    "tcp".to_string()
                } else {
                    "unknown".to_string()
                };

                devices.push(AdbDevice {
                    serial,
                    state: AdbDeviceState::from_str_state(state_str),
                    transport_type,
                });
            }
        }

        debug!(device_count = devices.len(), "ADB devices enumerated");
        Ok(devices)
    }

    fn shell_command(&self, serial: &str, command: &str) -> OracleResult<String> {
        debug!(serial = %serial, command = %command, "ADB shell command");
        self.run_adb_command(&["-s", serial, "shell", command])
    }

    fn get_prop(&self, serial: &str, prop_name: &str) -> OracleResult<String> {
        debug!(serial = %serial, property = %prop_name, "Reading device property");
        let cmd = format!("getprop {}", prop_name);
        self.shell_command(serial, &cmd)
    }

    fn pull_file(&self, serial: &str, remote_path: &str, local_path: &str) -> OracleResult<()> {
        debug!(
            serial = %serial,
            remote = %remote_path,
            local = %local_path,
            "Pulling file from device"
        );
        // adb pull is the ONLY acquisition method. No fallbacks.
        // If it fails, the exact error is recorded for the forensic report.
        self.run_adb_command(&["-s", serial, "pull", remote_path, local_path])?;
        Ok(())
    }

    fn check_file_exists(&self, serial: &str, path: &str) -> OracleResult<bool> {
        let cmd = format!("[ -e '{}' ] && echo EXISTS || echo MISSING", path);
        let output = self.shell_command(serial, &cmd)?;
        Ok(output.contains("EXISTS"))
    }

    fn check_file_readable(&self, serial: &str, path: &str) -> OracleResult<bool> {
        let cmd = format!("[ -r '{}' ] && echo READABLE || echo UNREADABLE", path);
        let output = self.shell_command(serial, &cmd)?;
        Ok(output.contains("READABLE"))
    }

    fn stat_file(&self, serial: &str, path: &str) -> OracleResult<FileStatResult> {
        // Use stat with a parseable format string
        let cmd = format!("stat -c '%a %s %U %G' '{}' 2>&1", path);
        let output = self.shell_command(serial, &cmd)?;

        if output.contains("No such file") || output.contains("cannot stat") {
            return Ok(FileStatResult {
                exists: false,
                permissions: None,
                size_bytes: None,
                owner: None,
                group: None,
                selinux_context: None,
            });
        }

        let parts: Vec<&str> = output.split_whitespace().collect();
        let permissions = parts.first().map(|s| s.to_string());
        let size_bytes = parts.get(1).and_then(|s| s.parse::<u64>().ok());
        let owner = parts.get(2).map(|s| s.to_string());
        let group = parts.get(3).map(|s| s.to_string());

        // Get SELinux context separately
        let ls_cmd = format!("ls -Z '{}' 2>/dev/null", path);
        let ls_output = self.shell_command(serial, &ls_cmd).unwrap_or_default();
        let selinux_context = ls_output.split_whitespace().next().map(|s| s.to_string());

        Ok(FileStatResult {
            exists: true,
            permissions,
            size_bytes,
            owner,
            group,
            selinux_context,
        })
    }

    fn verify_connection(&self, expected_serial: &str) -> OracleResult<String> {
        info!(expected_serial = %expected_serial, "Running ADB connection pre-flight checks");

        // 1. Verify ADB binary is reachable
        let devices = self.list_devices()?;

        // 2. Check device count
        if devices.is_empty() {
            return Err(OracleError::NoDeviceDetected);
        }

        // 3. Find the expected device
        let target = devices.iter().find(|d| d.serial == expected_serial);
        let device = match target {
            Some(d) => d,
            None => {
                // Check if multiple devices and serial doesn't match
                if devices.len() > 1 {
                    return Err(OracleError::AmbiguousDeviceSelection {
                        count: devices.len(),
                    });
                }
                return Err(OracleError::AdbCommandFailed {
                    serial: expected_serial.to_string(),
                    command: "devices".to_string(),
                    reason: format!(
                        "Device {} not found. Connected devices: {}",
                        expected_serial,
                        devices.iter().map(|d| d.serial.as_str()).collect::<Vec<_>>().join(", ")
                    ),
                });
            }
        };

        // 4. Check device state
        match &device.state {
            AdbDeviceState::Device => {}
            AdbDeviceState::Unauthorized => {
                return Err(OracleError::DeviceUnauthorized {
                    serial: expected_serial.to_string(),
                });
            }
            AdbDeviceState::Offline => {
                return Err(OracleError::DeviceOffline {
                    serial: expected_serial.to_string(),
                    state: "offline".to_string(),
                });
            }
            AdbDeviceState::Unknown(s) => {
                return Err(OracleError::DeviceOffline {
                    serial: expected_serial.to_string(),
                    state: s.clone(),
                });
            }
        }

        // 5. Shell echo test — confirm the transport is responsive
        let echo_result = self.shell_command(expected_serial, "echo ORACLE_VERIFY");
        match echo_result {
            Ok(output) if output.contains("ORACLE_VERIFY") => {}
            Ok(output) => {
                return Err(OracleError::AdbCommandFailed {
                    serial: expected_serial.to_string(),
                    command: "shell echo ORACLE_VERIFY".to_string(),
                    reason: format!("Echo test returned unexpected output: {}", output),
                });
            }
            Err(e) => {
                return Err(OracleError::AdbCommandFailed {
                    serial: expected_serial.to_string(),
                    command: "shell echo ORACLE_VERIFY".to_string(),
                    reason: format!("Shell echo test failed: {}", e),
                });
            }
        }

        info!(serial = %expected_serial, "ADB connection verified successfully");
        Ok(expected_serial.to_string())
    }
}

/// Result of a `stat` operation on a device file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStatResult {
    /// Whether the file exists.
    pub exists: bool,
    /// Unix permissions (octal, e.g., "644").
    pub permissions: Option<String>,
    /// File size in bytes.
    pub size_bytes: Option<u64>,
    /// File owner.
    pub owner: Option<String>,
    /// File group.
    pub group: Option<String>,
    /// SELinux security context.
    pub selinux_context: Option<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Mock ADB Interface
// ──────────────────────────────────────────────────────────────────────────────

/// Test double for [`AdbInterface`] with configurable responses.
///
/// Use the builder methods (`with_device`, `with_prop`, etc.) to set up
/// the mock state before passing it to the detector.
///
/// # Examples
///
/// ```
/// use oracle_capability::adb::{MockAdbInterface, AdbDeviceState};
///
/// let mock = MockAdbInterface::new()
///     .with_device("ABC123", AdbDeviceState::Device)
///     .with_prop("ABC123", "ro.product.model", "Pixel 8")
///     .with_shell_response("ABC123", "getenforce", "Enforcing");
/// ```
#[derive(Debug, Default, Clone)]
pub struct MockAdbInterface {
    /// The list of devices to return from `list_devices()`.
    pub devices: Vec<AdbDevice>,
    /// Keyed by `"{serial}:{command}"`. Returns the value as shell output.
    pub shell_responses: HashMap<String, String>,
    /// Keyed by `"{serial}:{prop_name}"`. Returns the value as the property.
    pub prop_responses: HashMap<String, String>,
    /// Keyed by `"{serial}:{path}"`. Returns whether the file exists.
    pub file_exists: HashMap<String, bool>,
    /// Keyed by `"{serial}:{path}"`. Returns whether the file is readable.
    pub file_readable: HashMap<String, bool>,
    /// If true, `pull_file()` will return an error.
    pub pull_should_fail: bool,
}

impl MockAdbInterface {
    /// Creates a new empty mock ADB interface.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a device to the mock device list.
    pub fn with_device(mut self, serial: &str, state: AdbDeviceState) -> Self {
        self.devices.push(AdbDevice {
            serial: serial.to_string(),
            state,
            transport_type: "usb".to_string(),
        });
        self
    }

    /// Registers a property response for `get_prop()` calls.
    pub fn with_prop(mut self, serial: &str, prop: &str, value: &str) -> Self {
        self.prop_responses
            .insert(format!("{}:{}", serial, prop), value.to_string());
        self
    }

    /// Registers a shell command response for `shell_command()` calls.
    pub fn with_shell_response(mut self, serial: &str, command: &str, response: &str) -> Self {
        self.shell_responses
            .insert(format!("{}:{}", serial, command), response.to_string());
        self
    }

    /// Registers a file existence check result.
    pub fn with_file_exists(mut self, serial: &str, path: &str, exists: bool) -> Self {
        self.file_exists
            .insert(format!("{}:{}", serial, path), exists);
        self
    }

    /// Registers a file readability check result.
    pub fn with_file_readable(mut self, serial: &str, path: &str, readable: bool) -> Self {
        self.file_readable
            .insert(format!("{}:{}", serial, path), readable);
        self
    }
}

impl AdbInterface for MockAdbInterface {
    fn list_devices(&self) -> OracleResult<Vec<AdbDevice>> {
        Ok(self.devices.clone())
    }

    fn shell_command(&self, serial: &str, command: &str) -> OracleResult<String> {
        let key = format!("{}:{}", serial, command);
        Ok(self.shell_responses.get(&key).cloned().unwrap_or_default())
    }

    fn get_prop(&self, serial: &str, prop_name: &str) -> OracleResult<String> {
        let key = format!("{}:{}", serial, prop_name);
        Ok(self.prop_responses.get(&key).cloned().unwrap_or_default())
    }

    fn pull_file(&self, serial: &str, remote_path: &str, _local_path: &str) -> OracleResult<()> {
        if self.pull_should_fail {
            return Err(OracleError::AdbCommandFailed {
                serial: serial.to_string(),
                command: format!("pull {}", remote_path),
                reason: "Mock pull failure".to_string(),
            });
        }
        Ok(())
    }

    fn check_file_exists(&self, serial: &str, path: &str) -> OracleResult<bool> {
        let key = format!("{}:{}", serial, path);
        Ok(self.file_exists.get(&key).copied().unwrap_or(false))
    }

    fn check_file_readable(&self, serial: &str, path: &str) -> OracleResult<bool> {
        let key = format!("{}:{}", serial, path);
        Ok(self.file_readable.get(&key).copied().unwrap_or(false))
    }

    fn stat_file(&self, serial: &str, path: &str) -> OracleResult<FileStatResult> {
        let key = format!("{}:{}", serial, path);
        let exists = self.file_exists.get(&key).copied().unwrap_or(false);
        Ok(FileStatResult {
            exists,
            permissions: if exists { Some("644".to_string()) } else { None },
            size_bytes: if exists { Some(1024) } else { None },
            owner: if exists { Some("system".to_string()) } else { None },
            group: if exists { Some("system".to_string()) } else { None },
            selinux_context: if exists { Some("u:object_r:system_data_file:s0".to_string()) } else { None },
        })
    }

    fn verify_connection(&self, expected_serial: &str) -> OracleResult<String> {
        let device = self.devices.iter().find(|d| d.serial == expected_serial);
        match device {
            Some(d) if d.state == AdbDeviceState::Device => Ok(expected_serial.to_string()),
            Some(d) if d.state == AdbDeviceState::Unauthorized => {
                Err(OracleError::DeviceUnauthorized { serial: expected_serial.to_string() })
            }
            Some(_) => Err(OracleError::DeviceOffline {
                serial: expected_serial.to_string(),
                state: "unknown".to_string(),
            }),
            None if self.devices.is_empty() => Err(OracleError::NoDeviceDetected),
            None => Err(OracleError::AdbCommandFailed {
                serial: expected_serial.to_string(),
                command: "devices".to_string(),
                reason: format!("Device {} not found", expected_serial),
            }),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adb_device_state_parsing() {
        assert_eq!(AdbDeviceState::from_str_state("device"), AdbDeviceState::Device);
        assert_eq!(AdbDeviceState::from_str_state("offline"), AdbDeviceState::Offline);
        assert_eq!(AdbDeviceState::from_str_state("unauthorized"), AdbDeviceState::Unauthorized);
        assert_eq!(AdbDeviceState::from_str_state("DEVICE"), AdbDeviceState::Device);
        assert_eq!(
            AdbDeviceState::from_str_state("sideload"),
            AdbDeviceState::Unknown("sideload".to_string())
        );
    }

    #[test]
    fn test_mock_list_devices() {
        let mock = MockAdbInterface::new()
            .with_device("ABC123", AdbDeviceState::Device)
            .with_device("DEF456", AdbDeviceState::Unauthorized);

        let devices = mock.list_devices().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].serial, "ABC123");
        assert_eq!(devices[0].state, AdbDeviceState::Device);
        assert_eq!(devices[1].serial, "DEF456");
        assert_eq!(devices[1].state, AdbDeviceState::Unauthorized);
    }

    #[test]
    fn test_mock_shell_command() {
        let mock = MockAdbInterface::new()
            .with_shell_response("SER1", "getenforce", "Enforcing");

        let result = mock.shell_command("SER1", "getenforce").unwrap();
        assert_eq!(result, "Enforcing");

        // Unknown command returns empty string
        let empty = mock.shell_command("SER1", "unknown_cmd").unwrap();
        assert_eq!(empty, "");
    }

    #[test]
    fn test_mock_get_prop() {
        let mock = MockAdbInterface::new()
            .with_prop("SER1", "ro.product.model", "Pixel 8 Pro");

        let model = mock.get_prop("SER1", "ro.product.model").unwrap();
        assert_eq!(model, "Pixel 8 Pro");

        let empty = mock.get_prop("SER1", "ro.nonexistent").unwrap();
        assert_eq!(empty, "");
    }

    #[test]
    fn test_mock_file_operations() {
        let mock = MockAdbInterface::new()
            .with_file_exists("SER1", "/system/build.prop", true)
            .with_file_readable("SER1", "/system/build.prop", true)
            .with_file_exists("SER1", "/data/secret", true)
            .with_file_readable("SER1", "/data/secret", false);

        assert!(mock.check_file_exists("SER1", "/system/build.prop").unwrap());
        assert!(mock.check_file_readable("SER1", "/system/build.prop").unwrap());
        assert!(mock.check_file_exists("SER1", "/data/secret").unwrap());
        assert!(!mock.check_file_readable("SER1", "/data/secret").unwrap());
        assert!(!mock.check_file_exists("SER1", "/nonexistent").unwrap());
    }

    #[test]
    fn test_mock_pull_file_success() {
        let mock = MockAdbInterface::new();
        assert!(mock.pull_file("SER1", "/remote/file", "/local/file").is_ok());
    }

    #[test]
    fn test_mock_pull_file_failure() {
        let mut mock = MockAdbInterface::new();
        mock.pull_should_fail = true;
        assert!(mock.pull_file("SER1", "/remote/file", "/local/file").is_err());
    }

    #[test]
    fn test_mock_builder_chaining() {
        let mock = MockAdbInterface::new()
            .with_device("DEV1", AdbDeviceState::Device)
            .with_prop("DEV1", "ro.product.model", "TestPhone")
            .with_shell_response("DEV1", "id", "uid=0(root)")
            .with_file_exists("DEV1", "/data/adb/ksu", false)
            .with_file_readable("DEV1", "/system/build.prop", true);

        assert_eq!(mock.devices.len(), 1);
        assert_eq!(mock.get_prop("DEV1", "ro.product.model").unwrap(), "TestPhone");
        assert_eq!(mock.shell_command("DEV1", "id").unwrap(), "uid=0(root)");
        assert!(!mock.check_file_exists("DEV1", "/data/adb/ksu").unwrap());
        assert!(mock.check_file_readable("DEV1", "/system/build.prop").unwrap());
    }
}
