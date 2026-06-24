<div align="center">

![GPCSSI 2024 Logo](docs/images/media__1782323355445.png)

# ORACLE
### Over-the-air Reconnaissance and Acquisition for Connected Log Environments
**The Definitive Android Mobile Network Forensics Platform**

*Developed for the Gurugram Cyber Police — GPCSSI 2024 Internship Program*

[![Build & Test Status](https://github.com/hunny0025/HotspotDebugger/actions/workflows/rust.yml/badge.svg)](https://github.com/hunny0025/HotspotDebugger/actions)
[![Language](https://img.shields.io/badge/Language-Rust--stable-orange.svg)](https://www.rust-lang.org/)
[![Confidence Model](https://img.shields.io/badge/Scoring%20Engine-Confidence%20Model%20v2.0.0-blue.svg)](#)

</div>

---

## 📖 Project Overview

**ORACLE** is a production-grade, forensically sound logical acquisition and analysis platform built entirely in **Rust** to extract, parse, correlate, and score wireless and connectivity logs from Android devices. 

Designed under a strict **Write-Before-Execute** philosophy, ORACLE guarantees absolute data integrity by computing SHA-256 hashes of all raw source logs immediately upon extraction and maintaining a cryptographically chained, append-only SQLite audit log. 

It eliminates the "black box" nature of traditional forensic tools by implementing the **Confidence Model v2.0.0** — a transparent mathematical scoring engine that assigns confidence values and embeds explicit, human-readable reasoning chains to justify every finding in court.

---

## 📄 Branded Project Reports & Guides
All final internship report deliverables are compiled inside the `docs/` folder:
*   **[Interactive HTML Project Report](docs/oracle_internship_report.html):** A self-contained, beautifully styled HTML document featuring GPCSSI 2024 dark-mode branding, embedded mathematical equations, and embedded high-fidelity CLI terminal screenshots. **Perfect for opening in any web browser and saving/printing as a PDF.**
*   **[Definitive Markdown Project Guide](docs/project_report.md):** The complete technical architecture specification, scoring formula logic, and anomaly detection rules.

---

## 🛠️ System Architecture (15-Crate Workspace)

ORACLE is organized as a modular Rust workspace consisting of 15 crates:

```
oracle-workspace/
├── crates/
│   ├── oracle-core/         # Primitive types, unified errors, and hashing utilities
│   ├── oracle-cli/          # CLI command orchestrator and entry point
│   ├── oracle-capability/   # ADB interface, connection verification, and BFU state probers
│   ├── oracle-discovery/    # Traversers for both live devices and offline virtual filesystems (VFS)
│   ├── oracle-parser/       # Schema-versioned parsers (DHCP leases, WpaSupplicant, WifiConfigStore)
│   ├── oracle-oem/          # Proprietary vendor parsers (e.g. Samsung custom wifi logs)
│   ├── oracle-normalize/    # Schema unification and record conflict detection
│   ├── oracle-correlate/    # Timeline builder, session overlap checker, and anomaly engine
│   ├── oracle-confidence/   # Confidence Model v2.0.0 scoring formula evaluator
│   ├── oracle-report/       # Pixel-perfect PDF & JSON report generators with integrity seals
│   ├── oracle-audit/        # Cryptographically chained SQLite audit database logger
│   ├── oracle-evidence/     # Content-Addressable Storage (CAS) for raw source evidence
│   ├── oracle-graph/        # Graph-based network connection maps
│   ├── oracle-ai/           # Extension point for AI-assisted case narrative generation
│   └── oracle-validation/   # High-integrity ground truth regression test suite
```

---

## ⚡ Quick Start & Setup Guide

### 📋 Prerequisites
To build and run ORACLE, you need:
1.  **Rust Stable Toolchain:** Install from [rustup.rs](https://rustup.rs/)
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2.  **Android Debug Bridge (ADB):** Ensure `adb` is installed and available in your system `PATH`.
3.  *(Optional)* A connected Android device with **USB Debugging enabled** for live logical extraction.

---

### 📥 Installation & Compilation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/hunny0025/HotspotDebugger.git
    cd HotspotDebugger
    ```
2.  **Build the entire workspace:**
    ```bash
    cargo build --workspace --release
    ```
    This compiles all crates and generates the optimized production binary `target/release/oracle.exe` (or `oracle` on Linux/macOS).

---

### 🧪 Running Test Suites
ORACLE features **77 unit and integration tests** validating parser safety, timeline correlation, and confidence scoring math.
```bash
cargo test --workspace
```

---

## 💻 CLI Command Reference

ORACLE is driven by an command-line interface. Run `cargo run -- --help` or `target/release/oracle --help` for the full reference.

### 1. Pre-Flight Environment Audit
Validates that ADB is online, the database is healthy, and configuration settings are correct:
```bash
cargo run --bin oracle -- doctor
```

### 2. Initialise a Case Workspace
Creates a secure, append-only SQLite database for tracking the chain of custody:
```bash
cargo run --bin oracle -- case new --name "CASE-2024-001" --examiner "Investigator Sharma"
```

### 3. Live Logical Ingestion & Parsing
Performs pre-flight capability checks, probes for BFU/AFU lock states, acquires wireless logs via ADB, computes SHA-256 hashes, normalizes data, correlations timeline events, and applies confidence math:
```bash
cargo run --bin oracle -- analyze --case "CASE-2024-001" --verbose
```

### 4. Compile the Final Court Deliverables
Generates the cryptographically sealed PDF evidence book and raw JSON data export:
```bash
cargo run --bin oracle -- report compile --case "CASE-2024-001" --output-dir "./reports"
```

---

## 📊 Confidence Scoring Model (v2.0.0)

Every connection finding receives a definitive score using:
$$C_{final} = \text{clamp}\left(0.0, 1.0, \left((W_{SR} \times S_R + W_{CS} \times C_S) \times T_T \times A_V \times C_V \times (1 - A_F)\right) - C_P\right)$$

*   **Source Reliability ($S_R$):** `WifiConfigStore.xml` (**0.95**), `DHCP Leases` (**0.92**), `WpaSupplicant` (**0.90**).
*   **Corroboration Score ($C_S$):** Boosted logarithmically based on the number of overlapping log sources.
*   **Contradiction Penalty ($C_P$):** Large deductions applied if a device appears connected to physically disjoint access points simultaneously.
*   **Timestamp Trust ($T_T$):** Deducted if there are signs of local device clock tampering.

---

## 🔒 License
Proprietary — Developed under the **GPCSSI 2024 Internship Program** at Gurugram Cyber Police. Unauthorized distribution is prohibited.

**Gurugram Cyber Police — Keeping Gurugram Cyber Safe**