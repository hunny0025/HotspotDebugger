//! # ORACLE CLI
//!
//! Command-line interface for the ORACLE Android Network Forensics Platform.
//!
//! This binary provides the primary user interface for conducting forensic
//! investigations, managing evidence, and generating court-ready reports.

mod startup;
mod pipeline;
mod commands;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

/// ORACLE — Android Network Forensics Platform
///
/// A forensic analysis tool for extracting, correlating, and reporting
/// network activity evidence from Android devices.
#[derive(Parser, Debug)]
#[command(
    name = "oracle",
    version,
    author,
    about = "ORACLE Android Network Forensics Platform",
    long_about = "ORACLE is a forensic analysis platform for extracting, correlating, \
                  and reporting network activity evidence from Android devices. \
                  All operations maintain cryptographic chain of custody."
)]
struct Cli {
    /// Path to the ORACLE configuration file.
    ///
    /// If not specified, ORACLE will look for `config/default.toml` relative
    /// to the current working directory, then fall back to built-in defaults.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable verbose debug logging (overrides config log level).
    #[arg(short, long)]
    verbose: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available ORACLE subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage investigation workspaces (new, list, open, export).
    Case {
        #[command(subcommand)]
        action: CaseAction,
    },
    /// Inspect connected device hardware and capabilities.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Ingest forensic artifacts from a device or filesystem image.
    Ingest {
        #[command(subcommand)]
        action: IngestAction,
    },
    /// Execute parsing, normalization, correlation, and scoring.
    Analyze {
        /// Investigation ID to analyze.
        #[arg(short, long)]
        investigation_id: String,
    },
    /// Manage and verify hashes of ingested raw files.
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    /// View the reconstructed network activity timeline.
    Timeline {
        /// Investigation ID to view.
        #[arg(short, long)]
        investigation_id: String,
    },
    /// Compile formal investigation reports and PDF evidence books.
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },
    /// Verify cryptographic integrity of case audit log database.
    #[command(name = "verify-audit")]
    VerifyAudit {
        /// Investigation ID to verify.
        #[arg(short, long)]
        investigation_id: String,
    },
    /// Run diagnostic health checks on tools, paths, and databases.
    Doctor,
    /// Interactive forensic shell.
    Shell,
}

#[derive(Subcommand, Debug)]
enum CaseAction {
    /// Initialize a new case and database workspace.
    New {
        /// Human-readable case identifier (e.g., "CASE-2026-0042").
        #[arg(short = 'n', long)]
        case_name: String,

        /// Name of the forensic examiner conducting the investigation.
        #[arg(short, long)]
        examiner: String,

        /// Optional case notes or description.
        #[arg(short = 'd', long)]
        description: Option<String>,
    },
    /// Show all cases found in the investigations directory.
    List,
}

#[derive(Subcommand, Debug)]
enum DeviceAction {
    /// Perform capability detection and hardware assessment.
    Inspect {
        /// Device serial or identifier.
        #[arg(short, long)]
        serial: String,
    },
}

#[derive(Subcommand, Debug)]
enum IngestAction {
    /// Logical acquisition from a connected USB device.
    Device {
        /// Investigation ID to ingest artifacts into.
        #[arg(short, long)]
        investigation_id: String,

        /// Source path (device serial or identifier).
        #[arg(short, long)]
        source: String,
    },
    /// Read forensic files from a filesystem image (.tar, .img).
    Image {
        /// Investigation ID to ingest artifacts into.
        #[arg(short, long)]
        investigation_id: String,

        /// Source path (filesystem image file).
        #[arg(short, long)]
        source: String,
    },
    /// Import files from a logical backup folder.
    Directory {
        /// Investigation ID to ingest artifacts into.
        #[arg(short, long)]
        investigation_id: String,

        /// Source path (logical backup folder).
        #[arg(short, long)]
        source: String,
    },
}

#[derive(Subcommand, Debug)]
enum EvidenceAction {
    /// Run SHA-256 hash checks on all ingested artifacts.
    Verify {
        /// Investigation ID to verify.
        #[arg(short, long)]
        investigation_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum ReportAction {
    /// Generate all reports (JSON + PDF) for a completed case.
    Generate {
        /// Investigation ID.
        #[arg(short, long)]
        investigation_id: String,
    },
}

/// Print the ORACLE startup banner to the terminal.
fn print_banner() {
    eprintln!(
        r#"
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║    ██████╗ ██████╗  █████╗  ██████╗██╗     ███████╗       ║
  ║   ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║     ██╔════╝       ║
  ║   ██║   ██║██████╔╝███████║██║     ██║     █████╗         ║
  ║   ██║   ██║██╔══██╗██╔══██║██║     ██║     ██╔══╝         ║
  ║   ╚██████╔╝██║  ██║██║  ██║╚██████╗███████╗███████╗       ║
  ║    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝       ║
  ║                                                           ║
  ║   Android Network Forensics Platform   v{:<17} ║
  ║   All operations are cryptographically audited.           ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
"#,
        env!("CARGO_PKG_VERSION")
    );
}

/// Initialize the tracing subscriber for structured logging.
///
/// Respects the `ORACLE_LOG` environment variable if set, otherwise
/// uses the log level from the configuration file.
fn init_tracing(log_level: &str, verbose: bool) {
    let filter = if verbose {
        "debug".to_string()
    } else {
        std::env::var("ORACLE_LOG").unwrap_or_else(|_| log_level.to_string())
    };

    let subscriber = fmt()
        .with_env_filter(
            EnvFilter::try_new(&filter).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global tracing subscriber");
}

/// Load the ORACLE configuration from the specified path or defaults.
///
/// Resolution order:
/// 1. Explicit `--config` path (error if not found)
/// 2. `config/default.toml` in the current working directory
/// 3. Built-in default configuration
fn load_config(config_path: Option<&PathBuf>) -> Result<oracle_core::OracleConfig> {
    if let Some(path) = config_path {
        info!(path = %path.display(), "Loading configuration from explicit path");
        oracle_core::OracleConfig::load_from_file(path)
            .context(format!("Failed to load config from {}", path.display()))
    } else {
        let default_path = PathBuf::from("config/default.toml");
        if default_path.exists() {
            info!("Loading configuration from config/default.toml");
            oracle_core::OracleConfig::load_from_file(&default_path)
                .context("Failed to load config from config/default.toml")
        } else {
            info!("No configuration file found, using built-in defaults");
            let base_dir = std::env::current_dir()
                .context("Failed to determine current working directory")?;
            Ok(oracle_core::OracleConfig::default_config(&base_dir))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration before printing the banner so we can
    // fail fast on configuration errors.
    let config = load_config(cli.config.as_ref())?;

    // Initialize tracing with the resolved log level.
    init_tracing(&config.general.log_level, cli.verbose);

    print_banner();

    // Run pre-flight checks: ADB, directory writability, audit integrity, plugins.
    if let Err(e) = startup::run_preflight_checks(&config) {
        tracing::warn!("Pre-flight check warning: {:#}", e);
        eprintln!("⚠  Pre-flight check issue: {:#}", e);
        eprintln!("   Some features may be unavailable. Proceeding with caution.");
    }

    info!(
        organization = %config.general.organization_name,
        investigations_dir = %config.general.investigations_dir.display(),
        "ORACLE initialized"
    );

    match cli.command {
        Commands::Case { action } => match action {
            CaseAction::New {
                case_name,
                examiner,
                description,
            } => {
                commands::handle_new_investigation(&config, case_name, examiner, description)?;
            }
            CaseAction::List => {
                commands::handle_list_cases(&config)?;
            }
        },
        Commands::Device { action } => match action {
            DeviceAction::Inspect { serial } => {
                commands::handle_detect_capabilities(&config, &serial)?;
            }
        },
        Commands::Ingest { action } => match action {
            IngestAction::Device { investigation_id, source }
            | IngestAction::Image { investigation_id, source }
            | IngestAction::Directory { investigation_id, source } => {
                commands::handle_acquire(&config, &source, &investigation_id)?;
            }
        },
        Commands::Analyze { investigation_id } => {
            commands::handle_parse(&config, &investigation_id)?;
            commands::handle_normalize(&config, &investigation_id)?;
            commands::handle_correlate(&config, &investigation_id)?;
            commands::handle_score(&config, &investigation_id)?;
        }
        Commands::Evidence { action } => match action {
            EvidenceAction::Verify { investigation_id } => {
                commands::handle_verify_evidence(&config, &investigation_id)?;
            }
        },
        Commands::Timeline { investigation_id } => {
            commands::handle_timeline(&config, &investigation_id)?;
        }
        Commands::Report { action } => match action {
            ReportAction::Generate { investigation_id } => {
                commands::handle_generate_report(&config, &investigation_id)?;
            }
        },
        Commands::VerifyAudit { investigation_id } => {
            commands::handle_verify_audit(&config, &investigation_id)?;
        }
        Commands::Doctor => {
            commands::handle_doctor(&config)?;
        }
        Commands::Shell => {
            commands::handle_shell(&config)?;
        }
    }

    info!("ORACLE shutting down cleanly");
    Ok(())
}
