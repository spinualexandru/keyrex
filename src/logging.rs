//! Structured logging configuration using the tracing crate
//!
//! This module initializes the tracing subscriber for structured logging
//! throughout the application. Logs can be controlled via the RUST_LOG
//! environment variable.
//!
//! Example usage:
//! ```bash
//! # Enable debug logging
//! RUST_LOG=debug keyrex add mykey myvalue
//!
//! # Enable trace logging for specific module
//! RUST_LOG=keyrex::vault=trace keyrex list
//! ```

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the tracing subscriber with environment-based filtering
///
/// By default, only shows warnings and errors unless RUST_LOG is set.
/// This respects the RUST_LOG environment variable for fine-grained control.
pub fn init() {
    // Default to showing only warnings and errors unless RUST_LOG is set
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    fmt()
        .with_env_filter(env_filter)
        .with_target(false) // Don't show module paths in logs (cleaner output)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();
}

/// Initialize tracing with a specific log level
///
/// Use this for testing or programmatic configuration.
/// Level can be: "trace", "debug", "info", "warn", "error"
#[allow(dead_code)]
pub fn init_with_level(level: &str) {
    let env_filter = EnvFilter::new(level);

    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .compact()
        .init();
}
