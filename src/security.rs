//! Security utilities and validation
//!
//! This module provides security-related checks and validations including:
//! - File permission validation (Unix)
//! - Security warnings for insecure configurations

use colored::Colorize;
use std::fs;
use std::path::Path;
use tracing::warn;

/// Check if a file has secure permissions (0600 on Unix)
/// Displays a warning if permissions are too open
#[cfg(unix)]
pub fn check_file_permissions_warn(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        if let Ok(metadata) = fs::metadata(path) {
            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // Check if permissions are exactly 0600 (owner read/write only)
            // Mode includes file type bits, so we mask with 0o777 to get permission bits
            let perm_bits = mode & 0o777;

            if perm_bits != 0o600 {
                warn!(
                    path = %path.display(),
                    permissions = format!("{:o}", perm_bits),
                    "File has insecure permissions"
                );
                eprintln!(
                    "{}",
                    format!(
                        "⚠ Warning: Vault file has insecure permissions ({:o})",
                        perm_bits
                    )
                    .yellow()
                    .bold()
                );
                eprintln!(
                    "{}",
                    format!("  Recommended: chmod 600 {}", path.display()).yellow()
                );
                eprintln!(
                    "{}",
                    "  Other users may be able to read your secrets!"
                        .yellow()
                        .bold()
                );
                eprintln!();
            }
        }
    }
}

/// Check permissions on non-Unix systems (no-op, permissions work differently)
#[cfg(not(unix))]
pub fn check_file_permissions_warn(_path: &Path) {
    // On Windows, file permissions work differently (ACLs)
    // This is a no-op for now, but could be implemented using Windows APIs
}
