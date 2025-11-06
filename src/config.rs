//! Configuration management
//!
//! This module handles configuration loading from multiple sources with the following priority:
//! 1. Command-line argument (`--config` flag)
//! 2. Config file at platform-specific location
//! 3. Default fallback path
//!
//! ## Configuration File Locations
//!
//! - **Linux/Unix**: `$XDG_CONFIG_HOME/keyrex/config.toml` or `~/.config/keyrex/config.toml`
//! - **macOS**: `~/Library/Application Support/keyrex/config.toml`
//! - **Windows**: `%APPDATA%\keyrex\config.toml`
//!
//! ## Configuration Format
//!
//! ```toml
//! [default]
//! path = "/path/to/vault.dat"
//! ```

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Could not determine config directory")]
    ConfigDirNotFound,

    #[error("Could not determine home directory")]
    HomeDirNotFound,

    #[error("Invalid path in config: {0}")]
    InvalidPath(String),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub default: DefaultConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct DefaultConfig {
    pub path: Option<String>,
}

impl Config {
    /// Load configuration from file or use defaults
    ///
    /// Priority order:
    /// 1. Explicit config path provided via CLI (`--config`)
    /// 2. Platform-specific config directory
    /// 3. Default vault path
    pub fn load(explicit_config_path: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
        // Try explicit config path first (highest priority)
        if let Some(config_path) = explicit_config_path {
            debug!(path = %config_path.display(), "Loading config from explicit path");
            return Self::load_from_file(&config_path);
        }

        // Try platform-specific config location
        if let Ok(config_path) = Self::get_config_file_path() {
            if config_path.exists() {
                debug!(path = %config_path.display(), "Loading config from platform default location");
                return Self::load_from_file(&config_path);
            } else {
                debug!(path = %config_path.display(), "Config file not found at platform location");
            }
        }

        // Fall back to default vault path
        debug!("Using default vault path");
        Self::get_default_vault_path()
    }

    /// Get the platform-specific configuration file path
    ///
    /// - Linux/Unix: `$XDG_CONFIG_HOME/keyrex/config.toml` or `~/.config/keyrex/config.toml`
    /// - macOS: `~/Library/Application Support/keyrex/config.toml`
    /// - Windows: `%APPDATA%\keyrex\config.toml`
    fn get_config_file_path() -> Result<PathBuf, ConfigError> {
        let mut config_dir = dirs::config_dir().ok_or(ConfigError::ConfigDirNotFound)?;
        config_dir.push("keyrex");
        config_dir.push("config.toml");
        Ok(config_dir)
    }

    /// Load and parse configuration from a file
    fn load_from_file(path: &PathBuf) -> Result<PathBuf, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;

        if let Some(vault_path) = config.default.path {
            debug!(vault_path = %vault_path, "Parsed vault path from config");

            // Expand environment variables in path
            let expanded_path = Self::expand_path(&vault_path)?;
            debug!(expanded_path = %expanded_path.display(), "Expanded vault path");

            Ok(expanded_path)
        } else {
            warn!("Config file exists but no path specified, using default");
            Self::get_default_vault_path()
        }
    }

    /// Get the default vault path
    ///
    /// Returns: `~/.keyrex/vault.dat`
    fn get_default_vault_path() -> Result<PathBuf, ConfigError> {
        let mut path = dirs::home_dir().ok_or(ConfigError::HomeDirNotFound)?;
        path.push(".keyrex");

        // Ensure directory exists
        if let Err(e) = fs::create_dir_all(&path) {
            warn!(error = %e, path = %path.display(), "Failed to create vault directory");
        }

        path.push("vault.dat");
        Ok(path)
    }

    /// Expand environment variables and ~ in paths
    fn expand_path(path_str: &str) -> Result<PathBuf, ConfigError> {
        let expanded = shellexpand::full(path_str)
            .map_err(|e| ConfigError::InvalidPath(format!("Failed to expand path: {}", e)))?;

        Ok(PathBuf::from(expanded.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_path_is_valid() {
        let path = Config::get_default_vault_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains(".keyrex"));
        assert!(path.to_string_lossy().ends_with("vault.dat"));
    }

    #[test]
    fn test_expand_path_with_home() {
        let result = Config::expand_path("${HOME}/.keyrex/test.dat");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(!path.to_string_lossy().contains("${HOME}"));
    }

    #[test]
    fn test_expand_path_with_tilde() {
        let result = Config::expand_path("~/.keyrex/test.dat");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(!path.to_string_lossy().contains("~"));
    }
}
