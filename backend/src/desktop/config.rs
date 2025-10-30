// Desktop configuration management for local-only authentication
//
// This module handles persistent configuration for desktop mode, storing
// user preferences like auth mode selection and default user ID in the
// app data directory.

use crate::db::DbId;
use crate::errors::AppError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, error, info};

/// Authentication mode for desktop app
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Quick Start mode: Default user, no login required
    QuickStart,
    /// Account mode: Full authentication with username/password
    Account,
}

/// Deployment mode for future thin-client support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    /// Local mode: SQLite + LanceDB stack
    Local,
    /// Remote mode: Thin client hitting remote API
    Remote,
}

/// Desktop application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopConfig {
    /// Whether initial setup has been completed
    pub setup_complete: bool,
    /// Current authentication mode
    pub auth_mode: Option<AuthMode>,
    /// Current deployment mode
    #[serde(default = "default_deployment_mode")]
    pub deployment_mode: DeploymentMode,
    /// Default user ID for quick_start mode
    pub default_user_id: Option<DbId>,
    /// Remote endpoint URL (for future remote mode)
    pub remote_endpoint: Option<String>,
}

fn default_deployment_mode() -> DeploymentMode {
    DeploymentMode::Local
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            setup_complete: false,
            auth_mode: None,
            deployment_mode: DeploymentMode::Local,
            default_user_id: None,
            remote_endpoint: None,
        }
    }
}

/// Get the path to the desktop config file
///
/// Returns the platform-specific app data directory path:
/// - Linux: ~/.config/scribe/desktop-config.json
/// - macOS: ~/Library/Application Support/scribe/desktop-config.json
/// - Windows: %APPDATA%\scribe\desktop-config.json
fn get_config_path() -> Result<PathBuf, AppError> {
    // Use directories crate to get platform-specific app data directory
    let config_dir = dirs::config_dir()
        .ok_or_else(|| AppError::ConfigError("Could not determine config directory".to_string()))?;

    let scribe_dir = config_dir.join("scribe");

    // Create directory if it doesn't exist
    if !scribe_dir.exists() {
        fs::create_dir_all(&scribe_dir).map_err(|e| {
            AppError::ConfigError(format!("Failed to create config directory: {}", e))
        })?;
        info!("Created desktop config directory: {}", scribe_dir.display());
    }

    Ok(scribe_dir.join("desktop-config.json"))
}

/// Load desktop configuration from disk
///
/// Returns default configuration if file doesn't exist.
pub fn load_desktop_config() -> Result<DesktopConfig, AppError> {
    let config_path = get_config_path()?;

    debug!("Loading desktop config from: {}", config_path.display());

    if !config_path.exists() {
        info!("Desktop config file not found, using defaults");
        return Ok(DesktopConfig::default());
    }

    let contents = fs::read_to_string(&config_path).map_err(|e| {
        AppError::ConfigError(format!("Failed to read desktop config file: {}", e))
    })?;

    let config: DesktopConfig = serde_json::from_str(&contents).map_err(|e| {
        error!("Failed to parse desktop config: {}", e);
        AppError::ConfigError(format!("Invalid desktop config format: {}", e))
    })?;

    debug!("Loaded desktop config: {:?}", config);
    Ok(config)
}

/// Save desktop configuration to disk
pub fn save_desktop_config(config: &DesktopConfig) -> Result<(), AppError> {
    let config_path = get_config_path()?;

    debug!("Saving desktop config to: {}", config_path.display());

    let contents = serde_json::to_string_pretty(config).map_err(|e| {
        AppError::ConfigError(format!("Failed to serialize desktop config: {}", e))
    })?;

    fs::write(&config_path, contents).map_err(|e| {
        AppError::ConfigError(format!("Failed to write desktop config file: {}", e))
    })?;

    info!("Saved desktop config successfully");
    Ok(())
}

/// Get current auth mode
pub fn get_auth_mode() -> Result<Option<AuthMode>, AppError> {
    let config = load_desktop_config()?;
    Ok(config.auth_mode)
}

/// Set auth mode and save configuration
pub fn set_auth_mode(mode: AuthMode) -> Result<(), AppError> {
    let mut config = load_desktop_config()?;
    config.auth_mode = Some(mode);
    save_desktop_config(&config)
}

/// Mark setup as complete
pub fn mark_setup_complete() -> Result<(), AppError> {
    let mut config = load_desktop_config()?;
    config.setup_complete = true;
    save_desktop_config(&config)
}

/// Get default user ID for quick_start mode
pub fn get_default_user_id() -> Result<Option<DbId>, AppError> {
    let config = load_desktop_config()?;
    Ok(config.default_user_id)
}

/// Set default user ID for quick_start mode
pub fn set_default_user_id(user_id: DbId) -> Result<(), AppError> {
    let mut config = load_desktop_config()?;
    config.default_user_id = Some(user_id);
    save_desktop_config(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DesktopConfig::default();
        assert!(!config.setup_complete);
        assert!(config.auth_mode.is_none());
        assert_eq!(config.deployment_mode, DeploymentMode::Local);
        assert!(config.default_user_id.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = DesktopConfig {
            setup_complete: true,
            auth_mode: Some(AuthMode::QuickStart),
            deployment_mode: DeploymentMode::Local,
            default_user_id: Some(DbId::new()),
            remote_endpoint: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DesktopConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.setup_complete, deserialized.setup_complete);
        assert_eq!(config.auth_mode, deserialized.auth_mode);
        assert_eq!(config.deployment_mode, deserialized.deployment_mode);
    }
}
