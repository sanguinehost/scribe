// Desktop-specific functionality for local-only deployment
//
// This module provides authentication, configuration, and user management
// specific to desktop mode (SQLite + LanceDB stack with local users).

pub mod config;
pub mod user;

pub use config::{
    get_auth_mode, get_default_user_id, get_quick_start_dek, load_desktop_config,
    mark_setup_complete, save_desktop_config, set_auth_mode, set_default_user_id,
    set_quick_start_dek, AuthMode, DeploymentMode, DesktopConfig,
};

pub use user::ensure_default_user_exists;
