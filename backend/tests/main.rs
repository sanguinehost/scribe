use ctor::ctor;
use dotenvy;
use std::path::PathBuf;

// This function will run once when the test executable is loaded.
#[ctor]
fn initialize_tests() {
    // CARGO_MANIFEST_DIR points to the directory of Cargo.toml for the current crate (scribe-backend)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Assuming .env is in the workspace root, which is the parent of manifest_dir for this crate.
    let workspace_root = manifest_dir.parent().unwrap_or_else(|| {
        eprintln!("[tests/main.rs @ initialize_tests] Warning: Could not determine parent directory of CARGO_MANIFEST_DIR ({}). Assuming current manifest_dir is workspace root for .env lookup.", manifest_dir.display());
        &manifest_dir
    });
    let dot_env_path = workspace_root.join(".env");

    if dot_env_path.exists() {
        match dotenvy::from_path(dot_env_path.as_path()) {
            Ok(_) => eprintln!("[tests/main.rs @ initialize_tests] Successfully loaded .env from: {}", dot_env_path.display()),
            Err(e) => eprintln!("[tests/main.rs @ initialize_tests] Error loading .env from {}: {}", dot_env_path.display(), e),
        }
    } else {
        eprintln!("[tests/main.rs @ initialize_tests] .env file not found at: {}. Environment variables will not be loaded from this file.", dot_env_path.display());
    }
}

// Declare all test files and subdirectories as modules.
// This file acts as the root of the integration test crate.

// Individual test files
pub mod auth_tests;
pub mod character_card_tests;
pub mod chat_generate_non_stream_tests;
pub mod chat_generate_rag_tests;
pub mod chat_generate_stream_auth_tests;
pub mod chat_generate_stream_error_tests;
pub mod chat_generate_stream_misc_tests;
pub mod chat_generate_stream_rag_tests;
pub mod chat_generate_stream_success_tests;
pub mod chat_message_api_tests;
pub mod chat_session_api_tests;
pub mod chat_settings_api_tests;
pub mod chat_suggested_actions_tests;
pub mod chat_overrides_api_tests;
pub mod db_integration_tests;
pub mod embedding_pipeline_tests;
pub mod first_user_admin_tests;
pub mod health_check;
pub mod qdrant_integration_tests;
pub mod qdrant_pipeline_tests;
pub mod recovery_key_tests;
pub mod token_counter_tests;
pub mod tokenizer_tests;
pub mod user_store_tests;
pub mod user_persona_api_tests; // Added for User Persona API tests

// New characters test module (directory)
pub mod characters;

// Service level or other specific tests
pub mod user_persona_service_tests;