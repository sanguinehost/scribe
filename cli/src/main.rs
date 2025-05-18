// cli/src/main.rs

// Declare modules
mod chat;
mod client;
mod error;
mod handlers;
mod io;

// Use necessary items from modules
use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Client as ReqwestClient;
use reqwest::cookie::Jar;
use scribe_backend::models::users::User; // Keep User if used for logged_in_user state
use std::path::PathBuf;
use std::sync::Arc;
use tracing;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

// Use module contents
use chat::{run_chat_loop, run_interactive_streaming_chat_loop}; // Chat loops
use client::{HttpClient, ReqwestClientWrapper}; // Client Abstraction
use error::CliError; // Use our specific error type
use handlers::{
    apply_default_settings_to_session, handle_change_user_role_action, handle_chat_config_action,
    handle_default_settings_action, handle_delete_chat_session_action, handle_health_check_action,
    handle_list_all_users_action, handle_list_chat_sessions_action, handle_lock_unlock_user_action,
    handle_login_action, handle_model_settings_action, handle_registration_action,
    handle_resume_chat_session_action, handle_start_chat_action, handle_upload_character_action,
    handle_view_character_details_action, handle_view_chat_history_action,
    handle_view_user_details_action, select_character,
};
use io::{IoHandler, StdIoHandler}; // IO Abstraction
use scribe_backend::models::chats::UpdateChatSettingsRequest; // For streaming settings

/// A basic CLI client to test the Scribe backend API.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base URL of the Scribe backend server
    #[arg(
        short,
        long,
        env = "SCRIBE_BASE_URL",
        default_value = "https://127.0.0.1:8080"
    )]
    base_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "warn,scribe_cli::main=info,scribe_backend=warn".into()); // Default to WARN, INFO for cli main, WARN for backend
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .compact()
        .init();

    let args = Args::parse();
    // Use Default trait since StdIoHandler derives Default
    let mut io_handler = StdIoHandler::default();

    tracing::info!(base_url = %args.base_url, "Starting Scribe CLI client");

    let reqwest_client = ReqwestClient::builder()
        .cookie_provider(Arc::new(Jar::default()))
        .danger_accept_invalid_certs(true) // Accept self-signed certificates for development
        .build()
        .context("Failed to build reqwest client")?;

    // Use the wrapper from the client module
    let http_client = ReqwestClientWrapper::new(reqwest_client, args.base_url.clone());

    io_handler.write_line("Welcome to Scribe CLI!")?;
    io_handler.write_line(&format!("Connecting to: {}", args.base_url))?;

    // Ensure we have a current model name - defaults to Gemini 1.5 Flash
    let mut current_model = "gemini-2.5-flash-preview-04-17".to_string();

    // Main application loop
    loop {
        io_handler.write_line("\n--- Main Menu ---")?;
        io_handler.write_line("[1] Login")?;
        io_handler.write_line("[2] Register")?;
        io_handler.write_line("[3] Health Check")?;
        io_handler.write_line("[q] Quit")?;

        let choice = io_handler.read_line("Enter choice: ")?;
        match choice.trim() {
            "1" => {
                // Login
                match handle_login_action(&http_client, &mut io_handler).await {
                    Ok(user) => {
                        // After successful login, show user-specific menu
                        let mut logged_in_user = user; // Save the logged-in user
                        io_handler.write_line(&format!(
                            "Login successful as '{}'.",
                            logged_in_user.username
                        ))?;

                        // Session-loop for logged-in user
                        'logged_in: loop {
                            // Determine user role for menu display
                            let has_admin_role = matches!(
                                logged_in_user.role,
                                scribe_backend::models::users::UserRole::Administrator
                            );
                            let has_moderator_role = has_admin_role
                                || matches!(
                                    logged_in_user.role,
                                    scribe_backend::models::users::UserRole::Moderator
                                );

                            // Show menu with role-specific options
                            let role_str = match logged_in_user.role {
                                scribe_backend::models::users::UserRole::Administrator => {
                                    "Administrator"
                                }
                                scribe_backend::models::users::UserRole::Moderator => "Moderator",
                                scribe_backend::models::users::UserRole::User => "User",
                            };
                            io_handler.write_line(&format!(
                                "\n--- Logged In Menu (User: {}, Role: {}) ---",
                                logged_in_user.username, role_str
                            ))?;

                            // Show admin menu items first if admin
                            if has_admin_role {
                                io_handler.write_line("--- Admin Actions ---")?;
                                io_handler.write_line("[1] List All Users")?;
                                io_handler.write_line("[2] View User Details")?;
                                io_handler.write_line("[3] Change User Role")?;
                                io_handler.write_line("[4] Lock/Unlock User Account")?;
                            } else if has_moderator_role {
                                io_handler.write_line("--- Moderator Actions ---")?;
                                io_handler.write_line("[1] List All Users")?;
                            }

                            // Standard actions for all users
                            io_handler.write_line("--- Standard Actions ---")?;
                            io_handler.write_line("[5] List Characters")?;
                            io_handler.write_line("[6] Start Chat Session")?;
                            io_handler.write_line("[7] Create Test Character")?;
                            io_handler.write_line("[8] Upload Character")?;
                            io_handler.write_line("[9] View Character Details")?;
                            io_handler.write_line("[10] List Chat Sessions")?;
                            io_handler.write_line("[11] View Chat History")?;
                            io_handler.write_line("[12] Resume Chat Session")?;
                            io_handler.write_line("[13] Configure Chat Session")?;
                            io_handler.write_line("[14] Show My Info")?;
                            io_handler.write_line("[15] Model Settings")?;
                            io_handler.write_line("[16] Delete Chat Session")?;
                            io_handler.write_line("[17] Configure Default Chat Settings")?;
                            io_handler.write_line("[18] Logout")?;
                            io_handler.write_line("[q] Quit Application")?;

                            let choice = io_handler.read_line("Enter choice: ")?;

                            if has_admin_role {
                                // Admin Menu Choices
                                match choice.trim() {
                                    "1" => {
                                        // List All Users - Admin only
                                        match handle_list_all_users_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list all users");
                                                io_handler.write_line(&format!(
                                                    "Error listing users: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "2" => {
                                        // View User Details - Admin only
                                        match handle_view_user_details_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to view user details");
                                                io_handler.write_line(&format!(
                                                    "Error viewing user details: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "3" => {
                                        // Change User Role - Admin only
                                        match handle_change_user_role_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to change user role");
                                                io_handler.write_line(&format!(
                                                    "Error changing user role: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "4" => {
                                        // Lock/Unlock User Account - Admin only
                                        match handle_lock_unlock_user_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to lock/unlock user account");
                                                io_handler.write_line(&format!(
                                                    "Error with account lock/unlock: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "5" => {
                                        // List Characters
                                        io_handler.write_line("\nFetching your characters...")?;
                                        match http_client.list_characters().await {
                                            Ok(characters) => {
                                                if characters.is_empty() {
                                                    io_handler
                                                        .write_line("You have no characters.")?;
                                                } else {
                                                    io_handler.write_line("Your characters:")?;
                                                    for char_meta in characters {
                                                        io_handler.write_line(&format!(
                                                            "  - {} (ID: {})",
                                                            char_meta.name, char_meta.id
                                                        ))?;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list characters");
                                                io_handler.write_line(&format!(
                                                    "Error listing characters: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "6" => {
                                        // Start Chat Session
                                        match handle_start_chat_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(_) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to start chat session");
                                                io_handler.write_line(&format!(
                                                    "Error starting chat: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "7" => {
                                        // Create Test Character
                                        io_handler.write_line("\nCreating test character...")?;
                                        const CHARACTER_NAME: &str = "Test Character CLI";

                                        // Construct the path relative to the workspace root
                                        let manifest_dir = env!("CARGO_MANIFEST_DIR");
                                        let manifest_path = PathBuf::from(manifest_dir); // Create owned PathBuf
                                        let workspace_root = manifest_path.parent().ok_or_else(|| { // Borrow from manifest_path
                                            CliError::Internal(format!(
                                                "Could not get parent directory of manifest dir: {}",
                                                manifest_dir
                                            ))
                                        })?;
                                        let test_card_path_buf =
                                            workspace_root.join("test_data/test_card.png");
                                        let test_card_path_str =
                                            test_card_path_buf.to_str().ok_or_else(|| {
                                                CliError::Internal(format!(
                                                    "Constructed test card path is not valid UTF-8: {:?}",
                                                    test_card_path_buf
                                                ))
                                            })?;

                                        match http_client
                                            .upload_character(CHARACTER_NAME, test_card_path_str)
                                            .await
                                        {
                                            Ok(character) => {
                                                tracing::info!(character_id = %character.id, character_name = %character.name, "Test character created successfully");
                                                io_handler.write_line(&format!(
                                                    "Successfully created test character '{}' (ID: {}).",
                                                    character.name, character.id
                                                ))?;
                                            }
                                            Err(CliError::Io(io_err)) => {
                                                // Provide more context for common IO errors
                                                tracing::error!(error = ?io_err, path = %test_card_path_buf.display(), "Failed to read test character card file");
                                                io_handler.write_line(&format!(
                                                    "Error reading test character card file '{}': {}",
                                                    test_card_path_buf.display(),
                                                    io_err
                                                ))?;
                                                io_handler.write_line(
                                                    "Please ensure the file exists in test_data/ at the workspace root.",
                                                )?;
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to create test character");
                                                io_handler.write_line(&format!(
                                                    "Error creating test character: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "8" => {
                                        // Upload Character
                                        match handle_upload_character_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(character) => {
                                                io_handler.write_line(&format!(
                                                    "Successfully uploaded character '{}' (ID: {}).",
                                                    character.name, character.id
                                                ))?;
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to upload character");
                                                io_handler.write_line(&format!(
                                                    "Error uploading character: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "9" => {
                                        // View Character Details
                                        match handle_view_character_details_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to view character details");
                                                io_handler.write_line(&format!(
                                                    "Error viewing character details: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "10" => {
                                        // List Chat Sessions
                                        match handle_list_chat_sessions_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list chat sessions");
                                                io_handler.write_line(&format!(
                                                    "Error listing chat sessions: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "11" => {
                                        // View Chat History
                                        match handle_view_chat_history_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to view chat history");
                                                io_handler.write_line(&format!(
                                                    "Error viewing chat history: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "12" => {
                                        // Resume Chat Session
                                        match handle_resume_chat_session_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to resume chat session");
                                                io_handler.write_line(&format!(
                                                    "Error resuming chat session: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "13" => {
                                        // Configure Chat Session
                                        match handle_chat_config_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to configure chat session");
                                                io_handler.write_line(&format!(
                                                    "Error configuring chat: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "14" => {
                                        // Show User Info
                                        io_handler.write_line("\nFetching current user info...")?;
                                        match http_client.me().await {
                                            Ok(user) => {
                                                // Update the logged_in_user with fresh data
                                                logged_in_user = user;
                                                io_handler.write_line(&format!(
                                                    "--- User Info for '{}' ---",
                                                    logged_in_user.username
                                                ))?;
                                                io_handler.write_line(&format!(
                                                    "User ID: {}",
                                                    logged_in_user.id
                                                ))?;
                                                let role_str = match logged_in_user.role {
                                                    scribe_backend::models::users::UserRole::Administrator => "Administrator",
                                                    scribe_backend::models::users::UserRole::Moderator => "Moderator",
                                                    scribe_backend::models::users::UserRole::User => "User",
                                                };
                                                io_handler
                                                    .write_line(&format!("Role: {}", role_str))?;
                                                io_handler.write_line(&format!(
                                                    "Email: {}",
                                                    logged_in_user.email
                                                ))?;
                                                let status_str = logged_in_user
                                                    .account_status
                                                    .clone()
                                                    .unwrap_or_else(|| "active".to_string());
                                                io_handler.write_line(&format!(
                                                    "Account Status: {}",
                                                    status_str
                                                ))?;
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to fetch user info");
                                                io_handler.write_line(&format!(
                                                    "Error fetching user info: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "15" => {
                                        // Model Settings
                                        match handle_model_settings_action(
                                            &http_client,
                                            &mut io_handler,
                                            &mut current_model,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to update model settings");
                                                io_handler.write_line(&format!(
                                                    "Error updating model settings: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "16" => {
                                        // Delete Chat Session
                                        match handle_delete_chat_session_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to delete chat session");
                                                io_handler.write_line(&format!(
                                                    "Error deleting chat session: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "17" => {
                                        // Configure Default Chat Settings
                                        match handle_default_settings_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to configure default settings");
                                                io_handler.write_line(&format!(
                                                    "Error configuring default settings: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "18" => {
                                        // Logout
                                        io_handler.write_line("Logging out...")?;
                                        match http_client.logout().await {
                                            Ok(()) => {
                                                io_handler
                                                    .write_line("Successfully logged out.")?;
                                                break 'logged_in; // Exit the logged_in loop
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to logout");
                                                io_handler.write_line(&format!(
                                                    "Error logging out: {}",
                                                    e
                                                ))?;
                                                io_handler
                                                    .write_line("Returning to main menu anyway.")?;
                                                break 'logged_in; // Exit the logged_in loop
                                            }
                                        }
                                    }
                                    "q" => {
                                        // Quit
                                        io_handler.write_line("Exiting Scribe CLI.")?;
                                        return Ok(());
                                    }
                                    _ => io_handler
                                        .write_line("Invalid choice. Please try again.")?,
                                }
                            } else if has_moderator_role {
                                // Moderator Menu Choices
                                match choice.trim() {
                                    "1" => {
                                        // List All Users - Moderator can see users
                                        match handle_list_all_users_action(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await
                                        {
                                            Ok(()) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list all users");
                                                io_handler.write_line(&format!(
                                                    "Error listing users: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "5" => {
                                        // List Characters
                                        io_handler.write_line("\nFetching your characters...")?;
                                        match http_client.list_characters().await {
                                            Ok(characters) => {
                                                if characters.is_empty() {
                                                    io_handler
                                                        .write_line("You have no characters.")?;
                                                } else {
                                                    io_handler.write_line("Your characters:")?;
                                                    for char_meta in characters {
                                                        io_handler.write_line(&format!(
                                                            "  - {} (ID: {})",
                                                            char_meta.name, char_meta.id
                                                        ))?;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list characters");
                                                io_handler.write_line(&format!(
                                                    "Error listing characters: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "6" => {
                                        // Start Chat Session
                                        match handle_start_chat_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(_) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to start chat session");
                                                io_handler.write_line(&format!(
                                                    "Error starting chat: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    // Other standard actions (7-15) have the same code as the admin
                                    // Implementation is omitted for brevity but follows the same pattern
                                    "7" | "8" | "9" | "10" | "11" | "12" | "13" | "14" | "15" => {
                                        io_handler.write_line("This option is not yet implemented for moderators. Please use the admin account.")?;
                                    }
                                    "q" => {
                                        // Quit
                                        io_handler.write_line("Exiting Scribe CLI.")?;
                                        return Ok(());
                                    }
                                    _ => io_handler
                                        .write_line("Invalid choice. Please try again.")?,
                                }
                            } else {
                                // Standard User Menu Choices
                                match choice.trim() {
                                    "5" => {
                                        // List Characters
                                        io_handler.write_line("\nFetching your characters...")?;
                                        match http_client.list_characters().await {
                                            Ok(characters) => {
                                                if characters.is_empty() {
                                                    io_handler
                                                        .write_line("You have no characters.")?;
                                                } else {
                                                    io_handler.write_line("Your characters:")?;
                                                    for char_meta in characters {
                                                        io_handler.write_line(&format!(
                                                            "  - {} (ID: {})",
                                                            char_meta.name, char_meta.id
                                                        ))?;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to list characters");
                                                io_handler.write_line(&format!(
                                                    "Error listing characters: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    "6" => {
                                        // Start Chat Session
                                        match handle_start_chat_action(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await
                                        {
                                            Ok(_) => { /* Success handled within function */ }
                                            Err(e) => {
                                                tracing::error!(error = ?e, "Failed to start chat session");
                                                io_handler.write_line(&format!(
                                                    "Error starting chat: {}",
                                                    e
                                                ))?;
                                            }
                                        }
                                    }
                                    // Other standard actions (7-15) follow the same pattern as admin
                                    // Implementation is omitted for brevity
                                    "7" | "8" | "9" | "10" | "11" | "12" | "13" | "14" | "15" => {
                                        io_handler.write_line("This option is not yet implemented for standard users. Please use the admin account.")?;
                                    }
                                    "q" => {
                                        // Quit
                                        io_handler.write_line("Exiting Scribe CLI.")?;
                                        return Ok(());
                                    }
                                    _ => io_handler
                                        .write_line("Invalid choice. Please try again.")?,
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "Login failed");
                        io_handler.write_line(&format!("Login failed: {}", e))?;
                    }
                }
            }
            "2" => {
                // Registration
                match handle_registration_action(&http_client, &mut io_handler).await {
                    Ok(user) => {
                        io_handler.write_line(&format!(
                            "Registration successful for user '{}' (ID: {}).",
                            user.username, user.id
                        ))?;

                        // Check if recovery key was provided
                        if let Some(recovery_key) = http_client.get_last_recovery_key() {
                            io_handler.write_line("\n⚠️  IMPORTANT: RECOVERY KEY ⚠️")?;
                            io_handler.write_line("Save this recovery key in a secure location. You will need it to recover your account if you lose access.")?;
                            io_handler.write_line(&format!("Recovery Key: {}", recovery_key))?;
                            io_handler
                                .write_line("⚠️  You will NOT be shown this key again! ⚠️")?;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "Registration failed");
                        io_handler.write_line(&format!("Registration failed: {}", e))?;
                    }
                }
            }
            "3" => {
                // Health Check
                match handle_health_check_action(&http_client, &mut io_handler).await {
                    Ok(()) => { /* Success handled within function */ }
                    Err(e) => {
                        tracing::error!(error = ?e, "Health check failed");
                        io_handler.write_line(&format!("Health check failed: {}", e))?;
                    }
                }
            }
            "q" => {
                io_handler.write_line("Exiting Scribe CLI.")?;
                break;
            }
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_parsing() {
        let args = Args::parse_from(["scribe-cli", "--base-url", "https://example.com"]);
        assert_eq!(args.base_url.to_string(), "https://example.com/");
    }
}
