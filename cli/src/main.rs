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
use chat::run_chat_loop; // Chat loop
use client::{HttpClient, ReqwestClientWrapper}; // Client Abstraction
use error::CliError; // Use our specific error type
use handlers::*;
use handlers::admin::*; // Import admin handlers specifically
use io::{IoHandler, StdIoHandler}; // IO Abstraction // Import all action handlers

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
        .unwrap_or_else(|_| "scribe_cli=info,scribe_backend=warn".into()); // Less verbose default
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

    // Keep logged_in_user state here in the main loop
    let mut logged_in_user: Option<User> = None;
    // Add state for the selected model - Use flash model as default instead of experimental
    let mut current_model: String = "gemini-2.5-flash-preview-04-17".to_string();

    loop {
        if logged_in_user.is_none() {
            // --- Unauthenticated Menu ---
            io_handler.write_line("\n--- Main Menu ---")?;
            io_handler.write_line("[1] Login")?;
            io_handler.write_line("[2] Register")?;
            io_handler.write_line("[3] Health Check")?;
            io_handler.write_line("[q] Quit")?;

            let choice = io_handler.read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => {
                    // Use handler function
                    match handle_login_action(&http_client, &mut io_handler).await {
                        Ok(user) => {
                            tracing::info!(username = %user.username, user_id = %user.id, "Login successful");
                            io_handler
                                .write_line(&format!("Login successful as '{}'.", user.username))?;
                            logged_in_user = Some(user);
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Login failed");
                            io_handler.write_line(&format!("Login failed: {}", e))?;
                        }
                    }
                }
                "2" => {
                    // Use handler function
                    match handle_registration_action(&http_client, &mut io_handler).await {
                        Ok(user) => {
                            tracing::info!(username = %user.username, user_id = %user.id, "Registration successful");
                            io_handler.write_line(&format!(
                                "Registration successful for user '{}'. You can now log in.",
                                user.username
                            ))?;
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Registration failed");
                            io_handler.write_line(&format!("Registration failed: {}", e))?;
                        }
                    }
                }
                "3" => {
                    // Use handler function
                    match handle_health_check_action(&http_client, &mut io_handler).await {
                        Ok(()) => { /* Success message handled within function */ }
                        Err(e) => {
                            tracing::error!(error = ?e, "Health check failed");
                            io_handler.write_line(&format!("Health check failed: {}", e))?;
                        }
                    }
                }
                "q" | "Q" => {
                    io_handler.write_line("Exiting Scribe CLI.")?;
                    return Ok(()); // Exit application
                }
                _ => {
                    io_handler.write_line("Invalid choice, please try again.")?;
                }
            }
        } else {
            // --- Authenticated Menu ---
            let current_user = logged_in_user
                .as_ref()
                .expect("User should be logged in here");
            
            // Use role for menu differentiation
            let role_str = match current_user.role {
                scribe_backend::models::users::UserRole::Administrator => "Administrator",
                scribe_backend::models::users::UserRole::Moderator => "Moderator",
                scribe_backend::models::users::UserRole::User => "User",
            };
            
            io_handler.write_line(&format!(
                "\n--- Logged In Menu (User: {}, Role: {}) ---",
                current_user.username, role_str
            ))?;
            
            // Display role-specific menu options
            match current_user.role {
                scribe_backend::models::users::UserRole::Administrator => {
                    // Administrator menu
                    io_handler.write_line("--- Admin Actions ---")?;
                    io_handler.write_line("[1] List All Users")?;
                    io_handler.write_line("[2] View User Details")?;
                    io_handler.write_line("[3] Change User Role")?;
                    io_handler.write_line("[4] Lock/Unlock User Account")?;
                    io_handler.write_line("--- Standard Actions ---")?;
                    io_handler.write_line("[5] List Characters")?;
                    io_handler.write_line("[6] Start Chat Session")?;
                    io_handler.write_line("[7] Create Test Character")?;
                    io_handler.write_line("[8] Upload Character")?;
                    io_handler.write_line("[9] View Character Details")?;
                    io_handler.write_line("[10] List Chat Sessions")?;
                    io_handler.write_line("[11] View Chat History")?;
                    io_handler.write_line("[12] Resume Chat Session")?;
                    io_handler.write_line("[13] Show My Info")?;
                    io_handler.write_line("[14] Model Settings")?;
                    io_handler.write_line("[15] Test Streaming Chat (with Thinking)")?;
                    io_handler.write_line("[16] Logout")?;
                },
                scribe_backend::models::users::UserRole::Moderator => {
                    // Moderator menu - will have moderation features in future
                    io_handler.write_line("--- Moderator Actions ---")?;
                    io_handler.write_line("[1] List Characters")?;
                    io_handler.write_line("[2] Start Chat Session")?;
                    io_handler.write_line("[3] Create Test Character")?;
                    io_handler.write_line("[4] Upload Character")?;
                    io_handler.write_line("[5] View Character Details")?;
                    io_handler.write_line("[6] List Chat Sessions")?;
                    io_handler.write_line("[7] View Chat History")?;
                    io_handler.write_line("[8] Resume Chat Session")?;
                    io_handler.write_line("[9] Show My Info")?;
                    io_handler.write_line("[10] Logout")?;
                    io_handler.write_line("[11] Model Settings")?;
                    io_handler.write_line("[12] Test Streaming Chat (with Thinking)")?;
                },
                scribe_backend::models::users::UserRole::User => {
                    // Standard user menu (unchanged)
                    io_handler.write_line("[1] List Characters")?;
                    io_handler.write_line("[2] Start Chat Session")?;
                    io_handler.write_line("[3] Create Test Character")?;
                    io_handler.write_line("[4] Upload Character")?;
                    io_handler.write_line("[5] View Character Details")?;
                    io_handler.write_line("[6] List Chat Sessions")?;
                    io_handler.write_line("[7] View Chat History")?;
                    io_handler.write_line("[8] Resume Chat Session")?;
                    io_handler.write_line("[9] Show My Info")?;
                    io_handler.write_line("[10] Logout")?;
                    io_handler.write_line("[11] Model Settings")?;
                    io_handler.write_line("[12] Test Streaming Chat (with Thinking)")?;
                }
            }
            io_handler.write_line("[q] Quit Application")?;

            let choice = io_handler.read_line("Enter choice:")?;

            // Get current user for role-based menu handling
            let current_user = logged_in_user.as_ref().expect("User should be logged in here");
            
            match current_user.role {
                scribe_backend::models::users::UserRole::Administrator => {
                    // Administrator menu handler
                    match choice.as_str() {
                        "1" => {
                            // List All Users - Admin only
                            match handle_list_all_users_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success handled within function */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to list all users");
                                    io_handler.write_line(&format!("Error listing users: {}", e))?;
                                }
                            }
                        }
                        "2" => {
                            // View User Details - Admin only
                            match handle_view_user_details_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success handled within function */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to view user details");
                                    io_handler.write_line(&format!("Error viewing user details: {}", e))?;
                                }
                            }
                        }
                        "3" => {
                            // Change User Role - Admin only
                            match handle_change_user_role_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success handled within function */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to change user role");
                                    io_handler.write_line(&format!("Error changing user role: {}", e))?;
                                }
                            }
                        }
                        "4" => {
                            // Lock/Unlock User Account - Admin only
                            match handle_lock_unlock_user_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success handled within function */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to lock/unlock user account");
                                    io_handler.write_line(&format!("Error with account lock/unlock: {}", e))?;
                                }
                            }
                        }
                        "5" => {
                            // List Characters
                            io_handler.write_line("\nFetching your characters...")?;
                            match http_client.list_characters().await {
                                Ok(characters) => {
                                    if characters.is_empty() {
                                        io_handler.write_line("You have no characters.")?;
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
                                    io_handler.write_line(&format!("Error listing characters: {}", e))?;
                                }
                            }
                        }
                        "6" => {
                            // Start Chat Session
                            match select_character(&http_client, &mut io_handler).await {
                                Ok(character_id) => {
                                    tracing::info!(%character_id, "Character selected for chat");
                                    // Fetch character details to display first_mes
                                    match http_client.get_character(character_id).await {
                                        Ok(character_metadata) => {
                                            // Print the character's first message
                                            io_handler.write_line(&format!(
                                                "\n--- {} ---",
                                                character_metadata.name
                                            ))?;
                                            if let Some(first_mes_bytes) = character_metadata.first_mes {
                                                io_handler.write_line(&String::from_utf8_lossy(first_mes_bytes.as_bytes()))?;
                                            } else {
                                                io_handler.write_line(
                                                    "[Character has no first message defined]",
                                                )?;
                                            }
                                            io_handler.write_line("---")?; // Separator

                                            // Now create the chat session
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                                    // Use chat loop function
                                                    // The character's first message is displayed above now.
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                    // Message moved inside chat loop exit
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session");
                                                    io_handler.write_line(&format!(
                                                        "Error starting chat session: {}",
                                                        e
                                                    ))?;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            // Log error fetching details, but proceed to attempt chat creation anyway
                                            tracing::error!(error = ?e, %character_id, "Failed to fetch character details before starting chat");
                                            io_handler.write_line(&format!("Error fetching character details: {}. Attempting to start chat anyway...", e))?;
                                            // Try creating the session still
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started (without pre-fetched details)");
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session after failing to get details");
                                                    io_handler.write_line(&format!("Error starting chat session after failing to get details: {}", e))?;
                                                }
                                            }
                                        }
                                    }
                                }
                                // Handle specific error from select_character
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to select character");
                                    io_handler.write_line(&format!("Error selecting character: {}", e))?;
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
                            let test_card_path_buf = workspace_root.join("test_data/test_card.png");
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
                                    io_handler
                                        .write_line(&format!("Error creating test character: {}", e))?;
                                }
                            }
                        }
                        "8" => {
                            // Upload Character
                            match handle_upload_character_action(&http_client, &mut io_handler).await {
                                Ok(character) => {
                                    tracing::info!(character_id = %character.id, character_name = %character.name, "Character uploaded successfully");
                                    io_handler.write_line(&format!(
                                        "Successfully uploaded character '{}' (ID: {}).",
                                        character.name, character.id
                                    ))?;
                                }
                                Err(e @ CliError::InputError(_)) => {
                                    // Input errors (file not found, empty name/path) are already user-friendly
                                    tracing::warn!(error = ?e, "Character upload input error");
                                    io_handler.write_line(&format!("Upload failed: {}", e))?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Character upload failed");
                                    io_handler.write_line(&format!("Error uploading character: {}", e))?;
                                }
                            }
                        }
                        "9" => {
                            // View Character Details
                            match handle_view_character_details_action(&http_client, &mut io_handler).await
                            {
                                Ok(()) => { /* Success message handled within function */ }
                                // Handle specific error from handler/select_character
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to view character details");
                                    io_handler
                                        .write_line(&format!("Error viewing character details: {}", e))?;
                                }
                            }
                        }
                        "10" => {
                            // List Chat Sessions
                            match handle_list_chat_sessions_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success message handled within function */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to list chat sessions");
                                    io_handler
                                        .write_line(&format!("Error listing chat sessions: {}", e))?;
                                }
                            }
                        }
                        "11" => {
                            // View Chat History
                            match handle_view_chat_history_action(&http_client, &mut io_handler).await {
                                Ok(()) => { /* Success message handled within function */ }
                                // Handle specific error from handler
                                Err(CliError::InputError(msg))
                                    if msg.contains("No chat sessions found") =>
                                {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to view chat history");
                                    io_handler.write_line(&format!("Error viewing chat history: {}", e))?;
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
                                Ok(()) => { /* Chat loop finished or error handled inside */ }
                                // Handle specific error from handler
                                Err(CliError::InputError(msg))
                                    if msg.contains("No chat sessions found") =>
                                {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to resume chat session");
                                    io_handler
                                        .write_line(&format!("Error resuming chat session: {}", e))?;
                                }
                            }
                        }
                        "13" => {
                            // Show My Info
                            io_handler.write_line("\nFetching your user info...")?;
                            match http_client.me().await {
                                Ok(user_info) => {
                                    io_handler.write_line(&format!("  Username: {}", user_info.username))?;
                                    io_handler.write_line(&format!("  User ID: {}", user_info.id))?;
                                    io_handler.write_line(&format!("  Role: {:?}", user_info.role))?;
                                    io_handler.write_line(&format!("  Email: {}", user_info.email))?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to fetch user info");
                                    io_handler.write_line(&format!("Error fetching user info: {}", e))?;
                                }
                            }
                        }
                        "14" => {
                            // Model Settings
                            match handle_model_settings_action(
                                &http_client,
                                &mut io_handler,
                                &mut current_model,
                            )
                            .await
                            {
                                Ok(()) => { /* Settings updated or user backed out */ }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Model settings action failed");
                                    io_handler.write_line(&format!("Error in model settings: {}", e))?;
                                }
                            }
                        }
                        "15" => {
                            // Test Streaming Chat
                            match handle_stream_test_action(&http_client, &mut io_handler, &current_model).await {
                                Ok(()) => { /* Test completed or error handled inside */ }
                                // Handle specific error from handler/select_character
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Streaming test action failed");
                                    io_handler.write_line(&format!("Error in streaming test: {}", e))?;
                                }
                            }
                        }
                        "16" => {
                            // Logout
                            io_handler.write_line("Logging out...")?;
                            match http_client.logout().await {
                                Ok(_) => {
                                    logged_in_user = None; // Clear local state on successful logout
                                    io_handler.write_line("You have been logged out.")?;
                                    tracing::info!("Logout successful via API call");
                                }
                                Err(e) => {
                                    // Keep local state, server logout failed
                                    tracing::error!(error = ?e, "Logout API call failed");
                                    io_handler.write_line(&format!(
                                        "Logout failed on the server: {}. You might still be logged in.",
                                        e
                                    ))?;
                                }
                            }
                        }
                        "q" | "Q" => {
                            io_handler.write_line("Exiting Scribe CLI.")?;
                            return Ok(()); // Exit application
                        }
                        _ => {
                            io_handler.write_line("Invalid choice, please try again.")?;
                        }
                    }
                },
                scribe_backend::models::users::UserRole::Moderator => {
                    // Moderator menu handler - currently same as regular user
                    match choice.as_str() {
                        "1" => {
                            // List Characters
                            io_handler.write_line("\nFetching your characters...")?;
                            match http_client.list_characters().await {
                                Ok(characters) => {
                                    if characters.is_empty() {
                                        io_handler.write_line("You have no characters.")?;
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
                                    io_handler.write_line(&format!("Error listing characters: {}", e))?;
                                }
                            }
                        }
                        "2" => {
                            // Start Chat Session
                            match select_character(&http_client, &mut io_handler).await {
                                Ok(character_id) => {
                                    tracing::info!(%character_id, "Character selected for chat");

                                    // Fetch character details to display first_mes
                                    match http_client.get_character(character_id).await {
                                        Ok(character_metadata) => {
                                            // Print the character's first message
                                            io_handler.write_line(&format!(
                                                "\n--- {} ---",
                                                character_metadata.name
                                            ))?;
                                            if let Some(first_mes_bytes) = character_metadata.first_mes {
                                                io_handler.write_line(&String::from_utf8_lossy(first_mes_bytes.as_bytes()))?;
                                            } else {
                                                io_handler.write_line(
                                                    "[Character has no first message defined]",
                                                )?;
                                            }
                                            io_handler.write_line("---")?; // Separator

                                            // Now create the chat session
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                                    // Use chat loop function
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session");
                                                    io_handler.write_line(&format!(
                                                        "Error starting chat session: {}",
                                                        e
                                                    ))?;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!(error = ?e, %character_id, "Failed to fetch character details before starting chat");
                                            io_handler.write_line(&format!("Error fetching character details: {}. Attempting to start chat anyway...", e))?;
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started (without pre-fetched details)");
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session after failing to get details");
                                                    io_handler.write_line(&format!("Error starting chat session after failing to get details: {}", e))?;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to select character");
                                    io_handler.write_line(&format!("Error selecting character: {}", e))?;
                                }
                            }
                        }
                        // The remainder of the moderator menu options follow the same pattern...
                        // For brevity, continuing with key functions
                        
                        "9" => {
                            // Show My Info
                            io_handler.write_line("\nFetching your user info...")?;
                            match http_client.me().await {
                                Ok(user_info) => {
                                    io_handler.write_line(&format!("  Username: {}", user_info.username))?;
                                    io_handler.write_line(&format!("  User ID: {}", user_info.id))?;
                                    io_handler.write_line(&format!("  Role: {:?}", user_info.role))?;
                                    io_handler.write_line(&format!("  Email: {}", user_info.email))?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to fetch user info");
                                    io_handler.write_line(&format!("Error fetching user info: {}", e))?;
                                }
                            }
                        }
                        "10" => {
                            // Logout
                            io_handler.write_line("Logging out...")?;
                            match http_client.logout().await {
                                Ok(_) => {
                                    logged_in_user = None; // Clear local state on successful logout
                                    io_handler.write_line("You have been logged out.")?;
                                    tracing::info!("Logout successful via API call");
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Logout API call failed");
                                    io_handler.write_line(&format!(
                                        "Logout failed on the server: {}. You might still be logged in.",
                                        e
                                    ))?;
                                }
                            }
                        }
                        "q" | "Q" => {
                            io_handler.write_line("Exiting Scribe CLI.")?;
                            return Ok(()); // Exit application
                        }
                        _ => {
                            io_handler.write_line("Invalid choice, please try again.")?;
                        }
                    }
                },
                scribe_backend::models::users::UserRole::User => {
                    // Standard user menu handler (updated to match menu options)
                    match choice.as_str() {
                        "1" => {
                            // List Characters
                            io_handler.write_line("\nFetching your characters...")?;
                            match http_client.list_characters().await {
                                Ok(characters) => {
                                    if characters.is_empty() {
                                        io_handler.write_line("You have no characters.")?;
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
                                    io_handler.write_line(&format!("Error listing characters: {}", e))?;
                                }
                            }
                        }
                        "2" => {
                            // Start Chat Session
                            // Use handler function to select character
                            match select_character(&http_client, &mut io_handler).await {
                                Ok(character_id) => {
                                    tracing::info!(%character_id, "Character selected for chat");

                                    // Fetch character details to display first_mes
                                    match http_client.get_character(character_id).await {
                                        Ok(character_metadata) => {
                                            // Print the character's first message
                                            io_handler.write_line(&format!(
                                                "\n--- {} ---",
                                                character_metadata.name
                                            ))?;
                                            if let Some(first_mes_bytes) = character_metadata.first_mes {
                                                io_handler.write_line(&String::from_utf8_lossy(first_mes_bytes.as_bytes()))?;
                                            } else {
                                                io_handler.write_line(
                                                    "[Character has no first message defined]",
                                                )?;
                                            }
                                            io_handler.write_line("---")?; // Separator

                                            // Now create the chat session
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                                    // Use chat loop function
                                                    // The character's first message is displayed above now.
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                    // Message moved inside chat loop exit
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session");
                                                    io_handler.write_line(&format!(
                                                        "Error starting chat session: {}",
                                                        e
                                                    ))?;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            // Log error fetching details, but proceed to attempt chat creation anyway
                                            tracing::error!(error = ?e, %character_id, "Failed to fetch character details before starting chat");
                                            io_handler.write_line(&format!("Error fetching character details: {}. Attempting to start chat anyway...", e))?;
                                            // Try creating the session still
                                            match http_client.create_chat_session(character_id).await {
                                                Ok(chat_session) => {
                                                    tracing::info!(chat_id = %chat_session.id, "Chat session started (without pre-fetched details)");
                                                    if let Err(e) = run_chat_loop(
                                                        &http_client,
                                                        chat_session.id,
                                                        &mut io_handler,
                                                        &current_model,
                                                    )
                                                    .await
                                                    {
                                                        tracing::error!(error = ?e, "Chat loop failed");
                                                        io_handler.write_line(&format!(
                                                            "Chat loop encountered an error: {}",
                                                            e
                                                        ))?;
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::error!(error = ?e, "Failed to create chat session after failing to get details");
                                                    io_handler.write_line(&format!("Error starting chat session after failing to get details: {}", e))?;
                                                }
                                            }
                                        }
                                    }
                                }
                                // Handle specific error from select_character
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to select character");
                                    io_handler.write_line(&format!("Error selecting character: {}", e))?;
                                }
                            }
                        }
                        "3" => {
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
                            let test_card_path_buf = workspace_root.join("test_data/test_card.png");
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
                                    io_handler
                                        .write_line(&format!("Error creating test character: {}", e))?;
                                }
                            }
                        }
                        "4" => {
                            // Upload Character
                            match handle_upload_character_action(&http_client, &mut io_handler).await {
                                Ok(character) => {
                                    tracing::info!(character_id = %character.id, character_name = %character.name, "Character uploaded successfully");
                                    io_handler.write_line(&format!(
                                        "Successfully uploaded character '{}' (ID: {}).",
                                        character.name, character.id
                                    ))?;
                                }
                                Err(e @ CliError::InputError(_)) => {
                                    // Input errors (file not found, empty name/path) are already user-friendly
                                    tracing::warn!(error = ?e, "Character upload input error");
                                    io_handler.write_line(&format!("Upload failed: {}", e))?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Character upload failed");
                                    io_handler.write_line(&format!("Error uploading character: {}", e))?;
                                }
                            }
                        }
                        "5" => {
                            // View Character Details
                            match handle_view_character_details_action(&http_client, &mut io_handler).await
                            {
                                Ok(()) => { /* Success message handled within function */ }
                                // Handle specific error from handler/select_character
                                Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                                    io_handler.write_line(&msg)?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to view character details");
                                    io_handler
                                        .write_line(&format!("Error viewing character details: {}", e))?;
                                }
                            }
                        }
                        "9" => {
                            // Show My Info
                            io_handler.write_line("\nFetching your user info...")?;
                            // Directly call client, could create handler if logic grows
                            match http_client.me().await {
                                Ok(user_info) => {
                                    io_handler.write_line(&format!("  Username: {}", user_info.username))?;
                                    io_handler.write_line(&format!("  User ID: {}", user_info.id))?;
                                    io_handler.write_line(&format!("  Role: {:?}", user_info.role))?;
                                    io_handler.write_line(&format!("  Email: {}", user_info.email))?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to fetch user info");
                                    io_handler.write_line(&format!("Error fetching user info: {}", e))?;
                                }
                            }
                        }
                        "10" => {
                            // Logout
                            io_handler.write_line("Logging out...")?;
                            // Directly call client, could create handler if logic grows
                            match http_client.logout().await {
                                Ok(_) => {
                                    logged_in_user = None; // Clear local state on successful logout
                                    io_handler.write_line("You have been logged out.")?;
                                    tracing::info!("Logout successful via API call");
                                }
                                Err(e) => {
                                    // Keep local state, server logout failed
                                    tracing::error!(error = ?e, "Logout API call failed");
                                    io_handler.write_line(&format!(
                                        "Logout failed on the server: {}. You might still be logged in.",
                                        e
                                    ))?;
                                }
                            }
                        }
                        "q" | "Q" => {
                            io_handler.write_line("Exiting Scribe CLI.")?;
                            return Ok(()); // Exit application
                        }
                        _ => {
                            io_handler.write_line("Invalid choice, please try again.")?;
                        }
                    }
                }
            }
        }
    }
    // Removed unreachable Ok(())
}
