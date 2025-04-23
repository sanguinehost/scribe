// cli/src/main.rs

// Relative path to the test card image - Keep this constant here if only used by main loop logic
const TEST_CARD_PATH: &str = "test_data/test_card.png";

// Declare modules
mod error;
mod io;
mod client;
mod handlers;
mod chat;

// Use necessary items from modules
use anyhow::{Context, Result};
use clap::Parser;
use reqwest::cookie::Jar;
use reqwest::Client as ReqwestClient;
use scribe_backend::models::users::User; // Keep User if used for logged_in_user state
use std::sync::Arc;
use tracing;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

// Use module contents
use error::CliError; // Use our specific error type
use io::{IoHandler, StdIoHandler}; // IO Abstraction
use client::{HttpClient, ReqwestClientWrapper}; // Client Abstraction
use chat::run_chat_loop; // Chat loop
use handlers::*; // Import all action handlers


/// A basic CLI client to test the Scribe backend API.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base URL of the Scribe backend server
    #[arg(short, long, env = "SCRIBE_BASE_URL", default_value = "http://127.0.0.1:3000")]
    base_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "scribe_cli=info,scribe_backend=warn".into());
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();

    let args = Args::parse();
    // Use Default trait since StdIoHandler derives Default
    let mut io_handler = StdIoHandler::default();

    tracing::info!(base_url = %args.base_url, "Starting Scribe CLI client");

    let reqwest_client = ReqwestClient::builder()
        .cookie_provider(Arc::new(Jar::default()))
        .build()
        .context("Failed to build reqwest client")?;

    // Use the wrapper from the client module
    let http_client = ReqwestClientWrapper::new(reqwest_client, args.base_url.clone());

    io_handler.write_line("Welcome to Scribe CLI!")?;
    io_handler.write_line(&format!("Connecting to: {}", args.base_url))?;

    // Keep logged_in_user state here in the main loop
    let mut logged_in_user: Option<User> = None;
    // Add state for the selected model - Use full name as default
    let mut current_model: String = "gemini-2.5-pro-exp-03-25".to_string();

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
                            io_handler.write_line(&format!("Login successful as '{}'.", user.username))?;
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
            let current_user = logged_in_user.as_ref().expect("User should be logged in here");
            io_handler.write_line(&format!("\n--- Logged In Menu (User: {}) ---", current_user.username))?;
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
            io_handler.write_line("[q] Quit Application")?;

            let choice = io_handler.read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => { // List Characters
                    io_handler.write_line("\nFetching your characters...")?;
                    match http_client.list_characters().await {
                        Ok(characters) => {
                            if characters.is_empty() {
                                io_handler.write_line("You have no characters.")?;
                            } else {
                                io_handler.write_line("Your characters:")?;
                                for char_meta in characters {
                                    // Consider using select_character display format here for consistency?
                                    io_handler.write_line(&format!("  - {} (ID: {})", char_meta.name, char_meta.id))?;
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Failed to list characters");
                            io_handler.write_line(&format!("Error listing characters: {}", e))?;
                        }
                    }
                }
                "2" => { // Start Chat Session
                     // Use handler function to select character
                    match select_character(&http_client, &mut io_handler).await {
                        Ok(character_id) => {
                            tracing::info!(%character_id, "Character selected for chat");
                            // Now create the session
                            match http_client.create_chat_session(character_id).await {
                                Ok(chat_session) => {
                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                    // Use chat loop function
                                    if let Err(e) = run_chat_loop(&http_client, chat_session.id, &mut io_handler, &current_model).await {
                                         tracing::error!(error = ?e, "Chat loop failed");
                                         io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
                                    }
                                    // Message moved inside chat loop exit
                                    // io_handler.write_line("Chat finished.")?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to create chat session");
                                    io_handler.write_line(&format!("Error starting chat session: {}", e))?;
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
                "3" => { // Create Test Character
                    io_handler.write_line("\nCreating test character...")?;
                    const CHARACTER_NAME: &str = "Test Character CLI";
                    // Use the constant path defined at the top
                    // Note: This directly calls the client method, not a handler. Could create a handler if needed.
                    match http_client.upload_character(CHARACTER_NAME, TEST_CARD_PATH).await {
                         Ok(character) => {
                             tracing::info!(character_id = %character.id, character_name = %character.name, "Test character created successfully");
                             io_handler.write_line(&format!("Successfully created test character '{}' (ID: {}).", character.name, character.id))?;
                         }
                         Err(CliError::Io(io_err)) => {
                             // Provide more context for common IO errors
                              tracing::error!(error = ?io_err, path = TEST_CARD_PATH, "Failed to read test character card file");
                              io_handler.write_line(&format!("Error reading test character card file '{}': {}", TEST_CARD_PATH, io_err))?;
                              io_handler.write_line("Please ensure the file exists relative to the CLI executable or workspace root.")?;
                         }
                         Err(e) => {
                            tracing::error!(error = ?e, "Failed to create test character");
                            io_handler.write_line(&format!("Error creating test character: {}", e))?;
                        }
                    }
                }
                "4" => { // Upload Character
                    // Use handler function
                   match handle_upload_character_action(&http_client, &mut io_handler).await {
                       Ok(character) => {
                           tracing::info!(character_id = %character.id, character_name = %character.name, "Character uploaded successfully");
                           io_handler.write_line(&format!("Successfully uploaded character '{}' (ID: {}).", character.name, character.id))?;
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
               "5" => { // View Character Details
                   // Use handler function
                   match handle_view_character_details_action(&http_client, &mut io_handler).await {
                       Ok(()) => { /* Success message handled within function */ }
                       // Handle specific error from handler/select_character
                       Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                            io_handler.write_line(&msg)?;
                       }
                       Err(e) => {
                           tracing::error!(error = ?e, "Failed to view character details");
                           io_handler.write_line(&format!("Error viewing character details: {}", e))?;
                       }
                   }
               }
              "6" => { // List Chat Sessions
                  // Use handler function
                  match handle_list_chat_sessions_action(&http_client, &mut io_handler).await {
                      Ok(()) => { /* Success message handled within function */ }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to list chat sessions");
                          io_handler.write_line(&format!("Error listing chat sessions: {}", e))?;
                      }
                  }
              }
              "7" => { // View Chat History
                  // Use handler function
                  match handle_view_chat_history_action(&http_client, &mut io_handler).await {
                      Ok(()) => { /* Success message handled within function */ }
                      // Handle specific error from handler
                      Err(CliError::InputError(msg)) if msg.contains("No chat sessions found") => {
                           io_handler.write_line(&msg)?;
                      }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to view chat history");
                          io_handler.write_line(&format!("Error viewing chat history: {}", e))?;
                      }
                  }
              }
              "8" => { // Resume Chat Session
                  // Use handler function
                  match handle_resume_chat_session_action(&http_client, &mut io_handler, &current_model).await {
                      Ok(()) => { /* Chat loop finished or error handled inside */ }
                      // Handle specific error from handler
                      Err(CliError::InputError(msg)) if msg.contains("No chat sessions found") => {
                           io_handler.write_line(&msg)?;
                      }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to resume chat session");
                          io_handler.write_line(&format!("Error resuming chat session: {}", e))?;
                      }
                  }
              }
             "9" => { // Show My Info
                  io_handler.write_line("\nFetching your user info...")?;
                   // Directly call client, could create handler if logic grows
                  match http_client.me().await {
                      Ok(user_info) => {
                            io_handler.write_line(&format!("  Username: {}", user_info.username))?;
                            io_handler.write_line(&format!("  User ID: {}", user_info.id))?;
                        }
                        Err(e) => {
                             tracing::error!(error = ?e, "Failed to fetch user info");
                             io_handler.write_line(&format!("Error fetching user info: {}", e))?;
                        }
                    }
                }
               "10" => { // Logout
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
                            io_handler.write_line(&format!("Logout failed on the server: {}. You might still be logged in.", e))?;
                        }
                    }
                }
                "11" => { // Model Settings
                    // Call a new handler function for model settings
                    // Pass the current_model mutably so the handler can change it
                    match handle_model_settings_action(&http_client, &mut io_handler, &mut current_model).await {
                        Ok(()) => { /* Settings updated or user backed out */ }
                        Err(e) => {
                            // Errors should ideally be handled within the action, but log if they propagate
                            tracing::error!(error = ?e, "Model settings action failed");
                            io_handler.write_line(&format!("Error in model settings: {}", e))?;
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
    // Removed unreachable Ok(())
}