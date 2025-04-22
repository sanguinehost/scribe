// backend/src/bin/scribe_cli.rs

// Static bytes for test card image (adjust path as necessary)
const TEST_CARD_BYTES: &[u8] = include_bytes!("../../tests/test_data/test_card.png");

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::cookie::Jar;
use reqwest::Client as ReqwestClient;
use scribe_backend::models::auth::Credentials;
use scribe_backend::models::characters::CharacterMetadata;
use scribe_backend::models::chats::{ChatSession, ChatMessage}; // Removed NewChatMessageRequest
use scribe_backend::models::users::User; // Import from backend lib
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::{stdin, stdout, Write}; // For reading user input
use std::sync::Arc;
use reqwest::multipart; // For multipart form data
use tracing;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;
use uuid::Uuid;

// Define the expected response structure from the /generate endpoint
#[derive(serde::Deserialize, Debug)] // Add Deserialize
struct GenerateResponseCli {
    ai_message: ChatMessage,
}

// Custom Error type for the CLI client (can be simplified or expanded later)
#[derive(thiserror::Error, Debug)]
pub enum CliError {
    #[error("Request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON deserialization error: {0}")]
    JsonDeser(#[from] serde_json::Error),
    #[error("API returned an error: status={status}, message={message}")]
    ApiError { status: reqwest::StatusCode, message: String },
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    #[error("Registration failed: {0}")] // Added for registration errors
    RegistrationFailed(String),
    #[error("Resource not found")]
    NotFound,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InputError(String),
    #[error("Internal client error: {0}")]
    Internal(String),
}

/// A basic CLI client to test the Scribe backend API.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Base URL of the Scribe backend server
    #[arg(short, long, env = "SCRIBE_BASE_URL", default_value = "http://127.0.0.1:3000")]
    base_url: Url,
}

// Helper to join path to base URL
fn build_url(base: &Url, path: &str) -> Result<Url, CliError> {
    base.join(path).map_err(CliError::UrlParse)
}

// Helper to read a line from stdin
fn read_line(prompt: &str) -> Result<String, CliError> {
    print!("{} ", prompt);
    stdout().flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// Helper to handle API responses
async fn handle_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, CliError> {
    let status = response.status();
    if status.is_success() {
        response.json::<T>().await.map_err(CliError::Reqwest)
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error body".to_string());
        tracing::error!(%status, error_body = %error_text, "API request failed");
        Err(CliError::ApiError {
            status,
            message: error_text,
        })
    }
}

// --- Chat Session Creation ---
async fn create_chat_session(
    client: &ReqwestClient,
    base_url: &Url,
    character_id: Uuid,
) -> Result<ChatSession, CliError> {
    let url = build_url(base_url, "/api/chats")?;
    tracing::info!(%url, %character_id, "Creating chat session");
    let payload = json!({ "character_id": character_id });
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    handle_response(response).await
}

// --- Chat Loop ---
async fn generate_response(
    client: &ReqwestClient,
    base_url: &Url,
    chat_id: Uuid,
    message_content: &str,
) -> Result<ChatMessage, CliError> {
    let url = build_url(base_url, &format!("/api/chats/{}/generate", chat_id))?;
    tracing::debug!(%url, %chat_id, "Sending message and generating response");
    // The backend expects a JSON body like: {"content": "..."}
    // which matches the NewChatMessageRequest struct implicitly.
    let payload = json!({ "content": message_content });

    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    // Deserialize into GenerateResponseCli first, then extract ChatMessage
    let generate_response_body: GenerateResponseCli = handle_response(response).await?;
    Ok(generate_response_body.ai_message)
}

async fn run_chat_loop(
    client: &ReqwestClient,
    base_url: &Url,
    chat_id: Uuid,
) -> Result<(), CliError> {
    println!("\nEntering chat session (ID: {}). Type 'quit' or 'exit' to leave.", chat_id);
    println!("--------------------------------------------------");

    loop {
        let user_input = read_line("You:")?;

        if user_input.eq_ignore_ascii_case("quit") || user_input.eq_ignore_ascii_case("exit") {
            println!("Leaving chat session.");
            break;
        }

        if user_input.is_empty() {
            continue; // Skip empty input
        }

        // Send message and get response
        match generate_response(client, base_url, chat_id, &user_input).await {
            Ok(ai_message) => {
                // Print AI response
                // TODO: Improve formatting, maybe handle streaming later
                println!("AI: {}", ai_message.content);
            }
            Err(e) => {
                tracing::error!(error = ?e, "Failed to get AI response");
                println!("Error: Could not get response from AI. Please try again. ({})", e);
                // Decide if we should break or continue on error
                // continue;
            }
        }
        println!("--------------------------------------------------"); // Separator
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing (using RUST_LOG environment variable)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "scribe_cli=info,scribe_backend=warn".into());
    fmt()
        .with_env_filter(filter)
        .with_target(true) // Include module path
        .compact()
        .init();

    let args = Args::parse();

    tracing::info!(base_url = %args.base_url, "Starting Scribe CLI client");

    // Create a reqwest client with a cookie store
    let http_client = ReqwestClient::builder()
        .cookie_provider(Arc::new(Jar::default())) // Use Arc for cookie jar
        .build()
        .context("Failed to build reqwest client")?;

    println!("Welcome to Scribe CLI!");
    println!("Connecting to: {}", args.base_url);

    let mut logged_in_user: Option<User> = None;

    // Main application loop
    loop {
        // If not logged in, show the Login/Register Menu
        if logged_in_user.is_none() {
            println!("\n--- Main Menu ---");
            println!("[1] Login");
            println!("[2] Register");
            println!("[q] Quit");

            let choice = read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => {
                    match handle_login(&http_client, &args.base_url).await {
                        Ok(user) => {
                            tracing::info!(username = %user.username, user_id = %user.id, "Login successful");
                            println!("Login successful as '{}'.", user.username);
                            logged_in_user = Some(user);
                            // Continue the outer loop, will now enter the 'else' block
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Login failed");
                            println!("Login failed: {}", e);
                        }
                    }
                }
                "2" => {
                    match handle_registration(&http_client, &args.base_url).await {
                        Ok(user) => {
                            tracing::info!(username = %user.username, user_id = %user.id, "Registration successful");
                            println!(
                                "Registration successful for user '{}'. You can now log in.",
                                user.username
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Registration failed");
                            println!("Registration failed: {}", e);
                        }
                    }
                }
                "q" | "Q" => {
                    println!("Exiting Scribe CLI.");
                    return Ok(()); // Exit application
                }
                _ => {
                    println!("Invalid choice, please try again.");
                }
            }
        } else {
            // User is logged in, show the Post-Login Menu
            let current_user = logged_in_user.as_ref().unwrap();
            println!("\n--- Logged In Menu (User: {}) ---", current_user.username);
            println!("[1] List Characters");
            println!("[2] Start Chat Session");
            println!("[3] Create Test Character");
            println!("[4] Logout");
            println!("[q] Quit Application");

            let choice = read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => {
                    // List Characters
                    println!("\nFetching your characters...");
                    match list_characters(&http_client, &args.base_url).await {
                        Ok(characters) => {
                            if characters.is_empty() {
                                println!("You have no characters.");
                            } else {
                                println!("Your characters:");
                                for char_meta in characters {
                                    println!("  - {} (ID: {})", char_meta.name, char_meta.id);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Failed to list characters");
                            println!("Error listing characters: {}", e);
                        }
                    }
                }
                "2" => {
                    // Start Chat Session
                    match select_character(&http_client, &args.base_url).await {
                        Ok(character_id) => {
                            tracing::info!(%character_id, "Character selected for chat");
                            match create_chat_session(&http_client, &args.base_url, character_id).await {
                                Ok(chat_session) => {
                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                    if let Err(e) = run_chat_loop(&http_client, &args.base_url, chat_session.id).await {
                                         tracing::error!(error = ?e, "Chat loop failed");
                                         println!("Chat loop encountered an error: {}", e);
                                    }
                                    println!("Chat finished."); // Indicate chat loop ended
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to create chat session");
                                    println!("Error starting chat session: {}", e);
                                }
                            }
                        }
                        Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                             println!("{}", msg); // Show the specific 'no characters' message
                        }
                        Err(e) => {
                            tracing::error!(error = ?e, "Failed to select character");
                            println!("Error selecting character: {}", e);
                        }
                    }
                }
                "3" => { // New option: Create Test Character
                    println!("\nCreating test character...");
                    match handle_create_test_character(&http_client, &args.base_url).await {
                         Ok(character) => {
                             tracing::info!(character_id = %character.id, character_name = %character.name, "Test character created successfully");
                             println!("Successfully created test character '{}' (ID: {}).", character.name, character.id);
                         }
                         Err(e) => {
                            tracing::error!(error = ?e, "Failed to create test character");
                            println!("Error creating test character: {}", e);
                        }
                    }
                }
                "4" => { // Renumbered Logout
                    // Logout
                    println!("Logging out...");
                    // TODO: Ideally call a /logout endpoint if it exists and clears server session
                    // For now, just clear the client state
                    logged_in_user = None;
                    println!("You have been logged out.");
                    // Continue the outer loop, which will now show the Main Menu again
                }
                "q" | "Q" => {
                    println!("Exiting Scribe CLI.");
                    return Ok(()); // Exit application
                }
                _ => {
                    println!("Invalid choice, please try again.");
                }
            }
        }
    } // End of main application loop

    // Ok(()) // Main loop now handles exit, so this is unreachable unless loop breaks unexpectedly
}

// --- API Interaction Functions (using http_client and base_url) ---

// Renamed from perform_login
async fn handle_login(client: &ReqwestClient, base_url: &Url) -> Result<User, CliError> {
    println!("\nPlease log in.");
    let username = read_line("Username:")?;
    let password = read_line("Password:")?;

    let url = build_url(base_url, "/api/auth/login")?;
    // Use the Credentials struct directly
    let credentials = Credentials {
        username,
        password,
    };

    tracing::info!(%url, username = %credentials.username, "Attempting login");

    let response = client
        .post(url)
        .json(&credentials)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    match handle_response::<User>(response).await {
        Ok(user) => Ok(user),
        Err(e) => {
            // Return specific AuthFailed error
            Err(CliError::AuthFailed(format!("{}", e)))
        }
    }
}

// New function for handling registration
async fn handle_registration(client: &ReqwestClient, base_url: &Url) -> Result<User, CliError> {
    println!("\nPlease register a new user.");
    let username = read_line("Choose Username:")?;
    let password = read_line("Choose Password:")?;

    // Basic client-side validation (optional but good practice)
    if username.len() < 3 {
        return Err(CliError::InputError("Username must be at least 3 characters long.".into()));
    }
    if password.len() < 8 {
        return Err(CliError::InputError("Password must be at least 8 characters long.".into()));
    }

    let url = build_url(base_url, "/api/auth/register")?;
    // Use the Credentials struct directly
    let credentials = Credentials {
        username,
        password,
    };

    tracing::info!(%url, username = %credentials.username, "Attempting registration");

    let response = client
        .post(url)
        .json(&credentials)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    // Registration endpoint returns the created User on success (status 201)
    // Use handle_response which checks for success status
    match handle_response::<User>(response).await {
        Ok(user) => Ok(user),
        Err(e) => {
            // Return specific RegistrationFailed error
            Err(CliError::RegistrationFailed(format!("{}", e)))
        }
    }
}

// --- Character Selection ---
async fn list_characters(
    client: &ReqwestClient,
    base_url: &Url,
) -> Result<Vec<CharacterMetadata>, CliError> {
    let url = build_url(base_url, "/api/characters")?;
    tracing::info!(%url, "Listing characters");
    let response = client
        .get(url)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    handle_response(response).await
}

async fn select_character(client: &ReqwestClient, base_url: &Url) -> Result<Uuid, CliError> {
    println!("\nFetching your characters...");
    let characters = list_characters(client, base_url).await?;

    if characters.is_empty() {
        return Err(CliError::InputError(
            "No characters found. Please upload a character first.".to_string(),
        ));
    }

    println!("Available characters:");
    for (index, char) in characters.iter().enumerate() {
        println!("  [{}] {} (ID: {})", index + 1, char.name, char.id);
    }

    loop {
        let choice_str = read_line("Select character by number:")?;
        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= characters.len() => {
                let selected_char = &characters[choice - 1];
                println!("Selected: {}", selected_char.name);
                return Ok(selected_char.id);
            }
            _ => {
                println!("Invalid selection. Please enter a number between 1 and {}.", characters.len());
            }
        }
    }
}

// Modified function to create a test character using include_bytes!
async fn handle_create_test_character(client: &ReqwestClient, base_url: &Url) -> Result<CharacterMetadata, CliError> {
    // Embed the file bytes directly into the binary at compile time
    // Path is relative to this source file (src/bin/scribe_cli.rs)
    const TEST_CARD_BYTES: &[u8] = include_bytes!("../../tests/test_data/test_card.png");
    const CHARACTER_NAME: &str = "Test Character CLI";
    const FILE_NAME: &str = "test_card.png";

    tracing::info!(character_name = CHARACTER_NAME, file_name = FILE_NAME, "Attempting to create test character from embedded data");

    // 1. Create multipart part from embedded bytes
    let file_part = multipart::Part::bytes(TEST_CARD_BYTES)
        .file_name(FILE_NAME.to_string()) // Use the const filename
        .mime_str("image/png")
        .map_err(|e| CliError::Internal(format!("Failed to create multipart file part: {}", e)))?;

    // 2. Create the form and add parts
    let form = multipart::Form::new()
        .text("name", CHARACTER_NAME.to_string()) // Use the const name
        .part("character_card", file_part);

    // 3. Build URL and send request
    let url = build_url(base_url, "/api/characters/upload")?;
    tracing::info!(%url, "Sending character upload request");

    let response = client
        .post(url)
        .multipart(form)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    // 4. Handle response
    match handle_response::<CharacterMetadata>(response).await {
        Ok(metadata) => Ok(metadata),
        Err(e) => {
            // Simplify error handling, handle_response already creates ApiError
            Err(e)
        }
    }
}

/*
async fn generate_response(
    client: &ReqwestClient,
    base_url: &Url,
    chat_id: Uuid,
    message_content: &str,
) -> Result<ChatMessage, CliError> {
    let url = build_url(base_url, &format!("/api/chats/{}/generate", chat_id))?;
    tracing::info!(%url, %chat_id, "Sending message and generating response");
    let payload = NewChatMessageRequest {
        content: message_content.to_string(),
    };

    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(CliError::Reqwest)?;

    handle_response(response).await
}
*/