// cli/src/main.rs

// Relative path to the test card image
const TEST_CARD_PATH: &str = "../../backend/tests/test_data/test_card.png";

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::cookie::Jar;
use reqwest::Client as ReqwestClient;
use scribe_backend::models::auth::Credentials;
use scribe_backend::models::characters::CharacterMetadata;
use scribe_backend::models::chats::{ChatSession, ChatMessage};
use scribe_backend::models::users::User;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::io::{stdin, stdout, Write}; // For reading user input
use std::sync::Arc;
use std::fs; // Added for file reading
use std::path::Path; // Added for path manipulation
use reqwest::multipart; // For multipart form data
use tracing;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;
use uuid::Uuid;
use async_trait::async_trait;
use chrono::Utc; // Added for timestamps in User mock

// --- I/O Abstraction ---

/// Trait for handling Command Line Input/Output to allow mocking in tests.
trait IoHandler { // Removed pub
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError>;
    fn write_line(&mut self, line: &str) -> Result<(), CliError>;
    // Add write or other methods if needed
}

/// Standard I/O handler using stdin and stdout.
struct StdIoHandler; // Removed pub

impl IoHandler for StdIoHandler {
    fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
        print!("{} ", prompt);
        stdout().flush().map_err(CliError::Io)?;
        let mut input = String::new();
        stdin().read_line(&mut input).map_err(CliError::Io)?;
        Ok(input.trim().to_string())
    }

    fn write_line(&mut self, line: &str) -> Result<(), CliError> {
        println!("{}", line);
        Ok(())
    }
}

// Define the expected response structure from the /generate endpoint
#[derive(serde::Deserialize, Debug)]
struct GenerateResponseCli {
    ai_message: ChatMessage,
}

// Define the expected response structure from the /health endpoint (matching backend)
#[derive(serde::Deserialize, Debug, Clone)] // Added Clone
struct HealthStatus { // Added HealthStatus struct
    status: String,
}

// --- HTTP Client Abstraction ---

/// Trait for abstracting HTTP client interactions to allow mocking in tests.
#[async_trait]
trait HttpClient { // Removed pub
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn register(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError>;
    async fn generate_response(&self, chat_id: Uuid, message_content: &str) -> Result<ChatMessage, CliError>;
    async fn upload_character(&self, name: &str, file_path: &str) -> Result<CharacterMetadata, CliError>; // Changed signature
    async fn health_check(&self) -> Result<HealthStatus, CliError>; // Added health check
    async fn logout(&self) -> Result<(), CliError>; // Added logout
    async fn me(&self) -> Result<User, CliError>; // Added me
    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError>; // Added get_character
    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError>; // Added list_chat_sessions
    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError>; // Added get_chat_messages
}

/// Wrapper around ReqwestClient implementing the HttpClient trait.
struct ReqwestClientWrapper { // Removed pub
    client: ReqwestClient,
    base_url: Url,
}

impl ReqwestClientWrapper {
    // Keep pub as it's used in main
    pub fn new(client: ReqwestClient, base_url: Url) -> Self {
        Self { client, base_url }
    }
}

#[async_trait]
impl HttpClient for ReqwestClientWrapper {
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/login")?;
        tracing::info!(%url, username = %credentials.username, "Attempting login via HttpClient");
        let response = self.client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        match handle_response::<User>(response).await {
            Ok(user) => Ok(user),
            Err(e) => Err(CliError::AuthFailed(format!("{}", e))),
        }
    }

    async fn register(&self, credentials: &Credentials) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/register")?;
        tracing::info!(%url, username = %credentials.username, "Attempting registration via HttpClient");
        let response = self.client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        match handle_response::<User>(response).await {
            Ok(user) => Ok(user),
            Err(e) => Err(CliError::RegistrationFailed(format!("{}", e))),
        }
    }

    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError> {
        let url = build_url(&self.base_url, "/api/characters")?;
        tracing::info!(%url, "Listing characters via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(%url, %character_id, "Creating chat session via HttpClient");
        let payload = json!({ "character_id": character_id });
        let response = self.client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

     async fn generate_response(&self, chat_id: Uuid, message_content: &str) -> Result<ChatMessage, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        tracing::debug!(%url, %chat_id, "Sending message and generating response via HttpClient");
        let payload = json!({ "content": message_content });
        let response = self.client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        let generate_response_body: GenerateResponseCli = handle_response(response).await?;
        Ok(generate_response_body.ai_message)
    }

    async fn upload_character(&self, name: &str, file_path: &str) -> Result<CharacterMetadata, CliError> {
        tracing::info!(character_name = name, %file_path, "Attempting to upload character via HttpClient");

        // Read the file content
        let file_bytes = fs::read(file_path)
            .map_err(|e| {
                tracing::error!(error = ?e, %file_path, "Failed to read character card file");
                CliError::Io(e)
            })?;

        // Extract filename from path
        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .ok_or_else(|| CliError::InputError(format!("Invalid file path: {}", file_path)))?;

        // Basic MIME type check (assuming PNG for now)
        let mime_type = if file_name.to_lowercase().ends_with(".png") {
            "image/png"
        } else {
             tracing::warn!(%file_name, "Uploading non-PNG file, assuming image/png MIME type");
            // Allow upload but warn, backend might reject it later if it's strict.
            // Alternatively, return Err(CliError::InputError("Only PNG character cards are supported.".to_string()));
             "image/png" // Or default to application/octet-stream? Backend expects image.
        };

        let file_part = multipart::Part::bytes(file_bytes) // Use read bytes
            .file_name(file_name.to_string())
            .mime_str(mime_type)
            .map_err(|e| CliError::Internal(format!("Failed to create multipart file part: {}", e)))?;

        let form = multipart::Form::new()
            .text("name", name.to_string())
            .part("character_card", file_part);

        let url = build_url(&self.base_url, "/api/characters/upload")?;
        tracing::info!(%url, "Sending character upload request via HttpClient");

        let response = self.client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn health_check(&self) -> Result<HealthStatus, CliError> {
        let url = build_url(&self.base_url, "/api/health")?; // Corrected path
        tracing::info!(%url, "Performing health check via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn logout(&self) -> Result<(), CliError> {
        let url = build_url(&self.base_url, "/api/auth/logout")?;
        tracing::info!(%url, "Attempting logout via HttpClient");
        let response = self.client
            .post(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            tracing::error!(%status, error_body = %error_text, "Logout API request failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    async fn me(&self) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/me")?;
        tracing::info!(%url, "Fetching current user info via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError> {
        let url = build_url(&self.base_url, &format!("/api/characters/{}", character_id))?;
        tracing::info!(%url, %character_id, "Fetching character details via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(%url, "Listing chat sessions via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/messages", session_id))?;
        tracing::info!(%url, %session_id, "Fetching chat messages via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }
}

// Custom Error type for the CLI client
#[derive(thiserror::Error, Debug)]
enum CliError { // Removed pub
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
    #[error("Registration failed: {0}")]
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

// --- Chat Loop ---
async fn run_chat_loop<IO: IoHandler, Http: HttpClient>(
    http_client: &Http,
    chat_id: Uuid,
    io_handler: &mut IO,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("\nEntering chat session (ID: {}). Type 'quit' or 'exit' to leave.", chat_id))?;
    io_handler.write_line("--------------------------------------------------")?;

    loop {
        let user_input = io_handler.read_line("You:")?;

        if user_input.eq_ignore_ascii_case("quit") || user_input.eq_ignore_ascii_case("exit") {
            io_handler.write_line("Leaving chat session.")?;
            break;
        }

        if user_input.is_empty() {
            continue;
        }

        match http_client.generate_response(chat_id, &user_input).await {
            Ok(ai_message) => {
                io_handler.write_line(&format!("AI: {}", ai_message.content))?;
            }
            Err(e) => {
                tracing::error!(error = ?e, "Failed to get AI response");
                io_handler.write_line(&format!("Error: Could not get response from AI. Please try again. ({})", e))?;
            }
        }
        io_handler.write_line("--------------------------------------------------")?;
    }
    Ok(())
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
    let mut io_handler = StdIoHandler;

    tracing::info!(base_url = %args.base_url, "Starting Scribe CLI client");

    let reqwest_client = ReqwestClient::builder()
        .cookie_provider(Arc::new(Jar::default()))
        .build()
        .context("Failed to build reqwest client")?;

    let http_client = ReqwestClientWrapper::new(reqwest_client, args.base_url.clone());

    io_handler.write_line("Welcome to Scribe CLI!")?;
    io_handler.write_line(&format!("Connecting to: {}", args.base_url))?;

    let mut logged_in_user: Option<User> = None;

    loop {
        if logged_in_user.is_none() {
            io_handler.write_line("\n--- Main Menu ---")?;
            io_handler.write_line("[1] Login")?;
            io_handler.write_line("[2] Register")?;
            io_handler.write_line("[3] Health Check")?;
            io_handler.write_line("[q] Quit")?;

            let choice = io_handler.read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => {
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
                    return Ok(());
                }
                _ => {
                    io_handler.write_line("Invalid choice, please try again.")?;
                }
            }
        } else {
            let current_user = logged_in_user.as_ref().unwrap();
            io_handler.write_line(&format!("\n--- Logged In Menu (User: {}) ---", current_user.username))?;
            io_handler.write_line("[1] List Characters")?;
            io_handler.write_line("[2] Start Chat Session")?;
            io_handler.write_line("[3] Create Test Character")?;
            io_handler.write_line("[4] Upload Character")?;
            io_handler.write_line("[5] View Character Details")?;
            io_handler.write_line("[6] List Chat Sessions")?;
            io_handler.write_line("[7] View Chat History")?;
            io_handler.write_line("[8] Resume Chat Session")?; // New option
            io_handler.write_line("[9] Show My Info")?; // Renumbered
            io_handler.write_line("[10] Logout")?; // Renumbered
            io_handler.write_line("[q] Quit Application")?;

            let choice = io_handler.read_line("Enter choice:")?;

            match choice.as_str() {
                "1" => {
                    io_handler.write_line("\nFetching your characters...")?;
                    match http_client.list_characters().await {
                        Ok(characters) => {
                            if characters.is_empty() {
                                io_handler.write_line("You have no characters.")?;
                            } else {
                                io_handler.write_line("Your characters:")?;
                                for char_meta in characters {
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
                "2" => {
                    match select_character(&http_client, &mut io_handler).await {
                        Ok(character_id) => {
                            tracing::info!(%character_id, "Character selected for chat");
                            match http_client.create_chat_session(character_id).await {
                                Ok(chat_session) => {
                                    tracing::info!(chat_id = %chat_session.id, "Chat session started");
                                    if let Err(e) = run_chat_loop(&http_client, chat_session.id, &mut io_handler).await {
                                         tracing::error!(error = ?e, "Chat loop failed");
                                         io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
                                    }
                                    io_handler.write_line("Chat finished.")?;
                                }
                                Err(e) => {
                                    tracing::error!(error = ?e, "Failed to create chat session");
                                    io_handler.write_line(&format!("Error starting chat session: {}", e))?;
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
                "3" => { // Create Test Character (uses new signature with path)
                    io_handler.write_line("\nCreating test character...")?;
                    const CHARACTER_NAME: &str = "Test Character CLI";
                    // Use the constant path defined at the top
                    match http_client.upload_character(CHARACTER_NAME, TEST_CARD_PATH).await {
                         Ok(character) => {
                             tracing::info!(character_id = %character.id, character_name = %character.name, "Test character created successfully");
                             io_handler.write_line(&format!("Successfully created test character '{}' (ID: {}).", character.name, character.id))?;
                         }
                         Err(e) => {
                            tracing::error!(error = ?e, "Failed to create test character");
                            io_handler.write_line(&format!("Error creating test character: {}", e))?;
                        }
                    }
                }
                "4" => { // New option: Upload Character
                   match handle_upload_character_action(&http_client, &mut io_handler).await {
                       Ok(character) => {
                           tracing::info!(character_id = %character.id, character_name = %character.name, "Character uploaded successfully");
                           io_handler.write_line(&format!("Successfully uploaded character '{}' (ID: {}).", character.name, character.id))?;
                       }
                       Err(e) => {
                           tracing::error!(error = ?e, "Character upload failed");
                           io_handler.write_line(&format!("Error uploading character: {}", e))?;
                       }
                   }
                }
               "5" => { // New option: View Character Details
                   match handle_view_character_details_action(&http_client, &mut io_handler).await {
                       Ok(()) => { /* Success message handled within function */ }
                       Err(CliError::InputError(msg)) if msg.contains("No characters found") => {
                            io_handler.write_line(&msg)?; // Display the specific error from the action
                       }
                       Err(e) => {
                           tracing::error!(error = ?e, "Failed to view character details");
                           io_handler.write_line(&format!("Error viewing character details: {}", e))?;
                       }
                   }
               }
              "6" => { // New option: List Chat Sessions
                  match handle_list_chat_sessions_action(&http_client, &mut io_handler).await {
                      Ok(()) => { /* Success message handled within function */ }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to list chat sessions");
                          io_handler.write_line(&format!("Error listing chat sessions: {}", e))?;
                      }
                  }
              }
              "7" => { // New option: View Chat History
                  match handle_view_chat_history_action(&http_client, &mut io_handler).await {
                      Ok(()) => { /* Success message handled within function */ }
                      Err(CliError::InputError(msg)) if msg.contains("No chat sessions found") => {
                           io_handler.write_line(&msg)?; // Display the specific error from the action
                      }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to view chat history");
                          io_handler.write_line(&format!("Error viewing chat history: {}", e))?;
                      }
                  }
              }
              "8" => { // New option: Resume Chat Session
                  match handle_resume_chat_session_action(&http_client, &mut io_handler).await {
                      Ok(()) => { /* Chat loop finished or error handled inside */ }
                      Err(CliError::InputError(msg)) if msg.contains("No chat sessions found") => {
                           io_handler.write_line(&msg)?;
                      }
                      Err(e) => {
                          tracing::error!(error = ?e, "Failed to resume chat session");
                          io_handler.write_line(&format!("Error resuming chat session: {}", e))?;
                      }
                  }
              }
             "9" => { // Renumbered: Show My Info
                  io_handler.write_line("\nFetching your user info...")?;
                  match http_client.me().await {
                      Ok(user_info) => {
                            io_handler.write_line(&format!("  Username: {}", user_info.username))?;
                            io_handler.write_line(&format!("  User ID: {}", user_info.id))?;
                            // Add other fields if available and relevant in User struct
                        }
                        Err(e) => {
                             tracing::error!(error = ?e, "Failed to fetch user info");
                             io_handler.write_line(&format!("Error fetching user info: {}", e))?;
                        }
                    }
                }
               "10" => { // Renumbered Logout
                   io_handler.write_line("Logging out...")?;
                   match http_client.logout().await {
                       Ok(_) => {
                            logged_in_user = None;
                            io_handler.write_line("You have been logged out.")?;
                            tracing::info!("Logout successful via API call");
                        }
                        Err(e) => {
                            // Log error, but still clear local state as a fallback? Or keep logged in?
                            // Let's keep the user logged in locally if the API call fails, as they might still have a valid session cookie.
                            tracing::error!(error = ?e, "Logout API call failed");
                            io_handler.write_line(&format!("Logout failed on the server: {}. You might still be logged in.", e))?;
                            // logged_in_user = None; // Decide if local state should be cleared even on API error
                        }
                    }
                }
                "q" | "Q" => {
                    io_handler.write_line("Exiting Scribe CLI.")?;
                    return Ok(());
                }
                _ => {
                    io_handler.write_line("Invalid choice, please try again.")?;
                }
            }
        }
    }
}

// --- Action Functions ---

async fn handle_login_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<User, CliError> {
    io_handler.write_line("\nPlease log in.")?;
    let username = io_handler.read_line("Username:")?;
    let password = io_handler.read_line("Password:")?;
    let credentials = Credentials { username, password };
    http_client.login(&credentials).await
}

async fn handle_registration_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<User, CliError> {
    io_handler.write_line("\nPlease register a new user.")?;
    let username = io_handler.read_line("Choose Username:")?;
    let password = io_handler.read_line("Choose Password:")?;
    if username.len() < 3 {
        return Err(CliError::InputError("Username must be at least 3 characters long.".into()));
    }
    if password.len() < 8 {
        return Err(CliError::InputError("Password must be at least 8 characters long.".into()));
    }
    let credentials = Credentials { username, password };
    http_client.register(&credentials).await
}

async fn handle_health_check_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<(), CliError> {
    io_handler.write_line("\nChecking backend health...")?;
    match http_client.health_check().await {
        Ok(health_status) => {
            io_handler.write_line(&format!("Backend status: {}", health_status.status))?;
            Ok(())
        }
        Err(e) => {
            // Error is logged by the caller, just propagate it
            Err(e)
        }
    }
}

async fn handle_upload_character_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<CharacterMetadata, CliError> {
   io_handler.write_line("\nUpload a new character.")?;
   let name = io_handler.read_line("Character Name:")?;
   let file_path = io_handler.read_line("Path to Character Card (.png):")?;

   if name.trim().is_empty() {
       return Err(CliError::InputError("Character name cannot be empty.".into()));
   }
   if file_path.trim().is_empty() {
       return Err(CliError::InputError("File path cannot be empty.".into()));
   }
   // Basic check, could be more robust
   if !file_path.to_lowercase().ends_with(".png") {
        io_handler.write_line("Warning: File does not end with .png. The backend might reject it.")?;
   }

   // Check if file exists before attempting upload
   if !Path::new(&file_path).exists() {
       return Err(CliError::InputError(format!("File not found at path: {}", file_path)));
   }

   io_handler.write_line("Uploading...")?;
   http_client.upload_character(&name, &file_path).await
}

async fn handle_view_character_details_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<(), CliError> {
   // Reuse select_character logic to get the ID
   let character_id = select_character(http_client, io_handler).await?;

   io_handler.write_line("\nFetching character details...")?;
   match http_client.get_character(character_id).await {
       Ok(character) => {
           io_handler.write_line(&format!("--- Character Details (ID: {}) ---", character.id))?;
           io_handler.write_line(&format!("  Name: {}", character.name))?;
           io_handler.write_line(&format!("  Description: {}", character.description.as_deref().unwrap_or("N/A")))?;
           io_handler.write_line("------------------------------------")?;
           Ok(())
       }
       Err(e) => {
           // Error logged by caller
           Err(e)
       }
   }
}

async fn handle_list_chat_sessions_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<(), CliError> {
  io_handler.write_line("\nFetching your chat sessions...")?;
  match http_client.list_chat_sessions().await {
      Ok(sessions) => {
          if sessions.is_empty() {
              io_handler.write_line("You have no active chat sessions.")?;
          } else {
              io_handler.write_line("Your chat sessions:")?;
              // TODO: Ideally, fetch character names for better display instead of just IDs
              for session in sessions {
                  io_handler.write_line(&format!(
                      "  - Session ID: {}, Character ID: {}, Last Updated: {}",
                      session.id, session.character_id, session.updated_at
                  ))?;
              }
          }
          Ok(())
      }
      Err(e) => Err(e), // Logged by caller
  }
}

async fn handle_view_chat_history_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<(), CliError> {
 io_handler.write_line("\nSelect a chat session to view its history.")?;

 // 1. List sessions
 let sessions = http_client.list_chat_sessions().await?;
 if sessions.is_empty() {
     return Err(CliError::InputError("No chat sessions found.".to_string()));
 }

 io_handler.write_line("Available chat sessions:")?;
 // TODO: Fetch character names for better display
 for (index, session) in sessions.iter().enumerate() {
     io_handler.write_line(&format!(
         "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
         index + 1, session.id, session.character_id, session.updated_at
     ))?;
 }

 // 2. Prompt for selection
 let selected_session_id = loop {
     let choice_str = io_handler.read_line("Select session by number:")?;
     match choice_str.parse::<usize>() {
         Ok(choice) if choice > 0 && choice <= sessions.len() => {
             break sessions[choice - 1].id;
         }
         _ => {
             io_handler.write_line(&format!("Invalid selection. Please enter a number between 1 and {}.", sessions.len()))?;
         }
     }
 };

 // 3. Fetch and display messages
 io_handler.write_line(&format!("\nFetching messages for session {}...", selected_session_id))?;
 match http_client.get_chat_messages(selected_session_id).await {
     Ok(messages) => {
         io_handler.write_line(&format!("--- Chat History (Session: {}) ---", selected_session_id))?;
         if messages.is_empty() {
             io_handler.write_line("  (No messages in this session yet)")?;
         } else {
             for message in messages {
                 let prefix = match message.message_type {
                     scribe_backend::models::chats::MessageRole::User => "You:",
                     scribe_backend::models::chats::MessageRole::Assistant => "AI:",
                     scribe_backend::models::chats::MessageRole::System => "System:", // Should not typically appear here
                 };
                 // Consider adding timestamps if available/needed
                 io_handler.write_line(&format!("  {} {}", prefix, message.content))?;
             }
         }
         io_handler.write_line("------------------------------------")?;
         Ok(())
     }
     Err(e) => Err(e), // Logged by caller
 }
}

async fn handle_resume_chat_session_action<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<(), CliError> {
io_handler.write_line("\nSelect a chat session to resume.")?;

// 1. List sessions
let sessions = http_client.list_chat_sessions().await?;
if sessions.is_empty() {
    return Err(CliError::InputError("No chat sessions found to resume.".to_string()));
}

io_handler.write_line("Available chat sessions:")?;
// TODO: Fetch character names for better display
for (index, session) in sessions.iter().enumerate() {
    io_handler.write_line(&format!(
        "  [{}] Session ID: {}, Character ID: {}, Last Updated: {}",
        index + 1, session.id, session.character_id, session.updated_at
    ))?;
}

// 2. Prompt for selection
let selected_session_id = loop {
    let choice_str = io_handler.read_line("Select session by number:")?;
    match choice_str.parse::<usize>() {
        Ok(choice) if choice > 0 && choice <= sessions.len() => {
            break sessions[choice - 1].id;
        }
        _ => {
            io_handler.write_line(&format!("Invalid selection. Please enter a number between 1 and {}.", sessions.len()))?;
        }
    }
};

// 3. Fetch and display recent messages before entering the loop
io_handler.write_line(&format!("\nFetching recent messages for session {}...", selected_session_id))?;
match http_client.get_chat_messages(selected_session_id).await {
    Ok(messages) => {
        io_handler.write_line(&format!("--- Recent History (Session: {}) ---", selected_session_id))?;
        if messages.is_empty() {
            io_handler.write_line("  (No messages in this session yet)")?;
        } else {
            // Display maybe the last N messages? Or all? Let's display all for now.
            for message in messages {
                let prefix = match message.message_type {
                    scribe_backend::models::chats::MessageRole::User => "You:",
                    scribe_backend::models::chats::MessageRole::Assistant => "AI:",
                    scribe_backend::models::chats::MessageRole::System => "System:",
                };
                io_handler.write_line(&format!("  {} {}", prefix, message.content))?;
            }
        }
        io_handler.write_line("------------------------------------")?;
    }
    Err(e) => {
        // Log the error but proceed to the chat loop anyway? Or abort?
        // Let's log and proceed, the user might still want to chat.
        tracing::error!(error = ?e, %selected_session_id, "Failed to fetch chat history before resuming");
        io_handler.write_line(&format!("Warning: Could not fetch recent chat history: {}", e))?;
    }
}

// 4. Enter chat loop with the selected session ID
tracing::info!(chat_id = %selected_session_id, "Resuming chat session");
if let Err(e) = run_chat_loop(http_client, selected_session_id, io_handler).await {
     tracing::error!(error = ?e, "Chat loop failed");
     // Propagate error to be handled in the main loop? Or just log here?
     // Let's just log it here and return Ok(()) from the action itself.
     io_handler.write_line(&format!("Chat loop encountered an error: {}", e))?;
}
io_handler.write_line("Chat finished.")?; // Indicate chat loop exit
Ok(())
}

// --- Character Selection ---
async fn select_character<Http: HttpClient, IO: IoHandler>(http_client: &Http, io_handler: &mut IO) -> Result<Uuid, CliError> {
io_handler.write_line("\nFetching your characters...")?;
    let characters = http_client.list_characters().await?;

    if characters.is_empty() {
        return Err(CliError::InputError(
            "No characters found. Please upload a character first.".to_string(),
        ));
    }

    io_handler.write_line("Available characters:")?;
    for (index, char) in characters.iter().enumerate() {
        io_handler.write_line(&format!("  [{}] {} (ID: {})", index + 1, char.name, char.id))?;
    }

    loop {
        let choice_str = io_handler.read_line("Select character by number:")?;
        match choice_str.parse::<usize>() {
            Ok(choice) if choice > 0 && choice <= characters.len() => {
                let selected_char = &characters[choice - 1];
                io_handler.write_line(&format!("Selected: {}", selected_char.name))?;
                return Ok(selected_char.id);
            }
            _ => {
                io_handler.write_line(&format!("Invalid selection. Please enter a number between 1 and {}.", characters.len()))?;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn test_build_url_success() {
        let base = Url::parse("http://localhost:3000").unwrap();
        let expected = Url::parse("http://localhost:3000/api/users").unwrap();
        assert_eq!(build_url(&base, "/api/users").unwrap(), expected);

        let base_with_path = Url::parse("http://example.com/base/").unwrap();
        let expected_with_path = Url::parse("http://example.com/base/path").unwrap();
        assert_eq!(build_url(&base_with_path, "path").unwrap(), expected_with_path);

        let base_no_slash = Url::parse("http://example.com").unwrap();
        let expected_no_slash = Url::parse("http://example.com/path").unwrap();
        assert_eq!(build_url(&base_no_slash, "/path").unwrap(), expected_no_slash);
    }

    #[test]
    fn test_build_url_invalid_path() {
        let base = Url::parse("http://localhost:3000").unwrap();
        let result = build_url(&base, "ftp:");
        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::UrlParse(_) => {} 
            e => panic!("Expected UrlParse error, but got {:?}", e),
        }
    }

    #[test]
    fn test_cli_error_display() {
        let proxy_error = reqwest::Proxy::http("invalid proxy url").unwrap_err();
        let reqwest_error = CliError::Reqwest(proxy_error);
        assert!(reqwest_error.to_string().contains("Request failed"));

        let url_parse_error = CliError::UrlParse(url::ParseError::EmptyHost);
        assert!(url_parse_error.to_string().contains("URL parsing error"));

        let json_error = CliError::JsonDeser(serde_json::from_str::<serde_json::Value>("{").unwrap_err());
        assert!(json_error.to_string().contains("JSON deserialization error"));

        let api_error = CliError::ApiError { status: reqwest::StatusCode::BAD_REQUEST, message: "Invalid input".to_string() };
        assert!(api_error.to_string().contains("API returned an error: status=400 Bad Request, message=Invalid input"));

        let auth_failed = CliError::AuthFailed("Wrong password".to_string());
        assert_eq!(auth_failed.to_string(), "Authentication failed: Wrong password");

        let reg_failed = CliError::RegistrationFailed("Username taken".to_string());
        assert_eq!(reg_failed.to_string(), "Registration failed: Username taken");

        let not_found = CliError::NotFound;
        assert_eq!(not_found.to_string(), "Resource not found");

        let io_error = CliError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"));
        assert!(io_error.to_string().contains("I/O error"));

        let input_error = CliError::InputError("Bad choice".to_string());
        assert_eq!(input_error.to_string(), "Invalid input: Bad choice");

        let internal_error = CliError::Internal("Something broke".to_string());
        assert_eq!(internal_error.to_string(), "Internal client error: Something broke");
    }
    use tempfile::NamedTempFile;

    use std::cell::RefCell;
    use std::collections::VecDeque;
    use scribe_backend::models::users::User; // Add User import
    use uuid::Uuid; // Add Uuid import
    use scribe_backend::models::chats::MessageRole;
    use std::sync::Arc; // Added for Arc<Result<...>> in MockHttpClient

    // --- Mocks ---

    // Define a simple, cloneable error for mocking purposes
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MockCliError {
        AuthFailed(String),
        RegistrationFailed(String),
        ApiError(String), // Simplified API error
        NotFound,
        Internal(String),
        // Add other variants as needed for specific test cases
    }

    // Simple conversion from MockCliError to the real CliError
    // This allows the mock client to work with cloneable results
    // while the test assertions check for the real CliError types.
    impl From<MockCliError> for CliError {
        fn from(mock_err: MockCliError) -> Self {
            match mock_err {
                MockCliError::AuthFailed(msg) => CliError::AuthFailed(msg),
                MockCliError::RegistrationFailed(msg) => CliError::RegistrationFailed(msg),
                MockCliError::ApiError(msg) => CliError::ApiError {
                    status: reqwest::StatusCode::INTERNAL_SERVER_ERROR, // Use a default status
                    message: msg,
                },
                MockCliError::NotFound => CliError::NotFound,
                MockCliError::Internal(msg) => CliError::Internal(msg),
            }
        }
    }

    struct MockIoHandler {
        inputs: RefCell<VecDeque<String>>,
        outputs: RefCell<Vec<String>>,
    }

    impl MockIoHandler {
        fn new(inputs: Vec<&str>) -> Self {
            MockIoHandler {
                inputs: RefCell::new(inputs.into_iter().map(String::from).collect()),
                outputs: RefCell::new(Vec::new()),
            }
        }

        fn expect_output(&self, expected: &str) {
            assert!(self.outputs.borrow().iter().any(|line| line.contains(expected)),
                    "Expected output containing '{}', but got: {:?}", expected, self.outputs.borrow());
        }

         fn expect_no_output_containing(&self, unexpected: &str) {
            assert!(!self.outputs.borrow().iter().any(|line| line.contains(unexpected)),
                    "Did not expect output containing '{}', but got: {:?}", unexpected, self.outputs.borrow());
        }
    }

    impl IoHandler for MockIoHandler {
        fn read_line(&mut self, prompt: &str) -> Result<String, CliError> {
            // Simulate writing the prompt to the output stream
            self.outputs.borrow_mut().push(prompt.to_string());
            // Then, read the next input
            self.inputs
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| CliError::InputError("MockIoHandler: No more inputs provided".to_string()))
        }

        fn write_line(&mut self, line: &str) -> Result<(), CliError> {
            self.outputs.borrow_mut().push(line.to_string());
            Ok(())
        }
    }

    #[derive(Default)] // Use default for simple mock state
    struct MockHttpClient {
        // Store results using the cloneable MockCliError
        login_result: Option<Arc<Result<User, MockCliError>>>,
        register_result: Option<Arc<Result<User, MockCliError>>>,
        health_check_result: Option<Arc<Result<HealthStatus, MockCliError>>>,
        upload_character_result: Option<Arc<Result<CharacterMetadata, MockCliError>>>,
        list_characters_result: Option<Arc<Result<Vec<CharacterMetadata>, MockCliError>>>,
        get_character_result: Option<Arc<Result<CharacterMetadata, MockCliError>>>,
        list_chat_sessions_result: Option<Arc<Result<Vec<ChatSession>, MockCliError>>>,
        get_chat_messages_result: Option<Arc<Result<Vec<ChatMessage>, MockCliError>>>,
        generate_response_result: Option<Arc<Result<ChatMessage, MockCliError>>>,
        // Add fields for other methods as needed
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn login(&self, _credentials: &Credentials) -> Result<User, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.login_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal(
                        "MockHttpClient: login result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Convert MockCliError to CliError
        }

        async fn register(&self, _credentials: &Credentials) -> Result<User, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.register_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: register result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }

        // Implement other methods as needed, returning errors by default
        async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.list_characters_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: list_characters result not set".into(),
                    )))
                }),
            );
             mock_result.map_err(Into::into) // Added conversion
        }
        async fn create_chat_session(&self, _character_id: Uuid) -> Result<ChatSession, CliError> {
             Err(CliError::Internal("MockHttpClient: create_chat_session not implemented".into())) // No change needed here as it directly returns CliError
        }
        async fn generate_response(&self, _chat_id: Uuid, _message_content: &str) -> Result<ChatMessage, CliError> {
             let mock_result = Arc::unwrap_or_clone(
                 self.generate_response_result.clone().unwrap_or_else(|| {
                     Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                         "MockHttpClient: generate_response result not set".into(),
                     )))
                 }),
             );
             mock_result.map_err(Into::into) // Added conversion
        }
        async fn upload_character(&self, _name: &str, _file_path: &str) -> Result<CharacterMetadata, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.upload_character_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: upload_character result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }
        async fn health_check(&self) -> Result<HealthStatus, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.health_check_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: health_check result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }
        async fn logout(&self) -> Result<(), CliError> { Err(CliError::Internal("MockHttpClient: logout not implemented".into())) } // No change needed
        async fn me(&self) -> Result<User, CliError> { Err(CliError::Internal("MockHttpClient: me not implemented".into())) } // No change needed
        async fn get_character(&self, _character_id: Uuid) -> Result<CharacterMetadata, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.get_character_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: get_character result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }
        async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.list_chat_sessions_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: list_chat_sessions result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }
        async fn get_chat_messages(&self, _session_id: Uuid) -> Result<Vec<ChatMessage>, CliError> {
            let mock_result = Arc::unwrap_or_clone(
                self.get_chat_messages_result.clone().unwrap_or_else(|| {
                    Arc::new(Err(MockCliError::Internal( // Corrected to MockCliError
                        "MockHttpClient: get_chat_messages result not set".into(),
                    )))
                }),
            );
            mock_result.map_err(Into::into) // Added conversion
        }
    }

    // --- Action Handler Tests ---

    #[tokio::test]
    async fn test_handle_login_action_success() {
        let mut mock_io = MockIoHandler::new(vec!["testuser", "password123"]);
        let mock_http = MockHttpClient {
            login_result: Some(Arc::new(Ok(User {
                id: Uuid::new_v4(),
                username: "testuser".to_string(),
                password_hash: "".to_string(), // Mocked
                created_at: Utc::now(),      // Mocked
                updated_at: Utc::now(),      // Mocked
            }))),
            ..Default::default()
        };

        let result = handle_login_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "testuser");
        mock_io.expect_output("Please log in.");
        // Prompts are ignored by mock, but we know they were called implicitly
    }

    #[tokio::test]
    async fn test_handle_login_action_failure() {
        let mut mock_io = MockIoHandler::new(vec!["testuser", "wrongpass"]);
        let mock_http = MockHttpClient {
            // Use MockCliError here
            login_result: Some(Arc::new(Err(MockCliError::AuthFailed("Invalid credentials".to_string())))),
            ..Default::default()
        };

        let result = handle_login_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        // Check for the converted CliError type
        match result.err().unwrap() {
            CliError::AuthFailed(msg) => assert_eq!(msg, "Invalid credentials"),
            e => panic!("Expected AuthFailed error, got {:?}", e),
        }
        mock_io.expect_output("Please log in.");
    }

     #[tokio::test]
    async fn test_handle_registration_action_success() {
        let mut mock_io = MockIoHandler::new(vec!["newuser", "goodpassword"]);
        let mock_http = MockHttpClient {
            register_result: Some(Arc::new(Ok(User {
                 id: Uuid::new_v4(),
                 username: "newuser".to_string(),
                 password_hash: "".to_string(), // Mocked
                 created_at: Utc::now(),      // Mocked
                 updated_at: Utc::now(),      // Mocked
            }))),
            ..Default::default()
        };

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "newuser");
        mock_io.expect_output("Please register a new user.");
    } // End test_handle_registration_action_success


    // Moved test test_handle_registration_action_failure_username_taken out of previous test
    #[tokio::test]
    async fn test_handle_registration_action_failure_username_taken() {
        let mut mock_io = MockIoHandler::new(vec!["existinguser", "goodpassword"]);
        let mock_http = MockHttpClient {
             // Use MockCliError here
            register_result: Some(Arc::new(Err(MockCliError::RegistrationFailed("Username already taken".to_string())))),
            ..Default::default()

        };

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        // Check for the converted CliError type
        match result.err().unwrap() {
            CliError::RegistrationFailed(msg) => assert_eq!(msg, "Username already taken"),
            e => panic!("Expected RegistrationFailed error, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    }

    // Moved test test_handle_registration_action_failure_short_username out of previous test
    #[tokio::test]
    async fn test_handle_registration_action_failure_short_username() {
        let mut mock_io = MockIoHandler::new(vec!["us", "goodpassword"]);
        let mock_http = MockHttpClient::default(); // HTTP client won't be called

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("Username must be at least 3 characters long")),
            e => panic!("Expected InputError for short username, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    }

    // Moved test test_handle_registration_action_failure_short_password out of previous test
    #[tokio::test]
    async fn test_handle_registration_action_failure_short_password() {
        let mut mock_io = MockIoHandler::new(vec!["newuser", "pass"]);
        let mock_http = MockHttpClient::default(); // HTTP client won't be called

        let result = handle_registration_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("Password must be at least 8 characters long")),
            e => panic!("Expected InputError for short password, got {:?}", e),
        }
        mock_io.expect_output("Please register a new user.");
    } // End test_handle_registration_action_failure_short_password


    #[tokio::test]
    async fn test_handle_health_check_action_success() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            health_check_result: Some(Arc::new(Ok(HealthStatus { status: "OK".to_string() }))),
            ..Default::default()
         };

        let result = handle_health_check_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Checking backend health...");
        mock_io.expect_output("Backend status: OK");
    }

    #[tokio::test]
    async fn test_handle_health_check_action_failure() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
             // Use MockCliError here
            health_check_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Database connection failed".to_string(),
             )))),
             ..Default::default()
        };

        let result = handle_health_check_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        // Check for the converted CliError type
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => {
                // Status code might be defaulted in the From impl, check message
                assert_eq!(message, "Database connection failed");
            }
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Checking backend health...");
        mock_io.expect_no_output_containing("Backend status:");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_success() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "dummy png data").unwrap(); // Write some dummy data
        let file_path_str = temp_file.path().to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let expected_char_id = Uuid::new_v4();
        let mock_http = MockHttpClient {
            upload_character_result: Some(Arc::new(Ok(CharacterMetadata {
                id: expected_char_id,
                user_id: Uuid::new_v4(), // Mock user ID
                name: "Test Char".to_string(),
                description: Some("Uploaded char".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                // Removed non-existent fields
            }))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        let character = result.unwrap();
        assert_eq!(character.id, expected_char_id);
        assert_eq!(character.name, "Test Char");
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Uploading...");
        // Success message is printed by the main loop
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_empty_name() {
        let mut mock_io = MockIoHandler::new(vec!["", "dummy_path.png"]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("Character name cannot be empty")),
            e => panic!("Expected InputError for empty name, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_empty_path() {
        let mut mock_io = MockIoHandler::new(vec!["Test Char", ""]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("File path cannot be empty")),
            e => panic!("Expected InputError for empty path, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_file_not_found() {
        let non_existent_path = "./non_existent_file_for_test.png";
        // Ensure the file doesn't exist
        let _ = fs::remove_file(non_existent_path);

        let mut mock_io = MockIoHandler::new(vec!["Test Char", non_existent_path]);
        let mock_http = MockHttpClient::default(); // Won't be called

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("File not found at path")),
            e => panic!("Expected InputError for file not found, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
    }


    #[tokio::test]
    async fn test_handle_upload_character_action_not_png_warning() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "dummy data").unwrap();
        let file_path_str = temp_file.path().to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let mock_http = MockHttpClient {
            // Assume upload succeeds despite non-png (backend might handle it)
            upload_character_result: Some(Arc::new(Ok(CharacterMetadata {
                id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                name: "Test Char".to_string(),
                description: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                // Removed non-existent fields
            }))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Warning: File does not end with .png");
        mock_io.expect_output("Uploading...");
    }

    #[tokio::test]
    async fn test_handle_upload_character_action_api_error() {
        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), "dummy png data").unwrap();
        let file_path_str = temp_file.path().to_str().unwrap().to_string();

        let mut mock_io = MockIoHandler::new(vec!["Test Char", &file_path_str]);
        let mock_http = MockHttpClient {
             // Use MockCliError here
            upload_character_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Invalid character card format".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_upload_character_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        // Check for the converted CliError type
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => {
                // Status code might be defaulted in the From impl, check message
                 assert_eq!(message, "Invalid character card format");
            }
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Upload a new character.");
        mock_io.expect_output("Uploading...");
    }


    // --- Tests for handle_view_character_details_action ---

    fn create_mock_character_metadata(id: Uuid, name: &str, description: Option<&str>) -> CharacterMetadata {
        CharacterMetadata {
            id,
            user_id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.map(String::from),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            // Removed non-existent fields
        }
    }

    #[tokio::test]
    async fn test_handle_view_character_details_success() {
        let char1_id = Uuid::new_v4();
        let char2_id = Uuid::new_v4();
        let characters = vec![
            create_mock_character_metadata(char1_id, "Char One", Some("Desc 1")),
            create_mock_character_metadata(char2_id, "Char Two", None),
        ];
        let selected_char_details = create_mock_character_metadata(char1_id, "Char One", Some("Desc 1"));

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first character
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(characters))),
            get_character_result: Some(Arc::new(Ok(selected_char_details))),
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your characters...");
        mock_io.expect_output("[1] Char One");
        mock_io.expect_output("[2] Char Two");
        mock_io.expect_output("Select character by number:");
        mock_io.expect_output("Selected: Char One");
        mock_io.expect_output("Fetching character details...");
        mock_io.expect_output(&format!("--- Character Details (ID: {}) ---", char1_id));
        mock_io.expect_output("Name: Char One");
        mock_io.expect_output("Description: Desc 1");
    }

    #[tokio::test]
    async fn test_handle_view_character_details_no_characters() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed as it fails early
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("No characters found")),
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your characters...");
    }


    #[tokio::test]
    async fn test_handle_view_character_details_list_api_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            // Use MockCliError
            list_characters_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Access denied".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => assert_eq!(message, "Access denied"),
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your characters...");
    }

    #[tokio::test]
    async fn test_handle_view_character_details_get_api_error() {
        let char1_id = Uuid::new_v4();
        let characters = vec![create_mock_character_metadata(char1_id, "Char One", None)];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first character
        let mock_http = MockHttpClient {
            list_characters_result: Some(Arc::new(Ok(characters))),
            // Use MockCliError
            get_character_result: Some(Arc::new(Err(MockCliError::NotFound))), // Simulate get error
            ..Default::default()
        };

        let result = handle_view_character_details_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::NotFound => { /* Expected */ }
            e => panic!("Expected NotFound error, got {:?}", e),
        }
        mock_io.expect_output("Fetching character details...");
    }


    // --- Tests for handle_list_chat_sessions_action ---

    fn create_mock_chat_session(id: Uuid, character_id: Uuid) -> ChatSession {
        ChatSession {
            id,
            user_id: Uuid::new_v4(),
            character_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            // Removed non-existent fields: summary, title
        }
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_success() {
        let session1_id = Uuid::new_v4();
        let session2_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let char2_id = Uuid::new_v4();
        let sessions = vec![
            create_mock_chat_session(session1_id, char1_id),
            create_mock_chat_session(session2_id, char2_id),
        ];

        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your chat sessions...");
        mock_io.expect_output("Your chat sessions:");
        mock_io.expect_output(&format!("Session ID: {}", session1_id));
        mock_io.expect_output(&format!("Character ID: {}", char1_id));
        mock_io.expect_output(&format!("Session ID: {}", session2_id));
        mock_io.expect_output(&format!("Character ID: {}", char2_id));
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_empty() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Fetching your chat sessions...");
        mock_io.expect_output("You have no active chat sessions.");
        mock_io.expect_no_output_containing("Your chat sessions:");
    }

    #[tokio::test]
    async fn test_handle_list_chat_sessions_api_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            // Use MockCliError
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::ApiError(
                "Not logged in".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_list_chat_sessions_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status: _, message } => assert_eq!(message, "Not logged in"),
            e => panic!("Expected ApiError, got {:?}", e),
        }
        mock_io.expect_output("Fetching your chat sessions...");
    }


    // --- Tests for handle_view_chat_history_action ---

    fn create_mock_chat_message(id: Uuid, session_id: Uuid, role: MessageRole, content: &str) -> ChatMessage {
        ChatMessage {
            id,
            session_id,
            message_type: role,
            content: content.to_string(),
            created_at: Utc::now(),
            // Removed non-existent fields: metadata, token_count
        }
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_success() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];
        let messages = vec![
            create_mock_chat_message(Uuid::new_v4(), session1_id, MessageRole::User, "Hello"),
            create_mock_chat_message(Uuid::new_v4(), session1_id, MessageRole::Assistant, "Hi there!"),
        ];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first session
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(messages))),
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Select a chat session to view its history.");
        mock_io.expect_output("Available chat sessions:");
        mock_io.expect_output(&format!("[{}] Session ID: {}", 1, session1_id));
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching messages for session {}...", session1_id));
        mock_io.expect_output(&format!("--- Chat History (Session: {}) ---", session1_id));
        mock_io.expect_output("You: Hello");
        mock_io.expect_output("AI: Hi there!");
        mock_io.expect_output("------------------------------------");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_no_sessions() {
        let mut mock_io = MockIoHandler::new(vec![]); // No input needed
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // Empty list
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("No chat sessions found")),
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to view its history.");
    }

     #[tokio::test]
    async fn test_handle_view_chat_history_list_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            // Use MockCliError
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::Internal("DB error".to_string())))),
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::Internal(msg) => assert_eq!(msg, "DB error"),
            e => panic!("Expected Internal error, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to view its history.");
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_get_messages_error() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];

        let mut mock_io = MockIoHandler::new(vec!["1"]); // User selects the first session
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            // Use MockCliError
            get_chat_messages_result: Some(Arc::new(Err(MockCliError::NotFound))), // Simulate error fetching messages
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::NotFound => { /* Expected */ }
            e => panic!("Expected NotFound error, got {:?}", e),
        }
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching messages for session {}...", session1_id));
    }

    #[tokio::test]
    async fn test_handle_view_chat_history_invalid_selection() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];

        // Provide invalid input first, then valid
        let mut mock_io = MockIoHandler::new(vec!["abc", "0", "2", "1"]); 
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(vec![]))), // Empty messages for simplicity
            ..Default::default()
        };

        let result = handle_view_chat_history_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok()); // Should eventually succeed after valid input
        mock_io.expect_output("Invalid selection. Please enter a number between 1 and 1."); // Expect 3 error messages
        mock_io.expect_output("--- Chat History (Session:"); // Check final output part
    }


    // --- Tests for handle_resume_chat_session_action ---

    #[tokio::test]
    async fn test_handle_resume_chat_session_success() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];
        let messages = vec![
            create_mock_chat_message(Uuid::new_v4(), session1_id, MessageRole::User, "Previous message"),
        ];
        let ai_response = create_mock_chat_message(Uuid::new_v4(), session1_id, MessageRole::Assistant, "AI response");

        // Input: Select session 1, type 'hello', then 'quit'
        let mut mock_io = MockIoHandler::new(vec!["1", "hello", "quit"]); 
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(messages))),
            generate_response_result: Some(Arc::new(Ok(ai_response))), // Mock the generate response
            ..Default::default()
        };

        let result = handle_resume_chat_session_action(&mock_http, &mut mock_io).await;

        assert!(result.is_ok());
        mock_io.expect_output("Select a chat session to resume.");
        mock_io.expect_output("Available chat sessions:");
        mock_io.expect_output(&format!("[{}] Session ID: {}", 1, session1_id));
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching recent messages for session {}...", session1_id));
        mock_io.expect_output(&format!("--- Recent History (Session: {}) ---", session1_id));
        mock_io.expect_output("You: Previous message");
        mock_io.expect_output("Entering chat session");
        // Check for the prompt, not the combined input
        mock_io.expect_output("You:"); // Check user input was read via prompt
        mock_io.expect_output("AI: AI response"); // Check AI response was written
        mock_io.expect_output("You:"); // Check quit prompt was shown
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_no_sessions() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(vec![]))), // No sessions
            ..Default::default()
        };

        let result = handle_resume_chat_session_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::InputError(msg) => assert!(msg.contains("No chat sessions found to resume")),
            e => panic!("Expected InputError, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to resume.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_list_error() {
        let mut mock_io = MockIoHandler::new(vec![]);
        let mock_http = MockHttpClient {
            // Use MockCliError
            list_chat_sessions_result: Some(Arc::new(Err(MockCliError::Internal("List error".to_string())))),
            ..Default::default()
        };

        let result = handle_resume_chat_session_action(&mock_http, &mut mock_io).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::Internal(msg) => assert_eq!(msg, "List error"),
            e => panic!("Expected Internal error, got {:?}", e),
        }
        mock_io.expect_output("Select a chat session to resume.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_get_messages_error_warning() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];

        // Input: Select session 1, then 'quit' immediately in the chat loop
        let mut mock_io = MockIoHandler::new(vec!["1", "quit"]); 
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
             // Use MockCliError
            get_chat_messages_result: Some(Arc::new(Err(MockCliError::NotFound))), // Error fetching history
            // generate_response won't be called because user quits immediately
            ..Default::default()
        };

        let result = handle_resume_chat_session_action(&mock_http, &mut mock_io).await;

        // The action should still succeed overall, but log a warning
        assert!(result.is_ok()); 
        mock_io.expect_output("Select session by number:");
        mock_io.expect_output(&format!("Fetching recent messages for session {}...", session1_id));
        mock_io.expect_output("Warning: Could not fetch recent chat history"); // Check for warning
        mock_io.expect_output("Entering chat session");
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }

    #[tokio::test]
    async fn test_handle_resume_chat_session_generate_error() {
        let session1_id = Uuid::new_v4();
        let char1_id = Uuid::new_v4();
        let sessions = vec![create_mock_chat_session(session1_id, char1_id)];

        // Input: Select session 1, type 'hello', then 'quit'
        let mut mock_io = MockIoHandler::new(vec!["1", "hello", "quit"]); 
        let mock_http = MockHttpClient {
            list_chat_sessions_result: Some(Arc::new(Ok(sessions))),
            get_chat_messages_result: Some(Arc::new(Ok(vec![]))), // No history
             // Use MockCliError
            generate_response_result: Some(Arc::new(Err(MockCliError::ApiError( // Error during generation
                "LLM unavailable".to_string(),
            )))),
            ..Default::default()
        };

        let result = handle_resume_chat_session_action(&mock_http, &mut mock_io).await;

        // The action itself completes, but the chat loop logs an error
        assert!(result.is_ok()); 
        mock_io.expect_output("Entering chat session");
        // Check for the prompt, not the combined input
        mock_io.expect_output("You:"); // Check user input prompt
        mock_io.expect_output("Error: Could not get response from AI. Please try again."); // Check error message
        mock_io.expect_output("LLM unavailable"); // Check specific error is included
        mock_io.expect_output("You:"); // Check quit prompt
        mock_io.expect_output("Leaving chat session.");
        mock_io.expect_output("Chat finished.");
    }

} 