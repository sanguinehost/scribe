use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use bigdecimal::BigDecimal;
use scribe_backend::models::chats::UpdateChatSettingsRequest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSettings {
    pub model_name: String,
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    pub system_prompt: Option<String>,
    pub temperature: Option<String>, // Store as string to handle BigDecimal
    pub max_output_tokens: Option<i32>,
    pub stop_sequences: Option<Vec<String>>,
}

impl Default for DefaultSettings {
    fn default() -> Self {
        Self {
            model_name: "gemini-2.5-flash".to_string(),
            gemini_thinking_budget: Some(1024),
            gemini_enable_code_execution: Some(false),
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            stop_sequences: None,
        }
    }
}

impl DefaultSettings {
    pub fn to_update_request(&self) -> UpdateChatSettingsRequest {
        UpdateChatSettingsRequest {
            gemini_thinking_budget: self.gemini_thinking_budget,
            gemini_enable_code_execution: self.gemini_enable_code_execution,
            system_prompt: self.system_prompt.clone(),
            temperature: self.temperature.as_ref().map(|s| {
                BigDecimal::parse_bytes(s.as_bytes(), 10).unwrap_or_else(|| BigDecimal::from(0))
            }), // Convert string to BigDecimal
            max_output_tokens: self.max_output_tokens,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            seed: None,
            stop_sequences: self
                .stop_sequences
                .as_ref()
                .map(|sequences| sequences.iter().map(|s| Some(s.clone())).collect()),
            history_management_strategy: None,
            history_management_limit: None,
            model_name: Some(self.model_name.clone()),
        }
    }
}

/// Gets the default settings file path
fn get_settings_path() -> PathBuf {
    let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let config_dir = home_dir.join(".config").join("scribe-cli");

    // Create the directory if it doesn't exist
    if !config_dir.exists() {
        if let Err(e) = fs::create_dir_all(&config_dir) {
            tracing::warn!(target: "scribe_cli::default_settings", error = ?e, "Failed to create config directory");
        }
    }

    config_dir.join("default_settings.json")
}

/// Loads default settings from the filesystem
pub fn load_default_settings() -> DefaultSettings {
    let settings_path = get_settings_path();

    if !settings_path.exists() {
        let default_settings = DefaultSettings::default();
        // Try to save the default settings
        if let Err(e) = save_default_settings(&default_settings) {
            tracing::warn!(target: "scribe_cli::default_settings", error = ?e, "Failed to save default settings");
        }
        return default_settings;
    }

    match fs::read_to_string(&settings_path) {
        Ok(contents) => match serde_json::from_str::<DefaultSettings>(&contents) {
            Ok(settings) => settings,
            Err(e) => {
                tracing::error!(target: "scribe_cli::default_settings", error = ?e, "Failed to parse default settings");
                DefaultSettings::default()
            }
        },
        Err(e) => {
            tracing::error!(target: "scribe_cli::default_settings", error = ?e, "Failed to read default settings file");
            DefaultSettings::default()
        }
    }
}

/// Saves default settings to the filesystem
pub fn save_default_settings(settings: &DefaultSettings) -> Result<(), CliError> {
    let settings_path = get_settings_path();

    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| CliError::Internal(format!("Failed to serialize settings: {e}")))?;

    fs::write(&settings_path, json).map_err(CliError::Io)
}

/// Handler for configuring default chat settings
pub async fn handle_default_settings_action<H: IoHandler, C: HttpClient>(
    _client: &C,
    io_handler: &mut H,
    current_model: &str,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Configure Default Chat Settings ---")?;

    // Load current default settings
    let mut settings = load_default_settings();

    // Use the current model if it's different from the stored default
    if settings.model_name != current_model {
        settings.model_name = current_model.to_string();
    }

    // Show current settings
    io_handler.write_line("Current default settings:")?;
    io_handler.write_line(&format!("  Model: {}", settings.model_name))?;
    io_handler.write_line(&format!(
        "  Thinking Budget: {}",
        settings.gemini_thinking_budget.unwrap_or(0)
    ))?;
    io_handler.write_line(&format!(
        "  Enable Code Execution: {}",
        settings.gemini_enable_code_execution.unwrap_or(false)
    ))?;
    io_handler.write_line(&format!(
        "  System Prompt: {}",
        settings.system_prompt.as_deref().unwrap_or("None")
    ))?;
    io_handler.write_line(&format!(
        "  Temperature: {}",
        settings.temperature.as_deref().unwrap_or("0.0")
    ))?;
    io_handler.write_line(&format!(
        "  Max Output Tokens: {}",
        settings.max_output_tokens.unwrap_or(0)
    ))?;
    io_handler.write_line(&format!(
        "  Stop Sequences: {}",
        settings
            .stop_sequences
            .as_ref()
            .map_or("None".to_string(), |v| format!("{v:?}"))
    ))?;

    // Let the user choose which setting to update
    io_handler.write_line("\nSelect setting to update (or 's' to save, 'c' to cancel):")?;
    io_handler.write_line("[1] Thinking Budget (suggested: 1024)")?;
    io_handler.write_line("[2] Enable Code Execution (suggested: false)")?;
    io_handler.write_line("[3] System Prompt")?;
    io_handler.write_line("[4] Temperature (0.0 to 1.0, suggested: 0.7)")?;
    io_handler.write_line("[5] Max Output Tokens (suggested: 1024)")?;
    io_handler.write_line("[6] Stop Sequences (comma-separated)")?;

    let choice = io_handler
        .read_line("Enter choice: ")?
        .trim()
        .to_lowercase();

    match choice.as_str() {
        "1" => {
            let input = io_handler.read_line("Enter thinking budget (0 to disable): ")?;
            if let Ok(budget) = input.trim().parse::<i32>() {
                settings.gemini_thinking_budget = if budget > 0 { Some(budget) } else { None };
                io_handler.write_line(&format!(
                    "Thinking budget updated to: {:?}",
                    settings.gemini_thinking_budget
                ))?;
            } else {
                io_handler.write_line("Invalid input. Thinking budget not updated.")?;
            }
        }
        "2" => {
            let input = io_handler
                .read_line("Enable code execution? (y/n): ")?
                .trim()
                .to_lowercase();
            let enable = input == "y" || input == "yes";
            settings.gemini_enable_code_execution = Some(enable);
            io_handler.write_line(&format!("Code execution set to: {enable}"))?;
        }
        "3" => {
            let input = io_handler.read_line("Enter system prompt (leave empty to clear): ")?;
            settings.system_prompt = if input.trim().is_empty() {
                None
            } else {
                Some(input.trim().to_string())
            };
            io_handler.write_line(&format!(
                "System prompt updated to: {:?}",
                settings.system_prompt
            ))?;
        }
        "4" => {
            let input = io_handler.read_line("Enter temperature (0.0 to 1.0): ")?;
            if let Ok(temp) = input.trim().parse::<f32>() {
                if (0.0..=1.0).contains(&temp) {
                    settings.temperature = Some(temp.to_string());
                    io_handler.write_line(&format!("Temperature updated to: {temp}"))?;
                } else {
                    io_handler
                        .write_line("Temperature must be between 0.0 and 1.0. Not updated.")?;
                }
            } else {
                io_handler.write_line("Invalid input. Temperature not updated.")?;
            }
        }
        "5" => {
            let input = io_handler.read_line("Enter max output tokens (0 for default): ")?;
            if let Ok(tokens) = input.trim().parse::<i32>() {
                settings.max_output_tokens = if tokens > 0 { Some(tokens) } else { None };
                io_handler.write_line(&format!(
                    "Max output tokens updated to: {:?}",
                    settings.max_output_tokens
                ))?;
            } else {
                io_handler.write_line("Invalid input. Max output tokens not updated.")?;
            }
        }
        "6" => {
            let input = io_handler
                .read_line("Enter stop sequences (comma-separated, leave empty to clear): ")?;
            let trimmed_input = input.trim();
            settings.stop_sequences = if trimmed_input.is_empty() {
                None
            } else {
                Some(
                    trimmed_input
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect(),
                )
            };
            io_handler.write_line(&format!(
                "Stop sequences updated to: {:?}",
                settings.stop_sequences
            ))?;
        }
        "s" => {
            match save_default_settings(&settings) {
                Ok(_) => io_handler.write_line("Default settings saved successfully.")?,
                Err(e) => {
                    io_handler.write_line(&format!("Failed to save default settings: {e}"))?
                }
            }
            return Ok(());
        }
        "c" => {
            io_handler.write_line("Operation cancelled. Settings not saved.")?;
            return Ok(());
        }
        _ => {
            io_handler.write_line("Invalid choice. No settings were updated.")?;
        }
    }

    // Ask if the user wants to save the changes
    let save_choice = io_handler
        .read_line("Save these settings as default? (y/n): ")?
        .trim()
        .to_lowercase();
    if save_choice == "y" || save_choice == "yes" {
        match save_default_settings(&settings) {
            Ok(_) => io_handler.write_line("Default settings saved successfully.")?,
            Err(e) => io_handler.write_line(&format!("Failed to save default settings: {e}"))?,
        }
    } else {
        io_handler.write_line("Changes not saved.")?;
    }

    Ok(())
}

/// Apply default settings to a chat session
pub async fn apply_default_settings_to_session<C: HttpClient>(
    client: &C,
    session_id: uuid::Uuid,
) -> Result<(), CliError> {
    let settings = load_default_settings();
    let update_request = settings.to_update_request();

    tracing::info!(target: "scribe_cli::default_settings", %session_id, "Applying default settings to session");

    client
        .update_chat_settings(session_id, &update_request)
        .await?;

    Ok(())
}
