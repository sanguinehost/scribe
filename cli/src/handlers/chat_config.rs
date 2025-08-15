use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::{ChatSettingsResponse, UpdateChatSettingsRequest};

// Placeholder for system defaults
const SYSTEM_DEFAULT_MODEL: &str = "gemini-2.5-flash";
// Define other system defaults if needed, e.g.,
// const SYSTEM_DEFAULT_TEMPERATURE: f32 = 1.0;

/// Handler function for configuring chat session settings
pub async fn handle_chat_config_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    // current_model: &str, // Removed parameter
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Configure Chat Session Settings ---")?;

    // 1. List available chat sessions for user to select
    io_handler.write_line("Fetching your chat sessions...")?;
    let sessions = match client.list_chat_sessions().await {
        Ok(sessions) => {
            if sessions.is_empty() {
                io_handler
                    .write_line("You have no chat sessions. Please create a chat session first.")?;
                return Ok(());
            }
            sessions
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to list chat sessions");
            return Err(e);
        }
    };

    // 2. Let user select a session to configure
    io_handler.write_line("Available chat sessions:")?;
    for (i, session) in sessions.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] {} (ID: {}, Character: {})",
            i + 1,
            session.title.as_deref().unwrap_or("Untitled"), // Now decrypted
            session.id,
            session.character_id.map_or("None".to_string(), |id| id.to_string())
        ))?;
    }

    let session_choice =
        io_handler.read_line("Select a chat session to configure (enter number):")?;
    let session_index = match session_choice.trim().parse::<usize>() {
        Ok(idx) if idx >= 1 && idx <= sessions.len() => idx - 1,
        _ => {
            io_handler.write_line("Invalid selection. Please try again.")?;
            return Ok(());
        }
    };

    let selected_session = &sessions[session_index];
    let chat_id = selected_session.id;
    io_handler.write_line(&format!(
        "Configuring chat session: {} (ID: {})",
        selected_session.title.as_deref().unwrap_or("Untitled"), // Use decrypted title
        chat_id
    ))?;

    // Fetch current settings for the session and user defaults
    io_handler.write_line("Fetching current settings...")?;
    let session_settings = client.get_chat_settings(chat_id).await?;
    let user_default_settings = client.get_user_chat_settings().await?;

    // Helper to determine current value and source for prompts
    // Note: T must implement ToString. For Option<BigDecimal>, manual formatting is needed.
    fn get_current_value_display<'a, T: Clone + ToString>(
        session_value: Option<&'a T>,
        user_default_value: Option<&'a T>,
        system_default_value: Option<&'a T>, // Can be Option<&String> for string defaults
        default_text_if_all_none: &'a str,
    ) -> (String, String) {
        if let Some(val) = session_value {
            (val.to_string(), "[session]".to_string())
        } else if let Some(val) = user_default_value {
            (val.to_string(), "[user default]".to_string())
        } else if let Some(val) = system_default_value {
            (val.to_string(), "[system default]".to_string())
        } else {
            (
                default_text_if_all_none.to_string(),
                "[system default]".to_string(),
            )
        }
    }

    // 3. Create a settings object with defaults for non-changed settings
    let mut settings_to_update = UpdateChatSettingsRequest {
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        chronicle_id: None, // Not relevant for CLI
        agent_mode: None, // Not used in CLI
    };

    // 4. Configure model
    let (current_model_display, model_source) = get_current_value_display(
        Some(&session_settings.model_name), // model_name is not Option in ChatSettingsResponse
        user_default_settings
            .as_ref()
            .and_then(|uds| uds.default_model_name.as_ref()),
        Some(&SYSTEM_DEFAULT_MODEL.to_string()),
        SYSTEM_DEFAULT_MODEL,
    );
    let model_choice_prompt = format!(
        "Set model (current: {} {}, press Enter to keep current):",
        current_model_display, model_source
    );
    let model_choice_input = io_handler.read_line(&model_choice_prompt)?;
    if !model_choice_input.trim().is_empty() {
        settings_to_update.model_name = Some(model_choice_input.trim().to_string());
    }

    // 5. Configure thinking budget
    let (current_budget_display, budget_source) = get_current_value_display(
        session_settings.gemini_thinking_budget.as_ref(),
        user_default_settings
            .as_ref()
            .and_then(|uds| uds.default_gemini_thinking_budget.as_ref()),
        None::<&i32>,
        "Not set",
    );
    let budget_prompt = format!(
        "Set thinking budget (optional, integer, e.g. 1024, current: {} {}, press Enter to skip):",
        current_budget_display, budget_source
    );
    let budget_str_input = io_handler.read_line(&budget_prompt)?;
    if !budget_str_input.trim().is_empty() {
        match budget_str_input.trim().parse::<i32>() {
            Ok(budget) => settings_to_update.gemini_thinking_budget = Some(budget),
            Err(_) => io_handler.write_line("Invalid budget, skipping.")?,
        }
    }

    // 6. Configure code execution
    let (current_exec_display, exec_source) = get_current_value_display(
        session_settings.gemini_enable_code_execution.as_ref(),
        user_default_settings
            .as_ref()
            .and_then(|uds| uds.default_gemini_enable_code_execution.as_ref()),
        None::<&bool>,
        "Not set",
    );
    let exec_prompt = format!(
        "Enable code execution (optional, true/false, current: {} {}, press Enter to skip):",
        current_exec_display, exec_source
    );
    let exec_str_input = io_handler.read_line(&exec_prompt)?;
    if !exec_str_input.trim().is_empty() {
        match exec_str_input.trim().to_lowercase().as_str() {
            "true" => settings_to_update.gemini_enable_code_execution = Some(true),
            "false" => settings_to_update.gemini_enable_code_execution = Some(false),
            _ => io_handler.write_line("Invalid input, skipping code execution setting.")?,
        }
    }

    // 7. Configure system prompt
    // UserSettingsResponse does not have default_system_prompt.
    // So, we only consider session_settings or "Not set".
    let (current_prompt_display, prompt_source) = get_current_value_display(
        session_settings.system_prompt.as_ref(),
        None::<&String>, // No user default for system prompt
        None::<&String>,
        "Not set",
    );
    let system_prompt_prompt = format!(
        "Set system prompt (optional, current: \"{}\" {}, press Enter to skip):",
        current_prompt_display, prompt_source
    );
    let system_prompt_input = io_handler.read_line(&system_prompt_prompt)?;
    if !system_prompt_input.trim().is_empty() {
        settings_to_update.system_prompt = Some(system_prompt_input.trim().to_string());
    }

    // 8. Configure temperature
    let (current_temp_display, temp_source) =
        if let Some(val) = session_settings.temperature.as_ref() {
            (format!("{:.2}", val), "[session]".to_string())
        } else if let Some(val) = user_default_settings
            .as_ref()
            .and_then(|uds| uds.default_temperature.as_ref())
        {
            (format!("{:.2}", val), "[user default]".to_string())
        } else {
            // Assuming a system default temperature if desired, e.g., 1.0
            // For now, "Not set" if neither session nor user default exists.
            ("Not set".to_string(), "[system default]".to_string())
        };

    let temp_prompt = format!(
        "Set temperature (optional, float 0.0-2.0, current: {} {}, press Enter to skip):",
        current_temp_display, temp_source
    );
    let temp_str_input = io_handler.read_line(&temp_prompt)?;
    if !temp_str_input.trim().is_empty() {
        match temp_str_input.trim().parse::<f32>() {
            Ok(temp) if (0.0..=2.0).contains(&temp) => {
                // Convert f32 to BigDecimal for the API
                use bigdecimal::BigDecimal;
                use std::str::FromStr;
                let temp_str = temp.to_string();
                if let Ok(bd_temp) = BigDecimal::from_str(&temp_str) {
                    settings_to_update.temperature = Some(bd_temp);
                } else {
                    io_handler.write_line("Error converting temperature, skipping.")?;
                }
            }
            _ => io_handler.write_line("Invalid temperature, skipping.")?,
        }
    }

    // 9. Apply settings
    io_handler.write_line("Updating chat session settings...")?;
    match client
        .update_chat_settings(chat_id, &settings_to_update)
        .await
    {
        Ok(response) => {
            io_handler.write_line("Chat session settings updated successfully!")?;
            display_settings(io_handler, &response)?;
        }
        Err(e) => {
            tracing::error!(error = ?e, %chat_id, "Failed to update chat settings");
            io_handler.write_line(&format!("Error updating settings: {e}"))?;
        }
    }

    io_handler.write_line("\n[Chat config completed successfully]")?;

    Ok(())
}

/// Helper function to display current chat settings
fn display_settings<H: IoHandler>(
    io_handler: &mut H,
    settings: &ChatSettingsResponse,
) -> Result<(), CliError> {
    // Validate that the settings don't contain binary data
    if !settings.model_name.is_ascii() {
        tracing::warn!("Model name contains non-ASCII characters");
    }

    io_handler.write_line("\n--- Current Chat Settings ---")?;

    // Display model name
    io_handler.write_line(&format!("Model: {}", settings.model_name))?;

    if let Some(budget) = settings.gemini_thinking_budget {
        io_handler.write_line(&format!("Thinking Budget: {budget}"))?;
    }

    if let Some(exec) = settings.gemini_enable_code_execution {
        io_handler.write_line(&format!("Code Execution Enabled: {exec}"))?;
    }

    if let Some(prompt) = &settings.system_prompt {
        io_handler.write_line(&format!("System Prompt: {prompt}"))?;
    }

    if let Some(ref temp) = settings.temperature {
        io_handler.write_line(&format!("Temperature: {temp:.2}"))?;
    }

    if let Some(max_tokens) = settings.max_output_tokens {
        io_handler.write_line(&format!("Max Output Tokens: {max_tokens}"))?;
    }

    io_handler.write_line("---")?;

    // Flush output to ensure everything is properly displayed
    io_handler.flush()?;

    // Add a small delay to ensure terminal has processed output
    std::thread::sleep(std::time::Duration::from_millis(10));

    Ok(())
}
