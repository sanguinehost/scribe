use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::chats::{ChatSettingsResponse, UpdateChatSettingsRequest};

/// Handler function for configuring chat session settings
pub async fn handle_chat_config_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    current_model: &str,
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
            session.character_id
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
        "[Encrypted Title]", // Title is now encrypted
        chat_id
    ))?;

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
    };

    // 4. Configure model
    let model_choice = io_handler.read_line(&format!(
        "Set model (current: {}, press Enter to keep current):",
        current_model
    ))?;
    if !model_choice.trim().is_empty() {
        settings_to_update.model_name = Some(model_choice.trim().to_string());
    } else {
        settings_to_update.model_name = None;
    }

    // 5. Configure thinking budget
    let budget_str = io_handler
        .read_line("Set thinking budget (optional, integer, e.g. 1024, press Enter to skip):")?;
    if !budget_str.trim().is_empty() {
        match budget_str.trim().parse::<i32>() {
            Ok(budget) => settings_to_update.gemini_thinking_budget = Some(budget),
            Err(_) => io_handler.write_line("Invalid budget, skipping.")?,
        }
    }

    // 6. Configure code execution
    let exec_str = io_handler
        .read_line("Enable code execution (optional, true/false, press Enter to skip):")?;
    if !exec_str.trim().is_empty() {
        match exec_str.trim().to_lowercase().as_str() {
            "true" => settings_to_update.gemini_enable_code_execution = Some(true),
            "false" => settings_to_update.gemini_enable_code_execution = Some(false),
            _ => io_handler.write_line("Invalid input, skipping code execution setting.")?,
        }
    }

    // 7. Configure system prompt
    let system_prompt =
        io_handler.read_line("Set system prompt (optional, press Enter to skip):")?;
    if !system_prompt.trim().is_empty() {
        settings_to_update.system_prompt = Some(system_prompt.trim().to_string());
    }

    // 8. Configure temperature
    let temp_str =
        io_handler.read_line("Set temperature (optional, float 0.0-2.0, press Enter to skip):")?;
    if !temp_str.trim().is_empty() {
        match temp_str.trim().parse::<f32>() {
            Ok(temp) if temp >= 0.0 && temp <= 2.0 => {
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
            io_handler.write_line(&format!("Error updating settings: {}", e))?;
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
        io_handler.write_line(&format!("Thinking Budget: {}", budget))?;
    }

    if let Some(exec) = settings.gemini_enable_code_execution {
        io_handler.write_line(&format!("Code Execution Enabled: {}", exec))?;
    }

    if let Some(prompt) = &settings.system_prompt {
        io_handler.write_line(&format!("System Prompt: {}", prompt))?;
    }

    if let Some(ref temp) = settings.temperature {
        io_handler.write_line(&format!("Temperature: {:.2}", temp))?;
    }

    if let Some(max_tokens) = settings.max_output_tokens {
        io_handler.write_line(&format!("Max Output Tokens: {}", max_tokens))?;
    }

    io_handler.write_line("---")?;

    // Flush output to ensure everything is properly displayed
    io_handler.flush()?;

    // Add a small delay to ensure terminal has processed output
    std::thread::sleep(std::time::Duration::from_millis(10));

    Ok(())
}
