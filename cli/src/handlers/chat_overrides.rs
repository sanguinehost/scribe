use crate::ChatEditCharacterArgs; // Assuming ChatEditCharacterArgs is made public
use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use uuid::Uuid;

/// Handles the 'chat edit-character' command when arguments are provided as one-liners.
pub async fn handle_chat_edit_character_oneliner<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    args: ChatEditCharacterArgs,
) -> Result<(), CliError> {
    io_handler.write_line("Setting chat character override from command line arguments...")?;

    let session_id = args.session_id.ok_or_else(|| {
        CliError::InputError(
            "Missing --session-id argument for chat character override.".to_string(),
        )
    })?;
    let field_name = args.field.ok_or_else(|| {
        CliError::InputError("Missing --field argument for chat character override.".to_string())
    })?;
    let value = args.value.ok_or_else(|| {
        CliError::InputError("Missing --value argument for chat character override.".to_string())
    })?;

    // Validate field_name (basic validation, backend will do more)
    let allowed_fields = [
        "description",
        "personality",
        "first_mes",
        "system_prompt",
        "scenario",
    ]; // Add more as supported
    if !allowed_fields.contains(&field_name.as_str()) {
        io_handler.write_line(&format!(
            "Warning: Field '{}' may not be overridable. Allowed fields are currently: {:?}.",
            field_name, allowed_fields
        ))?;
    }

    match client
        .set_chat_character_override(session_id, field_name.clone(), value.clone())
        .await
    {
        Ok(response) => {
            io_handler.write_line(&format!(
                "Successfully applied override for field '{}' in chat session {}.",
                response.field_name, response.session_id
            ))?;
            io_handler.write_line(&format!("  New value: {}", response.new_value))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error setting chat character override: {}", e))?;
            return Err(e);
        }
    }
    Ok(())
}

/// Handles the interactive wizard for editing character overrides for a specific chat session.
pub async fn handle_chat_edit_character_wizard<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Edit Character Overrides for Chat Session (Wizard) ---")?;

    let session_id_str = io_handler.read_line("Enter Chat Session ID (UUID):")?;
    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| CliError::InputError(format!("Invalid UUID format: {}", session_id_str)))?;

    // Fetch chat session to get original_character_id
    io_handler.write_line("Fetching chat session details...")?;
    let chat_session = client.get_chat_session(session_id).await.map_err(|e| {
        io_handler
            .write_line(&format!(
                "Failed to fetch chat session {}: {}",
                session_id, e
            ))
            .ok();
        e
    })?;
    let original_character_id = chat_session.character_id;

    io_handler.write_line(&format!(
        "Fetching effective character data for session {} (Original Character ID: {})...",
        session_id, original_character_id
    ))?;

    let effective_char = client
        .get_effective_character_for_chat(original_character_id, session_id)
        .await
        .map_err(|e| {
            io_handler
                .write_line(&format!("Failed to fetch effective character data: {}", e))
                .ok();
            e
        })?;

    io_handler.write_line("\n--- Current Effective Character Details (with overrides) ---")?;
    // Use a helper similar to display_character_details from characters.rs if available and suitable
    // For now, display key fields:
    io_handler.write_line(&format!("  Name: {}", effective_char.name))?;
    io_handler.write_line(&format!(
        "  Description: {}",
        effective_char.description.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  Personality: {}",
        effective_char.personality.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  First Message: {}",
        effective_char.first_mes.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  System Prompt: {}",
        effective_char.system_prompt.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  Scenario: {}",
        effective_char.scenario.as_deref().unwrap_or("N/A")
    ))?;

    io_handler.write_line("\n--- Select Field to Override ---")?;
    // Define overridable fields based on plan (description, personality, first_mes initially)
    // Extend this list as more fields become overridable.
    let overridable_fields = vec![
        "description",
        "personality",
        "first_mes",
        "system_prompt",
        "scenario",
    ];
    for (idx, field) in overridable_fields.iter().enumerate() {
        io_handler.write_line(&format!("[{}] {}", idx + 1, field))?;
    }
    io_handler.write_line("[0] Cancel")?;

    let field_choice_str = io_handler.read_line("Enter field number to override:")?;
    let field_choice: usize = field_choice_str
        .parse()
        .map_err(|_| CliError::InputError("Invalid number.".to_string()))?;

    if field_choice == 0 {
        io_handler.write_line("Cancelled override.")?;
        return Ok(());
    }
    if field_choice > overridable_fields.len() {
        io_handler.write_line("Invalid selection.")?;
        return Err(CliError::InputError("Invalid field selection.".to_string()));
    }

    let field_to_override = overridable_fields[field_choice - 1].to_string();

    let current_value = match field_to_override.as_str() {
        "description" => effective_char
            .description
            .as_deref()
            .unwrap_or("")
            .to_string(),
        "personality" => effective_char
            .personality
            .as_deref()
            .unwrap_or("")
            .to_string(),
        "first_mes" => effective_char
            .first_mes
            .as_deref()
            .unwrap_or("")
            .to_string(),
        "system_prompt" => effective_char
            .system_prompt
            .as_deref()
            .unwrap_or("")
            .to_string(),
        "scenario" => effective_char.scenario.as_deref().unwrap_or("").to_string(),
        _ => "".to_string(), // Should not happen due to check above
    };

    io_handler.write_line(&format!(
        "Current value for '{}': {}",
        field_to_override,
        if current_value.is_empty() {
            "N/A"
        } else {
            &current_value
        }
    ))?;
    let new_value = io_handler.read_line(&format!(
        "Enter new value for '{}' (leave blank to clear override, if supported by backend):",
        field_to_override
    ))?;

    if crate::handlers::characters::prompt_yes_no(
        io_handler,
        &format!(
            "\nApply override for '{}' to '{}'? (Y/n)",
            field_to_override, new_value
        ),
    )? {
        match client
            .set_chat_character_override(session_id, field_to_override.clone(), new_value.clone())
            .await
        {
            Ok(response) => {
                io_handler.write_line(&format!(
                    "Successfully applied override for field '{}' in chat session {}.",
                    response.field_name, response.session_id
                ))?;
                io_handler.write_line(&format!("  New value: {}", response.new_value))?;
            }
            Err(e) => {
                io_handler.write_line(&format!("Error setting chat character override: {}", e))?;
                return Err(e);
            }
        }
    } else {
        io_handler.write_line("Override cancelled.")?;
    }

    Ok(())
}
