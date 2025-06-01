use crate::chat::run_interactive_streaming_chat_loop;
use crate::client::HttpClient;
use crate::error::CliError;
use crate::handlers::characters::select_character;
use crate::handlers::default_settings::apply_default_settings_to_session;
use crate::handlers::user_personas::get_user_personas;
use crate::io::IoHandler;
use scribe_backend::models::chats::UpdateChatSettingsRequest;
use tracing;
use uuid::Uuid;

/// Helper function to allow the user to select a persona for the chat.
async fn select_persona_for_chat<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<Option<Uuid>, CliError> {
    match get_user_personas(client).await {
        Ok(personas) => {
            if personas.is_empty() {
                io_handler.write_line(
                    "No custom personas found. Starting chat without a specific persona.",
                )?;
                return Ok(None);
            }

            io_handler.write_line("\nAvailable custom personas:")?;
            for (index, persona) in personas.iter().enumerate() {
                io_handler.write_line(&format!(
                    "  [{}] {} (ID: {})",
                    index + 1,
                    persona.name,
                    persona.id
                ))?;
            }
            io_handler.write_line("  [N] Continue without a custom persona")?;

            loop {
                let choice_str =
                    io_handler.read_line("Select persona by number or N to continue without: ")?;
                if choice_str.trim().eq_ignore_ascii_case("n") {
                    return Ok(None);
                }
                match choice_str.trim().parse::<usize>() {
                    Ok(num) if num > 0 && num <= personas.len() => {
                        let selected_persona = &personas[num - 1];
                        io_handler
                            .write_line(&format!("Using persona: {}", selected_persona.name))?;
                        return Ok(Some(selected_persona.id));
                    }
                    _ => {
                        io_handler.write_line("Invalid selection, please try again.")?;
                    }
                }
            }
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Error fetching personas: {e}. Continuing without persona selection."
            ))?;
            Ok(None) // Proceed without persona if fetching fails
        }
    }
}

/// Helper function to allow the user to select lorebooks for the chat.
async fn select_lorebooks_for_chat<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<Option<Vec<Uuid>>, CliError> {
    match client.list_lorebooks().await {
        Ok(lorebooks) => {
            if lorebooks.is_empty() {
                io_handler.write_line("No lorebooks found. Starting chat without lorebooks.")?;
                return Ok(None);
            }

            io_handler.write_line("\nAvailable lorebooks:")?;
            for (index, lorebook) in lorebooks.iter().enumerate() {
                io_handler.write_line(&format!(
                    "  [{}] {} (ID: {})",
                    index + 1,
                    lorebook.name,
                    lorebook.id
                ))?;
            }
            io_handler.write_line("  [N] Continue without selecting lorebooks")?;
            io_handler
                .write_line("  Enter numbers separated by commas (e.g., 1,3) or N to skip.")?;

            loop {
                let choice_str = io_handler.read_line("Select lorebooks: ")?;
                if choice_str.trim().eq_ignore_ascii_case("n") {
                    return Ok(None);
                }

                let mut selected_ids = Vec::new();
                let choices: Vec<&str> = choice_str.trim().split(',').map(|s| s.trim()).collect();
                let mut all_valid = true;

                if choices.is_empty() && !choice_str.trim().is_empty() {
                    // Handle single invalid number not caught by split
                    all_valid = false;
                }

                for choice in choices {
                    if choice.is_empty() {
                        // Skip empty strings that might result from trailing commas
                        continue;
                    }
                    match choice.parse::<usize>() {
                        Ok(num) if num > 0 && num <= lorebooks.len() => {
                            selected_ids.push(lorebooks[num - 1].id);
                        }
                        _ => {
                            all_valid = false;
                            break;
                        }
                    }
                }

                if all_valid && !selected_ids.is_empty() {
                    io_handler.write_line(&format!("Selected lorebook IDs: {selected_ids:?}"))?;
                    return Ok(Some(selected_ids));
                } else if all_valid && choice_str.trim().is_empty() {
                    // User just pressed enter
                    io_handler.write_line("No lorebooks selected.")?;
                    return Ok(None);
                } else {
                    io_handler.write_line("Invalid selection. Please enter comma-separated numbers from the list, or N to skip.")?;
                }
            }
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Error fetching lorebooks: {e}. Continuing without lorebook selection."
            ))?;
            Ok(None) // Proceed without lorebooks if fetching fails
        }
    }
}

/// Handler function for starting a new chat session with improved UX
pub async fn handle_start_chat_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    current_model: &str,
) -> Result<(), CliError> {
    // 1. Select a character
    let character_id = select_character(client, io_handler).await?;
    tracing::info!(%character_id, "Character selected for chat");

    // 1b. Select a Persona
    let selected_persona_id = select_persona_for_chat(client, io_handler).await?;
    if let Some(persona_id) = selected_persona_id {
        tracing::info!(%character_id, %persona_id, "Persona selected for chat");
    } else {
        tracing::info!(%character_id, "No persona selected for chat");
    }

    // 1c. Select Lorebooks
    let selected_lorebook_ids = select_lorebooks_for_chat(client, io_handler).await?;
    if let Some(ref ids) = selected_lorebook_ids {
        tracing::info!(%character_id, lorebook_ids = ?ids, "Lorebooks selected for chat");
    } else {
        tracing::info!(%character_id, "No lorebooks selected for chat");
    }

    let mut first_mes_content: Option<String> = None;

    // Fetch character details to display information
    let _character_metadata = match client.get_character(character_id).await {
        Ok(metadata) => {
            io_handler.write_line(&format!("\n--- Character: {} ---", metadata.name))?;
            if let Some(first_mes_bytes) = metadata.first_mes.as_ref() {
                first_mes_content =
                    Some(String::from_utf8_lossy(first_mes_bytes.as_bytes()).to_string());
                // Do not print here, will be passed to chat loop
                // io_handler.write_line(&first_mes_content.as_ref().unwrap())?;
            } else {
                io_handler.write_line("[Character has no introductory message defined]")?;
            }
            io_handler.write_line("------------------------")?;
            metadata
        }
        Err(e) => {
            tracing::error!(error = ?e, %character_id, "Failed to fetch character details");
            io_handler.write_line(&format!(
                "Warning: Could not fetch character details: {e}. Proceeding with chat creation."
            ))?;
            return Err(e); // Return error as we need character details
        }
    };

    // 2. Create the chat session
    let chat_session = match client
        .create_chat_session(
            character_id,
            selected_persona_id,
            selected_lorebook_ids.clone(),
        )
        .await
    {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(error = ?e, %character_id, ?selected_lorebook_ids, "Failed to create chat session");
            io_handler.write_line(&format!("Error creating chat session: {e}"))?;
            return Err(e);
        }
    };

    let chat_id = chat_session.id;
    tracing::info!(%chat_id, "Chat session created");

    // 3. Configure chat session with default settings
    io_handler.write_line(&format!(
        "Starting streaming chat with model: {current_model}"
    ))?;

    // Apply default settings from configuration
    io_handler.write_line("Applying default chat settings...")?;
    match apply_default_settings_to_session(client, chat_id).await {
        Ok(_) => {
            io_handler.write_line(
                "Session ready with your default settings. You can now start chatting.",
            )?;
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Warning: Failed to apply default settings: {e}. Proceeding with system defaults."
            ))?;

            // Fallback to basic settings if default settings application fails
            let settings_to_update = UpdateChatSettingsRequest {
                gemini_thinking_budget: Some(1024), // Default thinking budget is 1024
                gemini_enable_code_execution: None, // Not currently relevant
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
                model_name: Some(current_model.to_string()),
            };

            match client
                .update_chat_settings(chat_id, &settings_to_update)
                .await
            {
                Ok(_) => {
                    io_handler.write_line(
                        "Session ready with basic settings. You can now start chatting.",
                    )?;
                }
                Err(e) => {
                    io_handler.write_line(&format!(
                        "Warning: Failed to update session settings: {e}. Proceeding with defaults."
                    ))?;
                }
            }
        }
    }

    // 4. Start streaming chat session
    if let Err(e) = run_interactive_streaming_chat_loop(
        client,
        chat_id,
        io_handler,
        current_model,
        first_mes_content,
    )
    .await
    {
        tracing::error!(error = ?e, "Streaming chat loop failed");
        io_handler.write_line(&format!("Chat encountered an error: {e}"))?;
    }

    io_handler.write_line("Chat session ended.")?;
    Ok(())
}
