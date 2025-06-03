use crate::client::types::{CharacterCreateDto, CharacterUpdateDto};
use crate::client::{ClientCharacterDataForClient, HttpClient};
use crate::error::CliError;
use crate::io::IoHandler;
use crate::{CharacterCreateArgs, CharacterEditArgs}; // Assuming CharacterEditArgs is made public
use std::path::Path;
use uuid::Uuid;

/// Handler function for uploading a new character
pub async fn handle_upload_character_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<ClientCharacterDataForClient, CliError> {
    io_handler.write_line("\nUpload a new character.")?;
    let name = io_handler.read_line("Character Name:")?;
    let file_path = io_handler.read_line("Path to Character Card (.png):")?;

    if name.trim().is_empty() {
        return Err(CliError::InputError(
            "Character name cannot be empty.".into(),
        ));
    }
    if file_path.trim().is_empty() {
        return Err(CliError::InputError("File path cannot be empty.".into()));
    }
    // Basic check, could be more robust
    if !file_path.to_lowercase().ends_with(".png") {
        io_handler
            .write_line("Warning: File does not end with .png. The backend might reject it.")?;
    }

    // Check if file exists before attempting upload
    if !Path::new(&file_path).exists() {
        return Err(CliError::InputError(format!(
            "File not found at path: {file_path}"
        )));
    }

    io_handler.write_line("Uploading...")?;
    client.upload_character(&name, &file_path).await
}

/// Handler function for viewing character details
pub async fn handle_view_character_details_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    let character_id = select_character(client, io_handler).await?;

    io_handler.write_line("\nFetching character details...")?;
    match client.get_character(character_id).await {
        Ok(character) => {
            io_handler.write_line(&format!("--- Character Details (ID: {}) ---", character.id))?;
            io_handler.write_line(&format!("  Name: {}", character.name))?;
            // CharacterDataForClient has description as Option<String>
            let desc_str = character.description.as_deref().unwrap_or("N/A");
            io_handler.write_line(&format!("  Description: {desc_str}"))?;
            io_handler.write_line("------------------------------------")?;
            Ok(())
        }
        Err(e) => Err(e), // Error logged by caller
    }
}

/// Helper function for selecting a character from the list
pub async fn select_character<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<Uuid, CliError> {
    io_handler.write_line("\nFetching your characters...")?;
    let characters = client.list_characters().await?;

    if characters.is_empty() {
        return Err(CliError::InputError(
            "No characters found. Please upload a character first.".to_string(),
        ));
    }

    io_handler.write_line("Available characters:")?;
    for (index, char) in characters.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] {} (ID: {})",
            index + 1,
            char.name,
            char.id
        ))?;
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
                io_handler.write_line(&format!(
                    "Invalid selection. Please enter a number between 1 and {}.",
                    characters.len()
                ))?;
            }
        }
    }
}

/// Handles the 'character create' command when arguments are provided as one-liners.
pub async fn handle_character_create_oneliner<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    args: CharacterCreateArgs,
) -> Result<(), CliError> {
    io_handler.write_line("Creating character from command line arguments...")?;

    // Validate required fields are present (clap should handle this, but good for robustness)
    let name = args.name.ok_or_else(|| {
        CliError::InputError("Missing --name argument for character creation.".to_string())
    })?;
    let description = args.description.ok_or_else(|| {
        CliError::InputError("Missing --description argument for character creation.".to_string())
    })?;
    let first_mes = args.first_mes.ok_or_else(|| {
        CliError::InputError("Missing --first-mes argument for character creation.".to_string())
    })?;

    let character_data = CharacterCreateDto {
        name: Some(name),
        description: Some(description),
        first_mes: Some(first_mes),
        personality: args.personality.unwrap_or_default(),
        scenario: args.scenario.unwrap_or_default(),
        mes_example: String::new(), // Not in one-liner args, default to empty
        creator_notes: args.creator_notes.unwrap_or_default(),
        system_prompt: args.system_prompt.unwrap_or_default(),
        post_history_instructions: String::new(), // Not in one-liner args
        tags: args.tags.unwrap_or_default(),
        creator: args.creator.unwrap_or_default(),
        character_version: args.character_version.unwrap_or_default(),
        alternate_greetings: args.alternate_greetings.unwrap_or_default(),
        // Initialize other fields to their defaults or None
        creator_notes_multilingual: None,
        nickname: None,
        source: None,
        group_only_greetings: vec![],
        creation_date: None,
        modification_date: None,
        extensions: None,
        // V2 fields - default them for now
        persona: String::new(),
        world_scenario: String::new(),
        avatar: "none".to_string(),
        chat: String::new(),
        greeting: String::new(), // first_mes is primary
        definition: String::new(),
        default_voice: String::new(),
        data_id: None,
        category: String::new(),
        definition_visibility: "private".to_string(),
        depth: None,
        example_dialogue: String::new(),
        favorite: None,
        first_message_visibility: "private".to_string(),
        height: None,
        last_activity: None,
        migrated_from: String::new(),
        model_prompt: String::new(),
        model_prompt_visibility: "private".to_string(),
        model_temperature: None,
        num_interactions: None,
        permanence: None,
        persona_visibility: "private".to_string(),
        revision: None,
        sharing_visibility: "private".to_string(),
        status: "private".to_string(),
        system_prompt_visibility: "private".to_string(),
        system_tags: vec![],
        token_budget: None,
        usage_hints: None,
        user_persona: String::new(),
        user_persona_visibility: "private".to_string(),
        visibility: "private".to_string(),
        weight: None,
        world_scenario_visibility: "private".to_string(),
    };

    match client.create_character(character_data).await {
        Ok(created_char) => {
            io_handler.write_line(&format!(
                "Character '{}' created successfully with ID: {}",
                created_char.name, created_char.id
            ))?;
            // Optionally show more details
            io_handler.write_line(&format!(
                "  Description: {}",
                created_char.description.as_deref().unwrap_or("N/A")
            ))?;
            io_handler.write_line(&format!(
                "  First Message: {}",
                created_char.first_mes.as_deref().unwrap_or("N/A")
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error creating character: {e}"))?;
            return Err(e);
        }
    }
    Ok(())
}

/// Handles the interactive wizard for creating a new character.
pub async fn handle_character_create_wizard<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Create New Character (Manual Wizard) ---")?;

    let name = prompt_mandatory_field(io_handler, "Character Name:")?;
    let description = prompt_mandatory_field(io_handler, "Description:")?;
    let first_mes = prompt_mandatory_field(io_handler, "First Message (Greeting):")?;

    let mut character_data = CharacterCreateDto {
        name: Some(name),
        description: Some(description),
        first_mes: Some(first_mes),
        ..Default::default() // Initialize other fields to default
    };

    // Optional fields
    character_data.personality =
        prompt_optional_field_string(io_handler, "Personality (optional):")?.unwrap_or_default();
    character_data.scenario =
        prompt_optional_field_string(io_handler, "Scenario (optional):")?.unwrap_or_default();
    character_data.system_prompt =
        prompt_optional_field_string(io_handler, "System Prompt (optional):")?.unwrap_or_default();
    character_data.creator_notes =
        prompt_optional_field_string(io_handler, "Creator Notes (optional):")?.unwrap_or_default();

    if prompt_yes_no(io_handler, "Add tags? (y/N)")? {
        let tags_str = io_handler.read_line("Tags (comma-separated):")?;
        character_data.tags = tags_str.split(',').map(|s| s.trim().to_string()).collect();
    }
    if prompt_yes_no(io_handler, "Add alternate greetings? (y/N)")? {
        let alt_greetings_str = io_handler.read_line("Alternate Greetings (comma-separated):")?;
        character_data.alternate_greetings = alt_greetings_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
    }

    // TODO: Add prompts for other CharacterCreateDto fields as desired

    io_handler.write_line("\n--- Review Character ---")?;
    io_handler.write_line(&format!("Name: {}", character_data.name.as_ref().unwrap()))?;
    io_handler.write_line(&format!(
        "Description: {}",
        character_data.description.as_ref().unwrap()
    ))?;
    io_handler.write_line(&format!(
        "First Message: {}",
        character_data.first_mes.as_ref().unwrap()
    ))?;
    if !character_data.personality.is_empty() {
        io_handler.write_line(&format!("Personality: {}", character_data.personality))?;
    }
    if !character_data.scenario.is_empty() {
        io_handler.write_line(&format!("Scenario: {}", character_data.scenario))?;
    }
    // ... review other fields ...

    if prompt_yes_no(io_handler, "\nSubmit this character? (Y/n)")? {
        match client.create_character(character_data).await {
            Ok(created_char) => {
                io_handler.write_line(&format!(
                    "Character '{}' created successfully with ID: {}",
                    created_char.name, created_char.id
                ))?;
            }
            Err(e) => {
                io_handler.write_line(&format!("Error creating character: {e}"))?;
                return Err(e);
            }
        }
    } else {
        io_handler.write_line("Character creation cancelled.")?;
    }

    Ok(())
}

// Helper to prompt for a mandatory text field
fn prompt_mandatory_field<H: IoHandler>(
    io_handler: &mut H,
    prompt: &str,
) -> Result<String, CliError> {
    loop {
        let value = io_handler.read_line(prompt)?;
        if value.trim().is_empty() {
            io_handler.write_line("This field cannot be empty. Please provide a value.")?;
        } else {
            return Ok(value);
        }
    }
}

// Helper to prompt for an optional text field
fn prompt_optional_field_string<H: IoHandler>(
    io_handler: &mut H,
    prompt: &str,
) -> Result<Option<String>, CliError> {
    let value = io_handler.read_line(prompt)?;
    if value.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

// Helper to prompt for a yes/no question, defaulting to 'yes' if input is empty or 'y'
pub(crate) fn prompt_yes_no<H: IoHandler>(
    io_handler: &mut H,
    prompt: &str,
) -> Result<bool, CliError> {
    let response = io_handler.read_line(prompt)?.trim().to_lowercase();
    Ok(response.is_empty() || response == "y" || response == "yes")
}
/// Handles the 'character edit' command when arguments are provided as one-liners.
pub async fn handle_character_edit_oneliner<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
    args: CharacterEditArgs,
) -> Result<(), CliError> {
    io_handler.write_line("Updating character from command line arguments...")?;

    let character_id = args.id.ok_or_else(|| {
        CliError::InputError("Missing --id argument for character editing.".to_string())
    })?;

    // Construct CharacterUpdateDto with only the fields provided
    let character_update_data = CharacterUpdateDto {
        name: args.name,
        description: args.description,
        first_mes: args.first_mes,
        personality: args.personality,
        scenario: args.scenario,
        system_prompt: args.system_prompt,
        // TODO: Add all other editable fields from CharacterUpdateDto based on args
        // For example:
        // tags: args.tags,
        // alternate_greetings: args.alternate_greetings,
        ..Default::default() // Initialize unspecified fields to None
    };

    // Ensure at least one field is being updated
    if character_update_data.name.is_none()
        && character_update_data.description.is_none()
        && character_update_data.first_mes.is_none()
        && character_update_data.personality.is_none()
        && character_update_data.scenario.is_none()
        && character_update_data.system_prompt.is_none()
    // TODO: Add checks for all other fields from CharacterUpdateDto
    {
        io_handler.write_line("No fields provided to update. Use --interactive or provide at least one field to change. Exiting.")?;
        return Ok(());
    }

    match client
        .update_character(character_id, character_update_data)
        .await
    {
        Ok(updated_char) => {
            io_handler.write_line(&format!(
                "Character '{}' (ID: {}) updated successfully.",
                updated_char.name, updated_char.id
            ))?;
            // Optionally show changed fields by comparing with a fresh get_character call or by echoing provided args
        }
        Err(e) => {
            io_handler.write_line(&format!("Error updating character: {e}"))?;
            return Err(e);
        }
    }
    Ok(())
}

/// Handles the interactive wizard for editing an existing character.
pub async fn handle_character_edit_wizard<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Edit Existing Character (Wizard) ---")?;

    let character_id_str = io_handler.read_line("Enter Character ID (UUID) to edit:")?;
    let character_id = Uuid::parse_str(&character_id_str)
        .map_err(|_| CliError::InputError(format!("Invalid UUID format: {character_id_str}")))?;

    io_handler.write_line("Fetching current character data...")?;
    let mut current_char = client.get_character(character_id).await.map_err(|e| {
        io_handler
            .write_line(&format!(
                "Failed to fetch character {character_id}: {e}"
            ))
            .ok();
        e
    })?;

    io_handler.write_line("\n--- Current Character Details ---")?;
    display_character_details(io_handler, &current_char)?;

    let mut update_dto = CharacterUpdateDto::default();
    let mut changed_fields_summary = Vec::new();

    // Macro to simplify optional field editing
    macro_rules! edit_optional_field {
        ($field_name:ident, $prompt_text:expr, $current_value_display:expr) => {
            if prompt_yes_no(io_handler, &format!("Edit {} ('{}')? (y/N)", $prompt_text, $current_value_display))? {
                let new_value = prompt_optional_field_string(io_handler, &format!("New {} (leave blank to keep current, type 'none' to clear):", $prompt_text))?;
                if let Some(val_str) = new_value {
                    if val_str.trim().to_lowercase() == "none" {
                        update_dto.$field_name = Some(String::new()); // Or however backend expects clearing, might need specific handling for Option<String> vs String
                        changed_fields_summary.push(format!("{}: '{}' -> (cleared)", $prompt_text, $current_value_display));
                        current_char.$field_name = Some(String::new()); // Update local copy
                    } else {
                        update_dto.$field_name = Some(val_str.clone());
                        changed_fields_summary.push(format!("{}: '{}' -> '{}'", $prompt_text, $current_value_display, val_str));
                        current_char.$field_name = Some(val_str); // Update local copy
                    }
                }
            }
        };
        // For Vec<String> fields
        ($field_name:ident, $prompt_text:expr, $current_value_display:expr, vec) => {
            if prompt_yes_no(io_handler, &format!("Edit {} ('{}')? (y/N)", $prompt_text, $current_value_display.join(", ")))? {
                let new_value_str = io_handler.read_line(&format!("New {} (comma-separated, leave blank to keep current, type 'none' to clear):", $prompt_text))?;
                if !new_value_str.trim().is_empty() {
                    if new_value_str.trim().to_lowercase() == "none" {
                        update_dto.$field_name = Some(vec![]);
                        changed_fields_summary.push(format!("{}: '{}' -> (cleared)", $prompt_text, $current_value_display.join(", ")));
                        current_char.$field_name = Some(vec![]);
                    } else {
                        let new_vec = new_value_str.split(',').map(|s| s.trim().to_string()).collect::<Vec<String>>();
                        update_dto.$field_name = Some(new_vec.clone());
                        changed_fields_summary.push(format!("{}: '{}' -> '{}'", $prompt_text, $current_value_display.join(", "), new_vec.join(", ")));
                        current_char.$field_name = Some(new_vec.into_iter().map(Some).collect()); // Assuming ClientCharacterDataForClient stores Option<Vec<Option<String>>>
                    }
                }
            }
        };
    }

    // For ClientCharacterDataForClient, name is String, not Option<String>.
    // We'll handle it slightly differently:
    if prompt_yes_no(
        io_handler,
        &format!("Edit Name ('{}')? (y/N)", current_char.name),
    )? {
        let new_name_val = prompt_mandatory_field(io_handler, "New Name:")?; // Name is mandatory if changed
        update_dto.name = Some(new_name_val.clone());
        changed_fields_summary.push(format!(
            "Name: '{}' -> '{}'",
            current_char.name, new_name_val
        ));
        current_char.name = new_name_val;
    }

    edit_optional_field!(
        description,
        "Description",
        current_char.description.as_deref().unwrap_or("N/A")
    );
    edit_optional_field!(
        personality,
        "Personality",
        current_char.personality.as_deref().unwrap_or("N/A")
    );
    edit_optional_field!(
        scenario,
        "Scenario",
        current_char.scenario.as_deref().unwrap_or("N/A")
    );
    edit_optional_field!(
        first_mes,
        "First Message",
        current_char.first_mes.as_deref().unwrap_or("N/A")
    );
    edit_optional_field!(
        system_prompt,
        "System Prompt",
        current_char.system_prompt.as_deref().unwrap_or("N/A")
    );
    edit_optional_field!(
        creator_notes,
        "Creator Notes",
        current_char.creator_notes.as_deref().unwrap_or("N/A")
    );

    // Example for Vec<String> field: tags
    let current_tags_display = current_char
        .tags
        .as_ref()
        .map(|v| {
            v.iter()
                .filter_map(|s| s.as_ref().map(|x| x.as_str()))
                .collect::<Vec<&str>>()
                .join(", ")
        })
        .unwrap_or_else(|| "N/A".to_string());
    if prompt_yes_no(
        io_handler,
        &format!("Edit Tags ('{current_tags_display}')? (y/N)"),
    )? {
        let new_tags_str = io_handler.read_line("New Tags (comma-separated, 'none' to clear):")?;
        if new_tags_str.trim().to_lowercase() == "none" {
            update_dto.tags = Some(vec![]);
            changed_fields_summary.push(format!("Tags: '{current_tags_display}' -> (cleared)"));
        } else if !new_tags_str.is_empty() {
            let new_tags_vec = new_tags_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>();
            update_dto.tags = Some(new_tags_vec.clone());
            changed_fields_summary.push(format!(
                "Tags: '{}' -> '{}'",
                current_tags_display,
                new_tags_vec.join(", ")
            ));
        }
    }
    // TODO: Add prompts for ALL other editable fields in CharacterUpdateDto

    if changed_fields_summary.is_empty() {
        io_handler.write_line("No changes made. Exiting character edit.")?;
        return Ok(());
    }

    io_handler.write_line("\n--- Review Changes ---")?;
    for change in changed_fields_summary {
        io_handler.write_line(&format!("  - {change}"))?;
    }

    if prompt_yes_no(io_handler, "\nSubmit these changes? (Y/n)")? {
        match client.update_character(character_id, update_dto).await {
            Ok(updated_char_response) => {
                io_handler.write_line(&format!(
                    "Character '{}' (ID: {}) updated successfully.",
                    updated_char_response.name, updated_char_response.id
                ))?;
            }
            Err(e) => {
                io_handler.write_line(&format!("Error updating character: {e}"))?;
                return Err(e);
            }
        }
    } else {
        io_handler.write_line("Character update cancelled.")?;
    }

    Ok(())
}

// Helper to display character details consistently
fn display_character_details<H: IoHandler>(
    io_handler: &mut H,
    character: &ClientCharacterDataForClient,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("  ID: {}", character.id))?;
    io_handler.write_line(&format!("  Name: {}", character.name))?; // Name is String
    io_handler.write_line(&format!(
        "  Description: {}",
        character.description.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  Personality: {}",
        character.personality.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  Scenario: {}",
        character.scenario.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  First Message: {}",
        character.first_mes.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  System Prompt: {}",
        character.system_prompt.as_deref().unwrap_or("N/A")
    ))?;
    io_handler.write_line(&format!(
        "  Creator Notes: {}",
        character.creator_notes.as_deref().unwrap_or("N/A")
    ))?;
    let tags_display = character
        .tags
        .as_ref()
        .map(|v| {
            v.iter()
                .filter_map(|s| s.as_ref().map(String::as_str))
                .collect::<Vec<&str>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "N/A".to_string());
    io_handler.write_line(&format!("  Tags: {tags_display}"))?;
    let alt_greetings_display = character
        .alternate_greetings
        .as_ref()
        .map(|v| {
            v.iter()
                .filter_map(|s| s.as_ref().map(String::as_str))
                .collect::<Vec<&str>>()
                .join("; ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "N/A".to_string());
    io_handler.write_line(&format!("  Alternate Greetings: {alt_greetings_display}"))?;
    // TODO: Display other relevant fields from ClientCharacterDataForClient
    Ok(())
}
