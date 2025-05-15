use crate::client::{HttpClient, ClientCharacterDataForClient};
use crate::error::CliError;
use crate::io::IoHandler;
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
            "File not found at path: {}",
            file_path
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
            io_handler.write_line(&format!("  Description: {}", desc_str))?;
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