// cli/src/handlers/lorebooks.rs
// #![allow(unused_variables, dead_code)] // TODO: Remove this once implemented

use crate::client::types::lorebook_import::SillyTavernLorebookFile; // Added for parsing
use scribe_backend::models::lorebook_dtos::{
    AssociateLorebookToChatPayload,
    CreateLorebookEntryPayload,
    CreateLorebookPayload,
    UpdateLorebookEntryPayload,
    UpdateLorebookPayload, // Removed LorebookEntryResponse, LorebookResponse
};
use uuid::Uuid;

use crate::{
    MenuNavigation,
    MenuResult, // Import MenuNavigation and MenuResult
    client::interface::HttpClient,
    error::CliError,
    io::{self, IoHandler}, // Removed unused imports, added IoHandler
};

pub async fn handle_lorebook_management_menu<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
) -> MenuResult {
    // Changed return type to MenuResult
    loop {
        io_handler.write_line("\n--- Lorebook Management ---")?;
        io_handler.write_line("[1] List My Lorebooks")?;
        io_handler.write_line("[2] Create New Lorebook")?;
        io_handler.write_line("[3] Upload Lorebook (JSON)")?; // New option
        io_handler.write_line("[4] Manage Specific Lorebook")?; // Shifted option
        io_handler.write_line("[B] Back to Main Menu")?;

        match io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase()
            .as_str()
        {
            "1" => {
                if let Err(e) = list_my_lorebooks(client, io_handler).await {
                    io_handler.write_line(&format!("Error listing lorebooks: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) = create_new_lorebook(client, io_handler).await {
                    io_handler.write_line(&format!("Error creating lorebook: {}", e))?;
                }
            }
            "3" => {
                // New handler for upload
                if let Err(e) = upload_lorebook_json_handler(client, io_handler).await {
                    io_handler.write_line(&format!("Error uploading lorebook: {}", e))?;
                }
            }
            "4" => {
                // Shifted handler for manage specific
                if let Err(e) = manage_specific_lorebook_entrypoint(client, io_handler).await {
                    io_handler.write_line(&format!("Error managing specific lorebook: {}", e))?;
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
}

pub async fn list_my_lorebooks<C: HttpClient, H: IoHandler>(
    // Added pub
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nFetching your lorebooks...")?;
    match client.list_lorebooks().await {
        Ok(lorebooks) => {
            if lorebooks.is_empty() {
                io_handler.write_line("You have no lorebooks.")?;
            } else {
                io_handler.write_line("Your lorebooks:")?;
                for lorebook in lorebooks {
                    io_handler.write_line(&format!(
                        "  - {} (ID: {})", // Removed entry_count
                        lorebook.name, lorebook.id
                    ))?;
                    if let Some(description) = lorebook.description {
                        if !description.is_empty() {
                            io_handler.write_line(&format!("    Description: {}", description))?;
                        }
                    }
                }
            }
        }
        Err(e) => {
            io_handler.write_line(&format!("Error listing lorebooks: {}", e))?;
        }
    }
    Ok(())
}

pub async fn create_new_lorebook<C: HttpClient, H: IoHandler>(
    // Added pub
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nCreating a new lorebook...")?;

    let name = io::input_required(io_handler, "Enter lorebook name: ")?;
    let description = io::input_optional(io_handler, "Enter lorebook description (optional): ")?;

    let payload = CreateLorebookPayload {
        name,
        description,
        // Add other fields from CreateLorebookPayload if they exist and need prompting
        // For example:
        // entries: None, // Or prompt if direct entry creation is supported here
    };

    match client.create_lorebook(&payload).await {
        Ok(lorebook) => {
            io_handler.write_line(&format!(
                "Successfully created lorebook '{}' (ID: {}).",
                lorebook.name, lorebook.id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error creating lorebook: {}", e))?;
        }
    }
    Ok(())
}

// Placeholder for manage_specific_lorebook_entrypoint and its sub-menus
// These will be implemented in subsequent steps.
async fn manage_specific_lorebook_entrypoint<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Manage Specific Lorebook ---")?;
    let lorebook_id_str = io::input_required(io_handler, "Enter Lorebook ID to manage: ")?;
    let lorebook_id = match Uuid::parse_str(&lorebook_id_str) {
        Ok(id) => id,
        Err(_) => {
            io_handler.write_line("Invalid Lorebook ID format.")?;
            return Ok(());
        }
    };

    io_handler.write_line(&format!("Fetching lorebook {}...", lorebook_id))?;
    match client.get_lorebook(lorebook_id).await {
        Ok(lorebook) => {
            // Call the next menu function, passing the fetched lorebook details
            handle_specific_lorebook_menu(client, io_handler, lorebook.id, lorebook.name).await?;
        }
        Err(CliError::NotFound) => {
            io_handler.write_line(&format!("Lorebook with ID {} not found.", lorebook_id))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error fetching lorebook: {}", e))?;
        }
    }
    Ok(())
}

#[allow(dead_code, unused_variables)]
async fn handle_specific_lorebook_menu<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    lorebook_name: String,
) -> Result<(), CliError> {
    loop {
        io_handler.write_line(&format!(
            "\n--- Manage Lorebook: {} ({}) ---",
            lorebook_name, lorebook_id
        ))?;
        io_handler.write_line("[1] Manage Entries")?;
        io_handler.write_line("[2] Manage Chat Associations")?;
        io_handler.write_line("[3] Update Lorebook Details")?;
        io_handler.write_line("[4] Delete Lorebook")?;
        io_handler.write_line("[B] Back to Lorebook Management")?;

        match io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase()
            .as_str()
        {
            "1" => {
                if let Err(e) = handle_lorebook_entry_menu(
                    client,
                    io_handler,
                    lorebook_id,
                    lorebook_name.clone(),
                ) // Pass lorebook_name
                .await
                {
                    io_handler.write_line(&format!("Error managing lorebook entries: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) = handle_lorebook_chat_association_menu(
                    client,
                    io_handler,
                    lorebook_id,
                    lorebook_name.clone(),
                )
                .await
                {
                    io_handler.write_line(&format!("Error managing chat associations: {}", e))?;
                }
            }
            "3" => {
                if let Err(e) = update_lorebook_details(client, io_handler, lorebook_id).await {
                    io_handler.write_line(&format!("Error updating lorebook details: {}", e))?;
                }
            }
            "4" => {
                match delete_lorebook(client, io_handler, lorebook_id, lorebook_name.clone()).await
                {
                    Ok(true) => break, // Lorebook deleted, exit this menu
                    Ok(false) => {}    // Deletion cancelled or failed, continue menu
                    Err(e) => {
                        io_handler.write_line(&format!("Error deleting lorebook: {}", e))?;
                    }
                }
            }
            "b" => break,
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
    Ok(())
}

async fn update_lorebook_details<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\n--- Update Lorebook Details for ID: {} ---",
        lorebook_id
    ))?;

    let new_name =
        io::input_optional(io_handler, "Enter new name (leave blank to keep current): ")?;
    let new_description = io::input_optional(
        io_handler,
        "Enter new description (leave blank to keep current): ",
    )?;

    if new_name.is_none() && new_description.is_none() {
        io_handler.write_line("No changes specified. Lorebook details remain unchanged.")?;
        return Ok(());
    }

    let payload = UpdateLorebookPayload {
        name: new_name,
        description: new_description,
    };

    io_handler.write_line("Updating lorebook...")?;
    match client.update_lorebook(lorebook_id, &payload).await {
        Ok(updated_lorebook) => {
            io_handler.write_line(&format!(
                "Successfully updated lorebook '{}' (ID: {}).",
                updated_lorebook.name, updated_lorebook.id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error updating lorebook: {}", e))?;
        }
    }
    Ok(())
}

async fn delete_lorebook<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    lorebook_name: String,
) -> Result<bool, CliError> {
    // Changed return type
    io_handler.write_line(&format!(
        "\n--- Delete Lorebook: {} ({}) ---",
        lorebook_name, lorebook_id
    ))?;

    let confirmation_prompt = format!(
        "Are you sure you want to delete the lorebook '{}' (ID: {})? This action cannot be undone.",
        lorebook_name, lorebook_id
    );
    if io::confirm_action(io_handler, &confirmation_prompt)? {
        io_handler.write_line(&format!("Deleting lorebook '{}'...", lorebook_name))?;
        match client.delete_lorebook(lorebook_id).await {
            Ok(_) => {
                io_handler.write_line(&format!(
                    "Successfully deleted lorebook '{}'.",
                    lorebook_name
                ))?;
                Ok(true) // Signal successful deletion
            }
            Err(e) => {
                io_handler.write_line(&format!("Error deleting lorebook: {}", e))?;
                Ok(false) // Signal deletion failed, but menu can continue
            }
        }
    } else {
        io_handler.write_line("Deletion cancelled.")?;
        Ok(false) // Signal deletion cancelled
    }
}

// Removed #[allow(dead_code, unused_variables)]
async fn handle_lorebook_entry_menu<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    lorebook_name: String,
) -> Result<(), CliError> {
    loop {
        io_handler.write_line(&format!("\n--- Manage Entries for: {} ---", lorebook_name))?;
        io_handler.write_line("[1] List Entries")?;
        io_handler.write_line("[2] Create New Entry")?;
        io_handler.write_line("[3] View/Edit Specific Entry")?;
        io_handler.write_line("[B] Back to Specific Lorebook Menu")?;

        match io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase()
            .as_str()
        {
            "1" => {
                if let Err(e) = list_lorebook_entries(client, io_handler, lorebook_id).await {
                    io_handler.write_line(&format!("Error listing lorebook entries: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) = create_new_lorebook_entry(client, io_handler, lorebook_id).await {
                    io_handler.write_line(&format!("Error creating new lorebook entry: {}", e))?;
                }
            }
            "3" => {
                // Pass lorebook_name to manage_specific_entry_entrypoint
                if let Err(e) = manage_specific_entry_entrypoint(
                    client,
                    io_handler,
                    lorebook_id,
                    lorebook_name.clone(),
                )
                .await
                {
                    io_handler.write_line(&format!("Error managing specific entry: {}", e))?;
                }
            }
            "b" => break,
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn list_lorebook_entries<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\nFetching entries for lorebook {}...",
        lorebook_id
    ))?;
    match client.list_lorebook_entries(lorebook_id).await {
        Ok(entries) => {
            if entries.is_empty() {
                io_handler.write_line("This lorebook has no entries.")?;
            } else {
                io_handler.write_line("Lorebook Entries:")?;
                for entry in entries {
                    io_handler.write_line(&format!(
                        "  - Title: {} (ID: {})",
                        entry.entry_title, entry.id
                    ))?;
                    io_handler.write_line(&format!(
                        "    Enabled: {}, Constant: {}, Order: {}",
                        entry.is_enabled, entry.is_constant, entry.insertion_order
                    ))?;
                    // keys_text is not available in LorebookEntrySummaryResponse, so it's removed from display.
                    // If needed in the future, the backend would need to provide it or CLI would fetch full entry.
                }
            }
        }
        Err(e) => {
            io_handler.write_line(&format!("Error listing lorebook entries: {}", e))?;
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn create_new_lorebook_entry<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\n--- Create New Entry for Lorebook ID: {} ---",
        lorebook_id
    ))?;

    let entry_title = io::input_required(io_handler, "Enter entry title: ")?;
    let content = io::input_required(io_handler, "Enter entry content: ")?;
    let keys_text = io::input_optional(io_handler, "Enter keywords (comma-separated, optional): ")?;
    let comment = io::input_optional(io_handler, "Enter comment (optional): ")?;

    let is_enabled_str =
        io::input_optional(io_handler, "Enable this entry? (yes/no, default: yes): ")?;
    let is_enabled = match is_enabled_str.as_deref() {
        Some("no") => Some(false),
        _ => Some(true), // Default to true if "yes", blank, or anything else
    };

    let is_constant_str = io::input_optional(
        io_handler,
        "Mark entry as constant? (yes/no, default: no): ",
    )?;
    let is_constant = match is_constant_str.as_deref() {
        Some("yes") => Some(true),
        _ => Some(false), // Default to false
    };

    let insertion_order_str = io::input_optional(
        io_handler,
        "Enter insertion order (integer, default: 100): ",
    )?;
    let insertion_order = match insertion_order_str {
        Some(s) => match s.parse::<i32>() {
            Ok(val) => Some(val),
            Err(_) => {
                io_handler.write_line("Invalid insertion order, using default (100).")?;
                Some(100)
            }
        },
        None => Some(100),
    };

    let placement_hint = io::input_optional(
        io_handler,
        "Enter placement hint (e.g., before_prompt, optional): ",
    )?;

    let payload = CreateLorebookEntryPayload {
        entry_title,
        keys_text,
        content,
        comment,
        is_enabled,
        is_constant,
        insertion_order,
        placement_hint,
    };

    io_handler.write_line("Creating lorebook entry...")?;
    match client.create_lorebook_entry(lorebook_id, &payload).await {
        Ok(entry) => {
            io_handler.write_line(&format!(
                "Successfully created entry '{}' (ID: {}).",
                entry.entry_title, entry.id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error creating lorebook entry: {}", e))?;
        }
    }

    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn manage_specific_entry_entrypoint<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    lorebook_name: String, // Added lorebook_name
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\n--- Manage Specific Entry in Lorebook: {} ---",
        lorebook_name
    ))?;
    let entry_id_str = io::input_required(io_handler, "Enter Entry ID to manage: ")?;
    let entry_id = match Uuid::parse_str(&entry_id_str) {
        Ok(id) => id,
        Err(_) => {
            io_handler.write_line("Invalid Entry ID format.")?;
            return Ok(());
        }
    };

    io_handler.write_line(&format!("Fetching entry {}...", entry_id))?;
    match client.get_lorebook_entry(lorebook_id, entry_id).await {
        Ok(entry) => {
            handle_specific_entry_menu(
                client,
                io_handler,
                lorebook_id,
                entry_id,
                entry.entry_title,
            )
            .await?;
        }
        Err(CliError::NotFound) => {
            io_handler.write_line(&format!(
                "Entry with ID {} not found in lorebook {}.",
                entry_id, lorebook_id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error fetching entry: {}", e))?;
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn handle_specific_entry_menu<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    entry_id: Uuid,
    entry_title: String,
) -> Result<(), CliError> {
    loop {
        io_handler.write_line(&format!(
            "\n--- Manage Entry: {} ({}) ---",
            entry_title, entry_id
        ))?;
        io_handler.write_line("[1] View Entry Details")?;
        io_handler.write_line("[2] Update Entry")?;
        io_handler.write_line("[3] Delete Entry")?;
        io_handler.write_line("[B] Back to Entry Management for this Lorebook")?;

        match io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase()
            .as_str()
        {
            "1" => {
                if let Err(e) =
                    view_lorebook_entry_details(client, io_handler, lorebook_id, entry_id).await
                {
                    io_handler.write_line(&format!("Error viewing entry details: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) =
                    update_lorebook_entry(client, io_handler, lorebook_id, entry_id).await
                {
                    io_handler.write_line(&format!("Error updating entry: {}", e))?;
                }
            }
            "3" => {
                // Delete returns bool to indicate if we should break from this menu
                match delete_lorebook_entry(
                    client,
                    io_handler,
                    lorebook_id,
                    entry_id,
                    entry_title.clone(),
                )
                .await
                {
                    Ok(true) => break, // Entry deleted, exit this menu
                    Ok(false) => {}    // Deletion cancelled or failed
                    Err(e) => {
                        io_handler.write_line(&format!("Error deleting entry: {}", e))?;
                    }
                }
            }
            "b" => break,
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn view_lorebook_entry_details<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    entry_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\nFetching details for entry {} in lorebook {}...",
        entry_id, lorebook_id
    ))?;
    match client.get_lorebook_entry(lorebook_id, entry_id).await {
        Ok(entry) => {
            io_handler.write_line(&format!("--- Entry Details: {} ---", entry.entry_title))?;
            io_handler.write_line(&format!("ID: {}", entry.id))?;
            io_handler.write_line(&format!("Lorebook ID: {}", entry.lorebook_id))?;
            io_handler.write_line(&format!(
                "Keys: {}",
                entry.keys_text.as_deref().unwrap_or("N/A")
            ))?;
            io_handler.write_line(&format!("Content:\n{}", entry.content))?;
            io_handler.write_line(&format!(
                "Comment: {}",
                entry.comment.as_deref().unwrap_or("N/A")
            ))?;
            io_handler.write_line(&format!("Enabled: {}", entry.is_enabled))?;
            io_handler.write_line(&format!("Constant: {}", entry.is_constant))?;
            io_handler.write_line(&format!("Insertion Order: {}", entry.insertion_order))?;
            io_handler.write_line(&format!("Placement Hint: {}", entry.placement_hint))?;
            io_handler.write_line(&format!("Created At: {}", entry.created_at))?;
            io_handler.write_line(&format!("Updated At: {}", entry.updated_at))?;
        }
        Err(CliError::NotFound) => {
            io_handler.write_line(&format!(
                "Entry with ID {} not found in lorebook {}.",
                entry_id, lorebook_id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error fetching entry details: {}", e))?;
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn update_lorebook_entry<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    entry_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("\n--- Update Entry ID: {} ---", entry_id))?;

    let entry_title = io::input_optional(
        io_handler,
        "Enter new title (leave blank to keep current): ",
    )?;
    let content = io::input_optional(
        io_handler,
        "Enter new content (leave blank to keep current): ",
    )?;
    let keys_text = io::input_optional(
        io_handler,
        "Enter new keywords (leave blank to keep current): ",
    )?;
    let comment = io::input_optional(
        io_handler,
        "Enter new comment (leave blank to keep current): ",
    )?;

    let is_enabled_str = io::input_optional(
        io_handler,
        "Enable this entry? (yes/no, leave blank to keep current): ",
    )?;
    let is_enabled = match is_enabled_str.as_deref() {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None, // No change
    };

    let is_constant_str = io::input_optional(
        io_handler,
        "Mark entry as constant? (yes/no, leave blank to keep current): ",
    )?;
    let is_constant = match is_constant_str.as_deref() {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None, // No change
    };

    let insertion_order_str = io::input_optional(
        io_handler,
        "Enter new insertion order (integer, leave blank to keep current): ",
    )?;
    let insertion_order = match insertion_order_str {
        Some(s) if !s.is_empty() => match s.parse::<i32>() {
            Ok(val) => Some(val),
            Err(_) => {
                io_handler.write_line("Invalid insertion order, value not changed.")?;
                None
            }
        },
        _ => None, // No change
    };

    let placement_hint = io::input_optional(
        io_handler,
        "Enter new placement hint (leave blank to keep current): ",
    )?;

    let payload = UpdateLorebookEntryPayload {
        entry_title,
        keys_text,
        content,
        comment,
        is_enabled,
        is_constant,
        insertion_order,
        placement_hint,
    };

    if payload == UpdateLorebookEntryPayload::default() {
        io_handler.write_line("No changes specified. Entry remains unchanged.")?;
        return Ok(());
    }

    io_handler.write_line("Updating lorebook entry...")?;
    match client
        .update_lorebook_entry(lorebook_id, entry_id, &payload)
        .await
    {
        Ok(entry) => {
            io_handler.write_line(&format!(
                "Successfully updated entry '{}' (ID: {}).",
                entry.entry_title, entry.id
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("Error updating lorebook entry: {}", e))?;
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn delete_lorebook_entry<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    entry_id: Uuid,
    entry_title: String,
) -> Result<bool, CliError> {
    // Return bool to signal if menu should break
    io_handler.write_line(&format!(
        "\n--- Delete Entry: {} ({}) ---",
        entry_title, entry_id
    ))?;

    let confirmation_prompt = format!(
        "Are you sure you want to delete the entry '{}' (ID: {})? This action cannot be undone.",
        entry_title, entry_id
    );
    if io::confirm_action(io_handler, &confirmation_prompt)? {
        io_handler.write_line(&format!("Deleting entry '{}'...", entry_title))?;
        match client.delete_lorebook_entry(lorebook_id, entry_id).await {
            Ok(_) => {
                io_handler.write_line(&format!("Successfully deleted entry '{}'.", entry_title))?;
                Ok(true) // Signal successful deletion
            }
            Err(e) => {
                io_handler.write_line(&format!("Error deleting entry: {}", e))?;
                Ok(false) // Signal deletion failed
            }
        }
    } else {
        io_handler.write_line("Deletion cancelled.")?;
        Ok(false) // Signal deletion cancelled
    }
}

// Removed #[allow(dead_code, unused_variables)]
async fn handle_lorebook_chat_association_menu<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
    lorebook_name: String,
) -> Result<(), CliError> {
    loop {
        io_handler.write_line(&format!(
            "\n--- Manage Chat Associations for Lorebook: {} ({}) ---",
            lorebook_name, lorebook_id
        ))?;
        io_handler.write_line("[1] List Associated Chat Sessions")?;
        io_handler.write_line("[2] Associate with Chat Session")?;
        io_handler.write_line("[3] Disassociate from Chat Session")?;
        io_handler.write_line("[B] Back to Specific Lorebook Menu")?;

        match io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase()
            .as_str()
        {
            "1" => {
                if let Err(e) = list_associated_chat_sessions(client, io_handler, lorebook_id).await
                {
                    io_handler
                        .write_line(&format!("Error listing associated chat sessions: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) =
                    associate_lorebook_with_chat_session(client, io_handler, lorebook_id).await
                {
                    io_handler.write_line(&format!(
                        "Error associating lorebook with chat session: {}",
                        e
                    ))?;
                }
            }
            "3" => {
                if let Err(e) =
                    disassociate_lorebook_from_chat_session(client, io_handler, lorebook_id).await
                {
                    io_handler.write_line(&format!(
                        "Error disassociating lorebook from chat session: {}",
                        e
                    ))?;
                }
            }
            "b" => break,
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
    Ok(())
}

// Removed #[allow(dead_code, unused_variables)]
async fn list_associated_chat_sessions<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\nFetching chat sessions associated with lorebook {}...",
        lorebook_id
    ))?;
    match client
        .list_associated_chat_sessions_for_lorebook(lorebook_id)
        .await
    {
        Ok(chat_sessions) => {
            if chat_sessions.is_empty() {
                io_handler.write_line("This lorebook is not associated with any chat sessions.")?;
            } else {
                io_handler.write_line("Associated Chat Sessions:")?;
                for session in chat_sessions {
                    let title_display = session.title.as_deref().unwrap_or("Untitled Session");
                    io_handler.write_line(&format!(
                        "  - ID: {}, Title: \"{}\"",
                        session.chat_session_id, title_display
                    ))?;
                }
            }
        }
        Err(e) => {
            io_handler.write_line(&format!("Error listing associated chat sessions: {}", e))?;
        }
    }
    Ok(())
}

async fn associate_lorebook_with_chat_session<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\n--- Associate Lorebook ID: {} with Chat Session ---",
        lorebook_id
    ))?;

    let chat_session_id_str =
        io::input_required(io_handler, "Enter Chat Session ID to associate with: ")?;
    let chat_session_id = match Uuid::parse_str(&chat_session_id_str) {
        Ok(id) => id,
        Err(_) => {
            io_handler.write_line("Invalid Chat Session ID format.")?;
            return Ok(());
        }
    };

    let payload = AssociateLorebookToChatPayload { lorebook_id }; // lorebook_id is the function parameter

    io_handler.write_line(&format!(
        "Associating lorebook {} with chat session {}...",
        lorebook_id,
        chat_session_id // chat_session_id is from user prompt
    ))?;
    match client
        .associate_lorebook_to_chat(chat_session_id, &payload)
        .await
    {
        // First param is chat_session_id from prompt
        Ok(association) => {
            io_handler.write_line(&format!(
                "Successfully associated lorebook {} with chat session {}.",
                association.lorebook_id, association.chat_session_id
            ))?;
        }
        Err(CliError::Conflict(msg)) => {
            io_handler.write_line(&format!(
                "Conflict: {}. This lorebook may already be associated with this chat session.",
                msg
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Error associating lorebook with chat session: {}",
                e
            ))?;
        }
    }
    Ok(())
}

async fn disassociate_lorebook_from_chat_session<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
    lorebook_id: Uuid,
) -> Result<(), CliError> {
    io_handler.write_line(&format!(
        "\n--- Disassociate Lorebook ID: {} from Chat Session ---",
        lorebook_id
    ))?;

    let chat_session_id_str =
        io::input_required(io_handler, "Enter Chat Session ID to disassociate from: ")?;
    let chat_session_id_to_disassociate = match Uuid::parse_str(&chat_session_id_str) {
        Ok(id) => id,
        Err(_) => {
            io_handler.write_line("Invalid Chat Session ID format.")?;
            return Ok(());
        }
    };

    io_handler.write_line(&format!(
        "Disassociating lorebook {} from chat session {}...",
        lorebook_id, chat_session_id_to_disassociate
    ))?;
    match client
        .disassociate_lorebook_from_chat(lorebook_id, chat_session_id_to_disassociate)
        .await
    {
        Ok(_) => {
            io_handler.write_line(&format!(
                "Successfully disassociated lorebook {} from chat session {}.",
                lorebook_id, chat_session_id_to_disassociate
            ))?;
        }
        Err(CliError::NotFound) => {
            io_handler.write_line(&format!(
                "Association not found between lorebook {} and chat session {}.",
                lorebook_id, chat_session_id_to_disassociate
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!(
                "Error disassociating lorebook from chat session: {}",
                e
            ))?;
        }
    }
    Ok(())
}
async fn upload_lorebook_json_handler<C: HttpClient, H: IoHandler>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\n--- Upload Lorebook (JSON) ---")?;

    let file_path_str = io::input_optional(
        io_handler,
        "Enter path to lorebook JSON file (e.g., test_data/test_lorebook.json, leave blank for default): ",
    )?;

    let file_path = file_path_str.unwrap_or_else(|| "test_data/test_lorebook.json".to_string());

    io_handler.write_line(&format!("Reading lorebook file: {}...", file_path))?;

    let file_content = match std::fs::read_to_string(&file_path) {
        Ok(content) => content,
        Err(e) => {
            io_handler.write_line(&format!("Error reading file {}: {}", file_path, e))?;
            return Ok(());
        }
    };

    let parsed_lorebook: SillyTavernLorebookFile = match serde_json::from_str(&file_content) {
        Ok(parsed) => parsed,
        Err(e) => {
            io_handler.write_line(&format!("Error parsing JSON from {}: {}", file_path, e))?;
            return Ok(());
        }
    };

    if parsed_lorebook.entries.is_empty() {
        io_handler.write_line("The lorebook file contains no entries to import.")?;
        return Ok(());
    }

    // Prompt for a name for the new Lorebook that will be created
    let lorebook_name = io::input_required(io_handler, "Enter a name for this new lorebook: ")?;
    let lorebook_description = io::input_optional(
        io_handler,
        "Enter a description for this new lorebook (optional): ",
    )?;

    let create_lorebook_payload = CreateLorebookPayload {
        name: lorebook_name.clone(), // Clone here as it's used in messages later
        description: lorebook_description,
    };

    io_handler.write_line(&format!(
        "Creating new lorebook '{}' to import entries into...",
        create_lorebook_payload.name
    ))?;
    let new_lorebook = match client.create_lorebook(&create_lorebook_payload).await {
        Ok(lb) => {
            io_handler.write_line(&format!(
                "Successfully created lorebook '{}' (ID: {}).",
                lb.name, lb.id
            ))?;
            lb
        }
        Err(e) => {
            io_handler.write_line(&format!("Failed to create new lorebook: {}", e))?;
            return Ok(());
        }
    };

    io_handler.write_line(&format!(
        "Importing {} entries into '{}'...",
        parsed_lorebook.entries.len(),
        new_lorebook.name
    ))?;
    let mut success_count = 0;
    let mut fail_count = 0;

    for (_key, st_entry) in parsed_lorebook.entries {
        let keys: Vec<String> = st_entry
            .key
            .into_iter()
            .chain(st_entry.key_secondary.into_iter())
            .filter(|k| !k.is_empty())
            .collect();
        let keys_text = if keys.is_empty() {
            None
        } else {
            Some(keys.join(", "))
        };

        let entry_payload = CreateLorebookEntryPayload {
            entry_title: st_entry
                .comment
                .unwrap_or_else(|| "Untitled Entry".to_string()), // Use comment as title, or default
            keys_text,
            content: st_entry.content,
            comment: None, // SillyTavern comment is used as title, actual comment field not in this format
            is_enabled: Some(!st_entry.disable.unwrap_or(false)), // Invert ST 'disable'
            is_constant: st_entry.constant,
            insertion_order: st_entry.order,
            placement_hint: None, // Not in SillyTavern basic format
        };

        match client
            .create_lorebook_entry(new_lorebook.id, &entry_payload)
            .await
        {
            Ok(created_entry) => {
                io_handler.write_line(&format!(
                    "  Successfully imported entry: {}",
                    created_entry.entry_title
                ))?;
                success_count += 1;
            }
            Err(e) => {
                io_handler.write_line(&format!(
                    "  Failed to import entry titled '{}': {}",
                    entry_payload.entry_title, e
                ))?;
                fail_count += 1;
            }
        }
    }

    io_handler.write_line(&format!(
        "Lorebook import complete. Successfully imported {} entries. Failed to import {} entries.",
        success_count, fail_count
    ))?;

    Ok(())
}

// TODO: Functions to be added to chat_management.rs or start_chat.rs for associating lorebooks
// - prompt_and_associate_lorebooks_on_new_chat(client, new_chat_session_id)
// - handle_manage_chat_lorebook_associations_menu(client, chat_session_id)
