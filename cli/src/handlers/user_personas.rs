//! Handlers for User Persona CLI commands.

use crate::{
    PersonaClearDefaultArgs,
    // Argument structs from lib.rs
    PersonaCreateArgs,
    PersonaDeleteArgs,
    PersonaGetArgs,
    PersonaSetDefaultArgs,
    PersonaUpdateArgs,
    client::{
        interface::HttpClient,
        // User persona types are now directly available under crate::client::types
        types::{CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient},
    },
    error::CliError,
    io::IoHandler,
};
use uuid::Uuid; // Needed for parsing input for set-default

pub async fn handle_persona_create_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    args: PersonaCreateArgs,
) -> Result<(), CliError> {
    io_handler.write_line("Creating new user persona...")?;

    let create_dto = CreateUserPersonaDto {
        name: args.name,
        description: args.description,
        spec: args.spec,
        spec_version: args.spec_version,
        personality: args.personality,
        scenario: args.scenario,
        first_mes: args.first_mes,
        mes_example: args.mes_example,
        system_prompt: args.system_prompt,
        post_history_instructions: args.post_history_instructions,
        tags: args.tags.map(|t| t.into_iter().map(Some).collect()), // CLI tags are Vec<String>, DTO expects Vec<Option<String>>
        avatar: args.avatar,
    };

    match http_client.create_user_persona(create_dto).await {
        Ok(persona) => {
            io_handler.write_line(&format!(
                "Successfully created persona: '{}' (ID: {})",
                persona.name, persona.id
            ))?;
            // Optionally print more details of the created persona
            print_persona_details(io_handler, &persona)?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error creating persona: {}", e))?;
            Err(e.into()) // Propagate error
        }
    }
}

pub async fn handle_persona_list_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("Listing user personas...")?;
    match http_client.list_user_personas().await {
        Ok(personas) => {
            if personas.is_empty() {
                io_handler.write_line("No user personas found.")?;
            } else {
                io_handler.write_line("User Personas:")?;
                for persona in personas {
                    io_handler.write_line(&format!("- Name: {}", persona.name))?;
                    io_handler.write_line(&format!("  ID: {}", persona.id))?;
                    io_handler.write_line(&format!("  Description: {}", persona.description))?;
                    io_handler.write_line("")?; // Empty line between personas
                }
            }
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error listing personas: {}", e))?;
            Err(e.into()) // Propagate error
        }
    }
}

pub async fn handle_persona_get_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    args: PersonaGetArgs,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("Getting user persona with ID: {}...", args.id))?;
    match http_client.get_user_persona(args.id).await {
        Ok(persona) => {
            print_persona_details(io_handler, &persona)?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error getting persona: {}", e))?;
            Err(e.into()) // Propagate error
        }
    }
}

pub async fn handle_persona_update_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    args: PersonaUpdateArgs,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("Updating user persona with ID: {}...", args.id))?;

    let update_dto = UpdateUserPersonaDto {
        name: args.name,
        description: args.description,
        spec: args.spec,
        spec_version: args.spec_version,
        personality: args.personality,
        scenario: args.scenario,
        first_mes: args.first_mes,
        mes_example: args.mes_example,
        system_prompt: args.system_prompt,
        post_history_instructions: args.post_history_instructions,
        tags: args.tags.map(|t| t.into_iter().map(Some).collect()),
        avatar: args.avatar,
    };

    match http_client.update_user_persona(args.id, update_dto).await {
        Ok(persona) => {
            io_handler.write_line(&format!(
                "Successfully updated persona: '{}' (ID: {})",
                persona.name, persona.id
            ))?;
            print_persona_details(io_handler, &persona)?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error updating persona: {}", e))?;
            Err(e.into()) // Propagate error
        }
    }
}

pub async fn handle_persona_delete_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    args: PersonaDeleteArgs,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("Deleting user persona with ID: {}...", args.id))?;
    match http_client.delete_user_persona(args.id).await {
        Ok(()) => {
            io_handler.write_line(&format!(
                "Successfully deleted persona with ID: {}",
                args.id
            ))?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error deleting persona: {}", e))?;
            Err(e.into()) // Propagate error
        }
    }
}

/// Fetches user personas and returns them as a Vec, without printing.
pub async fn get_user_personas<C: HttpClient>(
    http_client: &C,
) -> Result<Vec<UserPersonaDataForClient>, CliError> {
    match http_client.list_user_personas().await {
        Ok(personas) => Ok(personas),
        Err(e) => Err(e.into()), // Propagate error, converting if necessary
    }
}

// Helper function to print persona details
fn print_persona_details<H: IoHandler>(
    io_handler: &mut H,
    persona: &UserPersonaDataForClient,
) -> Result<(), CliError> {
    io_handler.write_line(&format!("--- Persona Details: {} ---", persona.name))?;
    io_handler.write_line(&format!("ID: {}", persona.id))?;
    io_handler.write_line(&format!("User ID: {}", persona.user_id))?;
    io_handler.write_line(&format!("Description: {}", persona.description))?;
    if let Some(spec) = &persona.spec {
        io_handler.write_line(&format!("Spec: {}", spec))?;
    }
    if let Some(spec_version) = &persona.spec_version {
        io_handler.write_line(&format!("Spec Version: {}", spec_version))?;
    }
    if let Some(personality) = &persona.personality {
        io_handler.write_line(&format!("Personality: {}", personality))?;
    }
    if let Some(scenario) = &persona.scenario {
        io_handler.write_line(&format!("Scenario: {}", scenario))?;
    }
    if let Some(first_mes) = &persona.first_mes {
        io_handler.write_line(&format!("First Message: {}", first_mes))?;
    }
    if let Some(mes_example) = &persona.mes_example {
        io_handler.write_line(&format!("Message Example: {}", mes_example))?;
    }
    if let Some(system_prompt) = &persona.system_prompt {
        io_handler.write_line(&format!("System Prompt: {}", system_prompt))?;
    }
    if let Some(post_hist) = &persona.post_history_instructions {
        io_handler.write_line(&format!("Post History Instructions: {}", post_hist))?;
    }
    if let Some(tags) = &persona.tags {
        let tag_str = tags
            .iter()
            .filter_map(|t| t.as_ref())
            .cloned()
            .collect::<Vec<String>>()
            .join(", ");
        io_handler.write_line(&format!(
            "Tags: {}",
            if tag_str.is_empty() { "None" } else { &tag_str }
        ))?;
    }
    if let Some(avatar) = &persona.avatar {
        io_handler.write_line(&format!("Avatar: {}", avatar))?;
    }
    io_handler.write_line(&format!("Created At: {}", persona.created_at))?;
    io_handler.write_line(&format!("Updated At: {}", persona.updated_at))?;
    io_handler.write_line("------------------------------")?;
    Ok(())
}

pub async fn handle_persona_set_default_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    _args: PersonaSetDefaultArgs, // Args might be used if we allow direct ID input later
) -> Result<(), CliError> {
    io_handler.write_line("Fetching your personas to set a default...")?;
    let personas = match http_client.list_user_personas().await {
        Ok(p) => p,
        Err(e) => {
            io_handler.write_line(&format!("Error fetching personas: {}", e))?;
            return Err(e.into());
        }
    };

    if personas.is_empty() {
        io_handler.write_line("No personas available to set as default.")?;
        return Ok(());
    }

    io_handler.write_line("Available personas:")?;
    for (index, persona) in personas.iter().enumerate() {
        io_handler.write_line(&format!(
            "  [{}] {} (ID: {})",
            index + 1,
            persona.name,
            persona.id
        ))?;
    }

    let selection_prompt =
        "Enter the number or ID of the persona to set as default (or 'c' to cancel):";
    let choice_str = io_handler.read_line(selection_prompt)?.trim().to_string();

    if choice_str.eq_ignore_ascii_case("c") {
        io_handler.write_line("Operation cancelled.")?;
        return Ok(());
    }

    let selected_persona_id: Uuid = if let Ok(num) = choice_str.parse::<usize>() {
        if num > 0 && num <= personas.len() {
            personas[num - 1].id
        } else {
            io_handler.write_line("Invalid selection number.")?;
            return Err(CliError::InputError("Invalid selection.".to_string()));
        }
    } else if let Ok(id) = Uuid::parse_str(&choice_str) {
        // Check if this ID is in the list of fetched personas to ensure user owns it
        if !personas.iter().any(|p| p.id == id) {
            io_handler.write_line("Selected Persona ID not found in your list of personas.")?;
            return Err(CliError::InputError(
                "Persona ID not found or not owned by user.".to_string(),
            ));
        }
        id
    } else {
        io_handler.write_line("Invalid input. Please enter a number or a valid Persona ID.")?;
        return Err(CliError::InputError("Invalid input format.".to_string()));
    };

    io_handler.write_line(&format!(
        "Setting persona {} as default...",
        selected_persona_id
    ))?;
    match http_client.set_default_persona(selected_persona_id).await {
        Ok(user) => {
            io_handler.write_line(&format!(
                "Successfully set persona {} as default for user {}.",
                user.default_persona_id
                    .map_or_else(|| "None".to_string(), |id| id.to_string()),
                user.username
            ))?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error setting default persona: {}", e))?;
            Err(e.into())
        }
    }
}

pub async fn handle_persona_clear_default_action<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    _args: PersonaClearDefaultArgs,
) -> Result<(), CliError> {
    io_handler.write_line("Clearing default persona...")?;
    match http_client.clear_default_persona().await {
        Ok(()) => {
            io_handler.write_line("Successfully cleared default persona.")?;
            Ok(())
        }
        Err(e) => {
            io_handler.write_line(&format!("Error clearing default persona: {}", e))?;
            Err(e.into())
        }
    }
}
