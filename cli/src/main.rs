#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unused_async)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::items_after_statements)]

// cli/src/main.rs

use anyhow::{Context, Result};
use reqwest::Client as ReqwestClient;
use reqwest::cookie::Jar;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

// Items imported from the library crate
use clap::Parser;
use scribe_backend::models::users::User; // Corrected User import
use scribe_cli::{
    CharacterCommand,
    ChatCommand,
    CliArgs,
    Commands,
    MenuNavigation,
    MenuResult, // Menu enums and types from lib.rs
    MenuState,
    PersonaCommand,                             // Clap arg structs
    client::{HttpClient, ReqwestClientWrapper}, // Client Abstraction
    error::CliError,                            // Use our specific error type
    handlers::{
        // New character handlers
        characters::{
            handle_character_create_oneliner, handle_character_create_wizard,
            handle_character_edit_oneliner, handle_character_edit_wizard,
        },
        chat_overrides::{handle_chat_edit_character_oneliner, handle_chat_edit_character_wizard},
        handle_change_user_role_action,
        handle_chat_config_action,
        handle_default_settings_action,
        handle_delete_chat_session_action,
        handle_health_check_action,
        handle_list_all_users_action,
        handle_list_chat_sessions_action,
        handle_lock_unlock_user_action,
        handle_login_action,
        handle_model_settings_action,
        handle_registration_action,
        handle_resume_chat_session_action,
        handle_start_chat_action,
        handle_upload_character_action,
        handle_view_character_details_action,
        handle_view_chat_history_action,
        handle_view_user_details_action,
        lorebooks::{
            // Lorebook handlers
            handle_lorebook_management_menu as handle_cli_lorebooks_menu_entry,
            // TODO: Add other lorebook handlers here
        },
        user_personas::{
            handle_persona_clear_default_action, // Added new handlers
            // User Persona handlers
            handle_persona_create_action,
            handle_persona_delete_action,
            handle_persona_get_action,
            handle_persona_list_action,
            handle_persona_set_default_action,
            handle_persona_update_action,
        },
    },
    io::{IoHandler, StdIoHandler}, // IO Abstraction
}; // Required for CliArgs::parse()

// MenuState, MenuNavigation, and MenuResult are now imported from lib.rs

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "warn,scribe_cli::main=info,scribe_backend=warn".into());
    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .compact()
        .init();

    let cli_args = CliArgs::parse();
    let mut io_handler = StdIoHandler;

    info!(base_url = %cli_args.base_url, "Starting Scribe CLI client");

    let reqwest_client = ReqwestClient::builder()
        .cookie_provider(Arc::new(Jar::default()))
        .danger_accept_invalid_certs(true)
        .build()
        .context("Failed to build reqwest client")?;

    let http_client = ReqwestClientWrapper::new(reqwest_client, cli_args.base_url.clone());

    if let Some(command) = cli_args.command {
        // Handle direct command execution
        match command {
            Commands::Character(char_args) => {
                match char_args.command {
                    CharacterCommand::Create(create_args) => {
                        if create_args.interactive {
                            if let Err(e) =
                                handle_character_create_wizard(&http_client, &mut io_handler).await
                            {
                                io_handler.write_line(&format!(
                                    "Error during character creation wizard: {}",
                                    e
                                ))?;
                            }
                        } else {
                            // Ensure all required one-liner args are present, or clap would have exited.
                            // However, the DTO expects Options for these, so we map them.
                            if create_args.name.is_none()
                                || create_args.description.is_none()
                                || create_args.first_mes.is_none()
                            {
                                io_handler.write_line("Error: --name, --description, and --first-mes are required for non-interactive character creation.")?;
                            } else if let Err(e) = handle_character_create_oneliner(
                                &http_client,
                                &mut io_handler,
                                create_args,
                            )
                            .await
                            {
                                io_handler.write_line(&format!(
                                    "Error during character creation: {}",
                                    e
                                ))?;
                            }
                        }
                    }
                    CharacterCommand::Edit(edit_args) => {
                        if edit_args.interactive {
                            if let Err(e) =
                                handle_character_edit_wizard(&http_client, &mut io_handler).await
                            {
                                io_handler.write_line(&format!(
                                    "Error during character edit wizard: {}",
                                    e
                                ))?;
                            }
                        } else if edit_args.id.is_none() {
                            io_handler.write_line(
                                "Error: --id is required for non-interactive character editing.",
                            )?;
                        } else if let Err(e) =
                            handle_character_edit_oneliner(&http_client, &mut io_handler, edit_args)
                                .await
                        {
                            io_handler
                                .write_line(&format!("Error during character editing: {}", e))?;
                        }
                    }
                }
            }
            Commands::Chat(chat_args) => match chat_args.command {
                ChatCommand::EditCharacter(edit_char_args) => {
                    if edit_char_args.interactive {
                        if let Err(e) =
                            handle_chat_edit_character_wizard(&http_client, &mut io_handler).await
                        {
                            io_handler.write_line(&format!(
                                "Error during chat character override wizard: {}",
                                e
                            ))?;
                        }
                    } else if edit_char_args.session_id.is_none()
                        || edit_char_args.field.is_none()
                        || edit_char_args.value.is_none()
                    {
                        io_handler.write_line("Error: --session-id, --field, and --value are required for non-interactive chat character override.")?;
                    } else if let Err(e) = handle_chat_edit_character_oneliner(
                        &http_client,
                        &mut io_handler,
                        edit_char_args,
                    )
                    .await
                    {
                        io_handler
                            .write_line(&format!("Error during chat character override: {}", e))?;
                    }
                }
            },
            Commands::Persona(persona_args) => match persona_args.command {
                PersonaCommand::Create(create_args) => {
                    if let Err(e) =
                        handle_persona_create_action(&http_client, &mut io_handler, create_args)
                            .await
                    {
                        io_handler.write_line(&format!("Error creating persona: {}", e))?;
                    }
                }
                PersonaCommand::List => {
                    if let Err(e) = handle_persona_list_action(&http_client, &mut io_handler).await
                    {
                        io_handler.write_line(&format!("Error listing personas: {}", e))?;
                    }
                }
                PersonaCommand::Get(get_args) => {
                    if let Err(e) =
                        handle_persona_get_action(&http_client, &mut io_handler, get_args).await
                    {
                        io_handler.write_line(&format!("Error getting persona: {}", e))?;
                    }
                }
                PersonaCommand::Update(update_args) => {
                    if let Err(e) =
                        handle_persona_update_action(&http_client, &mut io_handler, update_args)
                            .await
                    {
                        io_handler.write_line(&format!("Error updating persona: {}", e))?;
                    }
                }
                PersonaCommand::Delete(delete_args) => {
                    if let Err(e) =
                        handle_persona_delete_action(&http_client, &mut io_handler, delete_args)
                            .await
                    {
                        io_handler.write_line(&format!("Error deleting persona: {}", e))?;
                    }
                }
                PersonaCommand::SetDefault(set_default_args) => {
                    if let Err(e) = handle_persona_set_default_action(
                        &http_client,
                        &mut io_handler,
                        set_default_args,
                    )
                    .await
                    {
                        io_handler.write_line(&format!("Error setting default persona: {}", e))?;
                    }
                }
                PersonaCommand::ClearDefault(clear_default_args) => {
                    if let Err(e) = handle_persona_clear_default_action(
                        &http_client,
                        &mut io_handler,
                        clear_default_args,
                    )
                    .await
                    {
                        io_handler.write_line(&format!("Error clearing default persona: {}", e))?;
                    }
                }
            },
        }
    } else {
        // Fallback to existing interactive main menu loop
        io_handler.write_line("Welcome to Scribe CLI! (Interactive Mode)")?;
        io_handler.write_line(&format!("Connecting to: {}", cli_args.base_url))?;

        let mut current_model = "gemini-2.5-flash-preview-05-20".to_string();

        // Main application loop
        loop {
            io_handler.write_line("\n--- Main Menu ---")?;
            io_handler.write_line("[1] Login")?;
            io_handler.write_line("[2] Register")?;
            io_handler.write_line("[3] Health Check")?;
            io_handler.write_line("[q] Quit")?;

            let choice = io_handler.read_line("Enter choice: ")?;
            match choice.trim() {
                "1" => {
                    // Login
                    match handle_login_action(&http_client, &mut io_handler).await {
                        Ok(user) => {
                            // After successful login, show user-specific menu
                            let mut logged_in_user = user; // Save the logged-in user
                            io_handler.write_line(&format!(
                                "Login successful as '{}'.",
                                logged_in_user.username
                            ))?;

                            let mut menu_state = MenuState::MainMenu;
                            // Session-loop for logged-in user
                            'logged_in: loop {
                                // Determine user role for menu display
                                let has_admin_role = matches!(
                                    logged_in_user.role,
                                    scribe_backend::models::users::UserRole::Administrator
                                );
                                let has_moderator_role = has_admin_role
                                    || matches!(
                                        logged_in_user.role,
                                        scribe_backend::models::users::UserRole::Moderator
                                    );

                                let navigation_result = match menu_state {
                                    MenuState::MainMenu => {
                                        handle_main_menu_logged_in(
                                            &mut io_handler,
                                            &logged_in_user,
                                            has_admin_role,
                                            has_moderator_role,
                                        )
                                        .await?
                                    }
                                    MenuState::UserManagement => {
                                        handle_user_management_menu(
                                            &http_client,
                                            &mut io_handler,
                                            has_admin_role, // Moderator access is a subset of admin
                                            has_moderator_role,
                                        )
                                        .await?
                                    }
                                    MenuState::CharacterManagement => {
                                        handle_character_management_menu(
                                            &http_client,
                                            &mut io_handler,
                                            &mut current_model, // For test character creation potentially
                                        )
                                        .await?
                                    }
                                    MenuState::ChatManagement => {
                                        handle_chat_management_menu(
                                            &http_client,
                                            &mut io_handler,
                                            &current_model,
                                        )
                                        .await?
                                    }
                                    MenuState::AccountSettings => {
                                        handle_account_settings_menu(
                                            &http_client,
                                            &mut io_handler,
                                            &mut logged_in_user,
                                            &mut current_model,
                                        )
                                        .await?
                                    }
                                    MenuState::PersonaManagement => {
                                        handle_persona_management_menu(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await?
                                    }
                                    MenuState::LorebookManagement => {
                                        handle_cli_lorebooks_menu_entry(
                                            &http_client,
                                            &mut io_handler,
                                        )
                                        .await?
                                    }
                                };

                                match navigation_result {
                                    MenuNavigation::GoTo(new_state) => menu_state = new_state,
                                    MenuNavigation::ReturnToMainMenu => {
                                        menu_state = MenuState::MainMenu
                                    }
                                    MenuNavigation::Logout => {
                                        io_handler.write_line("Logging out...")?;
                                        match http_client.logout().await {
                                            Ok(()) => {
                                                io_handler
                                                    .write_line("Successfully logged out.")?;
                                            }
                                            Err(e) => {
                                                error!(error = ?e, "Failed to logout");
                                                io_handler.write_line(&format!(
                                                    "Error logging out: {}",
                                                    e
                                                ))?;
                                                io_handler
                                                    .write_line("Returning to main menu anyway.")?;
                                            }
                                        }
                                        break 'logged_in;
                                    }
                                    MenuNavigation::Quit => {
                                        io_handler.write_line("Exiting Scribe CLI.")?;
                                        return Ok(());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(error = ?e, "Login failed");
                            io_handler.write_line(&format!("Login failed: {}", e))?;
                        }
                    }
                }
                "2" => {
                    // Registration
                    match handle_registration_action(&http_client, &mut io_handler).await {
                        Ok(user) => {
                            io_handler.write_line(&format!(
                                "Registration successful for user '{}' (ID: {}).",
                                user.username, user.id
                            ))?;

                            // Check if recovery key was provided
                            if let Some(recovery_key) = http_client.get_last_recovery_key() {
                                io_handler.write_line("\n⚠️  IMPORTANT: RECOVERY KEY ⚠️")?;
                                io_handler.write_line("Save this recovery key in a secure location. You will need it to recover your account if you lose access.")?;
                                io_handler
                                    .write_line(&format!("Recovery Key: {}", recovery_key))?;
                                io_handler
                                    .write_line("⚠️  You will NOT be shown this key again! ⚠️")?;
                            }
                        }
                        Err(e) => {
                            error!(error = ?e, "Registration failed");
                            io_handler.write_line(&format!("Registration failed: {}", e))?;
                        }
                    }
                }
                "3" => {
                    // Health Check
                    match handle_health_check_action(&http_client, &mut io_handler).await {
                        Ok(()) => { /* Success handled within function */ }
                        Err(e) => {
                            error!(error = ?e, "Health check failed");
                            io_handler.write_line(&format!("Health check failed: {}", e))?;
                        }
                    }
                }
                "q" => {
                    io_handler.write_line("Exiting Scribe CLI.")?;
                    break;
                }
                _ => io_handler.write_line("Invalid choice. Please try again.")?,
            }
        }
    }

    Ok(())
}

// --- Helper functions for interactive menu states ---

async fn handle_main_menu_logged_in<H: IoHandler>(
    io_handler: &mut H,
    logged_in_user: &User,
    _has_admin_role: bool, // Parameter can be kept for consistency or removed if not used
    _has_moderator_role: bool, // Parameter can be kept for consistency or removed if not used
) -> MenuResult {
    io_handler.write_line(&format!(
        "\n--- Main Menu (User: {}, Role: {}) ---",
        logged_in_user.username, logged_in_user.role
    ))?;

    // Define menu options. The order here will determine the displayed number.
    let options = [
        ("User & Access Management", MenuState::UserManagement),
        ("Character Management", MenuState::CharacterManagement),
        ("Persona Management", MenuState::PersonaManagement),
        ("Lorebook Management", MenuState::LorebookManagement), // New option
        ("Chat Session Management", MenuState::ChatManagement),
        ("My Account & Settings", MenuState::AccountSettings),
    ];

    for (i, (label, _)) in options.iter().enumerate() {
        io_handler.write_line(&format!("[{}] {}", i + 1, label))?;
    }
    io_handler.write_line("[L] Logout")?;
    io_handler.write_line("[Q] Quit Application")?;

    loop {
        let choice = io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase();
        match choice.as_str() {
            "1" => return Ok(MenuNavigation::GoTo(options[0].1)),
            "2" => return Ok(MenuNavigation::GoTo(options[1].1)),
            "3" => return Ok(MenuNavigation::GoTo(options[2].1)),
            "4" => return Ok(MenuNavigation::GoTo(options[3].1)), // Lorebook Management
            "5" => return Ok(MenuNavigation::GoTo(options[4].1)),
            "6" => return Ok(MenuNavigation::GoTo(options[5].1)),
            "l" => return Ok(MenuNavigation::Logout),
            "q" => return Ok(MenuNavigation::Quit),
            _ => io_handler.write_line("Invalid choice, please try again.")?,
        }
    }
}

async fn handle_user_management_menu<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    has_admin_role: bool,
    has_moderator_role: bool,
) -> MenuResult {
    loop {
        io_handler.write_line("\n--- User & Access Management ---")?;
        if has_admin_role {
            io_handler.write_line("[1] List All Users")?;
            io_handler.write_line("[2] View User Details")?;
            io_handler.write_line("[3] Change User Role")?;
            io_handler.write_line("[4] Lock/Unlock User Account")?;
        } else if has_moderator_role {
            io_handler.write_line("[1] List All Users")?;
        }
        io_handler.write_line("[B] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice: ")?;
        match choice.trim().to_lowercase().as_str() {
            "1" if has_admin_role || has_moderator_role => {
                if let Err(e) = handle_list_all_users_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error listing users: {}", e))?;
                }
            }
            "2" if has_admin_role => {
                if let Err(e) = handle_view_user_details_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error viewing user details: {}", e))?;
                }
            }
            "3" if has_admin_role => {
                if let Err(e) = handle_change_user_role_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error changing user role: {}", e))?;
                }
            }
            "4" if has_admin_role => {
                if let Err(e) = handle_lock_unlock_user_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error with account lock/unlock: {}", e))?;
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }
}

async fn handle_character_management_menu<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    _current_model: &mut String, // Keep for future use if needed by a char action
) -> MenuResult {
    loop {
        io_handler.write_line("\n--- Character Management ---")?;
        io_handler.write_line("[1] List My Characters")?;
        io_handler.write_line("[2] Create Character (Wizard)")?;
        io_handler.write_line("[3] Edit Character (Wizard)")?;
        io_handler.write_line("[4] Upload Character (PNG)")?;
        io_handler.write_line("[5] View Character Details")?;
        io_handler.write_line("[6] Create Test Character (PNG)")?;
        io_handler.write_line("[B] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice: ")?;
        match choice.trim().to_lowercase().as_str() {
            "1" => {
                io_handler.write_line("\nFetching your characters...")?;
                match http_client.list_characters().await {
                    Ok(characters) => {
                        if characters.is_empty() {
                            io_handler.write_line("You have no characters.")?;
                        } else {
                            io_handler.write_line("Your characters:")?;
                            for char_meta in characters {
                                io_handler.write_line(&format!(
                                    "  - {} (ID: {})",
                                    char_meta.name, char_meta.id
                                ))?;
                            }
                        }
                    }
                    Err(e) => io_handler.write_line(&format!("Error listing characters: {}", e))?,
                }
            }
            "2" => {
                if let Err(e) = handle_character_create_wizard(http_client, io_handler).await {
                    io_handler
                        .write_line(&format!("Error during character creation wizard: {}", e))?;
                }
            }
            "3" => {
                if let Err(e) = handle_character_edit_wizard(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error during character edit wizard: {}", e))?;
                }
            }
            "4" => match handle_upload_character_action(http_client, io_handler).await {
                Ok(character) => {
                    io_handler.write_line(&format!(
                        "Successfully uploaded character '{}' (ID: {}).",
                        character.name, character.id
                    ))?;
                }
                Err(e) => io_handler.write_line(&format!("Error uploading character: {}", e))?,
            },
            "5" => {
                if let Err(e) = handle_view_character_details_action(http_client, io_handler).await
                {
                    io_handler.write_line(&format!("Error viewing character details: {}", e))?;
                }
            }
            "6" => {
                io_handler.write_line("\nCreating test character...")?;
                const CHARACTER_NAME: &str = "Test Character CLI";
                let manifest_dir = env!("CARGO_MANIFEST_DIR");
                let manifest_path = PathBuf::from(manifest_dir);
                let workspace_root = manifest_path.parent().ok_or_else(|| {
                    CliError::Internal(format!(
                        "Could not get parent directory of manifest dir: {}",
                        manifest_dir
                    ))
                })?;
                let test_card_path_buf = workspace_root.join("test_data/test_card.png");
                let test_card_path_str = test_card_path_buf.to_str().ok_or_else(|| {
                    CliError::Internal(format!(
                        "Constructed test card path is not valid UTF-8: {:?}",
                        test_card_path_buf.display()
                    ))
                })?;
                match http_client
                    .upload_character(CHARACTER_NAME, test_card_path_str)
                    .await
                {
                    Ok(character) => {
                        tracing::info!(character_id = %character.id, character_name = %character.name, "Test character created successfully");
                        io_handler.write_line(&format!(
                            "Successfully created test character '{}' (ID: {}).",
                            character.name, character.id
                        ))?;
                    }
                    Err(CliError::Io(io_err)) => {
                        tracing::error!(error = ?io_err, path = %test_card_path_buf.display(), "Failed to read test character card file");
                        io_handler.write_line(&format!(
                            "Error reading test character card file '{}': {}",
                            test_card_path_buf.display(),
                            io_err
                        ))?;
                        io_handler.write_line(
                            "Please ensure the file exists in test_data/ at the workspace root.",
                        )?;
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "Failed to create test character");
                        io_handler.write_line(&format!("Error creating test character: {}", e))?;
                    }
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }
}

async fn handle_chat_management_menu<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    current_model: &String,
) -> MenuResult {
    loop {
        io_handler.write_line("\n--- Chat Session Management ---")?;
        io_handler.write_line("[1] Start New Chat Session")?;
        io_handler.write_line("[2] List Chat Sessions")?;
        io_handler.write_line("[3] View Chat History")?;
        io_handler.write_line("[4] Resume Chat Session")?;
        io_handler.write_line("[5] Configure Chat Session")?;
        io_handler.write_line("[6] Edit Character Overrides for Session (Wizard)")?;
        io_handler.write_line("[7] Delete Chat Session")?;
        io_handler.write_line("[B] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice: ")?;
        match choice.trim().to_lowercase().as_str() {
            "1" => {
                if let Err(e) =
                    handle_start_chat_action(http_client, io_handler, current_model).await
                {
                    io_handler.write_line(&format!("Error starting chat: {}", e))?;
                }
            }
            "2" => {
                if let Err(e) = handle_list_chat_sessions_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error listing chat sessions: {}", e))?;
                }
            }
            "3" => {
                if let Err(e) = handle_view_chat_history_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error viewing chat history: {}", e))?;
                }
            }
            "4" => {
                if let Err(e) =
                    handle_resume_chat_session_action(http_client, io_handler, current_model).await
                {
                    io_handler.write_line(&format!("Error resuming chat session: {}", e))?;
                }
            }
            "5" => {
                if let Err(e) =
                    handle_chat_config_action(http_client, io_handler, current_model).await
                {
                    io_handler.write_line(&format!("Error configuring chat: {}", e))?;
                }
            }
            "6" => {
                if let Err(e) = handle_chat_edit_character_wizard(http_client, io_handler).await {
                    io_handler.write_line(&format!(
                        "Error during chat character override wizard: {}",
                        e
                    ))?;
                }
            }
            "7" => {
                if let Err(e) = handle_delete_chat_session_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error deleting chat session: {}", e))?;
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }
}

async fn handle_account_settings_menu<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
    logged_in_user: &mut User,
    current_model: &mut String,
) -> MenuResult {
    loop {
        io_handler.write_line("\n--- My Account & Settings ---")?;
        io_handler.write_line("[1] Show My Info")?;
        io_handler.write_line("[2] Model Settings")?;
        io_handler.write_line("[3] Configure Default Chat Settings")?;
        io_handler.write_line("[B] Back to Main Menu")?;

        let choice = io_handler.read_line("Enter choice: ")?;
        match choice.trim().to_lowercase().as_str() {
            "1" => {
                io_handler.write_line("\nFetching current user info...")?;
                match http_client.me().await {
                    Ok(user_info) => {
                        *logged_in_user = user_info; // Update the mutable user reference
                        io_handler.write_line(&format!(
                            "--- User Info for '{}' ---",
                            logged_in_user.username
                        ))?;
                        io_handler.write_line(&format!("User ID: {}", logged_in_user.id))?;
                        let role_str = match logged_in_user.role {
                            scribe_backend::models::users::UserRole::Administrator => {
                                "Administrator"
                            }
                            scribe_backend::models::users::UserRole::Moderator => "Moderator",
                            scribe_backend::models::users::UserRole::User => "User",
                        };
                        io_handler.write_line(&format!("Role: {}", role_str))?;
                        io_handler.write_line(&format!("Email: {}", logged_in_user.email))?;
                        let status_str = logged_in_user
                            .account_status
                            .clone()
                            .unwrap_or_else(|| "active".to_string());
                        io_handler.write_line(&format!("Account Status: {}", status_str))?;
                    }
                    Err(e) => io_handler.write_line(&format!("Error fetching user info: {}", e))?,
                }
            }
            "2" => {
                if let Err(e) =
                    handle_model_settings_action(http_client, io_handler, current_model).await
                {
                    io_handler.write_line(&format!("Error updating model settings: {}", e))?;
                }
            }
            "3" => {
                if let Err(e) =
                    handle_default_settings_action(http_client, io_handler, current_model).await
                {
                    io_handler.write_line(&format!("Error configuring default settings: {}", e))?;
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }
}

async fn handle_persona_management_menu<C: HttpClient, H: IoHandler>(
    http_client: &C,
    io_handler: &mut H,
) -> MenuResult {
    loop {
        io_handler.write_line("\n--- Persona Management ---")?;
        io_handler.write_line("[1] List My Personas")?;
        io_handler.write_line("[2] Create Persona")?;
        io_handler.write_line("[3] View Persona Details")?;
        io_handler.write_line("[4] Update Persona")?;
        io_handler.write_line("[5] Delete Persona")?;
        io_handler.write_line("[6] Set Default Persona")?; // New option
        io_handler.write_line("[7] Clear Default Persona")?; // New option
        io_handler.write_line("[B] Back to Main Menu")?;

        let choice = io_handler
            .read_line("Enter choice: ")?
            .trim()
            .to_lowercase();
        match choice.as_str() {
            "1" => {
                if let Err(e) = handle_persona_list_action(http_client, io_handler).await {
                    io_handler.write_line(&format!("Error listing personas: {}", e))?;
                }
            }
            "2" => {
                io_handler.write_line("Creating a new persona...")?;
                let name = io_handler.read_line("Enter persona name: ")?;
                let description = io_handler.read_line("Enter persona description: ")?;
                let system_prompt_str = io_handler
                    .read_line("Enter system prompt (optional, press Enter to skip): ")?;
                let system_prompt = if system_prompt_str.trim().is_empty() {
                    None
                } else {
                    Some(system_prompt_str)
                };

                // TODO: Add prompts for other fields in PersonaCreateArgs as desired
                // spec, spec_version, personality, scenario, first_mes, mes_example, post_history_instructions, tags, avatar

                let create_args = scribe_cli::PersonaCreateArgs {
                    name,
                    description,
                    system_prompt,
                    spec: None,
                    spec_version: None,
                    personality: None,
                    scenario: None,
                    first_mes: None,
                    mes_example: None,
                    post_history_instructions: None,
                    tags: None,
                    avatar: None,
                };
                if let Err(e) =
                    handle_persona_create_action(http_client, io_handler, create_args).await
                {
                    io_handler.write_line(&format!("Error creating persona: {}", e))?;
                }
            }
            "3" => {
                let id_str = io_handler.read_line("Enter Persona ID to view: ")?;
                match uuid::Uuid::parse_str(&id_str) {
                    Ok(id) => {
                        let get_args = scribe_cli::PersonaGetArgs { id };
                        if let Err(e) =
                            handle_persona_get_action(http_client, io_handler, get_args).await
                        {
                            io_handler.write_line(&format!("Error viewing persona: {}", e))?;
                        }
                    }
                    Err(_) => {
                        io_handler.write_line("Invalid Persona ID format.")?;
                    }
                }
            }
            "4" => {
                let id_str = io_handler.read_line("Enter Persona ID to update: ")?;
                match uuid::Uuid::parse_str(&id_str) {
                    Ok(id) => {
                        io_handler
                            .write_line("Enter new values. Press Enter to keep current value.")?;
                        let name_str = io_handler.read_line("New name (optional): ")?;
                        let name = if name_str.trim().is_empty() {
                            None
                        } else {
                            Some(name_str)
                        };

                        let description_str =
                            io_handler.read_line("New description (optional): ")?;
                        let description = if description_str.trim().is_empty() {
                            None
                        } else {
                            Some(description_str)
                        };

                        let system_prompt_str =
                            io_handler.read_line("New system prompt (optional): ")?;
                        let system_prompt = if system_prompt_str.trim().is_empty() {
                            None
                        } else {
                            Some(system_prompt_str)
                        };

                        // TODO: Add prompts for other updatable fields in PersonaUpdateArgs
                        // spec, spec_version, personality, scenario, first_mes, mes_example, post_history_instructions, tags, avatar

                        if name.is_none() && description.is_none() && system_prompt.is_none()
                        /* && other_fields.is_none()... */
                        {
                            io_handler.write_line("No changes specified. Aborting update.")?;
                        } else {
                            let update_args = scribe_cli::PersonaUpdateArgs {
                                id,
                                name,
                                description,
                                system_prompt,
                                spec: None, // Add other fields as None or prompt for them
                                spec_version: None,
                                personality: None,
                                scenario: None,
                                first_mes: None,
                                mes_example: None,
                                post_history_instructions: None,
                                tags: None,
                                avatar: None,
                            };
                            if let Err(e) =
                                handle_persona_update_action(http_client, io_handler, update_args)
                                    .await
                            {
                                io_handler.write_line(&format!("Error updating persona: {}", e))?;
                            }
                        }
                    }
                    Err(_) => {
                        io_handler.write_line("Invalid Persona ID format.")?;
                    }
                }
            }
            "5" => {
                let id_str = io_handler.read_line("Enter Persona ID to delete: ")?;
                match uuid::Uuid::parse_str(&id_str) {
                    Ok(id) => {
                        let confirm = io_handler.read_line(&format!(
                            "Are you sure you want to delete persona {}? (yes/no): ",
                            id_str
                        ))?;
                        if confirm.trim().to_lowercase() == "yes" {
                            let delete_args = scribe_cli::PersonaDeleteArgs { id };
                            if let Err(e) =
                                handle_persona_delete_action(http_client, io_handler, delete_args)
                                    .await
                            {
                                io_handler.write_line(&format!("Error deleting persona: {}", e))?;
                            }
                        } else {
                            io_handler.write_line("Deletion cancelled.")?;
                        }
                    }
                    Err(_) => {
                        io_handler.write_line("Invalid Persona ID format.")?;
                    }
                }
            }
            "6" => {
                // Set Default Persona
                // Create empty args struct as the handler will prompt for ID
                let set_default_args = scribe_cli::PersonaSetDefaultArgs { id: None };
                if let Err(e) =
                    handle_persona_set_default_action(http_client, io_handler, set_default_args)
                        .await
                {
                    io_handler.write_line(&format!("Error setting default persona: {}", e))?;
                }
            }
            "7" => {
                // Clear Default Persona
                let clear_default_args = scribe_cli::PersonaClearDefaultArgs {};
                if let Err(e) =
                    handle_persona_clear_default_action(http_client, io_handler, clear_default_args)
                        .await
                {
                    io_handler.write_line(&format!("Error clearing default persona: {}", e))?;
                }
            }
            "b" => return Ok(MenuNavigation::ReturnToMainMenu),
            _ => io_handler.write_line("Invalid choice. Please try again.")?,
        }
    }
}

#[cfg(test)]
mod tests {
    use scribe_cli::Parser; // Import the Parser trait for parse_from
    // No super::* needed if all items are from scribe_cli or std/other crates

    #[test]
    fn test_arg_parsing() {
        // CliArgs is now from scribe_cli
        let args =
            scribe_cli::CliArgs::parse_from(["scribe-cli", "--base-url", "https://example.com"]);
        assert_eq!(args.base_url.to_string(), "https://example.com/");
    }
}
