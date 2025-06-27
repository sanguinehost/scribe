use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use uuid::Uuid;

/// Handler function for listing all users (admin only)
pub async fn handle_list_all_users_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nListing all users...")?;

    match client.admin_list_users().await {
        Ok(users) => {
            if users.is_empty() {
                io_handler.write_line("No users found.")?;
                return Ok(());
            }

            // Table header
            io_handler.write_line("\nUSER ID                               | USERNAME             | ROLE           | STATUS")?;
            io_handler.write_line(
                "----------------------------------------------------------------------",
            )?;

            // Print each user
            for user in users {
                io_handler.write_line(&format!(
                    "{:<36} | {:<20} | {:<14} | {}",
                    user.id, user.username, user.role, user.account_status
                ))?;
            }
        }
        Err(e) => {
            io_handler.write_line(&format!("\nError listing users: {e}"))?;
        }
    }

    Ok(())
}

/// Handler function for viewing details of a specific user (admin only)
pub async fn handle_view_user_details_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nView user details")?;

    // Prompt for the user ID or username
    let user_identifier = io_handler.read_line("Enter user ID or username:")?;
    if user_identifier.is_empty() {
        return Err(CliError::InputError(
            "User ID or username cannot be empty".to_string(),
        ));
    }

    // Parse as UUID if possible, otherwise treat as username
    let user_detail_result = if let Ok(user_id) = Uuid::parse_str(&user_identifier) {
        io_handler.write_line(&format!("\nViewing details for user ID: {user_id}"))?;
        client.admin_get_user(user_id).await
    } else {
        io_handler.write_line(&format!(
            "\nViewing details for username: {user_identifier}"
        ))?;
        client.admin_get_user_by_username(&user_identifier).await
    };

    match user_detail_result {
        Ok(user) => {
            io_handler.write_line("\nUSER DETAILS")?;
            io_handler.write_line("============")?;
            io_handler.write_line(&format!("ID:             {}", user.id))?;
            io_handler.write_line(&format!("Username:       {}", user.username))?;
            io_handler.write_line(&format!("Email:          {}", user.email))?;
            io_handler.write_line(&format!("Role:           {}", user.role))?;
            io_handler.write_line(&format!("Account Status: {}", user.account_status))?;
            io_handler.write_line(&format!("Created:        {}", user.created_at))?;
            io_handler.write_line(&format!("Last Updated:   {}", user.updated_at))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("\nError retrieving user details: {e}"))?;
        }
    }

    Ok(())
}

/// Handler function for changing a user's role (admin only)
pub async fn handle_change_user_role_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nChange user role")?;

    // Prompt for the user ID or username
    let user_identifier = io_handler.read_line("Enter user ID or username:")?;
    if user_identifier.is_empty() {
        return Err(CliError::InputError(
            "User ID or username cannot be empty".to_string(),
        ));
    }

    // Get user ID
    let user_id = match Uuid::parse_str(&user_identifier) {
        Ok(id) => id,
        Err(_) => {
            // Handle as username - need to look up the ID first
            match client.admin_get_user_by_username(&user_identifier).await {
                Ok(user) => user.id,
                Err(e) => {
                    io_handler.write_line(&format!("\nError finding user: {e}"))?;
                    return Ok(());
                }
            }
        }
    };

    // Prompt for the new role
    io_handler.write_line("\nSelect new role:")?;
    io_handler.write_line("[1] User")?;
    io_handler.write_line("[2] Moderator")?;
    io_handler.write_line("[3] Administrator")?;

    let role_choice = io_handler.read_line("Enter role choice:")?;
    let new_role = match role_choice.as_str() {
        "1" => "User",
        "2" => "Moderator",
        "3" => "Administrator",
        _ => {
            return Err(CliError::InputError(
                "Invalid role choice. Please select 1, 2, or 3.".to_string(),
            ));
        }
    };

    io_handler.write_line(&format!("\nChanging role to '{new_role}'..."))?;

    match client.admin_update_user_role(user_id, new_role).await {
        Ok(updated_user) => {
            io_handler.write_line(&format!(
                "Role successfully changed. User '{}' is now a '{}'.",
                updated_user.username, updated_user.role
            ))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("\nError changing user role: {e}"))?;
        }
    }

    Ok(())
}

/// Handler function for locking/unlocking a user account (admin only)
pub async fn handle_lock_unlock_user_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<(), CliError> {
    io_handler.write_line("\nLock/Unlock user account")?;

    // Prompt for the user ID or username
    let user_identifier = io_handler.read_line("Enter user ID or username:")?;
    if user_identifier.is_empty() {
        return Err(CliError::InputError(
            "User ID or username cannot be empty".to_string(),
        ));
    }

    // Get user ID
    let user_id = match Uuid::parse_str(&user_identifier) {
        Ok(id) => id,
        Err(_) => {
            // Handle as username - need to look up the ID first
            match client.admin_get_user_by_username(&user_identifier).await {
                Ok(user) => user.id,
                Err(e) => {
                    io_handler.write_line(&format!("\nError finding user: {e}"))?;
                    return Ok(());
                }
            }
        }
    };

    // Prompt for lock or unlock action
    io_handler.write_line("\nSelect action:")?;
    io_handler.write_line("[1] Lock account")?;
    io_handler.write_line("[2] Unlock account")?;

    let action_choice = io_handler.read_line("Enter action choice:")?;
    let action = match action_choice.as_str() {
        "1" => "lock",
        "2" => "unlock",
        _ => {
            return Err(CliError::InputError(
                "Invalid action choice. Please select 1 or 2.".to_string(),
            ));
        }
    };

    // Get username for confirmation message
    let username = match client.admin_get_user(user_id).await {
        Ok(user) => user.username,
        Err(_) => user_id.to_string(), // Fallback to ID if we can't get the username
    };

    io_handler.write_line(&format!(
        "\n{} account for user '{}'...",
        if action == "lock" {
            "Locking"
        } else {
            "Unlocking"
        },
        username
    ))?;

    // Perform the action
    let result = if action == "lock" {
        client.admin_lock_user(user_id).await
    } else {
        client.admin_unlock_user(user_id).await
    };

    match result {
        Ok(_) => {
            io_handler.write_line(&format!("User account successfully {action}ed."))?;
        }
        Err(e) => {
            io_handler.write_line(&format!("\nError {action}ing user account: {e}"))?;
        }
    }

    Ok(())
}

