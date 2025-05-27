use crate::client::HttpClient;
use crate::client::RegisterPayload;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::auth::LoginPayload;
use scribe_backend::models::users::User;
use secrecy::SecretString;

/// Handler function for the login action
pub async fn handle_login_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<User, CliError> {
    io_handler.write_line("\nPlease log in.")?;
    let username = io_handler.read_line("Username:")?;
    let password = io_handler.read_line("Password:")?;
    let credentials = LoginPayload {
        identifier: username,
        password: SecretString::new(password.into_boxed_str()),
    };
    client.login(&credentials).await
}

/// Handler function for the registration action
pub async fn handle_registration_action<H: IoHandler, C: HttpClient>(
    client: &C,
    io_handler: &mut H,
) -> Result<User, CliError> {
    io_handler.write_line("\nPlease register a new user.")?;
    let username = io_handler.read_line("Choose Username:")?;
    let email = io_handler.read_line("Enter Email:")?;
    let password = io_handler.read_line("Choose Password:")?;

    if username.len() < 3 {
        return Err(CliError::InputError(
            "Username must be at least 3 characters long.".into(),
        ));
    }
    if password.len() < 8 {
        return Err(CliError::InputError(
            "Password must be at least 8 characters long.".into(),
        ));
    }

    let credentials = RegisterPayload {
        username,
        email,
        password: SecretString::new(password.into_boxed_str()),
    };

    // Register the user
    let user = client.register(&credentials).await?;

    // Get the recovery key from the user
    if let Some(recovery_key) = client.get_last_recovery_key() {
        io_handler
            .write_line("\n┌─────────────────────────────────────────────────────────────┐")?;
        io_handler
            .write_line("│ IMPORTANT: Save your recovery key in a secure location!      │")?;
        io_handler
            .write_line("│ You will need this key to recover your account if you forget │")?;
        io_handler
            .write_line("│ your password. This key will not be shown again.             │")?;
        io_handler.write_line("└─────────────────────────────────────────────────────────────┘")?;

        io_handler.write_line("\nA recovery key has been generated for your account.")?;
        io_handler.write_line("Make sure you are in a secure location before viewing it.")?;

        loop {
            let choice = io_handler.read_line("\nChoose an option:\n  1. Display recovery key in terminal\n  2. Skip (I'll manage my account without recovery key)\nEnter your choice (1 or 2):")?;

            match choice.trim() {
                "1" => {
                    io_handler
                        .write_line("\n⚠️  RECOVERY KEY - DO NOT SHARE THIS WITH ANYONE ⚠️")?;
                    io_handler.write_line(&format!("\n{}", recovery_key))?;
                    io_handler
                        .write_line("\n⚠️  Make sure to save this key in a secure location ⚠️")?;
                    io_handler.write_line("\nPress Enter when you have saved the key...")?;
                    let _ = io_handler.read_line("")?;
                    break;
                }
                "2" => {
                    io_handler.write_line("\n⚠️  WARNING: Without a recovery key, you cannot recover your account if you forget your password!")?;
                    let confirm =
                        io_handler.read_line("Are you sure you want to skip? (yes/no):")?;
                    if confirm.trim().to_lowercase() == "yes" {
                        io_handler.write_line(
                            "\nRecovery key skipped. You can set up recovery later if needed.",
                        )?;
                        break;
                    }
                }
                _ => {
                    io_handler.write_line("Invalid choice. Please enter 1 or 2.")?;
                }
            }
        }
    }

    Ok(user)
}
