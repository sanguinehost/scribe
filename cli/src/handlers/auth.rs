use crate::client::HttpClient;
use crate::error::CliError;
use crate::io::IoHandler;
use scribe_backend::models::auth::LoginPayload;
use scribe_backend::models::users::User;
use secrecy::SecretString;
use crate::client::RegisterPayload;

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
        password: SecretString::new(password.into_boxed_str())
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
        password: SecretString::new(password.into_boxed_str())
    };
    client.register(&credentials).await
}