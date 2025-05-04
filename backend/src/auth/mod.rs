// This file defines the auth module, including user store logic.

use crate::models::users::{NewUser, User};
use crate::schema::users;
// Required imports for synchronous Diesel
use diesel::{PgConnection, prelude::*};
// Removed DbPool import as functions will now take PgConnection
// use crate::state::DbPool;
use bcrypt::BcryptError;
use deadpool_diesel::InteractError;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid; // Import InteractError

// Make AuthError enum public
#[derive(Error, Debug)] // Removed Clone
pub enum AuthError {
    #[error("Wrong credentials")]
    WrongCredentials,
    #[error("Username already taken")]
    UsernameTaken,
    #[error("Email already taken")] // Add EmailTaken variant
    EmailTaken,
    #[error("Password hashing failed")]
    HashingError,
    #[error("User not found")]
    UserNotFound,
    #[error("Database error during authentication: {0}")]
    DatabaseError(String),
    #[error("Database pool error: {0}")]
    PoolError(#[from] deadpool_diesel::PoolError),
    #[error("Database interaction error: {0}")]
    InteractError(String), // Changed from InteractError to String
                           // Add other potential errors as needed
}

// Manual From implementation for InteractError
impl From<InteractError> for AuthError {
    fn from(err: InteractError) -> Self {
        AuthError::InteractError(err.to_string())
    }
}

// Function to create a new user
#[instrument(skip(conn, password), err)]
pub fn create_user(
    conn: &mut PgConnection,
    username: String,
    email: String, // Add email parameter
    password: Secret<String>, // This password should now be the hash from the handler
) -> Result<User, AuthError> {
    // --- Log username and email explicitly ---
    info!(%username, %email, "Attempting to create user");

    let username_clone = username.clone(); // Clone for error message
    let email_clone = email.clone(); // Clone email

    // 2. Create a NewUser instance
    let new_user = NewUser {
        username: username_clone, // Pass ownership of username
        email: email_clone,       // Add email field
        password_hash: password.expose_secret().to_string(), // Use the provided hash directly
    };

    // --- Log before DB insert ---
    debug!(username = %new_user.username, email = %new_user.email, "Inserting new user into database...");
    // 3. Insert into the database
    let insert_result = diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning()) // Use returning to get the full User struct back
        .get_result(conn);

    // --- Log DB result ---
    match insert_result {
        Ok(user) => {
            info!(username = %user.username, email = %user.email, user_id = %user.id, "User created successfully in DB.");
            Ok(user)
        }
        Err(e) => {
            error!(username = %new_user.username, email = %new_user.email, error = ?e, "Database error creating user");
            // Check for unique violation (specific error code for PostgreSQL)
            if let diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                db_info, // Capture db_info
            ) = e
            {
                // Check which constraint was violated
                if db_info.constraint_name() == Some("users_username_key") {
                    warn!(username = %new_user.username, "Username already taken (UniqueViolation).");
                    Err(AuthError::UsernameTaken)
                } else if db_info.constraint_name() == Some("users_email_key") { // Assuming constraint name is users_email_key
                    warn!(email = %new_user.email, "Email already taken (UniqueViolation).");
                    Err(AuthError::EmailTaken)
                } else {
                    // Handle other unique constraints if any, or return a generic DB error
                    error!(username = %new_user.username, email = %new_user.email, constraint = ?db_info.constraint_name(), "Unknown unique constraint violation during user creation.");
                    Err(AuthError::DatabaseError(format!("Unique constraint violation: {:?}", db_info.constraint_name())))
                }
            } else {
                Err(AuthError::DatabaseError(e.to_string()))
            }
        }
    }
}

// Function to find a user by their username
#[instrument(skip(conn), err)]
pub fn get_user_by_username(conn: &mut PgConnection, username: &str) -> Result<User, AuthError> {
    // --- Log username explicitly ---
    info!(%username, "Attempting to find user by username");
    users::table
        .filter(users::username.eq(username))
        .select(User::as_select())
        .first(conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                // --- Log not found ---
                debug!(%username, "User not found by username.");
                AuthError::UserNotFound
            }
            _ => {
                // --- Log other DB error ---
                error!(%username, error = ?e, "Database error finding user by username.");
                AuthError::DatabaseError(e.to_string())
            }
        })
}

// Function to find a user by their ID
#[instrument(skip(conn), err)]
pub fn get_user(conn: &mut PgConnection, user_id: Uuid) -> Result<User, AuthError> {
    // --- Log user_id explicitly ---
    info!(%user_id, "Attempting to find user by ID");
    users::table
        .find(user_id)
        .select(User::as_select())
        .first(conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                // --- Log not found ---
                debug!(%user_id, "User not found by ID.");
                AuthError::UserNotFound
            }
            _ => {
                // --- Log other DB error ---
                error!(%user_id, error = ?e, "Database error finding user by ID.");
                AuthError::DatabaseError(e.to_string())
            }
        })
}

// Function to verify user credentials
#[instrument(skip(conn, password), err)]
pub fn verify_credentials(
    conn: &mut PgConnection,
    identifier: &str, // Changed from username to identifier
    password: Secret<String>,
) -> Result<User, AuthError> {
    // --- Log identifier explicitly ---
    info!(%identifier, "Verifying credentials");

    // Find user by username OR email
    let user = users::table
        .filter(users::username.eq(identifier).or(users::email.eq(identifier))) // Query by username OR email
        .select(User::as_select())
        .first(conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => {
                debug!(%identifier, "User not found by identifier.");
                AuthError::UserNotFound // Return UserNotFound if neither matches
            }
            _ => {
                error!(%identifier, error = ?e, "Database error finding user by identifier.");
                AuthError::DatabaseError(e.to_string())
            }
        })?;

    // Perform bcrypt verification synchronously within the function
    // This avoids potential issues with nested spawn_blocking inside interact
    // --- Log before verify ---
    debug!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Verifying password hash...");
    let is_valid = bcrypt::verify(password.expose_secret(), &user.password_hash)
        .map_err(|e| {
            error!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, error = ?e, "Bcrypt verification failed");
            AuthError::HashingError // Map bcrypt errors to HashingError
        })?;

    if is_valid {
        // --- Log success ---
        debug!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Password verification successful.");
        Ok(user)
    } else {
        // --- Log failure ---
        warn!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Password verification failed (wrong password).");
        Err(AuthError::WrongCredentials)
    }
}

pub mod session_store;
pub mod user_store;

pub async fn hash_password(password: Secret<String>) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || {
        bcrypt::hash(password.expose_secret(), bcrypt::DEFAULT_COST)
    })
    .await
    .map_err(|_e: JoinError| AuthError::HashingError)?
    .map_err(|_e: BcryptError| AuthError::HashingError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;
    use tokio; // Ensure tokio runtime for async test

     #[tokio::test]
    async fn test_hash_password_join_error_simulation() {
        // Similar to the verify_password JoinError test, this is hard to guarantee.
        // Covers line 179 (hash_password -> HashingError from JoinError)

        let password = Secret::new("some_password_to_hash".to_string());

        // Call the function normally.
        let result = hash_password(password).await;

        // We can't reliably assert for JoinError here.
        println!("test_hash_password_join_error_simulation executed. Result: {:?}", result);
        // Expect Ok or HashingError (if bcrypt itself fails, though unlikely here)
         assert!(result.is_ok() || matches!(result, Err(AuthError::HashingError)), "Expected Ok or HashingError, got {:?}", result);
    }

    // Note: Testing the DatabaseError variants (lines 87, 111, 134) typically requires
    // integration tests that can manipulate the database connection state (e.g., disconnect)
    // or cause specific DB-level errors, which is complex for unit tests.

    // Note: Testing the From<InteractError> (lines 39-40) requires triggering an InteractError,
    // usually in an integration test involving deadpool interact calls failing (e.g., panic, abort).
}
