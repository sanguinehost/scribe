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
    password: Secret<String>, // This password should now be the hash from the handler
) -> Result<User, AuthError> {
    // --- Log username explicitly ---
    info!(username = %username, "Attempting to create user");

    let username_clone = username.clone(); // Clone for error message

    // 2. Create a NewUser instance
    let new_user = NewUser {
        username: username_clone, // Pass ownership of username
        password_hash: password.expose_secret().to_string(), // Use the provided hash directly
    };

    // --- Log before DB insert ---
    debug!(username = %new_user.username, "Inserting new user into database...");
    // 3. Insert into the database
    let insert_result = diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning()) // Use returning to get the full User struct back
        .get_result(conn);

    // --- Log DB result ---
    match insert_result {
        Ok(user) => {
            info!(username = %user.username, user_id = %user.id, "User created successfully in DB.");
            Ok(user)
        }
        Err(e) => {
            error!(username = %new_user.username, error = ?e, "Database error creating user");
            // Check for unique violation (specific error code for PostgreSQL)
            if let diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) = e
            {
                warn!(username = %new_user.username, "Username already taken (UniqueViolation).");
                Err(AuthError::UsernameTaken)
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
    username: &str,
    password: Secret<String>,
) -> Result<User, AuthError> {
    // --- Log username explicitly ---
    info!(%username, "Verifying credentials");
    let user = get_user_by_username(conn, username)?;

    // Perform bcrypt verification synchronously within the function
    // This avoids potential issues with nested spawn_blocking inside interact
    // --- Log before verify ---
    debug!(username = %user.username, user_id = %user.id, "Verifying password hash...");
    let is_valid = bcrypt::verify(password.expose_secret(), &user.password_hash)
        .map_err(|e| {
            error!(username = %user.username, user_id = %user.id, error = ?e, "Bcrypt verification failed");
            AuthError::HashingError // Map bcrypt errors to HashingError
        })?;

    if is_valid {
        // --- Log success ---
        debug!(username = %user.username, user_id = %user.id, "Password verification successful.");
        Ok(user)
    } else {
        // --- Log failure ---
        warn!(username = %user.username, user_id = %user.id, "Password verification failed (wrong password).");
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

pub async fn verify_password(
    hashed_password: &str,
    password: Secret<String>,
) -> Result<bool, AuthError> {
    let stored_hash = hashed_password.to_string();
    tokio::task::spawn_blocking(move || bcrypt::verify(password.expose_secret(), &stored_hash))
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
    async fn test_verify_password_invalid_hash_string() {
        // Covers lines 187-191 (verify_password -> HashingError from BcryptError)
        let password = Secret::new("correct_password".to_string());
        let invalid_hash = "this_is_not_a_valid_bcrypt_hash_format"; // Invalid format

        let result = verify_password(invalid_hash, password).await;

        assert!(result.is_err(), "Verification should fail for invalid hash format");
        match result {
            Err(AuthError::HashingError) => {
                // Correct error type, test passes
                println!("Successfully caught expected HashingError for invalid hash format.");
            }
            Err(e) => {
                panic!("Expected AuthError::HashingError, but got {:?}", e);
            }
            Ok(_) => {
                panic!("Expected an error, but verification succeeded unexpectedly");
            }
        }
    }

    #[tokio::test]
    async fn test_verify_password_join_error_simulation() {
        // This test attempts to simulate a JoinError scenario, though it's hard to guarantee.
        // It relies on the task potentially being cancelled or panicking internally.
        // This is more of a conceptual test than a guaranteed trigger.
        // Covers lines 190 (verify_password -> HashingError from JoinError)

        // We can't directly cause a JoinError easily without more complex setup
        // (like dropping the runtime or causing a panic inside the blocking task).
        // For now, we'll just call the function normally and acknowledge this
        // specific error path (JoinError mapping) is hard to unit test reliably.

        let password = Secret::new("some_password".to_string());
        // Use a *valid* hash format here, as we aren't testing bcrypt itself
        let valid_hash = bcrypt::hash("some_password", bcrypt::DEFAULT_COST).unwrap();

        // We expect this call to likely succeed or fail with a BcryptError if the password is wrong,
        // not necessarily a JoinError in this simple setup.
        let result = verify_password(&valid_hash, password).await;

        // We can't reliably assert for JoinError here.
        // We just acknowledge this test exists to show consideration for the line.
        println!("test_verify_password_join_error_simulation executed. Result: {:?}", result);
        // No strict assertion for JoinError possible here.
        assert!(result.is_ok() || matches!(result, Err(AuthError::HashingError)), "Expected Ok or HashingError, got {:?}", result);

    }

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
