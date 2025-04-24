// This file defines the auth module, including user store logic.

use crate::models::users::{NewUser, User};
use crate::schema::users;
// Required imports for synchronous Diesel
use diesel::{prelude::*, PgConnection};
// Removed DbPool import as functions will now take PgConnection
// use crate::state::DbPool;
use secrecy::{ExposeSecret, Secret};
use tracing::{error, info, instrument, debug, warn};
use uuid::Uuid;
use thiserror::Error;
use tokio::task::JoinError;
use bcrypt::BcryptError;
use deadpool_diesel::InteractError; // Import InteractError

const BCRYPT_COST: u32 = 12; // Standard bcrypt cost factor

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
    password: Secret<String>,
) -> Result<User, AuthError> {
    // --- Log username explicitly ---
    info!(username = %username, "Attempting to create user");

    let username_clone = username.clone(); // Clone for error message
    let username_clone_for_hash_err = username.clone(); // Clone for hash error message

    // --- Log before hashing ---
    debug!(username = %username_clone_for_hash_err, "Hashing password using spawn_blocking...");
    let hashed_password = tokio::runtime::Handle::current().block_on(async move {
        tokio::task::spawn_blocking(move || {
            bcrypt::hash(password.expose_secret(), BCRYPT_COST)
        })
        .await
        .map_err(|e: JoinError| {
            // --- Log JoinError --- 
            error!(username=%username_clone_for_hash_err, error=%e, "Hashing task failed (JoinError)");
            AuthError::HashingError
        })?
        .map_err(|e: BcryptError| {
            // --- Log BcryptError ---
            error!(username=%username_clone_for_hash_err, error=%e, "Hashing failed (BcryptError)");
            AuthError::HashingError
        })
    })?;
    // --- Log after hashing ---
    debug!(username = %username_clone, "Password hashing successful.");

    // 2. Create a NewUser instance
    let new_user = NewUser {
        username: username_clone, // Pass ownership of username
        password_hash: hashed_password, // Pass owned String
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
    tokio::task::spawn_blocking(move || bcrypt::hash(password.expose_secret(), bcrypt::DEFAULT_COST))
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