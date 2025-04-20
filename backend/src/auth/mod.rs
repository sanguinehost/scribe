// This file defines the auth module, including user store logic.

use crate::models::users::{NewUser, User};
use crate::schema::users;
// Required imports for synchronous Diesel
use diesel::{prelude::*, PgConnection};
// Removed DbPool import as functions will now take PgConnection
// use crate::state::DbPool;
use secrecy::{ExposeSecret, Secret};
use tracing::{error, info, instrument};
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
    DatabaseError(#[from] diesel::result::Error),
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
#[instrument(skip(conn, username, password), err)]
pub fn create_user(
    conn: &mut PgConnection,
    username: String,
    password: Secret<String>,
) -> Result<User, AuthError> {
    info!(%username, "Attempting to create user");

    let username_clone = username.clone(); // Clone for error message
    let username_clone_for_hash_err = username.clone(); // Clone for hash error message
    let hashed_password = tokio::runtime::Handle::current().block_on(async move {
        tokio::task::spawn_blocking(move || {
            bcrypt::hash(password.expose_secret(), BCRYPT_COST)
        })
        .await
        .map_err(|_e: JoinError| AuthError::HashingError)?
        .map_err(|_e: BcryptError| AuthError::HashingError)
    })?;

    // 2. Create a NewUser instance
    let new_user = NewUser {
        username: username_clone, // Pass ownership of username
        password_hash: &hashed_password, // Pass borrowed hash
    };

    // 3. Insert into the database
    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(User::as_returning()) // Use returning to get the full User struct back
        .get_result(conn)
        .map_err(|e| {
            error!(%e, "Database error creating user: {}", username_clone_for_hash_err);
            // Check for unique violation (specific error code for PostgreSQL)
            if let diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) = e
            {
                AuthError::UsernameTaken
            } else {
                AuthError::DatabaseError(e)
            }
        })
}

// Function to find a user by their username
#[instrument(skip(conn, username), err)]
pub fn get_user_by_username(conn: &mut PgConnection, username: &str) -> Result<User, AuthError> {
    info!(%username, "Attempting to find user by username");
    users::table
        .filter(users::username.eq(username))
        .select(User::as_select())
        .first(conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AuthError::UserNotFound,
            _ => AuthError::DatabaseError(e),
        })
}

// Function to find a user by their ID
#[instrument(skip(conn), err)]
pub fn get_user(conn: &mut PgConnection, user_id: Uuid) -> Result<User, AuthError> {
    info!(%user_id, "Attempting to find user by ID");
    users::table
        .find(user_id)
        .select(User::as_select())
        .first(conn)
        .map_err(|e| match e {
            diesel::result::Error::NotFound => AuthError::UserNotFound,
            _ => AuthError::DatabaseError(e),
        })
}

// Function to verify user credentials
#[instrument(skip(conn, password), err)]
pub fn verify_credentials(
    conn: &mut PgConnection,
    username: &str,
    password: Secret<String>,
) -> Result<User, AuthError> {
    info!(%username, "Verifying credentials");
    let user = get_user_by_username(conn, username)?;

    let stored_hash = user.password_hash.clone();
    let password_clone = password.clone();

    let is_valid = tokio::runtime::Handle::current().block_on(async move {
        tokio::task::spawn_blocking(move || {
            bcrypt::verify(password_clone.expose_secret(), &stored_hash)
        })
        .await
        .map_err(|_e: JoinError| AuthError::HashingError)?
        .map_err(|_e: BcryptError| AuthError::HashingError)
    })?;

    if is_valid {
        Ok(user)
    } else {
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