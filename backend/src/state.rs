// Use deadpool-diesel types for async pooling
use crate::auth; // Import auth module
use crate::auth::AuthError; // Import AuthError enum
use crate::errors::AppError;
use crate::models::users::{User, UserCredentials};
use async_trait::async_trait;
use axum_login::{AuthUser, AuthnBackend};
use deadpool_diesel::postgres::Pool as DeadpoolDieselPool;
use diesel::PgConnection;
use tracing::{info, instrument};
use anyhow::anyhow; // Ensure anyhow is imported

// --- DB Connection Pool Type ---
pub type DbPool = DeadpoolDieselPool;
// Note: deadpool::Pool is already Cloneable.

// --- Shared application state ---
#[derive(Clone)] // Removed Debug as AuthnBackend doesn't require it
pub struct AppState {
    pub pool: DbPool,
}

// --- Implement AuthnBackend for AppState ---
#[async_trait]
impl AuthnBackend for AppState {
    // Specify the associated types required by AuthnBackend
    type User = User; // Our user model
    type Credentials = UserCredentials; // Credentials struct from models::users
    type Error = AppError; // Our application error type

    // Method to authenticate based on credentials
    #[instrument(skip(self, credentials), err)]
    async fn authenticate(
        &self, // Use &self to access the pool within AppState
        credentials: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        info!(username = %credentials.username, "AppState AuthnBackend: Authenticating user");
        let pool = self.pool.clone();
        let username = credentials.username.clone();
        let password = credentials.password.clone();

        // Use pool.get().await?.interact(...)
        let conn = pool.get().await.map_err(AppError::DbPoolError)?;
        // Run interact, map InteractError, then handle inner Result<User, AuthError>
        let user_result = conn.interact(move |conn: &mut PgConnection| {
            auth::verify_credentials(conn, &username, password)
        })
        .await
        .map_err(|interact_err| AppError::InternalServerError(anyhow!(interact_err.to_string())))?;

        // Match on Result<User, AuthError>
        match user_result {
            Ok(user) => Ok(Some(user)),
            Err(AuthError::WrongCredentials) => Ok(None),
            Err(e) => Err(AppError::AuthError(e)), // Propagate other AuthErrors
        }
    }

    // Method to retrieve user details based on user ID (from session)
    #[instrument(skip(self), err)]
    async fn get_user(
        &self, // Use &self to access the pool
        user_id: &<Self::User as AuthUser>::Id, // Use associated type for clarity
    ) -> Result<Option<Self::User>, Self::Error> {
        info!(%user_id, "AppState AuthnBackend: Getting user from session ID");
        let pool = self.pool.clone();
        let user_id = *user_id; // Copy Uuid

        // Use pool.get().await?.interact(...)
        let conn = pool.get().await.map_err(AppError::DbPoolError)?;
        // Run interact, map InteractError, then handle inner Result<User, AuthError>
        let user_result = conn.interact(move |conn: &mut PgConnection| {
             auth::get_user(conn, user_id)
         })
         .await
         .map_err(|interact_err| AppError::InternalServerError(anyhow!(interact_err.to_string())))?;

        // Match on Result<User, AuthError>
        match user_result {
            Ok(user) => Ok(Some(user)),
            Err(AuthError::UserNotFound) => Ok(None),
            Err(e) => Err(AppError::AuthError(e)), // Propagate other AuthErrors
        }
    }
}
