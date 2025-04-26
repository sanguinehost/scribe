// backend/src/auth/user_store.rs
use async_trait::async_trait;
use axum_login::{AuthnBackend, UserId};
use std::fmt::{self, Debug};
// Assuming User ID is Uuid
use tracing::{debug, error, info, instrument, warn};

use crate::auth::AuthError;
use crate::models::users::User; // Assuming your User model is here
use crate::models::users::UserCredentials;
use crate::state::DbPool; // Assuming you use a DbPool // <-- ADD import for model's credentials

// Manually implement Debug because DbPool doesn't implement it.
#[derive(Clone)]
pub struct Backend {
    pool: DbPool,
    // Optional in-memory cache if needed
    // users: Arc<RwLock<HashMap<Uuid, User>>,
}

// Manual Debug implementation
impl Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("pool", &"<DbPool>") // Avoid printing the pool
            .finish()
    }
}

impl Backend {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User; // Your User struct
    type Credentials = UserCredentials; // <-- USE the imported one
    type Error = AuthError; // Your custom AuthError enum

    #[instrument(skip(self, creds), err)]
    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Implementation using crate::auth::verify_credentials
        let pool = self.pool.clone();
        let username = creds.username.clone();
        let password = creds.password.clone();

        // --- Log before interact ---
        info!(username = %username, "AuthBackend: Authenticating via verify_credentials interact call...");

        let verify_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| crate::auth::verify_credentials(conn, &username, password))
            .await
            .map_err(AuthError::from)? // Use From trait for InteractError -> AuthError
            ;

        // Match the Result directly
        match verify_result {
            Ok(user) => {
                // --- Log success ---
                info!(username = %user.username, user_id = %user.id, "AuthBackend: Authentication successful.");
                Ok(Some(user))
            }
            Err(AuthError::WrongCredentials) => {
                // --- Log wrong creds ---
                warn!(username = %creds.username, "AuthBackend: Authentication failed (Wrong Credentials).");
                Ok(None)
            }
            Err(AuthError::UserNotFound) => {
                // --- Log user not found ---
                warn!(username = %creds.username, "AuthBackend: Authentication failed (User Not Found).");
                Ok(None)
            }
            Err(e) => {
                // --- Log other error ---
                error!(username = %creds.username, error = ?e, "AuthBackend: Authentication failed (Other Error).");
                Err(e)
            }
        }
    }

    #[instrument(skip(self), err)]
    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let pool = self.pool.clone();
        let id: uuid::Uuid = *user_id;

        // --- Log before interact ---
        info!(user_id = %id, "AuthBackend: Getting user via get_user interact call...");

        let get_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| crate::auth::get_user(conn, id))
            .await
            .map_err(AuthError::from)? // Use From trait
            ;

        // Match the Result directly
        match get_result {
            Ok(user) => {
                // --- Log success ---
                info!(user_id = %user.id, username = %user.username, "AuthBackend: Get user successful.");
                Ok(Some(user))
            }
            Err(AuthError::UserNotFound) => {
                // --- Log not found ---
                debug!(user_id = %id, "AuthBackend: Get user failed (User Not Found).");
                Ok(None) // User not found is not an error for get_user, return None
            }
            Err(e) => {
                // --- Log other error ---
                error!(user_id = %id, error = ?e, "AuthBackend: Get user failed (Other Error).");
                Err(e)
            }
        }
    }
}

// Optional: Implement AuthzBackend if needed for permissions
// #[async_trait]
// impl AuthzBackend for Backend {
//     type Permission = String; // Example permission type
//
//     async fn has_permission(
//         &self,
//         user: &Self::User,
//         permission: &Self::Permission,
//     ) -> Result<bool, Self::Error> {
//         // Implement permission checking logic here
//         Ok(true) // Placeholder
//     }
// }
