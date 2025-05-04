// backend/src/auth/user_store.rs
use async_trait::async_trait;
use axum_login::{AuthnBackend, UserId};
use std::fmt::{self, Debug};
// Assuming User ID is Uuid
use tracing::{debug, error, info, instrument, warn};

use crate::auth::AuthError;
use crate::models::auth::LoginPayload; // Import LoginPayload
use crate::models::users::User; // Assuming your User model is here
// Remove UserCredentials import if no longer needed elsewhere in this file
use crate::state::DbPool; // Assuming you use a DbPool

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
    type Credentials = LoginPayload; // Use LoginPayload
    type Error = AuthError; // Your custom AuthError enum

    #[instrument(skip(self, creds), err)]
    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Implementation using crate::auth::verify_credentials (which will be updated)
        let pool = self.pool.clone();
        let identifier = creds.identifier.clone(); // Use identifier from LoginPayload
        let password = creds.password.clone();

        // --- Log before interact ---
        info!(identifier = %identifier, "AuthBackend: Authenticating via verify_credentials interact call...");

        // Clone identifier for use after interact
        let identifier_for_logging = identifier.clone();

        let verify_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            // Pass identifier to verify_credentials
            .interact(move |conn| crate::auth::verify_credentials(conn, &identifier, password))
            .await
            .map_err(AuthError::from)? // Use From trait for InteractError -> AuthError
            ;

        // Match the Result directly
        match verify_result {
            Ok(user) => {
                // --- Log success ---
                info!(identifier = %identifier_for_logging, username = %user.username, email = %user.email, user_id = %user.id, "AuthBackend: Authentication successful.");
                Ok(Some(user))
            }
            Err(AuthError::WrongCredentials) => {
                // --- Log wrong creds ---
                warn!(identifier = %identifier_for_logging, "AuthBackend: Authentication failed (Wrong Credentials).");
                Ok(None)
            }
            Err(AuthError::UserNotFound) => {
                // --- Log user not found ---
                warn!(identifier = %identifier_for_logging, "AuthBackend: Authentication failed (User Not Found).");
                Ok(None)
            }
            Err(e) => {
                // --- Log other error ---
                error!(identifier = %identifier_for_logging, error = ?e, "AuthBackend: Authentication failed (Other Error).");
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
