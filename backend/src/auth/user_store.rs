// backend/src/auth/user_store.rs
use async_trait::async_trait;
use axum_login::{AuthnBackend, UserId};
use secrecy::Secret;
use std::fmt::{self, Debug};
 // Assuming User ID is Uuid

use crate::auth::AuthError;
use crate::models::users::User; // Assuming your User model is here
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
    type Credentials = UserCredentials; // Define a struct for credentials
    type Error = AuthError; // Your custom AuthError enum

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Implementation using crate::auth::verify_credentials
        let pool = self.pool.clone();
        let username = creds.username.clone();
        let password = creds.password.clone();

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
            Ok(user) => Ok(Some(user)), // Verification successful
            Err(AuthError::WrongCredentials) => Ok(None), // Correctly handled auth failure
            Err(AuthError::UserNotFound) => Ok(None), // Correctly handled auth failure
            Err(e) => Err(e), // Propagate other AuthErrors (e.g., DatabaseError from within verify_credentials)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let pool = self.pool.clone();
        let id: uuid::Uuid = *user_id;

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
            Ok(user) => Ok(Some(user)), // User found
            Err(AuthError::UserNotFound) => Ok(None), // User not found is not an error for get_user, return None
            Err(e) => Err(e), // Propagate other AuthErrors (e.g., DatabaseError from within get_user)
        }
    }
}

// Placeholder struct for credentials, adjust as needed
#[derive(Clone, Debug)]
pub struct UserCredentials {
    pub username: String,
    pub password: Secret<String>,
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