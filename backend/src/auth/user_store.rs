// backend/src/auth/user_store.rs
use async_trait::async_trait;
use axum_login::{AuthnBackend, UserId};
use std::fmt::{self, Debug};
// Assuming User ID is Uuid
use tracing::{debug, error, info, instrument, warn};

use crate::auth::AuthError;
use crate::models::auth::LoginPayload; // Import LoginPayload
use crate::models::users::{AccountStatus, User, UserDbQuery, NewUser}; // Removed unused SerializableSecretDek, UserCredentials
// Remove UserCredentials import if no longer needed elsewhere in this file
use crate::state::DbPool; // Assuming you use a DbPool
use diesel::SelectableHelper; // Added for as_returning
use diesel::RunQueryDsl; // Added for get_result
// use crate::models::users::{UserFilter, UserIdentifier}; // Removed unused imports
use crate::schema;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use anyhow::Context;

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
    type User = User;
    type Credentials = LoginPayload;
    type Error = AuthError;

    #[instrument(skip(self, creds))]
    async fn authenticate(&self, creds: Self::Credentials) -> Result<Option<Self::User>, Self::Error> {
        let pool = self.pool.clone();
        let identifier_clone = creds.identifier.clone();
        // Assuming SecretString can be cloned; if not, this needs adjustment or pass by ref if possible
        let password_clone = creds.password.clone(); 

        // Call the free function from crate::auth module within an interact block
        let verify_result = pool.get().await.map_err(AuthError::PoolError)?
            .interact(move |conn| crate::auth::verify_credentials(conn, &identifier_clone, password_clone))
            .await
            .map_err(AuthError::from)?; // Map InteractError to AuthError
        
        match verify_result {
            Ok((user, Some(dek_secret_box))) => {
                let mut user_with_dek = user;
                user_with_dek.dek = Some(crate::models::users::SerializableSecretDek(dek_secret_box));
                Ok(Some(user_with_dek))
            }
            Ok((user, None)) => {
                warn!(user_id = %user.id, "User authenticated but DEK was not available/decryptable during login.");
                Ok(Some(user)) 
            }
            Err(e) => Err(e), 
        }
    }

    #[instrument(skip(self), err)]
    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let pool = self.pool.clone();
        let id: uuid::Uuid = *user_id;

        // Added detailed logging for test_get_unauthorized debugging
        tracing::warn!(target: "auth_debug", "AuthBackend::get_user called with user_id from session: {:?}", user_id);
        tracing::warn!(target: "auth_debug", "AuthBackend::get_user (UUID): {}", id);


        info!(user_id = %id, "AuthBackend: Getting user via crate::auth::get_user...");

        // interact returns Result<Result<User, AuthError>, InteractError>
        let interact_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| crate::auth::get_user(conn, id))
            .await;

        match interact_result {
            Ok(Ok(user_from_db)) => { // Inner Ok: crate::auth::get_user succeeded
                info!(user_id = %user_from_db.id, dek_is_some = user_from_db.dek.is_some(), "AuthBackend::get_user: user loaded from DB (DEK is None as crate::auth::get_user doesn't decrypt it)."); // Removed PII: username
                Ok(Some(user_from_db))
            }
            Ok(Err(AuthError::UserNotFound)) => { // Inner Err: crate::auth::get_user returned UserNotFound
                debug!(user_id = %id, "AuthBackend::get_user: User not found via crate::auth::get_user.");
                Ok(None)
            }
            Ok(Err(other_auth_err)) => { // Inner Err: crate::auth::get_user returned other AuthError
                error!(user_id = %id, error = ?other_auth_err, "AuthBackend::get_user: AuthError from crate::auth::get_user.");
                Err(other_auth_err)
            }
            Err(interact_err) => { // Outer Err: .interact() itself failed
                error!(user_id = %id, error = %interact_err, "AuthBackend::get_user: InteractError.");
                Err(AuthError::from(interact_err)) // Map InteractError to AuthError
            }
        }
    }
}

impl Backend {
    #[instrument(skip(self, new_password_hash, new_kek_salt, new_encrypted_dek, new_dek_nonce, new_encrypted_dek_by_recovery, new_recovery_dek_nonce), err)]
    pub async fn update_password_and_encryption_keys(
        &self,
        user_id: uuid::Uuid,
        new_password_hash: String,
        new_kek_salt: String, // KEK salt might not change if password changes, but DEK is re-encrypted with new KEK
        new_encrypted_dek: Vec<u8>,
        new_dek_nonce: Vec<u8>, // Added
        new_encrypted_dek_by_recovery: Option<Vec<u8>>, // This would also need re-encryption if recovery phrase is involved
        new_recovery_dek_nonce: Option<Vec<u8>>, // Added
    ) -> Result<(), AuthError> {
        use crate::schema::users::dsl::*;
        use diesel::prelude::*;

        let pool = self.pool.clone();

        info!(user_id = %user_id, "AuthBackend: Updating password and encryption keys for user.");

        let update_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| {
                diesel::update(users.find(user_id))
                    .set((
                        password_hash.eq(new_password_hash),
                        kek_salt.eq(new_kek_salt), // Assuming KEK salt might be updated or is passed even if same
                        encrypted_dek.eq(new_encrypted_dek),
                        crate::schema::users::dsl::dek_nonce.eq(new_dek_nonce), // Added
                        encrypted_dek_by_recovery.eq(new_encrypted_dek_by_recovery),
                        crate::schema::users::dsl::recovery_dek_nonce.eq(new_recovery_dek_nonce), // Added
                        updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(conn)
            })
            .await
            .map_err(AuthError::from)?; // Handles InteractError

        match update_result {
            Ok(0) => {
                warn!(user_id = %user_id, "AuthBackend: Update password and keys failed, user not found during update.");
                Err(AuthError::UserNotFound) // Or a more specific error
            }
            Ok(_) => {
                info!(user_id = %user_id, "AuthBackend: Successfully updated password and encryption keys.");
                Ok(())
            }
            Err(diesel_error) => {
                error!(user_id = %user_id, error = ?diesel_error, "AuthBackend: Database error during password and keys update.");
                Err(AuthError::DatabaseError(diesel_error.to_string()))
            }
        }
    }
}

/// Creates a user directly in the database.
///
/// This function handles:
/// - Password hashing.
/// - KEK salt generation.
/// - DEK generation (if not provided) and encryption using KEK.
/// - Insertion of the new user record.
///
/// It returns a `UserDbQuery` which is the representation of the user from the database schema.
pub async fn create_user_in_db(
    pool: &crate::PgPool,
    username: &str,
    password_str: &str,
    email: &str,
    plaintext_dek_opt: Option<SecretString>,
) -> Result<UserDbQuery, anyhow::Error> {
    let conn = pool.get().await.context("Failed to get DB connection for create_user_in_db")?;

    let password_hash = crate::auth::hash_password(SecretString::from(password_str.to_string()))
        .await
        .context("Password hashing failed")?;

    let kek_salt = crate::crypto::generate_salt()
        .context("KEK salt generation failed")?;

    let dek_to_encrypt: SecretBox<Vec<u8>>;
    if let Some(provided_dek_ss) = plaintext_dek_opt {
        // Convert SecretString to SecretBox<Vec<u8>>
        let dek_bytes = provided_dek_ss.expose_secret().as_bytes().to_vec();
        dek_to_encrypt = SecretBox::new(Box::new(dek_bytes)); // Wrapped dek_bytes in Box::new()
    } else {
        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        dek_to_encrypt = crate::crypto::generate_dek()
            .context("DEK generation failed")?;
    }

    let kek = crate::crypto::derive_kek(&SecretString::from(password_str.to_string()), &kek_salt)
        .context("KEK derivation failed")?;

    let (encrypted_dek_bytes, dek_nonce_bytes) =
        crate::crypto::encrypt_gcm(dek_to_encrypt.expose_secret(), &kek) // expose_secret() on SecretBox<Vec<u8>> gives &Vec<u8>
            .context("DEK encryption failed")?;

    let new_user_payload = NewUser {
        username: username.to_string(),
        password_hash,
        email: email.to_string(),
        kek_salt,
        encrypted_dek: encrypted_dek_bytes,
        dek_nonce: dek_nonce_bytes,
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: crate::models::users::UserRole::User, // 'User' enum variant for DB
        account_status: AccountStatus::Active, // Default to Active account status
    };

    let user_from_db: UserDbQuery = conn.interact(move |conn_actual| {
        diesel::insert_into(schema::users::table)
            .values(new_user_payload)
            .returning(UserDbQuery::as_returning())
            .get_result::<UserDbQuery>(conn_actual)
    })
    .await
    .map_err(|interact_err| anyhow::anyhow!("DB interaction failed for create_user_in_db: {}", interact_err))? // Handle InteractError
    .context("Diesel query failed for create_user_in_db")?; // Handle inner Diesel error

    Ok(user_from_db)
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
