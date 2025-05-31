// backend/src/auth/user_store.rs
use async_trait::async_trait;
use axum_login::{AuthnBackend, UserId};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc; // Keep Arc
use tokio::sync::RwLock; // Change to tokio::sync::RwLock
// Assuming User ID is Uuid
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::auth::AuthError;
use crate::models::auth::LoginPayload; // Import LoginPayload
use crate::models::users::{AccountStatus, NewUser, SerializableSecretDek, User, UserDbQuery}; // Removed unused SerializableSecretDek, UserCredentials // Added SerializableSecretDek
// Remove UserCredentials import if no longer needed elsewhere in this file
use crate::state::DbPool; // Assuming you use a DbPool
use diesel::RunQueryDsl;
use diesel::SelectableHelper; // Added for as_returning // Added for get_result
// use crate::models::users::{UserFilter, UserIdentifier}; // Removed unused imports
use crate::schema;
use anyhow::Context;
use secrecy::{ExposeSecret, SecretBox, SecretString};

// Manually implement Debug because DbPool doesn't implement it.
pub struct Backend {
    pool: DbPool,
    pub dek_cache: Arc<RwLock<HashMap<Uuid, SerializableSecretDek>>>,
}

// Manual Clone implementation to ensure dek_cache is properly shared
impl Clone for Backend {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            // CRITICAL: Clone the Arc, not create a new one
            // This ensures all Backend instances share the same cache
            dek_cache: self.dek_cache.clone(),
        }
    }
}

// Manual Debug implementation
impl Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backend")
            .field("pool", &"<DbPool>") // Avoid printing the pool
            .field("dek_cache", &"<DekCache>") // Avoid printing the cache
            .finish()
    }
}

impl Backend {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            dek_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl AuthnBackend for Backend {
    type User = User;
    type Credentials = LoginPayload;
    type Error = AuthError;

    #[instrument(skip(self, creds))]
    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        warn!(target: "dek_cache_debug", "AuthBackend::authenticate CALLED");
        let pool = self.pool.clone();
        let identifier_clone = creds.identifier.clone();
        // Assuming SecretString can be cloned; if not, this needs adjustment or pass by ref if possible
        let password_clone = creds.password.clone();

        // Call the free function from crate::auth module within an interact block
        let verify_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| {
                crate::auth::verify_credentials(conn, &identifier_clone, password_clone)
            })
            .await
            .map_err(AuthError::from)?; // Map InteractError to AuthError

        match verify_result {
            Ok((mut user, Some(dek_secret_box))) => {
                // Store the DEK in the cache
                let dek_to_cache = crate::models::users::SerializableSecretDek(dek_secret_box);
                let mut cache = self.dek_cache.write().await; // Use .await
                cache.insert(user.id, dek_to_cache.clone());
                // More verbose logging
                warn!(target: "dek_cache_debug", user_id = %user.id, cache_ptr = ?Arc::as_ptr(&self.dek_cache), cache_size = cache.len(), "AuthBackend::authenticate - DEK CACHED (key: {}, value_present: true)", user.id);

                // CRITICAL: Set the user's DEK to None before returning
                // This prevents axum-login from serializing the DEK into the session
                user.dek = None;
                Ok(Some(user))
            }
            Ok((user, None)) => {
                warn!(user_id = %user.id, "User authenticated but DEK was not available/decryptable during login.");
                // Clear any potentially stale DEK from cache for this user if login proceeds without DEK
                {
                    let mut cache = self.dek_cache.write().await; // Use .await
                    if cache.remove(&user.id).is_some() {
                        warn!(target: "dek_cache_debug", user_id = %user.id, "AuthBackend::authenticate - STALE DEK REMOVED from cache (key: {})", user.id);
                    }
                } // cache lock is dropped here
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
            .interact(move |conn| crate::auth::get_user(conn, id)) // crate::auth::get_user returns User
            .await;

        match interact_result {
            Ok(Ok(mut user_from_db)) => {
                // user_from_db is of type User
                // Inner Ok: crate::auth::get_user succeeded
                info!(user_id = %user_from_db.id, initial_dek_is_some = user_from_db.dek.is_some(), "AuthBackend::get_user: user loaded from DB.");

                // Attempt to populate DEK from cache
                let cache_read_guard = self.dek_cache.read().await; // Use .await
                if let Some(cached_dek) = cache_read_guard.get(&user_from_db.id).cloned() {
                    user_from_db.dek = Some(cached_dek);
                    warn!(target: "dek_cache_debug", user_id = %user_from_db.id, "AuthBackend::get_user - DEK POPULATED FROM CACHE (key: {})", user_from_db.id);
                } else {
                    warn!(target: "dek_cache_debug", user_id = %user_from_db.id, cache_ptr = ?Arc::as_ptr(&self.dek_cache), cache_size = cache_read_guard.len(), "AuthBackend::get_user - DEK NOT FOUND IN CACHE (key: {}). User.dek remains as loaded from DB (should be None).", user_from_db.id);
                }
                Ok(Some(user_from_db))
            }
            Ok(Err(AuthError::UserNotFound)) => {
                // Inner Err: crate::auth::get_user returned UserNotFound
                debug!(user_id = %id, "AuthBackend::get_user: User not found via crate::auth::get_user.");
                Ok(None)
            }
            Ok(Err(other_auth_err)) => {
                // Inner Err: crate::auth::get_user returned other AuthError
                error!(user_id = %id, error = ?other_auth_err, "AuthBackend::get_user: AuthError from crate::auth::get_user.");
                Err(other_auth_err)
            }
            Err(interact_err) => {
                // Outer Err: .interact() itself failed
                error!(user_id = %id, error = %interact_err, "AuthBackend::get_user: InteractError.");
                Err(AuthError::from(interact_err)) // Map InteractError to AuthError
            }
        }
    }
}

impl Backend {
    #[instrument(
        skip(
            self,
            new_password_hash,
            new_dek_ciphertext,
            new_dek_nonce,
            new_kek_salt,
            new_recovery_dek_ciphertext,
            new_recovery_dek_nonce,
        ),
        err
    )]
    #[allow(clippy::too_many_arguments)] // This is a necessary evil for this specific update function
    pub async fn update_user_crypto_fields(
        &self,
        user_id: uuid::Uuid,
        new_password_hash: Option<String>,
        new_dek_ciphertext: Option<Vec<u8>>,
        new_dek_nonce: Option<Vec<u8>>,
        new_kek_salt: Option<String>, // KEK salt is stored as string
        new_recovery_dek_ciphertext: Option<Vec<u8>>, // Added
        new_recovery_dek_nonce: Option<Vec<u8>>,        // Added
    ) -> Result<(), AuthError> {
        use crate::schema::users::dsl::{encrypted_dek, encrypted_dek_by_recovery, kek_salt, password_hash, updated_at, users};
        use diesel::prelude::*;

        let pool = self.pool.clone();

        info!(user_id = %user_id, "AuthBackend: Updating password and encryption keys for user.");

        let update_result = pool
            .get()
            .await
            .map_err(AuthError::PoolError)?
            .interact(move |conn| {
                // Validate required fields (non-nullable in DB)
                let pwd_hash = new_password_hash.ok_or_else(|| {
                    diesel::result::Error::QueryBuilderError("password_hash must be provided".into())
                })?;
                let kek_salt_value = new_kek_salt.ok_or_else(|| {
                    diesel::result::Error::QueryBuilderError("kek_salt must be provided".into())
                })?;
                let dek_ciphertext = new_dek_ciphertext.ok_or_else(|| {
                    diesel::result::Error::QueryBuilderError("encrypted_dek must be provided".into())
                })?;
                let dek_nonce_value = new_dek_nonce.ok_or_else(|| {
                    diesel::result::Error::QueryBuilderError("dek_nonce must be provided".into())
                })?;
                
                diesel::update(users.find(user_id))
                    .set((
                        password_hash.eq(pwd_hash),
                        kek_salt.eq(kek_salt_value),
                        encrypted_dek.eq(dek_ciphertext),
                        crate::schema::users::dsl::dek_nonce.eq(dek_nonce_value),
                        encrypted_dek_by_recovery.eq(new_recovery_dek_ciphertext), // This is nullable
                        crate::schema::users::dsl::recovery_dek_nonce.eq(new_recovery_dek_nonce), // This is nullable
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

    /// Removes the DEK from the in-memory cache for a given user.
    /// This should be called when a user logs out to ensure their DEK
    /// is not kept in memory after their session ends.
    #[instrument(skip(self))]
    pub async fn remove_dek_from_cache(&self, user_id: &uuid::Uuid) {
        let mut cache = self.dek_cache.write().await;
        if cache.remove(user_id).is_some() {
            warn!(target: "dek_cache_debug", user_id = %user_id, "AuthBackend::remove_dek_from_cache - DEK REMOVED from cache (key: {})", user_id);
            info!(user_id = %user_id, "Successfully removed DEK from cache on logout");
        } else {
            debug!(user_id = %user_id, "No DEK found in cache to remove for user");
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
    let conn = pool
        .get()
        .await
        .context("Failed to get DB connection for create_user_in_db")?;

    let password_hash = crate::auth::hash_password(SecretString::from(password_str.to_string()))
        .await
        .context("Password hashing failed")?;

    let kek_salt = crate::crypto::generate_salt().context("KEK salt generation failed")?;

    let dek_to_encrypt: SecretBox<Vec<u8>>;
    if let Some(provided_dek_ss) = plaintext_dek_opt {
        // Convert SecretString to SecretBox<Vec<u8>>
        let dek_bytes = provided_dek_ss.expose_secret().as_bytes().to_vec();
        dek_to_encrypt = SecretBox::new(Box::new(dek_bytes)); // Wrapped dek_bytes in Box::new()
    } else {
        // Assuming generate_dek() now returns Result<SecretBox<Vec<u8>>, CryptoError>
        dek_to_encrypt = crate::crypto::generate_dek().context("DEK generation failed")?;
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
        account_status: AccountStatus::Active,      // Default to Active account status
    };

    let user_from_db: UserDbQuery = conn
        .interact(move |conn_actual| {
            diesel::insert_into(schema::users::table)
                .values(new_user_payload)
                .returning(UserDbQuery::as_returning())
                .get_result::<UserDbQuery>(conn_actual)
        })
        .await
        .map_err(|interact_err| {
            anyhow::anyhow!(
                "DB interaction failed for create_user_in_db: {}",
                interact_err
            )
        })? // Handle InteractError
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
