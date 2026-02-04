// backend/src/auth/user_store.rs
use async_trait::async_trait;

use axum_login::{AuthnBackend, UserId};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc; // Keep Arc
use tokio::sync::RwLock; // Change to tokio::sync::RwLock
                         // Assuming User ID is Uuid
use tracing::{debug, error, info, instrument, warn};

use crate::auth::AuthError;
use crate::models::auth::LoginPayload; // Import LoginPayload
use crate::models::users::{AccountStatus, NewUser, SerializableSecretDek, User, UserDbQuery}; // Removed unused SerializableSecretDek, UserCredentials // Added SerializableSecretDek
use crate::privacy::logging::loggable_user_id;
// Remove UserCredentials import if no longer needed elsewhere in this file
use crate::state::DbPool; // Assuming you use a DbPool
                          // diesel imports are used in cfg blocks where they're imported locally
                          // Added for as_returning // Added for get_result
                          // use crate::models::users::{UserFilter, UserIdentifier}; // Removed unused imports
use crate::schema;
use anyhow::Context;
use secrecy::{ExposeSecret, SecretBox, SecretString};

pub struct UserCryptoFields {
    pub password_hash: Option<String>,
    pub dek_ciphertext: Option<crate::db::DbBlob>,
    pub dek_nonce: Option<crate::db::DbBlob>,
    pub kek_salt: Option<String>,
    pub recovery_dek_ciphertext: Option<crate::db::DbBlob>,
    pub recovery_dek_nonce: Option<crate::db::DbBlob>,
}

// Manually implement Debug because DbPool doesn't implement it.
pub struct Backend {
    pool: DbPool,
    pub dek_cache: Arc<RwLock<HashMap<crate::db::DbId, SerializableSecretDek>>>,
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

        // Call the free function from crate::auth module
        let verify_result = crate::db::with_conn(&pool, move |conn| {
            // Unwrap the Result inside the closure so with_conn returns Result<Tuple, AppError> not Result<Result<Tuple, AppError>, AppError>
            let result = crate::auth::verify_credentials(conn, &identifier_clone, password_clone)
                .map_err(|e| {
                crate::errors::AppError::DatabaseQueryError(format!(
                    "Credential verification failed: {}",
                    e
                ))
            })?;
            Ok(result)
        })
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match verify_result {
            (mut user, Some(dek_secret_box)) => {
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
            (user, None) => {
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
        }
    }

    #[instrument(skip(self), err)]
    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let pool = self.pool.clone();
        let id = *user_id;

        // Added detailed logging for test_get_unauthorized debugging
        tracing::warn!(target: "auth_debug", "AuthBackend::get_user called with user_id from session: {}", loggable_user_id(*user_id));
        tracing::warn!(target: "auth_debug", "AuthBackend::get_user (UUID): {}", id);

        info!(user_id = %id, "AuthBackend: Getting user via crate::auth::get_user...");

        // Get user from database
        match crate::db::with_conn(&pool, move |conn| {
            crate::auth::get_user(conn, id).map_err(|e| {
                crate::errors::AppError::DatabaseQueryError(format!("Get user failed: {}", e))
            })
        })
        .await
        {
            Ok(mut user_from_db) => {
                // user_from_db is of type User
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
            Err(app_err) => {
                // Check if the error message indicates UserNotFound
                let err_msg = app_err.to_string();
                if err_msg.contains("User not found") || err_msg.contains("UserNotFound") {
                    debug!(user_id = %id, "AuthBackend::get_user: User not found.");
                    Ok(None)
                } else {
                    error!(user_id = %id, error = ?app_err, "AuthBackend::get_user: Error from get_user.");
                    Err(AuthError::DatabaseError(app_err.to_string()))
                }
            }
        }
    }
}

impl Backend {
    #[instrument(skip(self, crypto_fields), err)]
    pub async fn update_user_crypto_fields(
        &self,
        user_id: crate::db::DbId,
        crypto_fields: UserCryptoFields,
    ) -> Result<(), AuthError> {
        use crate::schema::users::dsl::{
            encrypted_dek, encrypted_dek_by_recovery, kek_salt, password_hash, updated_at, users,
        };
        use diesel::prelude::*;

        let pool = self.pool.clone();

        info!(user_id = %user_id, "AuthBackend: Updating password and encryption keys for user.");

        let update_result = crate::db::with_conn(&pool, move |conn| {
            // Validate required fields (non-nullable in DB)
            let pwd_hash = crypto_fields.password_hash.ok_or_else(|| {
                crate::errors::AppError::DatabaseQueryError("password_hash must be provided".into())
            })?;
            let kek_salt_value = crypto_fields.kek_salt.ok_or_else(|| {
                crate::errors::AppError::DatabaseQueryError("kek_salt must be provided".into())
            })?;
            let dek_ciphertext = crypto_fields.dek_ciphertext.ok_or_else(|| {
                crate::errors::AppError::DatabaseQueryError("encrypted_dek must be provided".into())
            })?;
            let dek_nonce_value = crypto_fields.dek_nonce.ok_or_else(|| {
                crate::errors::AppError::DatabaseQueryError("dek_nonce must be provided".into())
            })?;

            diesel::update(users.find(user_id))
                .set((
                    password_hash.eq(pwd_hash),
                    kek_salt.eq(kek_salt_value),
                    encrypted_dek.eq(dek_ciphertext),
                    crate::schema::users::dsl::dek_nonce.eq(dek_nonce_value),
                    encrypted_dek_by_recovery.eq(crypto_fields.recovery_dek_ciphertext), // This is nullable
                    crate::schema::users::dsl::recovery_dek_nonce
                        .eq(crypto_fields.recovery_dek_nonce), // This is nullable
                    updated_at.eq(crate::db::DbTimestamp::now()), // Use Rust timestamp instead of diesel::dsl::now for cross-DB compatibility
                ))
                .execute(conn)
                .map_err(|e| crate::errors::AppError::DatabaseQueryError(e.to_string()))
        })
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match update_result {
            0 => {
                warn!(user_id = %user_id, "AuthBackend: Update password and keys failed, user not found during update.");
                Err(AuthError::UserNotFound) // Or a more specific error
            }
            _ => {
                info!(user_id = %user_id, "AuthBackend: Successfully updated password and encryption keys.");
                Ok(())
            }
        }
    }

    /// Removes the DEK from the in-memory cache for a given user.
    /// This should be called when a user logs out to ensure their DEK
    /// is not kept in memory after their session ends.
    #[instrument(skip(self))]
    pub async fn remove_dek_from_cache(&self, user_id: &crate::db::DbId) {
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
///
/// # Errors
///
/// Returns an error if:
/// - Database connection cannot be obtained
/// - Password hashing fails
/// - Cryptographic operations (salt generation, DEK generation/encryption) fail
/// - Database insertion fails
/// - Any other database or system error occurs
pub async fn create_user_in_db(
    pool: &crate::db::DbPool,
    username: &str,
    password_str: &str,
    email: &str,
    plaintext_dek_opt: Option<SecretString>,
) -> Result<UserDbQuery, anyhow::Error> {
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
        id: crate::db::DbId::new(),
        username: username.to_string(),
        password_hash,
        email: email.to_string(),
        kek_salt,
        encrypted_dek: crate::db::DbBlob::from(encrypted_dek_bytes),
        dek_nonce: crate::db::DbBlob::from(dek_nonce_bytes),
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: crate::models::users::UserRole::User, // 'User' enum variant for DB
        account_status: AccountStatus::Active,      // Default to Active account status
        total_prompt_tokens: crate::db::DbBigInt::from(0),
        total_completion_tokens: crate::db::DbBigInt::from(0),
        total_token_cost_cents: crate::db::DbBigInt::from(0),
        tokens_last_reset_at: None,
        token_usage_updated_at: crate::db::DbTimestamp::now(),
        created_at: crate::db::DbTimestamp::now(),
        updated_at: crate::db::DbTimestamp::now(),
    };

    let user_from_db: UserDbQuery = crate::db::with_conn(pool, move |conn| {
        #[cfg(feature = "postgres-backend")]
        {
            use diesel::prelude::*;
            diesel::insert_into(schema::users::table)
                .values(new_user_payload)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
                .map_err(|e| {
                    crate::errors::AppError::DatabaseQueryError(format!(
                        "Diesel query failed for create_user_in_db: {}",
                        e
                    ))
                })
        }

        #[cfg(feature = "sqlite-backend")]
        {
            use diesel::prelude::*;
            // SQLite doesn't support RETURNING, so we insert and query back by username
            let username_clone = new_user_payload.username.clone();
            diesel::insert_into(schema::users::table)
                .values(new_user_payload)
                .execute(conn)
                .map_err(|e| {
                    crate::errors::AppError::DatabaseQueryError(format!(
                        "Diesel insert failed for create_user_in_db: {}",
                        e
                    ))
                })?;

            schema::users::table
                .filter(schema::users::username.eq(username_clone))
                .first::<UserDbQuery>(conn)
                .map_err(|e| {
                    crate::errors::AppError::DatabaseQueryError(format!(
                        "Diesel query failed for create_user_in_db (fetch after insert): {}",
                        e
                    ))
                })
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB operation failed for create_user_in_db: {}", e))?;

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
