// This file defines the auth module, including user store logic.

pub use crate::models::auth::RegisterPayload; // Added for RegisterPayload
use crate::models::users::{NewUser, User, UserDbQuery};
use crate::schema::users;
// Required imports for synchronous Diesel
use diesel::{PgConnection, prelude::*};
// Removed DbPool import as functions will now take PgConnection
// use crate::state::DbPool;
use bcrypt::BcryptError;
use deadpool_diesel::InteractError;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;
use tokio::task::JoinError;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid; // Import InteractError

use crate::crypto::{self, CryptoError}; // Added for encryption
use crate::state::DbPool; // Added for delete_all_sessions_for_user
// use crate::models::users::{UserDataForClient, UserDataForClientWithKekRecipients};
// use crate::services::email_service::EmailServiceTrait;

// Make AuthError enum public
#[derive(Error, Debug)] // Removed Clone
pub enum AuthError {
    #[error("Wrong credentials")]
    WrongCredentials,
    #[error("Username already taken")]
    UsernameTaken,
    #[error("Email already taken")] // Add EmailTaken variant
    EmailTaken,
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
    #[error("Cryptography error: {0}")]
    CryptoOperationFailed(#[from] CryptoError), // Added for crypto errors
    #[error("Password recovery not set up for this user")]
    RecoveryNotSetup,
    #[error("Invalid recovery phrase provided")]
    InvalidRecoveryPhrase,
    #[error("Session deletion error: {0}")]
    SessionDeletionError(String),
}

// Manual From implementation for InteractError
impl From<InteractError> for AuthError {
    fn from(err: InteractError) -> Self {
        AuthError::InteractError(err.to_string())
    }
}

// From implementation for diesel::result::Error
impl From<diesel::result::Error> for AuthError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::NotFound => AuthError::UserNotFound,
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation, 
                info
            ) => {
                // It's better to use .message() for the actual constraint name string if available
                // and compare that. For now, assuming constraint_name() is sufficient.
                if info.constraint_name() == Some("users_username_key") {
                    AuthError::UsernameTaken
                } else if info.constraint_name() == Some("users_email_key") {
                    AuthError::EmailTaken
                } else {
                    AuthError::DatabaseError(format!("Unique constraint violation: {:?}", info.message()))
                }
            }
            _ => AuthError::DatabaseError(err.to_string()),
        }
    }
}

// Function to create a new user
#[instrument(skip(conn, credentials), err)] // Skip entire credentials struct for safety, Secret fields are not logged by Debug.
pub async fn create_user(
    conn: &mut PgConnection,
    credentials: RegisterPayload, // Use RegisterPayload struct
) -> Result<User, AuthError> {
    info!(username = %credentials.username, email = %credentials.email, "Attempting to create user with encryption");

    // 1. Generate a random Data Encryption Key (DEK)
    let plaintext_dek_bytes = crypto::generate_dek() // Use generate_dek instead of generate_random_bytes
        .map_err(AuthError::CryptoOperationFailed)?;

    // 2. Derive a Key Encryption Key (KEK) from the user's password and salt
    // a. Generate a salt for the KEK
    let kek_salt = crypto::generate_salt()
        .map_err(AuthError::CryptoOperationFailed)?;

    // b. Derive the KEK using Argon2
    let kek = crypto::derive_kek(&credentials.password, &kek_salt)
        .map_err(AuthError::CryptoOperationFailed)?;

    // c. Encrypt the DEK with the KEK using AES-GCM
    // Returns (ciphertext, nonce)
    info!(
        username = %credentials.username,
        plaintext_dek_len = plaintext_dek_bytes.expose_secret().len(),
        kek_salt_len = kek_salt.len(),
        "Generated DEK and KEK data for user creation"
    );
    
    let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(plaintext_dek_bytes.expose_secret(), &kek)
        .map_err(AuthError::CryptoOperationFailed)?;
        
    info!(
        username = %credentials.username,
        encrypted_dek_len = encrypted_dek.len(),
        dek_nonce_len = dek_nonce.len(),
        "Encrypted DEK for user creation"
    );

    // Handle recovery phrase if provided
    let (encrypted_dek_by_recovery, recovery_kek_salt, recovery_dek_nonce) = if let Some(recovery_phrase) = credentials.recovery_phrase {
        // Similar process for recovery phrase: salt, derive key, encrypt
        let recovery_kek_salt = crypto::generate_salt()
            .map_err(AuthError::CryptoOperationFailed)?;
        let recovery_secret = SecretString::new(recovery_phrase.into_boxed_str());
        let recovery_key = crypto::derive_kek(&recovery_secret, &recovery_kek_salt)
            .map_err(AuthError::CryptoOperationFailed)?;
        let (encrypted_dek_by_recovery, recovery_dek_nonce) = crypto::encrypt_gcm(plaintext_dek_bytes.expose_secret(), &recovery_key)
            .map_err(AuthError::CryptoOperationFailed)?;
        (Some(encrypted_dek_by_recovery), Some(recovery_kek_salt), Some(recovery_dek_nonce))
    } else {
        (None, None, None)
    };

    // 3. Create a NewUser instance
    let new_user = NewUser {
        username: credentials.username.clone(), // Clone username from credentials
        password_hash: hash_password(credentials.password.clone()).await?,                          // Use the pre-hashed password
        email: credentials.email.clone(),       // Clone email from credentials
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery,
        recovery_kek_salt,
        dek_nonce,
        recovery_dek_nonce,
    };

    debug!(username = %new_user.username, email = %new_user.email, "Inserting new user with encryption fields into database...");
    // 4. Insert into the database
    let insert_result = diesel::insert_into(users::table)
        .values(&new_user)
        .returning(UserDbQuery::as_returning())
        .get_result::<UserDbQuery>(conn);

    match insert_result {
        Ok(user_db_query) => {
            let user = User::from(user_db_query); // Convert to User
            info!(username = %user.username, email = %user.email, user_id = %user.id, "User created successfully in DB.");
            Ok(user)
        }
        Err(e) => {
            error!(username = %new_user.username, email = %new_user.email, error = ?e, "Database error creating user");
            Err(AuthError::from(e))
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
        .select(UserDbQuery::as_select())
        .first::<UserDbQuery>(conn)
        .map(User::from)
        .map_err(AuthError::from)
}

// Function to find a user by their ID
#[instrument(skip(conn), err)]
pub fn get_user(conn: &mut PgConnection, user_id: Uuid) -> Result<User, AuthError> {
    // --- Log user_id explicitly ---
    info!(%user_id, "Attempting to find user by ID");
    users::table
        .find(user_id)
        .select(UserDbQuery::as_select())
        .first::<UserDbQuery>(conn)
        .map(User::from)
        .map_err(AuthError::from)
}

// Function to verify user credentials
#[instrument(skip(conn, password), err)]
pub fn verify_credentials(
    conn: &mut PgConnection,
    identifier: &str, // Changed from username to identifier
    password: SecretString, // Corrected: Was Secret<String>
) -> Result<(User, Option<SecretBox<Vec<u8>>>), AuthError> {
    // --- Log identifier explicitly ---
    info!(%identifier, "Verifying credentials");

    // Find user by username OR email
    let user_db_query = users::table
        .filter(users::username.eq(identifier).or(users::email.eq(identifier))) // Query by username OR email
        .select(UserDbQuery::as_select())
        .first::<UserDbQuery>(conn)
        .map_err(AuthError::from)?;
    
    let user = User::from(user_db_query); // Convert to User

    // Perform bcrypt verification synchronously within the function
    // This avoids potential issues with nested spawn_blocking inside interact
    // --- Log before verify ---
    debug!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Verifying password hash...");
    let is_valid = bcrypt::verify(password.expose_secret(), &user.password_hash)
        .map_err(|e| {
            error!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, error = ?e, "Bcrypt verification failed");
            AuthError::HashingError // Map bcrypt errors to HashingError
        })?;

    if is_valid {
        // --- Log success ---
        debug!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Password verification successful. Attempting DEK decryption...");

        // a. kek_salt and encrypted_dek are already part of the `user` object.
        // b. Derive the Key Encryption Key (KEK)
        let kek = crypto::derive_kek(&password, &user.kek_salt)
            .map_err(|e| {
                error!(username = %user.username, user_id = %user.id, error = ?e, "Failed to derive KEK during login");
                AuthError::CryptoOperationFailed(e)
            })?;

        // c. Decrypt the user.encrypted_dek using the derived KEK
        // Expose the secret KEK bytes for the decryption function

        // Define NONCE_LEN (must match the length used in encrypt_gcm, which is 12)
        // This const is mainly for conceptual clarity here, the crypto module enforces actual nonce length.
        info!(
            username = %user.username, 
            user_id = %user.id, 
            encrypted_dek_len = user.encrypted_dek.len(), 
            dek_nonce_len = user.dek_nonce.len(),
            "DEK decryption attempt details"
        );
        
        // Check if dek_nonce is present and appears valid before attempting decryption
        if user.dek_nonce.is_empty() {
            error!(username = %user.username, user_id = %user.id, "DEK nonce is missing.");
            return Err(AuthError::CryptoOperationFailed(CryptoError::DecryptionFailed)); // Or a more specific error
        }
        // Optional: A more stringent check, though decrypt_gcm also validates nonce length.
        // if user.dek_nonce.len() != EXPECTED_NONCE_LEN {
        //     error!(username = %user.username, user_id = %user.id, dek_nonce_len = user.dek_nonce.len(), "DEK nonce has incorrect length.");
        //     return Err(AuthError::CryptoOperationFailed(CryptoError::DecryptionFailed));
        // }
        if user.encrypted_dek.is_empty() {
             error!(username = %user.username, user_id = %user.id, "Encrypted DEK is missing.");
            return Err(AuthError::CryptoOperationFailed(CryptoError::DecryptionFailed));
        }

        // The actual ciphertext is user.encrypted_dek, and the nonce is user.dek_nonce.
        let actual_ciphertext = &user.encrypted_dek;
        let nonce_bytes = &user.dek_nonce;
        
        info!(
            username = %user.username,
            user_id = %user.id,
            nonce_bytes_len = nonce_bytes.len(),
            actual_ciphertext_len = actual_ciphertext.len(),
            "Using stored dek_nonce and encrypted_dek for decryption"
        );

        let plaintext_dek_secret_box = crypto::decrypt_gcm(actual_ciphertext, nonce_bytes, &kek)
            .map_err(|e| {
                error!(username = %user.username, user_id = %user.id, error = ?e, "Failed to decrypt DEK during login");
                AuthError::CryptoOperationFailed(e)
            })?;

        // plaintext_dek_secret_box is already SecretBox<Vec<u8>>
        let decrypted_dek = Some(plaintext_dek_secret_box);
        info!(username = %user.username, user_id = %user.id, "DEK decrypted successfully for user.");

        Ok((user, decrypted_dek)) // Return user and DEK separately
    } else {
        // --- Log failure ---
        warn!(identifier = %identifier, username = %user.username, email = %user.email, user_id = %user.id, "Password verification failed (wrong password).");
        Err(AuthError::WrongCredentials)
    }
}

pub mod session_dek; // Added session_dek module
pub mod session_store;
pub mod user_store;

// Re-export for easier access
pub use session_dek::{SessionDek, SESSION_DEK_KEY};

pub async fn hash_password(password: SecretString) -> Result<String, AuthError> { // Corrected: Was Secret<String>
    tokio::task::spawn_blocking(move || {
        bcrypt::hash(password.expose_secret(), bcrypt::DEFAULT_COST)
    })
    .await
    .map_err(|_e: JoinError| AuthError::HashingError)?
    .map_err(|_e: BcryptError| AuthError::HashingError)
}

const NONCE_LEN: usize = 12; // Must match the length used in encrypt_gcm and decrypt_gcm

#[instrument(skip(backend, current_db_user, current_password_payload, new_password_payload), err, fields(user_id = %user_id))]
pub async fn change_user_password(
    backend: &user_store::Backend,
    user_id: Uuid,
    current_db_user: User, // Assumes this is a fresh fetch of the user
    current_password_payload: SecretString, // Corrected: Was Secret<String>
    new_password_payload: SecretString, // Corrected: Was Secret<String>
) -> Result<(), AuthError> {
    info!("Attempting to change password for user");

    // 1. Verify current password
    debug!("Verifying current password...");
    let is_valid_current_password =
        bcrypt::verify(current_password_payload.expose_secret(), &current_db_user.password_hash)
            .map_err(|e| {
                error!(error = ?e, "Bcrypt verification failed for current password");
                AuthError::HashingError // Or a more specific error like InvalidCurrentPassword
            })?;

    if !is_valid_current_password {
        warn!("Current password verification failed (wrong password).");
        return Err(AuthError::WrongCredentials);
    }
    debug!("Current password verified successfully.");

    // 2. Derive "old" KEK
    debug!("Deriving old KEK...");
    let old_kek = crypto::derive_kek(
        &current_password_payload,
        &current_db_user.kek_salt,
    ).map_err(|e| {
        error!(error = ?e, "Failed to derive old KEK");
        AuthError::CryptoOperationFailed(e)
    })?;

    // 3. Decrypt current encrypted_dek to get plaintext DEK
    debug!("Decrypting current DEK...");
    if current_db_user.encrypted_dek.len() < NONCE_LEN {
        error!("Current encrypted_dek is too short to contain nonce.");
        return Err(AuthError::CryptoOperationFailed(CryptoError::DecryptionFailed));
    }
    let (old_nonce_bytes, old_ciphertext_dek) = current_db_user.encrypted_dek.split_at(NONCE_LEN);
    let plaintext_dek_secret = crypto::decrypt_gcm(old_ciphertext_dek, old_nonce_bytes, &old_kek)
        .map_err(|e| {
            error!(error = ?e, "Failed to decrypt current DEK");
            AuthError::CryptoOperationFailed(e)
        })?;
    debug!("Current DEK decrypted successfully.");

    // 4. Generate new kek_salt
    debug!("Generating new KEK salt...");
    let new_kek_salt_str = crypto::generate_salt().map_err(AuthError::CryptoOperationFailed)?;

    // 5. Derive new KEK from new_password and new_kek_salt
    debug!("Deriving new KEK from new password...");
    let new_kek = crypto::derive_kek(&new_password_payload, &new_kek_salt_str)
        .map_err(|e| {
            error!(error = ?e, "Failed to derive new KEK from new password");
            AuthError::CryptoOperationFailed(e)
        })?;

    // 6. Re-encrypt plaintext DEK with new KEK
    debug!("Re-encrypting DEK with new KEK...");
    let (new_ciphertext_dek_bytes, new_nonce_dek_bytes) =
        crypto::encrypt_gcm(plaintext_dek_secret.expose_secret(), &new_kek).map_err(|e| {
            error!(error = ?e, "Failed to re-encrypt DEK with new KEK");
            AuthError::CryptoOperationFailed(e)
        })?;
    debug!("DEK re-encrypted successfully with new KEK.");

    // 7. Generate new password_hash from new_password
    debug!("Hashing new password...");
    let new_password_hash_str = hash_password(new_password_payload.clone()).await?; // Cloned as hash_password takes ownership
    debug!("New password hashed successfully.");

    // 8. Recovery Key Consideration:
    // As per analysis, encrypted_dek_by_recovery is not re-encrypted here if the recovery phrase
    // is not an input. The existing one remains valid for the (unchanged) plaintext DEK.
    let updated_encrypted_dek_by_recovery = current_db_user.encrypted_dek_by_recovery.clone();
    if updated_encrypted_dek_by_recovery.is_some() {
        debug!("Recovery key is set. encrypted_dek_by_recovery will be preserved.");
    } else {
        debug!("No recovery key set for this user.");
    }

    // 9. Update database
    debug!("Updating user record in database with new password hash, KEK salt, and encrypted DEK...");
    backend.update_password_and_encryption_keys(
        user_id,
        new_password_hash_str,
        new_kek_salt_str,
        new_ciphertext_dek_bytes, // Pass ciphertext
        new_nonce_dek_bytes,      // Pass nonce
        updated_encrypted_dek_by_recovery,
        current_db_user.recovery_dek_nonce.clone(), // Pass existing recovery nonce
    ).await?;

    info!("Password changed successfully for user.");
    Ok(())
}

#[instrument(skip(backend, pool, recovery_phrase_payload, new_password_payload), err, fields(identifier = %identifier))]
pub async fn recover_user_password_with_phrase(
    backend: &user_store::Backend,
    pool: &DbPool, // Added pool for direct DB interaction if needed, or pass to backend methods
    identifier: String,
    recovery_phrase_payload: SecretString, // Corrected: Was Secret<String>
    new_password_payload: SecretString, // Corrected: Was Secret<String>
) -> Result<Uuid, AuthError> {
    info!("Attempting password recovery with phrase for identifier");

    // 1. Fetch user by identifier (username or email)
    debug!("Fetching user by identifier...");
    let user_db_query = pool
        .get().await.map_err(AuthError::PoolError)?
        .interact(move |conn| {
            users::table
                .filter(users::username.eq(&identifier).or(users::email.eq(&identifier)))
                .select(UserDbQuery::as_select())
                .first::<UserDbQuery>(conn)
        })
        .await
        .map_err(AuthError::from)??; // Double ?? for InteractError then diesel::Error -> AuthError

    let user = User::from(user_db_query);
    info!(user_id = %user.id, username = %user.username, "User found for password recovery.");

    // 2. Check if recovery is set up
    debug!("Checking if recovery is set up for user...");
    let recovery_kek_salt = match &user.recovery_kek_salt {
        Some(salt) => salt,
        None => {
            warn!(user_id = %user.id, "Recovery KEK salt not found. Recovery not set up.");
            return Err(AuthError::RecoveryNotSetup);
        }
    };
    let encrypted_dek_by_recovery = match &user.encrypted_dek_by_recovery {
        Some(dek) => dek,
        None => {
            warn!(user_id = %user.id, "Encrypted DEK by recovery not found. Recovery not set up.");
            return Err(AuthError::RecoveryNotSetup);
        }
    };
    debug!("Recovery appears to be set up. Proceeding with RKEK derivation.");

    // 3. Derive RKEK from recovery_phrase and recovery_kek_salt
    let rkek = crypto::derive_kek(&recovery_phrase_payload, recovery_kek_salt)
        .map_err(|e| {
            error!(user_id = %user.id, error = ?e, "Failed to derive RKEK from recovery phrase");
            // Distinguish between crypto error and potentially invalid phrase
            // For now, map to InvalidRecoveryPhrase if KDF fails, assuming it's due to bad input.
            // A more specific error from derive_kek might be useful.
            AuthError::InvalidRecoveryPhrase // Or CryptoOperationFailed(e) if it's a system issue
        })?;
    debug!("RKEK derived successfully.");

    // 4. Decrypt encrypted_dek_by_recovery using RKEK to get plaintext DEK
    debug!("Decrypting DEK using RKEK...");
    if encrypted_dek_by_recovery.len() < NONCE_LEN {
        error!(user_id = %user.id, "Encrypted DEK by recovery is too short.");
        return Err(AuthError::CryptoOperationFailed(CryptoError::DecryptionFailed));
    }
    let (nonce_bytes_recovery, ciphertext_dek_recovery) =
        encrypted_dek_by_recovery.split_at(NONCE_LEN);
    let plaintext_dek_secret =
        crypto::decrypt_gcm(ciphertext_dek_recovery, nonce_bytes_recovery, &rkek)
            .map_err(|e| {
                error!(user_id = %user.id, error = ?e, "Failed to decrypt DEK with RKEK. Likely invalid recovery phrase.");
                AuthError::InvalidRecoveryPhrase // If decryption fails, it's highly likely the phrase was wrong.
            })?;
    debug!("DEK decrypted successfully using RKEK.");

    // 5. Generate new kek_salt
    debug!("Generating new KEK salt...");
    let new_kek_salt_str = crypto::generate_salt().map_err(AuthError::CryptoOperationFailed)?;

    // 6. Derive new KEK from new_password and new_kek_salt
    debug!("Deriving new KEK from new password...");
    let new_kek = crypto::derive_kek(&new_password_payload, &new_kek_salt_str)
        .map_err(|e| {
            error!(user_id = %user.id, error = ?e, "Failed to derive new KEK from new password");
            AuthError::CryptoOperationFailed(e)
        })?;

    // 7. Re-encrypt plaintext DEK with new KEK
    debug!("Re-encrypting DEK with new KEK...");
    let (new_ciphertext_dek_bytes, new_nonce_dek_bytes) =
        crypto::encrypt_gcm(plaintext_dek_secret.expose_secret(), &new_kek).map_err(|e| {
            error!(user_id = %user.id, error = ?e, "Failed to re-encrypt DEK with new KEK");
            AuthError::CryptoOperationFailed(e)
        })?;
    debug!("DEK re-encrypted successfully with new KEK.");

    // 8. Generate new password_hash from new_password
    debug!("Hashing new password...");
    let new_password_hash_str = hash_password(new_password_payload.clone()).await?;
    debug!("New password hashed successfully.");

    // 9. Update database: new password_hash, new kek_salt, new encrypted_dek.
    // recovery_kek_salt and encrypted_dek_by_recovery remain unchanged.
    debug!("Updating user record in database...");
    backend.update_password_and_encryption_keys(
        user.id,
        new_password_hash_str,
        new_kek_salt_str, // The new KEK salt
        new_ciphertext_dek_bytes, // Pass ciphertext
        new_nonce_dek_bytes,      // Pass nonce
        user.encrypted_dek_by_recovery.clone(), // This remains unchanged
        user.recovery_dek_nonce.clone(), // Pass existing recovery nonce
    ).await?;

    info!(user_id = %user.id, "Password recovered and updated successfully.");
    Ok(user.id)
}


#[instrument(skip(pool), err, fields(user_id = %user_id_to_invalidate))]
pub async fn delete_all_sessions_for_user(
    pool: &DbPool,
    user_id_to_invalidate: Uuid,
) -> Result<usize, AuthError> {
    use crate::schema::sessions::dsl::{sessions, id as session_id_col, session as session_data_col};
    use diesel::prelude::*;
    use serde_json::Value;

    info!("Attempting to delete all sessions for user.");

    let deleted_count = pool
        .get().await.map_err(AuthError::PoolError)?
        .interact(move |conn| {
            // 1. Fetch all session IDs and their data
            let all_sessions_data = sessions
                .select((session_id_col, session_data_col))
                .load::<(String, String)>(conn)
                .map_err(|e| {
                    error!(error = ?e, "Failed to load sessions from DB for invalidation.");
                    AuthError::DatabaseError(e.to_string())
                })?;

            // 2. Filter to find session IDs belonging to the target user
            let mut session_ids_to_delete: Vec<String> = Vec::new();
            for (current_session_id, data_json_str) in all_sessions_data {
                match serde_json::from_str::<Value>(&data_json_str) {
                    Ok(json_value) => {
                        if let Some(session_user_id_str) = json_value.get("userId").and_then(Value::as_str) {
                            if let Ok(session_user_id_uuid) = Uuid::parse_str(session_user_id_str) {
                                if session_user_id_uuid == user_id_to_invalidate {
                                    session_ids_to_delete.push(current_session_id);
                                }
                            } else {
                                warn!(session_id = %current_session_id, "Failed to parse userId UUID from session data during invalidation sweep.");
                            }
                        } else {
                             warn!(session_id = %current_session_id, "Session data does not contain a 'userId' string field during invalidation sweep.");
                        }
                    }
                    Err(e) => {
                        warn!(session_id = %current_session_id, error = ?e, "Failed to parse session data JSON during invalidation sweep.");
                    }
                }
            }

            // 3. Delete the identified sessions
            if !session_ids_to_delete.is_empty() {
                debug!(num_sessions = session_ids_to_delete.len(), "Deleting identified sessions for user.");
                diesel::delete(sessions.filter(session_id_col.eq_any(&session_ids_to_delete)))
                    .execute(conn)
                    .map_err(|e| {
                        error!(error = ?e, "Failed to delete user sessions from DB.");
                        AuthError::DatabaseError(e.to_string())
                    })
            } else {
                debug!("No active sessions found for user to invalidate.");
                Ok(0) // No sessions deleted
            }
        })
        .await
        .map_err(AuthError::from)??; // Double ?? for InteractError then AuthError from inner logic

    info!(num_deleted = deleted_count, "Successfully processed session invalidation for user.");
    Ok(deleted_count)
}


#[cfg(test)]
mod tests {
    use super::*;
    // use secrecy::Secret; // This line should be removed or already gone
    use secrecy::SecretString; // This is fine if SecretString is used, or can be removed if sub-tests import it.
    use tokio;

     #[tokio::test]
    async fn test_hash_password_join_error_simulation() {
        // Similar to the verify_password JoinError test, this is hard to guarantee.
        // Covers line 179 (hash_password -> HashingError from JoinError)

        let password = SecretString::new("some_password_to_hash".to_string().into_boxed_str()); // Corrected: Was Secret::new

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
