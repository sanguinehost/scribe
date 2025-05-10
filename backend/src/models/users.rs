use crate::schema::users;
use axum_login::AuthUser;
use chrono::{DateTime, Utc};
use diesel::Insertable;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use secrecy::{SecretBox, SecretString};

// Helper struct for Diesel Querying - matches the DB schema exactly
#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserDbQuery {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email: String,
    pub kek_salt: String,
    pub encrypted_dek: Vec<u8>,
    pub encrypted_dek_by_recovery: Option<Vec<u8>>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: Vec<u8>,
    pub recovery_dek_nonce: Option<Vec<u8>>,
}

// Main User struct for application logic - includes non-DB 'dek' field
// Removed Queryable, Selectable. Kept Identifiable for AuthUser.
#[derive(Identifiable, Serialize, Deserialize)] 
#[diesel(table_name = users)] // Identifiable needs this to know the table for the ID.
#[diesel(primary_key(id))]    // Explicitly state primary key for Identifiable
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub kek_salt: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub encrypted_dek: Vec<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    pub dek_nonce: Vec<u8>, // Added
    #[serde(skip_serializing, skip_deserializing)]
    pub encrypted_dek_by_recovery: Option<Vec<u8>>,
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_kek_salt: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_dek_nonce: Option<Vec<u8>>, // Added
    #[serde(skip_serializing, skip_deserializing)]
    pub dek: Option<SecretBox<Vec<u8>>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Manual Debug implementation for User
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password_hash", &"<omitted>")
            .field("kek_salt", &self.kek_salt)
            .field("encrypted_dek", &"<omitted>")
            .field("dek_nonce", &"<omitted>") // Added
            .field("encrypted_dek_by_recovery", &self.encrypted_dek_by_recovery.as_ref().map(|_| "<omitted>"))
            .field("recovery_kek_salt", &self.recovery_kek_salt)
            .field("recovery_dek_nonce", &self.recovery_dek_nonce.as_ref().map(|_| "<omitted>")) // Added
            .field("dek", &self.dek.as_ref().map(|_| "<omitted>"))
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

// Conversion from DB representation to application representation
impl From<UserDbQuery> for User {
    fn from(user_from_db: UserDbQuery) -> Self {
        User {
            id: user_from_db.id,
            username: user_from_db.username,
            password_hash: user_from_db.password_hash,
            email: user_from_db.email,
            kek_salt: user_from_db.kek_salt,
            encrypted_dek: user_from_db.encrypted_dek,
            encrypted_dek_by_recovery: user_from_db.encrypted_dek_by_recovery,
            recovery_kek_salt: user_from_db.recovery_kek_salt,
            dek_nonce: user_from_db.dek_nonce,
            recovery_dek_nonce: user_from_db.recovery_dek_nonce,
            dek: None,
            created_at: user_from_db.created_at,
            updated_at: user_from_db.updated_at,
        }
    }
}

// Manual Clone implementation for User due to potential SecretBox clone issue
// and to control how 'dek' is cloned (or not cloned if it remains an issue).
impl Clone for User {
    fn clone(&self) -> Self {
        User {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            password_hash: self.password_hash.clone(),
            kek_salt: self.kek_salt.clone(),
            encrypted_dek: self.encrypted_dek.clone(),
            dek_nonce: self.dek_nonce.clone(), // Added
            encrypted_dek_by_recovery: self.encrypted_dek_by_recovery.clone(),
            recovery_kek_salt: self.recovery_kek_salt.clone(),
            recovery_dek_nonce: self.recovery_dek_nonce.clone(), // Added
            // TEMPORARY WORKAROUND for SecretBox clone issue / until DEK is properly managed in session
            dek: None,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl AuthUser for User {
    type Id = Uuid;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        // Use the password hash to ensure sessions are invalidated on password change.
        self.password_hash.as_bytes()
    }
}

/// Represents data needed to create a new user.
#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub kek_salt: String,
    pub encrypted_dek: Vec<u8>,
    pub encrypted_dek_by_recovery: Option<Vec<u8>>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: Vec<u8>,
    pub recovery_dek_nonce: Option<Vec<u8>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: SecretString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secrecy::SecretBox; // Ensure SecretBox is imported for tests
    use secrecy::ExposeSecret; // Import ExposeSecret for expose_secret() method

    impl User {
        #[allow(clippy::too_many_arguments)]
        fn new_test_user(
            id: Uuid,
            username: &str,
            password_hash: &str,
            email: &str,
            kek_salt: &str,
            encrypted_dek: Vec<u8>,
            encrypted_dek_by_recovery: Option<Vec<u8>>,
            recovery_kek_salt: Option<String>,
            dek_nonce: Vec<u8>,
            recovery_dek_nonce: Option<Vec<u8>>,
            dek: Option<SecretBox<Vec<u8>>>,
        ) -> Self {
            User {
                id,
                username: username.to_string(),
                password_hash: password_hash.to_string(),
                email: email.to_string(),
                kek_salt: kek_salt.to_string(),
                encrypted_dek,
                encrypted_dek_by_recovery,
                recovery_kek_salt,
                dek_nonce,
                recovery_dek_nonce,
                dek,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }
        }
    }

    #[test]
    fn test_user_struct_and_auth_impl() {
        let user_id = Uuid::new_v4();
        let _now = Utc::now();
        let test_kek_salt = "test_kek_salt".to_string();
        let test_encrypted_dek = vec![1, 2, 3];
        let test_dek_nonce = vec![7,8,9,10,11,12,13,14,15,16,17,18]; // Example 12-byte nonce
        let test_dek_bytes = vec![4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]; // Example 32-byte DEK
        let initial_test_dek = Some(SecretBox::new(Box::new(test_dek_bytes.clone())));

        let user = User::new_test_user(
            user_id,
            "testuser",
            "hashed_password",
            "test@example.com",
            &test_kek_salt,
            test_encrypted_dek.clone(),
            None,
            None,
            test_dek_nonce.clone(),
            None, // Added for recovery_dek_nonce
            initial_test_dek,
        );

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hashed_password");
        assert_eq!(user.kek_salt, test_kek_salt);
        assert_eq!(user.encrypted_dek, test_encrypted_dek);
        assert_eq!(user.dek_nonce, test_dek_nonce); // Added
        assert!(user.dek.is_some());
        if let Some(dek) = &user.dek {
             assert_eq!(dek.expose_secret(), &test_dek_bytes); // Compare with original bytes
        }

        // Test clone behavior (dek will be None due to temporary workaround)
        let cloned_user = user.clone();
        assert!(cloned_user.dek.is_none(), "Cloned user DEK should be None due to temporary workaround");


        assert_eq!(axum_login::AuthUser::id(&user), user_id);
        assert_eq!(user.session_auth_hash(), user.password_hash.as_bytes());
    }

    #[test]
    fn test_new_user_struct() {
        let username = "newuser".to_string();
        let password_hash = "new_hashed_password".to_string();
        let email = "new@example.com".to_string();
        let kek_salt = "new_kek_salt".to_string();
        let encrypted_dek = vec![4, 5, 6];
        let dek_nonce = vec![10,11,12,13,14,15,16,17,18,19,20,21]; // Example 12-byte nonce

        let new_user = NewUser {
            username: username.clone(),
            password_hash: password_hash.clone(),
            email: email.clone(),
            kek_salt: kek_salt.clone(),
            encrypted_dek: encrypted_dek.clone(),
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            dek_nonce: dek_nonce.clone(),
            recovery_dek_nonce: None,
        };

        assert_eq!(new_user.username, username);
        assert_eq!(new_user.email, email);
        assert_eq!(new_user.password_hash, password_hash);
        assert_eq!(new_user.kek_salt, kek_salt);
        assert_eq!(new_user.encrypted_dek, encrypted_dek);
        assert_eq!(new_user.dek_nonce, dek_nonce);
    }

    // Cannot easily test AuthnBackend methods here without a pool/runtime
    // These tests should be integration tests.
}
