use crate::schema::users;
use axum_login::AuthUser;
use diesel::prelude::*;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid; // Removed unused ExposeSecret

#[derive(Queryable, Selectable, Identifiable, Debug, Serialize, Deserialize, Clone)] // Added Deserialize and Clone
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing, skip_deserializing)] // Don't send or receive password hash directly
    pub password_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl AuthUser for User {
    type Id = Uuid;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        // WARNING: This is NOT a secure way to generate the session hash.
        // It should be derived from a secret key or the password hash itself in a secure manner.
        // For now, using the user ID as a placeholder for demonstration.
        // TODO: Implement secure session hashing.
        self.id.as_bytes()
    }
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    // Use lifetime for borrowed password hash
    pub username: String,
    pub password_hash: &'a str, // Borrow the hash
                                // id, created_at, updated_at are handled by the DB
}

// You might want a struct for user input during registration
#[derive(Deserialize, Debug)]
pub struct UserCredentials {
    pub username: String,
    pub password: Secret<String>, // Use Secret for password handling
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use secrecy::ExposeSecret; // Import the ExposeSecret trait
    use secrecy::SecretString;

    #[test]
    fn test_user_struct_and_auth_impl() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let user = User {
            id: user_id,
            username: "testuser".to_string(),
            password_hash: "hashed_password".to_string(),
            created_at: now,
            updated_at: now,
        };

        // Test basic fields
        assert_eq!(user.username, "testuser");
        assert_eq!(user.password_hash, "hashed_password");

        // Test AuthUser implementation
        assert_eq!(axum_login::AuthUser::id(&user), user_id); // Disambiguate trait method
        // Test the current placeholder implementation for session_auth_hash
        assert_eq!(user.session_auth_hash(), user_id.as_bytes());
    }

    #[test]
    fn test_new_user_struct() {
        let username = "newuser".to_string();
        let password_hash = "new_hashed_password";
        let new_user = NewUser {
            username: username.clone(),
            password_hash,
        };

        assert_eq!(new_user.username, username);
        assert_eq!(new_user.password_hash, password_hash);
    }

    #[test]
    fn test_user_credentials_struct() {
        let username = "loginuser".to_string();
        let password = SecretString::new("password123".to_string());
        let credentials = UserCredentials {
            username: username.clone(),
            password: password.clone(),
        };

        assert_eq!(credentials.username, username);
        // Note: We can't directly compare Secret values easily,
        // but we can ensure it holds the secret type.
        // Accessing the secret value requires `expose_secret()`.
        assert_eq!(credentials.password.expose_secret(), "password123");
    }
}
