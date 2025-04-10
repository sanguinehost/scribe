use diesel::prelude::*;
use crate::schema::users;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use axum_login::AuthUser;
use secrecy::{Secret, ExposeSecret};

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
pub struct NewUser<'a> { // Use lifetime for borrowed password hash
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
