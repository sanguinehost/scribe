use crate::schema::users;
use axum_login::AuthUser;
use chrono::{DateTime, Utc};
use diesel::Insertable;
use diesel::prelude::*;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: Secret<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    impl User {
        fn new_test_user(id: Uuid, username: &str, password_hash: &str) -> Self {
            User {
                id,
                username: username.to_string(),
                password_hash: password_hash.to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            }
        }
    }

    #[test]
    fn test_user_struct_and_auth_impl() {
        let user_id = Uuid::new_v4();
        let _now = Utc::now();
        let user = User::new_test_user(user_id, "testuser", "hashed_password");

        assert_eq!(user.username, "testuser");
        assert_eq!(user.password_hash, "hashed_password");

        assert_eq!(axum_login::AuthUser::id(&user), user_id);
        assert_eq!(user.session_auth_hash(), user.password_hash.as_bytes());
    }

    #[test]
    fn test_new_user_struct() {
        let username = "newuser".to_string();
        let password_hash = "new_hashed_password".to_string();
        let new_user = NewUser {
            username: username.clone(),
            password_hash: password_hash.clone(),
        };

        assert_eq!(new_user.username, username);
        assert_eq!(new_user.password_hash, password_hash);
    }

    // Cannot easily test AuthnBackend methods here without a pool/runtime
    // These tests should be integration tests.
}
