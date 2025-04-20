use crate::schema::users;
use axum_login::{AuthUser};
use diesel::prelude::*;
use diesel::Insertable;
use secrecy::{Secret};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable, Debug, Serialize, Deserialize, Clone)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing, skip_deserializing)]
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
        // TODO: Implement secure session hashing.
        self.id.as_bytes()
    }
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: String,
    pub password_hash: &'a str,
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

        assert_eq!(user.username, "testuser");
        assert_eq!(user.password_hash, "hashed_password");

        assert_eq!(axum_login::AuthUser::id(&user), user_id);
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

    // Cannot easily test AuthnBackend methods here without a pool/runtime
    // These tests should be integration tests.
}
