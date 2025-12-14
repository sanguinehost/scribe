use crate::db::{DbBlob, DbId, DbInt, DbTimestamp};
use crate::schema::users;
use axum_login::AuthUser;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use diesel::Insertable;
use diesel::{Identifiable, Queryable, Selectable};
use secrecy::ExposeSecret;
use secrecy::{SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};
use tracing;

// User role enum
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, diesel_derive_enum::DbEnum,
)]
#[ExistingTypePath = "crate::schema::sql_types::UserRole"]
pub enum UserRole {
    #[default]
    #[db_rename = "User"]
    User,
    #[db_rename = "Moderator"]
    Moderator,
    #[db_rename = "Administrator"]
    Administrator,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Moderator => write!(f, "Moderator"),
            Self::Administrator => write!(f, "Administrator"),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, diesel_derive_enum::DbEnum,
)]
#[ExistingTypePath = "crate::schema::sql_types::AccountStatus"]
pub enum AccountStatus {
    #[default]
    #[db_rename = "active"]
    Active,
    #[db_rename = "locked"]
    Locked,
    #[db_rename = "pending"]
    Pending,
}

// SQLite implementations for UserRole - store as TEXT
#[cfg(feature = "sqlite-backend")]
impl diesel::deserialize::FromSql<diesel::sql_types::Text, diesel::sqlite::Sqlite> for UserRole {
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> diesel::deserialize::Result<Self> {
        let text = <String as diesel::deserialize::FromSql<
            diesel::sql_types::Text,
            diesel::sqlite::Sqlite,
        >>::from_sql(bytes)?;
        match text.as_str() {
            "User" => Ok(UserRole::User),
            "Moderator" => Ok(UserRole::Moderator),
            "Administrator" => Ok(UserRole::Administrator),
            _ => Err("Invalid UserRole variant".into()),
        }
    }
}

#[cfg(feature = "sqlite-backend")]
impl diesel::serialize::ToSql<diesel::sql_types::Text, diesel::sqlite::Sqlite> for UserRole {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::sqlite::Sqlite>,
    ) -> diesel::serialize::Result {
        out.set_value(self.to_string());
        Ok(diesel::serialize::IsNull::No)
    }
}

// SQLite implementations for AccountStatus - store as TEXT
#[cfg(feature = "sqlite-backend")]
impl diesel::deserialize::FromSql<diesel::sql_types::Text, diesel::sqlite::Sqlite>
    for AccountStatus
{
    fn from_sql(bytes: diesel::sqlite::SqliteValue) -> diesel::deserialize::Result<Self> {
        let text = <String as diesel::deserialize::FromSql<
            diesel::sql_types::Text,
            diesel::sqlite::Sqlite,
        >>::from_sql(bytes)?;
        match text.as_str() {
            "active" => Ok(AccountStatus::Active),
            "locked" => Ok(AccountStatus::Locked),
            "pending" => Ok(AccountStatus::Pending),
            _ => Err("Invalid AccountStatus variant".into()),
        }
    }
}

#[cfg(feature = "sqlite-backend")]
impl diesel::serialize::ToSql<diesel::sql_types::Text, diesel::sqlite::Sqlite> for AccountStatus {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::sqlite::Sqlite>,
    ) -> diesel::serialize::Result {
        let value = match self {
            AccountStatus::Active => "active",
            AccountStatus::Locked => "locked",
            AccountStatus::Pending => "pending",
        };
        out.set_value(value);
        Ok(diesel::serialize::IsNull::No)
    }
}

// --- Newtype wrapper for DEK serialization ---
#[derive(Debug)] // Manual Debug to redact SecretBox
pub struct SerializableSecretDek(pub SecretBox<Vec<u8>>); // Made pub for access in User clone

impl SerializableSecretDek {
    // Helper to expose bytes, useful for clone or other operations
    #[must_use]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

// Manual Clone for SerializableSecretDek
impl Clone for SerializableSecretDek {
    fn clone(&self) -> Self {
        Self(SecretBox::new(Box::new(self.0.expose_secret().clone())))
    }
}

impl Serialize for SerializableSecretDek {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let dek_bytes = self.0.expose_secret();
        let base64_encoded = BASE64.encode(dek_bytes);
        serializer.serialize_str(&base64_encoded)
    }
}

impl<'de> Deserialize<'de> for SerializableSecretDek {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        tracing::debug!("SerializableSecretDek::deserialize CALLED");
        let s = String::deserialize(deserializer)?;
        match BASE64.decode(s) {
            Ok(bytes) => {
                tracing::debug!(
                    "SerializableSecretDek::deserialize: Successfully decoded base64, byte length: {}",
                    bytes.len()
                );
                Ok(Self(SecretBox::new(Box::new(bytes))))
            }
            Err(e) => {
                tracing::error!(
                    "SerializableSecretDek::deserialize: Failed to decode base64: {}",
                    e
                );
                Err(serde::de::Error::custom(format!(
                    "Base64 decode error for DEK: {e}"
                )))
            }
        }
    }
}

// Helper struct for Diesel Querying - matches the DB schema exactly
#[derive(Queryable, Selectable, Clone)] // Removed Debug for custom impl
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserDbQuery {
    pub id: DbId,
    pub username: String,
    pub password_hash: String,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub email: String,
    pub kek_salt: String,
    pub encrypted_dek: DbBlob,
    pub encrypted_dek_by_recovery: Option<DbBlob>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: DbBlob,
    pub recovery_dek_nonce: Option<DbBlob>,
    pub role: UserRole,
    pub account_status: AccountStatus,
    pub default_persona_id: Option<DbId>,
    pub total_prompt_tokens: DbInt,
    pub total_completion_tokens: DbInt,
    pub total_token_cost_cents: DbInt,
    pub tokens_last_reset_at: Option<DbTimestamp>,
    pub token_usage_updated_at: DbTimestamp,
    pub cached_credit_balance: Option<i32>,
    pub cached_subscription_tier: Option<String>,
    pub last_daily_usage_reset: Option<DbTimestamp>,
}

impl std::fmt::Debug for UserDbQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserDbQuery")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password_hash", &"<omitted>")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("email", &self.email)
            .field("kek_salt", &self.kek_salt)
            .field("encrypted_dek", &"<omitted>")
            .field(
                "encrypted_dek_by_recovery",
                &self.encrypted_dek_by_recovery.as_ref().map(|_| "<omitted>"),
            )
            .field("recovery_kek_salt", &self.recovery_kek_salt)
            .field("dek_nonce", &"<omitted>")
            .field(
                "recovery_dek_nonce",
                &self.recovery_dek_nonce.as_ref().map(|_| "<omitted>"),
            )
            .field("role", &self.role)
            .field("account_status", &self.account_status)
            .field("default_persona_id", &self.default_persona_id)
            .field("total_prompt_tokens", &self.total_prompt_tokens)
            .field("total_completion_tokens", &self.total_completion_tokens)
            .field("total_token_cost_cents", &self.total_token_cost_cents)
            .field("tokens_last_reset_at", &self.tokens_last_reset_at)
            .field("token_usage_updated_at", &self.token_usage_updated_at)
            .field("cached_credit_balance", &self.cached_credit_balance)
            .field("cached_subscription_tier", &self.cached_subscription_tier)
            .field("last_daily_usage_reset", &self.last_daily_usage_reset)
            .finish()
    }
}

// Main User struct for application logic - includes non-DB 'dek' field
// Removed Queryable and Selectable. Kept Identifiable for AuthUser.
#[derive(Identifiable, Serialize, Deserialize)] // <<< REMOVED Selectable
#[diesel(table_name = users)] // Identifiable needs this to know the table for the ID.
#[diesel(primary_key(id))] // Explicitly state primary key for Identifiable
pub struct User {
    pub id: DbId,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub password_hash: String,
    pub kek_salt: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub encrypted_dek: DbBlob,
    #[serde(skip_serializing, skip_deserializing)]
    pub dek_nonce: DbBlob,
    #[serde(skip_serializing, skip_deserializing)]
    pub encrypted_dek_by_recovery: Option<DbBlob>,
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_kek_salt: Option<String>,
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_dek_nonce: Option<DbBlob>,

    // DEK field now uses the newtype wrapper
    // THIS MUST NOT BE SERIALIZED INTO THE SESSION. IT IS CACHED SERVER-SIDE.
    #[serde(skip_serializing, skip_deserializing)]
    pub dek: Option<SerializableSecretDek>,

    // Recovery phrase field for registration process (not stored in DB)
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_phrase: Option<String>,

    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub role: UserRole,
    pub account_status: Option<String>, // Added for CLI compatibility
    pub default_persona_id: Option<DbId>,
    pub total_prompt_tokens: DbInt,
    pub total_completion_tokens: DbInt,
    pub total_token_cost_cents: DbInt,
    pub tokens_last_reset_at: Option<DbTimestamp>,
    pub token_usage_updated_at: DbTimestamp,
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
            .field("dek_nonce", &"<omitted>")
            .field(
                "encrypted_dek_by_recovery",
                &self.encrypted_dek_by_recovery.as_ref().map(|_| "<omitted>"),
            )
            .field("recovery_kek_salt", &self.recovery_kek_salt)
            .field(
                "recovery_dek_nonce",
                &self.recovery_dek_nonce.as_ref().map(|_| "<omitted>"),
            )
            // Updated Debug for Option<SerializableSecretDek>
            .field(
                "dek",
                &self
                    .dek
                    .as_ref()
                    .map(|_wrapper| "<SerializableSecretDek_omitted>"),
            )
            .field(
                "recovery_phrase",
                &self
                    .recovery_phrase
                    .as_ref()
                    .map(|_| "<recovery_phrase_omitted>"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("role", &self.role)
            .field("account_status", &self.account_status)
            .field("default_persona_id", &self.default_persona_id)
            .field("total_prompt_tokens", &self.total_prompt_tokens)
            .field("total_completion_tokens", &self.total_completion_tokens)
            .field("total_token_cost_cents", &self.total_token_cost_cents)
            .field("tokens_last_reset_at", &self.tokens_last_reset_at)
            .field("token_usage_updated_at", &self.token_usage_updated_at)
            .finish()
    }
}

// Conversion from DB representation to application representation
impl From<UserDbQuery> for User {
    fn from(user_from_db: UserDbQuery) -> Self {
        Self {
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
            recovery_phrase: None, // Not stored in DB
            created_at: user_from_db.created_at,
            updated_at: user_from_db.updated_at,
            role: user_from_db.role,
            account_status: Some(format!("{:?}", user_from_db.account_status).to_lowercase()),
            default_persona_id: user_from_db.default_persona_id,
            total_prompt_tokens: user_from_db.total_prompt_tokens,
            total_completion_tokens: user_from_db.total_completion_tokens,
            total_token_cost_cents: user_from_db.total_token_cost_cents,
            tokens_last_reset_at: user_from_db.tokens_last_reset_at,
            token_usage_updated_at: user_from_db.token_usage_updated_at,
        }
    }
}

// Manual Clone implementation for User
impl Clone for User {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            username: self.username.clone(),
            email: self.email.clone(),
            password_hash: self.password_hash.clone(),
            kek_salt: self.kek_salt.clone(),
            encrypted_dek: self.encrypted_dek.clone(),
            dek_nonce: self.dek_nonce.clone(),
            encrypted_dek_by_recovery: self.encrypted_dek_by_recovery.clone(),
            recovery_kek_salt: self.recovery_kek_salt.clone(),
            recovery_dek_nonce: self.recovery_dek_nonce.clone(),
            // Properly clone the Option<SerializableSecretDek>
            dek: self.dek.clone(), // SerializableSecretDek implements Clone
            recovery_phrase: self.recovery_phrase.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            role: self.role,
            account_status: self.account_status.clone(),
            default_persona_id: self.default_persona_id,
            total_prompt_tokens: self.total_prompt_tokens,
            total_completion_tokens: self.total_completion_tokens,
            total_token_cost_cents: self.total_token_cost_cents,
            tokens_last_reset_at: self.tokens_last_reset_at,
            token_usage_updated_at: self.token_usage_updated_at,
        }
    }
}

impl AuthUser for User {
    type Id = crate::db::DbId;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        // Use the password hash to ensure sessions are invalidated on password change.
        self.password_hash.as_bytes()
    }
}

/// Represents data needed to create a new user.
#[derive(Insertable)] // Removed Debug for custom impl
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUser {
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub kek_salt: String,
    pub encrypted_dek: DbBlob,
    pub encrypted_dek_by_recovery: Option<DbBlob>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: DbBlob,
    pub recovery_dek_nonce: Option<DbBlob>,
    pub role: UserRole,
    pub account_status: AccountStatus,
    pub total_prompt_tokens: DbInt,
    pub total_completion_tokens: DbInt,
    pub total_token_cost_cents: DbInt,
    pub tokens_last_reset_at: Option<DbTimestamp>,
    pub token_usage_updated_at: DbTimestamp,
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("password_hash", &"<omitted>")
            .field("email", &self.email)
            .field("kek_salt", &self.kek_salt)
            .field("encrypted_dek", &"<omitted>")
            .field(
                "encrypted_dek_by_recovery",
                &self.encrypted_dek_by_recovery.as_ref().map(|_| "<omitted>"),
            )
            .field("recovery_kek_salt", &self.recovery_kek_salt)
            .field("dek_nonce", &"<omitted>")
            .field(
                "recovery_dek_nonce",
                &self.recovery_dek_nonce.as_ref().map(|_| "<omitted>"),
            )
            .field("role", &self.role)
            .field("account_status", &self.account_status)
            .field("total_prompt_tokens", &self.total_prompt_tokens)
            .field("total_completion_tokens", &self.total_completion_tokens)
            .field("total_token_cost_cents", &self.total_token_cost_cents)
            .field("tokens_last_reset_at", &self.tokens_last_reset_at)
            .field("token_usage_updated_at", &self.token_usage_updated_at)
            .finish()
    }
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
    use uuid::Uuid;

    struct TestUserParams<'a> {
        id: crate::db::DbId,
        username: &'a str,
        password_hash: &'a str,
        email: &'a str,
        kek_salt: &'a str,
        encrypted_dek: Vec<u8>,
        encrypted_dek_by_recovery: Option<Vec<u8>>,
        recovery_kek_salt: Option<String>,
        dek_nonce: Vec<u8>,
        recovery_dek_nonce: Option<Vec<u8>>,
        dek: Option<SerializableSecretDek>,
        role: UserRole,
        default_persona_id: Option<crate::db::DbId>,
    }

    impl User {
        fn new_test_user(params: TestUserParams<'_>) -> Self {
            Self {
                id: params.id,
                username: params.username.to_string(),
                password_hash: params.password_hash.to_string(),
                email: params.email.to_string(),
                kek_salt: params.kek_salt.to_string(),
                encrypted_dek: params.encrypted_dek,
                encrypted_dek_by_recovery: params.encrypted_dek_by_recovery,
                recovery_kek_salt: params.recovery_kek_salt,
                dek_nonce: params.dek_nonce,
                recovery_dek_nonce: params.recovery_dek_nonce,
                dek: params.dek,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                role: params.role,
                account_status: Some("active".to_string()),
                recovery_phrase: None, // Add the recovery_phrase field
                default_persona_id: params.default_persona_id,
                token_usage_updated_at: chrono::Utc::now(),
                tokens_last_reset_at: None,
                total_completion_tokens: 0,
                total_token_cost_cents: 0,
                total_prompt_tokens: 0,
            }
        }
    }

    #[test]
    fn test_user_struct_and_auth_impl() {
        let user_id = Uuid::new_v4();
        let _now = Utc::now();
        let test_kek_salt = "test_kek_salt".to_string();
        let test_encrypted_dek = vec![1, 2, 3];
        let test_dek_nonce = vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];
        let test_dek_bytes = vec![
            4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27, 28, 29, 30, 31, 32,
        ];
        let initial_test_dek = Some(SerializableSecretDek(SecretBox::new(Box::new(
            test_dek_bytes.clone(),
        ))));

        let user = User::new_test_user(TestUserParams {
            id: user_id,
            username: "testuser",
            password_hash: "hashed_password",
            email: "test@example.com",
            kek_salt: &test_kek_salt,
            encrypted_dek: test_encrypted_dek.clone(),
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            dek_nonce: test_dek_nonce.clone(),
            recovery_dek_nonce: None,
            dek: initial_test_dek,
            role: UserRole::User,
            default_persona_id: None,
        });

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hashed_password");
        assert_eq!(user.kek_salt, test_kek_salt);
        assert_eq!(user.encrypted_dek, test_encrypted_dek);
        assert_eq!(user.dek_nonce, test_dek_nonce);
        assert!(user.dek.is_some());
        if let Some(wrapped_dek) = &user.dek {
            assert_eq!(wrapped_dek.expose_secret_bytes(), &test_dek_bytes);
        }
        assert_eq!(user.role, UserRole::User);
        assert_eq!(user.default_persona_id, None);

        let cloned_user = &user;
        assert!(
            cloned_user.dek.is_some(),
            "Cloned user DEK should be preserved"
        );
        if let Some(wrapped_dek) = &cloned_user.dek {
            assert_eq!(
                wrapped_dek.expose_secret_bytes(),
                &test_dek_bytes,
                "Cloned DEK should match original"
            );
        }

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
        let dek_nonce = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]; // Example 12-byte nonce

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
            role: UserRole::User,
            account_status: AccountStatus::Active,
            token_usage_updated_at: chrono::Utc::now(),
            tokens_last_reset_at: None,
            total_completion_tokens: 0,
            total_prompt_tokens: 0,
            total_token_cost_cents: 0,
        };

        assert_eq!(new_user.username, username);
        assert_eq!(new_user.email, email);
        assert_eq!(new_user.password_hash, password_hash);
        assert_eq!(new_user.kek_salt, kek_salt);
        assert_eq!(new_user.encrypted_dek, encrypted_dek);
        assert_eq!(new_user.dek_nonce, dek_nonce);
        assert_eq!(new_user.role, UserRole::User);
    }

    // Cannot easily test AuthnBackend methods here without a pool/runtime
    // These tests should be integration tests.
}
