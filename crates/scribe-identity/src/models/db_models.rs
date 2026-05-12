use serde::{Deserialize, Serialize, Deserializer, Serializer};
use crate::db::{DbId, DbTimestamp};
use crate::db::{DbBigInt, DbBlob};
use scribe_core::{AccountStatus, UserRole};
use crate::schema::users;
use secrecy::{ExposeSecret, SecretBox};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use diesel::{Insertable, Identifiable, Queryable, Selectable};

use axum_login::AuthUser;

#[cfg_attr(feature = "postgres-backend", derive(diesel_derive_enum::DbEnum))]
#[cfg_attr(feature = "postgres-backend", ExistingTypePath = "crate::schema::sql_types::UserRole")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DbUserRole {
    #[default]
    User,
    Moderator,
    Administrator,
}

impl From<DbUserRole> for UserRole {
    fn from(r: DbUserRole) -> Self {
        match r {
            DbUserRole::User => Self::User,
            DbUserRole::Moderator => Self::Moderator,
            DbUserRole::Administrator => Self::Administrator,
        }
    }
}

impl From<UserRole> for DbUserRole {
    fn from(r: UserRole) -> Self {
        match r {
            UserRole::User => Self::User,
            UserRole::Moderator => Self::Moderator,
            UserRole::Administrator => Self::Administrator,
        }
    }
}

#[cfg_attr(feature = "postgres-backend", derive(diesel_derive_enum::DbEnum))]
#[cfg_attr(feature = "postgres-backend", ExistingTypePath = "crate::schema::sql_types::AccountStatus")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DbAccountStatus {
    #[default]
    Active,
    Locked,
    Pending,
}

impl From<DbAccountStatus> for AccountStatus {
    fn from(s: DbAccountStatus) -> Self {
        match s {
            DbAccountStatus::Active => Self::Active,
            DbAccountStatus::Locked => Self::Locked,
            DbAccountStatus::Pending => Self::Pending,
        }
    }
}

impl From<AccountStatus> for DbAccountStatus {
    fn from(s: AccountStatus) -> Self {
        match s {
            AccountStatus::Active => Self::Active,
            AccountStatus::Locked => Self::Locked,
            AccountStatus::Pending => Self::Pending,
        }
    }
}

// --- Newtype wrapper for DEK serialization ---
#[derive(Debug)]
pub struct SerializableSecretDek(pub SecretBox<Vec<u8>>);

impl SerializableSecretDek {
    #[must_use]
    pub fn expose_secret_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

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
        let s = String::deserialize(deserializer)?;
        match BASE64.decode(s) {
            Ok(bytes) => Ok(Self(SecretBox::new(Box::new(bytes)))),
            Err(e) => Err(serde::de::Error::custom(format!("Base64 decode error for DEK: {e}"))),
        }
    }
}

#[derive(Queryable, Selectable, Clone)]
#[diesel(table_name = users)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(all(feature = "sqlite-backend", not(feature = "postgres-backend")), diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct UserDbQuery {
    pub id: DbId,
    pub username: String,
    pub password_hash: String,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    #[cfg(feature = "postgres-backend")]
    pub email: String,
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub email: Option<String>,
    pub kek_salt: String,
    pub encrypted_dek: DbBlob,
    pub encrypted_dek_by_recovery: Option<DbBlob>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: DbBlob,
    pub recovery_dek_nonce: Option<DbBlob>,
    #[cfg(feature = "postgres-backend")]
    pub role: DbUserRole,
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub role: String,

    #[cfg(feature = "postgres-backend")]
    pub account_status: DbAccountStatus,
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub account_status: String,
    pub default_persona_id: Option<DbId>,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub total_token_cost_cents: DbBigInt,
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
            .field("role", &self.role)
            .field("account_status", &self.account_status)
            .finish()
    }
}

#[derive(Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = users)]
#[diesel(primary_key(id))]
pub struct User {
    pub id: DbId,
    pub username: String,
    pub email: Option<String>,
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
    #[serde(skip_serializing, skip_deserializing)]
    pub dek: Option<SerializableSecretDek>,
    #[serde(skip_serializing, skip_deserializing)]
    pub recovery_phrase: Option<String>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub role: UserRole,
    pub account_status: Option<String>,
    pub default_persona_id: Option<DbId>,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub total_token_cost_cents: DbBigInt,
    pub tokens_last_reset_at: Option<DbTimestamp>,
    pub token_usage_updated_at: DbTimestamp,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("role", &self.role)
            .field("account_status", &self.account_status)
            .finish()
    }
}

impl From<UserDbQuery> for User {
    fn from(user_from_db: UserDbQuery) -> Self {
        Self {
            id: user_from_db.id,
            username: user_from_db.username,
            password_hash: user_from_db.password_hash,
            #[cfg(feature = "postgres-backend")]
            email: Some(user_from_db.email),
            #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
            email: user_from_db.email,
            kek_salt: user_from_db.kek_salt,
            encrypted_dek: user_from_db.encrypted_dek,
            encrypted_dek_by_recovery: user_from_db.encrypted_dek_by_recovery,
            recovery_kek_salt: user_from_db.recovery_kek_salt,
            dek_nonce: user_from_db.dek_nonce,
            recovery_dek_nonce: user_from_db.recovery_dek_nonce,
            dek: None,
            recovery_phrase: None,
            created_at: user_from_db.created_at,
            updated_at: user_from_db.updated_at,
            #[cfg(feature = "postgres-backend")]
            role: user_from_db.role.into(),
            #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
            role: match user_from_db.role.as_str() {
                "Moderator" => UserRole::Moderator,
                "Administrator" => UserRole::Administrator,
                _ => UserRole::User,
            },
            #[cfg(feature = "postgres-backend")]
            account_status: Some(format!("{:?}", user_from_db.account_status).to_lowercase()),
            #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
            account_status: Some(user_from_db.account_status.to_lowercase()),
            default_persona_id: user_from_db.default_persona_id,
            total_prompt_tokens: user_from_db.total_prompt_tokens,
            total_completion_tokens: user_from_db.total_completion_tokens,
            total_token_cost_cents: user_from_db.total_token_cost_cents,
            tokens_last_reset_at: user_from_db.tokens_last_reset_at,
            token_usage_updated_at: user_from_db.token_usage_updated_at,
        }
    }
}

impl AuthUser for User {
    type Id = DbId;
    fn id(&self) -> Self::Id { self.id }
    fn session_auth_hash(&self) -> &[u8] { self.password_hash.as_bytes() }
}

#[derive(Insertable, Default, Clone)]
#[diesel(table_name = users)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(all(feature = "sqlite-backend", not(feature = "postgres-backend")), diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct NewUser {
    pub id: DbId,
    pub username: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub kek_salt: String,
    pub encrypted_dek: DbBlob,
    pub encrypted_dek_by_recovery: Option<DbBlob>,
    pub recovery_kek_salt: Option<String>,
    pub dek_nonce: DbBlob,
    pub recovery_dek_nonce: Option<DbBlob>,
    #[cfg(feature = "postgres-backend")]
    pub role: DbUserRole,
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub role: String,

    #[cfg(feature = "postgres-backend")]
    pub account_status: DbAccountStatus,
    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    pub account_status: String,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub total_token_cost_cents: DbBigInt,
    pub tokens_last_reset_at: Option<DbTimestamp>,
    pub token_usage_updated_at: DbTimestamp,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

impl std::fmt::Debug for NewUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .finish()
    }
}
