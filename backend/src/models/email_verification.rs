use crate::DbDateTime;
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use crate::DbUuid as Uuid;

use crate::schema::email_verification_tokens;

/// Email verification token as stored in the database
#[derive(Debug, Clone, PartialEq, Eq, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = email_verification_tokens)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(feature = "sqlite-backend", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct EmailVerificationToken {
    pub id: crate::DbUuid,
    pub user_id: crate::DbUuid,
    pub token: String,
    pub expires_at: DbDateTime,
    pub created_at: DbDateTime,
}

/// New email verification token for insertion
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = email_verification_tokens)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(feature = "sqlite-backend", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct NewEmailVerificationToken {
    pub user_id: crate::DbUuid,
    pub token: String,
    pub expires_at: DbDateTime,
}

/// Payload for email verification request
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyEmailPayload {
    pub token: String,
}
