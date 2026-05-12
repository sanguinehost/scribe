use scribe_core::{AccountStatus, DbBigInt, DbBlob, DbId, DbTimestamp, UserRole, User, NewUser, UserDbQuery, SerializableSecretDek};
use secrecy::SecretString;
use serde::Deserialize;

pub use scribe_core::models::*;

#[derive(Deserialize, Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: SecretString,
}
