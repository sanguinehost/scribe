pub use crate::models::db_models::{User, NewUser, UserDbQuery, SerializableSecretDek};
pub use scribe_core::{AccountStatus, UserRole};

use secrecy::SecretString;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct UserCredentials {
    pub username: String,
    pub password: SecretString,
}
