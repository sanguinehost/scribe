use diesel::prelude::*;
use crate::schema::users;
use serde::{Serialize};
use uuid::Uuid;

#[derive(Queryable, Selectable, Identifiable, Debug, Serialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)] // Don't send password hash to frontend
    pub password_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> { // Use lifetime for borrowed password hash
    pub username: String,
    pub password_hash: &'a str, // Borrow the hash
    // id, created_at, updated_at are handled by the DB
} 