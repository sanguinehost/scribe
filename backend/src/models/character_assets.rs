// backend/src/models/character_assets.rs

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::character_assets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct CharacterAsset {
    pub id: i32,
    pub character_id: Uuid,
    pub asset_type: String,
    pub uri: String,
    pub name: String,
    pub ext: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::character_assets)]
pub struct NewCharacterAsset {
    pub character_id: Uuid,
    pub asset_type: String,
    pub uri: String,
    pub name: String,
    pub ext: String,
}

impl NewCharacterAsset {
    pub fn new_avatar(character_id: Uuid, file_path: &str, name: &str) -> Self {
        Self {
            character_id,
            asset_type: "avatar".to_string(),
            uri: file_path.to_string(),
            name: name.to_string(),
            ext: "png".to_string(),
        }
    }
}