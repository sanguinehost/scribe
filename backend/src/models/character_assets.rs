// backend/src/models/character_assets.rs

use crate::DbDateTime;
use chrono::Utc;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use crate::DbUuid as Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::character_assets)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(feature = "sqlite-backend", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct CharacterAsset {
    pub id: i32,
    pub character_id: crate::DbUuid,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub created_at: DbDateTime,
    pub updated_at: DbDateTime,
    pub data: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::character_assets)]
#[cfg_attr(feature = "postgres-backend", diesel(check_for_backend(diesel::pg::Pg)))]
#[cfg_attr(feature = "sqlite-backend", diesel(check_for_backend(diesel::sqlite::Sqlite)))]
pub struct NewCharacterAsset {
    pub id: Option<crate::DbUuid>,
    pub character_id: crate::DbUuid,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub data: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

impl NewCharacterAsset {
    pub fn new_avatar(
        character_id: crate::DbUuid,
        name: &str,
        image_data: Vec<u8>,
        content_type: Option<String>,
    ) -> Self {
        // Determine extension based on content_type, default to "png"
        let ext = content_type.as_ref().map_or("png".to_string(), |ct| {
            if ct.contains("png") {
                "png".to_string()
            } else if ct.contains("jpeg") || ct.contains("jpg") {
                "jpeg".to_string()
            } else {
                "bin".to_string() // Fallback for unknown types
            }
        });

        Self {
            id: None,
            character_id,
            asset_type: "avatar".to_string(),
            uri: None, // No longer using file paths
            name: name.to_string(),
            ext, // Use derived extension
            data: Some(image_data),
            content_type, // Use provided content_type
        }
    }
}
