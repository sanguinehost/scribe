// backend/src/models_sqlite/character_assets.rs
// SQLite-specific version (id: DbId)

use crate::db::DbId;
use crate::db::DbTimestamp;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::character_assets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct CharacterAsset {
    pub id: crate::db::DbId,
    pub character_id: crate::db::DbId,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub data: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::character_assets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NewCharacterAsset {
    pub id: crate::db::DbId,
    pub character_id: crate::db::DbId,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub data: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

impl NewCharacterAsset {
    pub fn new_avatar(
        character_id: crate::db::DbId,
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

        let now = DbTimestamp::now();

        Self {
            id: DbId::new(),
            character_id,
            asset_type: "avatar".to_string(),
            uri: None, // No longer using file paths
            name: name.to_string(),
            ext, // Use derived extension
            created_at: now,
            updated_at: now,
            data: Some(image_data),
            content_type, // Use provided content_type
        }
    }
}
