// backend/src/models/user_assets.rs

use crate::db::{DbBlob, DbId, DbTimestamp};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user_assets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserAsset {
    pub id: Option<i32>,
    pub user_id: DbId,
    pub persona_id: Option<DbId>,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub data: Option<DbBlob>,
    pub content_type: Option<String>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::user_assets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewUserAsset {
    pub user_id: DbId,
    pub persona_id: Option<DbId>,
    pub asset_type: String,
    pub uri: Option<String>,
    pub name: String,
    pub ext: String,
    pub data: Option<DbBlob>,
    pub content_type: Option<String>,
}

impl NewUserAsset {
    /// Create a new user avatar asset
    pub fn new_user_avatar(
        user_id: DbId,
        name: &str,
        image_data: DbBlob,
        content_type: Option<String>,
    ) -> Self {
        let ext = content_type.as_ref().map_or("png".to_string(), |ct| {
            if ct.contains("png") {
                "png".to_string()
            } else if ct.contains("jpeg") || ct.contains("jpg") {
                "jpeg".to_string()
            } else {
                "bin".to_string()
            }
        });
        Self {
            user_id,
            persona_id: None, // NULL for user avatars
            asset_type: "avatar".to_string(),
            uri: None,
            name: name.to_string(),
            ext,
            data: Some(image_data),
            content_type,
        }
    }

    /// Create a new persona avatar asset
    pub fn new_persona_avatar(
        user_id: DbId,
        persona_id: DbId,
        name: &str,
        image_data: DbBlob,
        content_type: Option<String>,
    ) -> Self {
        let ext = content_type.as_ref().map_or("png".to_string(), |ct| {
            if ct.contains("png") {
                "png".to_string()
            } else if ct.contains("jpeg") || ct.contains("jpg") {
                "jpeg".to_string()
            } else {
                "bin".to_string()
            }
        });
        Self {
            user_id,
            persona_id: Some(persona_id), // Set for persona avatars
            asset_type: "avatar".to_string(),
            uri: None,
            name: name.to_string(),
            ext,
            data: Some(image_data),
            content_type,
        }
    }
}

impl UserAsset {
    /// Check if this asset is a user avatar (not a persona avatar)
    pub fn is_user_avatar(&self) -> bool {
        self.persona_id.is_none() && self.asset_type == "avatar"
    }

    /// Check if this asset is a persona avatar
    pub fn is_persona_avatar(&self) -> bool {
        self.persona_id.is_some() && self.asset_type == "avatar"
    }
}
