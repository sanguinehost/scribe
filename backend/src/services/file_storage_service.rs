// backend/src/services/file_storage_service.rs

use crate::errors::AppError;
use axum::body::Bytes;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, instrument};
use uuid::Uuid;

pub struct FileStorageService {
    base_path: PathBuf,
}

impl FileStorageService {
    pub fn new(base_path: &str) -> Result<Self, AppError> {
        let path = PathBuf::from(base_path);
        Ok(Self { base_path: path })
    }

    /// Initialize storage directories
    pub async fn init(&self) -> Result<(), AppError> {
        let characters_dir = self.base_path.join("characters");

        fs::create_dir_all(&characters_dir).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Failed to create upload directories: {}",
                e
            ))
        })?;

        info!("Initialized file storage at: {:?}", self.base_path);
        Ok(())
    }

    /// Save character avatar image
    #[instrument(skip(self, image_data), err)]
    pub async fn save_character_avatar(
        &self,
        character_id: Uuid,
        image_data: &Bytes,
    ) -> Result<String, AppError> {
        let characters_dir = self.base_path.join("characters");
        let filename = format!("{}.png", character_id);
        let file_path = characters_dir.join(&filename);

        // Ensure the directory exists
        fs::create_dir_all(&characters_dir).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Failed to create characters directory: {}",
                e
            ))
        })?;

        // Write the image data
        fs::write(&file_path, image_data).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to write avatar file: {}", e))
        })?;

        info!("Saved character avatar: {}", filename);

        // Return relative path from storage root
        Ok(format!("characters/{}", filename))
    }

    /// Load character avatar image
    #[instrument(skip(self), err)]
    pub async fn load_character_avatar(&self, relative_path: &str) -> Result<Bytes, AppError> {
        let file_path = self.base_path.join(relative_path);

        if !file_path.exists() {
            return Err(AppError::NotFound("Avatar file not found".to_string()));
        }

        let data = fs::read(&file_path).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to read avatar file: {}", e))
        })?;

        Ok(Bytes::from(data))
    }

    /// Delete character avatar image
    #[instrument(skip(self), err)]
    pub async fn delete_character_avatar(&self, relative_path: &str) -> Result<(), AppError> {
        let file_path = self.base_path.join(relative_path);

        if file_path.exists() {
            fs::remove_file(&file_path).await.map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Failed to delete avatar file: {}", e))
            })?;

            info!("Deleted character avatar: {}", relative_path);
        }

        Ok(())
    }

    /// Get full file system path (for internal use)
    pub fn get_full_path(&self, relative_path: &str) -> PathBuf {
        self.base_path.join(relative_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_character_avatar_storage() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorageService::new(temp_dir.path().to_str().unwrap()).unwrap();

        // Initialize storage
        storage.init().await.unwrap();

        let character_id = Uuid::new_v4();
        let test_data = Bytes::from("fake png data");

        // Save avatar
        let saved_path = storage
            .save_character_avatar(character_id, &test_data)
            .await
            .unwrap();

        assert_eq!(saved_path, format!("characters/{}.png", character_id));

        // Load avatar
        let loaded_data = storage.load_character_avatar(&saved_path).await.unwrap();

        assert_eq!(loaded_data, test_data);

        // Delete avatar
        storage.delete_character_avatar(&saved_path).await.unwrap();

        // Verify deletion
        assert!(storage.load_character_avatar(&saved_path).await.is_err());
    }
}
