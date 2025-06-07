#![cfg(test)]

use anyhow::Result;
use scribe_backend::{
    models::user_assets::{NewUserAsset, UserAsset},
    test_helpers::{TestDataGuard, ensure_tracing_initialized},
};
use uuid::Uuid;

/// Helper to create test image data
fn create_test_image_data() -> Vec<u8> {
    // Create a minimal valid PNG (1x1 pixel)
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, // PNG signature
        0, 0, 0, 13, // IHDR length
        73, 72, 68, 82, // IHDR
        0, 0, 0, 1, // Width
        0, 0, 0, 1, // Height
        8, 6, 0, 0, 0, // Bit depth, color type, compression, filter, interlace
        31, 21, 16, 166, // CRC
        0, 0, 0, 10, // IDAT length
        73, 68, 65, 84, // IDAT
        8, 29, 99, 96, 0, 0, 0, 3, 0, 1, // Compressed data
        122, 221, 46, 34, // CRC
        0, 0, 0, 0, // IEND length
        73, 69, 78, 68, // IEND
        174, 66, 96, 130 // CRC
    ]
}

// Test that the user assets model can be created for user avatars
#[tokio::test] 
async fn test_user_asset_model_creation() -> Result<()> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());

    let user_id = Uuid::new_v4();
    let image_data = create_test_image_data();
    
    // Test creating user avatar asset
    let new_user_avatar = NewUserAsset::new_user_avatar(
        user_id,
        "test_user_avatar",
        image_data.clone(),
        Some("image/png".to_string()),
    );

    // Verify the asset properties
    assert_eq!(new_user_avatar.user_id, user_id);
    assert_eq!(new_user_avatar.persona_id, None);
    assert_eq!(new_user_avatar.asset_type, "avatar");
    assert_eq!(new_user_avatar.ext, "png");
    assert_eq!(new_user_avatar.content_type, Some("image/png".to_string()));
    assert_eq!(new_user_avatar.data, Some(image_data.clone()));

    // Test creating persona avatar asset
    let persona_id = Uuid::new_v4();
    let new_persona_avatar = NewUserAsset::new_persona_avatar(
        user_id,
        persona_id,
        "test_persona_avatar",
        image_data.clone(),
        Some("image/png".to_string()),
    );

    // Verify the persona asset properties
    assert_eq!(new_persona_avatar.user_id, user_id);
    assert_eq!(new_persona_avatar.persona_id, Some(persona_id));
    assert_eq!(new_persona_avatar.asset_type, "avatar");
    assert_eq!(new_persona_avatar.ext, "png");
    assert_eq!(new_persona_avatar.content_type, Some("image/png".to_string()));
    assert_eq!(new_persona_avatar.data, Some(image_data));

    tracing::info!("User asset model creation tests completed successfully");
    Ok(())
}

// Test UserAsset helper methods
#[tokio::test]
async fn test_user_asset_helper_methods() -> Result<()> {
    ensure_tracing_initialized();
    let _test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

    let user_id = Uuid::new_v4();
    let persona_id = Uuid::new_v4();
    
    // Create mock UserAsset for user avatar
    let user_avatar = UserAsset {
        id: 1,
        user_id,
        persona_id: None,
        asset_type: "avatar".to_string(),
        uri: None,
        name: "user_avatar".to_string(),
        ext: "png".to_string(),
        data: Some(vec![1, 2, 3]),
        content_type: Some("image/png".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Create mock UserAsset for persona avatar
    let persona_avatar = UserAsset {
        id: 2,
        user_id,
        persona_id: Some(persona_id),
        asset_type: "avatar".to_string(),
        uri: None,
        name: "persona_avatar".to_string(),
        ext: "png".to_string(),
        data: Some(vec![4, 5, 6]),
        content_type: Some("image/png".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Test helper methods
    assert!(user_avatar.is_user_avatar());
    assert!(!user_avatar.is_persona_avatar());
    
    assert!(!persona_avatar.is_user_avatar());
    assert!(persona_avatar.is_persona_avatar());

    tracing::info!("UserAsset helper methods test completed successfully");
    Ok(())
}

// Test different asset types
#[tokio::test]
async fn test_different_asset_types() -> Result<()> {
    ensure_tracing_initialized();
    let _test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

    let user_id = Uuid::new_v4();
    let persona_id = Uuid::new_v4();
    
    // Create mock UserAsset for non-avatar asset
    let other_asset = UserAsset {
        id: 3,
        user_id,
        persona_id: Some(persona_id),
        asset_type: "banner".to_string(), // Not an avatar
        uri: None,
        name: "persona_banner".to_string(),
        ext: "png".to_string(),
        data: Some(vec![7, 8, 9]),
        content_type: Some("image/png".to_string()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Asset with persona_id but not avatar type should not be considered avatar
    assert!(!other_asset.is_user_avatar());
    assert!(!other_asset.is_persona_avatar());

    tracing::info!("Different asset types test completed successfully");
    Ok(())
}

// Test NewUserAsset helper constructors
#[tokio::test]
async fn test_new_user_asset_constructors() -> Result<()> {
    ensure_tracing_initialized();
    let _test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

    let user_id = Uuid::new_v4();
    let persona_id = Uuid::new_v4();
    let image_data = vec![1, 2, 3, 4, 5];

    // Test user avatar constructor
    let user_avatar = NewUserAsset::new_user_avatar(
        user_id,
        "my_user_avatar",
        image_data.clone(),
        Some("image/png".to_string()),
    );

    assert_eq!(user_avatar.user_id, user_id);
    assert_eq!(user_avatar.persona_id, None);
    assert_eq!(user_avatar.asset_type, "avatar");
    assert_eq!(user_avatar.name, "my_user_avatar");
    assert_eq!(user_avatar.ext, "png");
    assert_eq!(user_avatar.content_type, Some("image/png".to_string()));
    assert_eq!(user_avatar.data, Some(image_data.clone()));
    assert_eq!(user_avatar.uri, None);

    // Test persona avatar constructor
    let persona_avatar = NewUserAsset::new_persona_avatar(
        user_id,
        persona_id,
        "my_persona_avatar",
        image_data.clone(),
        Some("image/png".to_string()),
    );

    assert_eq!(persona_avatar.user_id, user_id);
    assert_eq!(persona_avatar.persona_id, Some(persona_id));
    assert_eq!(persona_avatar.asset_type, "avatar");
    assert_eq!(persona_avatar.name, "my_persona_avatar");
    assert_eq!(persona_avatar.ext, "png");
    assert_eq!(persona_avatar.content_type, Some("image/png".to_string()));
    assert_eq!(persona_avatar.data, Some(image_data));
    assert_eq!(persona_avatar.uri, None);

    tracing::info!("NewUserAsset constructors test completed successfully");
    Ok(())
}