#![cfg(feature = "postgres-backend")]
#![cfg(test)]

//! Unit tests for message variant system functionality
//!
//! This test module provides basic unit tests for the variant functionality.
//! Integration tests would require more complex setup and are left for future development.

use scribe_backend::models::chats::{
    CreateMessageVariantPayload, MessageResponse, MessageRole, MessageVariantResponse,
    SelectVariantRequest,
};
use uuid::Uuid;

/// Test that MessageResponse includes all required variant fields
#[test]
fn test_message_response_has_variant_fields() {
    let message_response = MessageResponse {
        id: Uuid::new_v4().into(),
        session_id: Uuid::new_v4().into(),
        message_type: MessageRole::Assistant,
        role: "assistant".to_string(),
        content: "Test content".to_string(),
        parts: serde_json::json!([]).into(),
        attachments: serde_json::json!([]).into(),
        created_at: chrono::Utc::now().into(),
        raw_prompt: None,
        prompt_tokens: Some(scribe_backend::db::DbBigInt(100)),
        completion_tokens: Some(scribe_backend::db::DbBigInt(200)),
        model_name: Some("gemini-1.5-pro".to_string()),
        status: "Completed".to_string(),
        error_message: None,
        variant_count: 2,
        current_variant_index: 1,
        is_variant: false,
        parent_message_id: None,
        variants: None,
        game_state: None,
    };

    // Verify variant metadata fields exist and have expected values
    assert_eq!(message_response.variant_count, 2);
    assert_eq!(message_response.current_variant_index, 1);
    assert_eq!(message_response.is_variant, false);
    assert_eq!(message_response.parent_message_id, None);
    assert_eq!(message_response.content, "Test content");
}

/// Test MessageVariantResponse structure
#[test]
fn test_message_variant_response_structure() {
    let variant_response = MessageVariantResponse {
        index: 1,
        content: "Variant content".to_string(),
        created_at: chrono::Utc::now().into(),
        prompt_tokens: Some(scribe_backend::db::DbBigInt(100)),
        completion_tokens: Some(scribe_backend::db::DbBigInt(150)),
        model_name: Some("gemini-1.5-pro".to_string()),
        game_state: None,
    };

    assert_eq!(variant_response.index, 1);
    assert_eq!(variant_response.content, "Variant content");
    assert_eq!(
        variant_response.prompt_tokens,
        Some(scribe_backend::db::DbBigInt(100))
    );
    assert_eq!(
        variant_response.completion_tokens,
        Some(scribe_backend::db::DbBigInt(150))
    );
    assert_eq!(
        variant_response.model_name,
        Some("gemini-1.5-pro".to_string())
    );
}

/// Test SelectVariantRequest structure
#[test]
fn test_select_variant_request_structure() {
    let select_request = SelectVariantRequest { variant_index: 2 };

    assert_eq!(select_request.variant_index, 2);
}

/// Test CreateMessageVariantPayload structure
#[test]
fn test_create_message_variant_payload_structure() {
    let create_request = CreateMessageVariantPayload {
        content: "New variant content".to_string(),
        reasoning: None,
    };

    assert_eq!(create_request.content, "New variant content");
}

/// Test JSON serialization/deserialization of variant types
#[test]
fn test_variant_json_serialization() {
    let variant_response = MessageVariantResponse {
        index: 0,
        content: "Original content".to_string(),
        created_at: chrono::Utc::now().into(),
        prompt_tokens: Some(scribe_backend::db::DbBigInt(50)),
        completion_tokens: Some(scribe_backend::db::DbBigInt(75)),
        model_name: Some("gemini-1.5-pro".to_string()),
        game_state: None,
    };

    // Test serialization
    let json_str = serde_json::to_string(&variant_response).expect("Failed to serialize");

    // Test deserialization
    let deserialized: MessageVariantResponse =
        serde_json::from_str(&json_str).expect("Failed to deserialize");

    assert_eq!(deserialized.index, variant_response.index);
    assert_eq!(deserialized.content, variant_response.content);
    assert_eq!(deserialized.prompt_tokens, variant_response.prompt_tokens);
    assert_eq!(
        deserialized.completion_tokens,
        variant_response.completion_tokens
    );
    assert_eq!(deserialized.model_name, variant_response.model_name);
}

/// Test that variant index is properly handled
#[test]
fn test_variant_index_logic() {
    // Original message should be index 0
    let original_variant = MessageVariantResponse {
        index: 0,
        content: "Original".to_string(),
        created_at: chrono::Utc::now().into(),
        prompt_tokens: None,
        completion_tokens: None,
        model_name: None,
        game_state: None,
    };

    // First regeneration should be index 1
    let first_variant = MessageVariantResponse {
        index: 1,
        content: "First variant".to_string(),
        created_at: chrono::Utc::now().into(),
        prompt_tokens: None,
        completion_tokens: None,
        model_name: None,
        game_state: None,
    };

    assert_eq!(original_variant.index, 0);
    assert_eq!(first_variant.index, 1);
    assert_ne!(original_variant.content, first_variant.content);
}
