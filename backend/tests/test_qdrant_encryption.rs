use scribe_backend::crypto::{encrypt_gcm, decrypt_gcm, crypto_generate_dek};
use scribe_backend::services::embeddings::metadata::{LorebookChunkMetadata, ChatMessageChunkMetadata};
use secrecy::ExposeSecret;
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;

#[test]
fn test_lorebook_metadata_encryption_fields() {
    // Test that LorebookChunkMetadata can handle encrypted fields
    let metadata = LorebookChunkMetadata {
        original_lorebook_entry_id: Uuid::new_v4(),
        lorebook_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        chunk_text: "[encrypted]".to_string(), // Placeholder for backward compat
        entry_title: Some("[encrypted]".to_string()),
        keywords: Some(vec!["test".to_string()]),
        is_enabled: true,
        is_constant: false,
        source_type: "lorebook".to_string(),
        // New encrypted fields
        encrypted_chunk_text: Some(vec![1, 2, 3, 4, 5]), // Mock encrypted data
        chunk_text_nonce: Some(vec![6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]),
        encrypted_title: Some(vec![18, 19, 20]),
        title_nonce: Some(vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]),
    };
    
    // Verify the struct can be serialized with encrypted fields
    let serialized = serde_json::to_value(&metadata).unwrap();
    assert!(serialized["encrypted_chunk_text"].is_array());
    assert!(serialized["chunk_text_nonce"].is_array());
    assert!(serialized["encrypted_title"].is_array());
    assert!(serialized["title_nonce"].is_array());
}

#[test]
fn test_chat_message_metadata_encryption_fields() {
    // Test that ChatMessageChunkMetadata can handle encrypted fields
    let metadata = ChatMessageChunkMetadata {
        message_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        user_id: Uuid::new_v4(),
        speaker: "assistant".to_string(),
        timestamp: Utc::now(),
        text: "[encrypted]".to_string(), // Placeholder for backward compat
        source_type: "chat".to_string(),
        // New encrypted fields
        encrypted_text: Some(vec![1, 2, 3, 4, 5]), // Mock encrypted data
        text_nonce: Some(vec![6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]),
    };
    
    // Verify the struct can be serialized with encrypted fields
    let serialized = serde_json::to_value(&metadata).unwrap();
    assert!(serialized["encrypted_text"].is_array());
    assert!(serialized["text_nonce"].is_array());
}

#[test]
fn test_encryption_decryption_flow() {
    // Test the actual encryption/decryption with the crypto module
    let dek = crypto_generate_dek().unwrap();
    let plaintext = "This is a test lorebook entry about dragons and magic.";
    
    // Encrypt the content
    let (encrypted_content, nonce) = encrypt_gcm(plaintext.as_bytes(), &dek).unwrap();
    
    // Verify encrypted content is different from plaintext
    assert_ne!(encrypted_content, plaintext.as_bytes());
    assert_eq!(nonce.len(), 12); // AES-GCM nonce is 12 bytes
    
    // Decrypt the content
    let decrypted = decrypt_gcm(&encrypted_content, &nonce, &dek).unwrap();
    let decrypted_text = String::from_utf8(decrypted.expose_secret().clone()).unwrap();
    
    // Verify we get back the original content
    assert_eq!(decrypted_text, plaintext);
}

#[test]
fn test_backward_compatibility_plaintext_only() {
    // Test that metadata can still work with plaintext-only (legacy) mode
    let metadata = LorebookChunkMetadata {
        original_lorebook_entry_id: Uuid::new_v4(),
        lorebook_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        chunk_text: "This is plaintext content for backward compatibility".to_string(),
        entry_title: Some("Legacy Entry".to_string()),
        keywords: Some(vec!["legacy".to_string()]),
        is_enabled: true,
        is_constant: false,
        source_type: "lorebook".to_string(),
        // No encrypted fields - legacy mode
        encrypted_chunk_text: None,
        chunk_text_nonce: None,
        encrypted_title: None,
        title_nonce: None,
    };
    
    // Verify the struct can be serialized without encrypted fields
    let serialized = serde_json::to_value(&metadata).unwrap();
    assert!(serialized["chunk_text"].is_string());
    assert!(serialized["encrypted_chunk_text"].is_null());
    assert!(serialized["chunk_text_nonce"].is_null());
}

#[test]
fn test_mixed_mode_encrypted_and_plaintext() {
    // Test that we can have both encrypted and plaintext fields
    // (during migration period)
    let dek = crypto_generate_dek().unwrap();
    let original_text = "Secret lorebook content";
    let (encrypted_text, nonce) = encrypt_gcm(original_text.as_bytes(), &dek).unwrap();
    
    let metadata = LorebookChunkMetadata {
        original_lorebook_entry_id: Uuid::new_v4(),
        lorebook_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        chunk_text: "[encrypted]".to_string(), // Placeholder when encrypted
        entry_title: Some("Entry Title".to_string()), // Can be plaintext
        keywords: Some(vec!["test".to_string()]),
        is_enabled: true,
        is_constant: false,
        source_type: "lorebook".to_string(),
        // Encrypted content
        encrypted_chunk_text: Some(encrypted_text),
        chunk_text_nonce: Some(nonce),
        encrypted_title: None, // Title not encrypted in this case
        title_nonce: None,
    };
    
    // Verify both fields exist
    let serialized = serde_json::to_value(&metadata).unwrap();
    assert_eq!(serialized["chunk_text"].as_str().unwrap(), "[encrypted]");
    assert!(serialized["encrypted_chunk_text"].is_array());
    assert!(serialized["chunk_text_nonce"].is_array());
    assert!(serialized["entry_title"].is_string());
    assert!(serialized["encrypted_title"].is_null());
}

#[test]
fn test_encryption_with_empty_content() {
    // Test edge case: encrypting empty content
    let dek = crypto_generate_dek().unwrap();
    let plaintext = "";
    
    let (encrypted_content, nonce) = encrypt_gcm(plaintext.as_bytes(), &dek).unwrap();
    
    // Even empty content should produce encrypted output (with authentication tag)
    assert!(!encrypted_content.is_empty());
    assert_eq!(nonce.len(), 12);
    
    // Decrypt should return empty string
    let decrypted = decrypt_gcm(&encrypted_content, &nonce, &dek).unwrap();
    let decrypted_text = String::from_utf8(decrypted.expose_secret().clone()).unwrap();
    assert_eq!(decrypted_text, plaintext);
}

#[test] 
fn test_encryption_with_unicode_content() {
    // Test that Unicode content encrypts/decrypts correctly
    let dek = crypto_generate_dek().unwrap();
    let plaintext = "测试中文内容 🐉 Dragon emoji and special chars: €£¥";
    
    let (encrypted_content, nonce) = encrypt_gcm(plaintext.as_bytes(), &dek).unwrap();
    
    let decrypted = decrypt_gcm(&encrypted_content, &nonce, &dek).unwrap();
    let decrypted_text = String::from_utf8(decrypted.expose_secret().clone()).unwrap();
    
    assert_eq!(decrypted_text, plaintext);
}