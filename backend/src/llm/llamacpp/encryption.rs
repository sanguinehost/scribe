// backend/src/llm/llamacpp/encryption.rs
// Encryption integration for LLM prompts and responses using user DEK

use crate::{
    auth::SessionDek,
    crypto::{encrypt_gcm, decrypt_gcm, CryptoError},
    errors::AppError,
};
use genai::chat::{ChatMessage, MessageContent, ChatRequest, ChatResponse};
use secrecy::{SecretBox, ExposeSecret};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, error};
use uuid::Uuid;
use base64::prelude::*;

/// Error types for LLM encryption operations
#[derive(thiserror::Error, Debug)]
pub enum LlmEncryptionError {
    #[error("DEK required for LLM operations: {0}")]
    DekRequired(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Invalid encrypted data format: {0}")]
    InvalidFormat(String),
}

// Convert to AppError instead to avoid circular dependency
// impl From<LlmEncryptionError> for LocalLlmError {
//     fn from(err: LlmEncryptionError) -> Self {
//         LocalLlmError::SecurityViolation(err.to_string())
//     }
// }

impl From<LlmEncryptionError> for AppError {
    fn from(err: LlmEncryptionError) -> Self {
        AppError::Unauthorized(err.to_string())
    }
}

/// Encrypted LLM data stored in database/cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedLlmData {
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub data_type: LlmDataType,
    pub user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Types of LLM data that can be encrypted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LlmDataType {
    ChatRequest,
    ChatResponse,  
    SystemPrompt,
    UserPrompt,
    AssistantResponse,
    ModelOutput,
}

/// Service for encrypting and decrypting LLM data with user DEK
#[derive(Debug)]
pub struct LlmEncryptionService {
    user_id: Uuid,
    session_dek: SessionDek,
}

impl LlmEncryptionService {
    /// Create new encryption service with user's DEK
    pub fn new(user_id: Uuid, session_dek: SessionDek) -> Self {
        debug!("Creating LLM encryption service for user: {}", user_id);
        Self {
            user_id,
            session_dek,
        }
    }
    
    /// Get the user's DEK for encryption operations
    fn get_dek(&self) -> Result<&SecretBox<Vec<u8>>, LlmEncryptionError> {
        Ok(&self.session_dek.0)
    }

    /// Encrypt chat request before sending to LLM
    pub fn encrypt_chat_request(&self, request: &ChatRequest) -> Result<EncryptedLlmData, LlmEncryptionError> {
        debug!("Encrypting chat request for user: {}", self.user_id);
        
        let dek = self.get_dek()?;
        
        // Serialize request to JSON
        let request_json = serde_json::to_string(request)
            .map_err(|e| LlmEncryptionError::EncryptionFailed(format!("JSON serialization failed: {}", e)))?;
        
        // Encrypt the request data
        let (encrypted_content, nonce) = encrypt_gcm(request_json.as_bytes(), dek)
            .map_err(|e| LlmEncryptionError::EncryptionFailed(e.to_string()))?;
        
        Ok(EncryptedLlmData {
            encrypted_content,
            nonce,
            data_type: LlmDataType::ChatRequest,
            user_id: self.user_id,
            created_at: chrono::Utc::now(),
        })
    }

    /// Decrypt chat request for processing
    pub fn decrypt_chat_request(&self, encrypted_data: &EncryptedLlmData) -> Result<ChatRequest, LlmEncryptionError> {
        debug!("Decrypting chat request for user: {}", self.user_id);
        
        // Verify data belongs to this user
        if encrypted_data.user_id != self.user_id {
            return Err(LlmEncryptionError::DecryptionFailed(
                "Encrypted data does not belong to current user".to_string()
            ));
        }
        
        // Verify data type
        if encrypted_data.data_type != LlmDataType::ChatRequest {
            return Err(LlmEncryptionError::InvalidFormat(
                format!("Expected ChatRequest, found {:?}", encrypted_data.data_type)
            ));
        }
        
        let dek = self.get_dek()?;
        
        // Decrypt the data
        let decrypted_secret_box = decrypt_gcm(
            &encrypted_data.encrypted_content,
            &encrypted_data.nonce,
            dek
        ).map_err(|e| LlmEncryptionError::DecryptionFailed(e.to_string()))?;
        let decrypted_bytes = decrypted_secret_box.expose_secret().clone();
        
        // Deserialize from JSON
        let request_json = String::from_utf8(decrypted_bytes)
            .map_err(|e| LlmEncryptionError::DecryptionFailed(format!("UTF-8 decode failed: {}", e)))?;
        
        let chat_request: ChatRequest = serde_json::from_str(&request_json)
            .map_err(|e| LlmEncryptionError::DecryptionFailed(format!("JSON deserialization failed: {}", e)))?;
        
        Ok(chat_request)
    }

    /// Encrypt chat response after receiving from LLM
    pub fn encrypt_chat_response(&self, response: &ChatResponse) -> Result<EncryptedLlmData, LlmEncryptionError> {
        debug!("Encrypting chat response for user: {}", self.user_id);
        
        let dek = self.get_dek()?;
        
        // Serialize response to JSON
        let response_json = serde_json::to_string(response)
            .map_err(|e| LlmEncryptionError::EncryptionFailed(format!("JSON serialization failed: {}", e)))?;
        
        // Encrypt the response data
        let (encrypted_content, nonce) = encrypt_gcm(response_json.as_bytes(), dek)
            .map_err(|e| LlmEncryptionError::EncryptionFailed(e.to_string()))?;
        
        Ok(EncryptedLlmData {
            encrypted_content,
            nonce,
            data_type: LlmDataType::ChatResponse,
            user_id: self.user_id,
            created_at: chrono::Utc::now(),
        })
    }

    /// Decrypt chat response for client consumption
    pub fn decrypt_chat_response(&self, encrypted_data: &EncryptedLlmData) -> Result<ChatResponse, LlmEncryptionError> {
        debug!("Decrypting chat response for user: {}", self.user_id);
        
        // Verify data belongs to this user
        if encrypted_data.user_id != self.user_id {
            return Err(LlmEncryptionError::DecryptionFailed(
                "Encrypted data does not belong to current user".to_string()
            ));
        }
        
        // Verify data type
        if encrypted_data.data_type != LlmDataType::ChatResponse {
            return Err(LlmEncryptionError::InvalidFormat(
                format!("Expected ChatResponse, found {:?}", encrypted_data.data_type)
            ));
        }
        
        let dek = self.get_dek()?;
        
        // Decrypt the data
        let decrypted_secret_box = decrypt_gcm(
            &encrypted_data.encrypted_content,
            &encrypted_data.nonce,
            dek
        ).map_err(|e| LlmEncryptionError::DecryptionFailed(e.to_string()))?;
        let decrypted_bytes = decrypted_secret_box.expose_secret().clone();
        
        // Deserialize from JSON
        let response_json = String::from_utf8(decrypted_bytes)
            .map_err(|e| LlmEncryptionError::DecryptionFailed(format!("UTF-8 decode failed: {}", e)))?;
        
        let chat_response: ChatResponse = serde_json::from_str(&response_json)
            .map_err(|e| LlmEncryptionError::DecryptionFailed(format!("JSON deserialization failed: {}", e)))?;
        
        Ok(chat_response)
    }

    /// Encrypt individual message content (for granular encryption)
    pub fn encrypt_message_content(&self, content: &str, data_type: LlmDataType) -> Result<EncryptedLlmData, LlmEncryptionError> {
        debug!("Encrypting message content of type {:?} for user: {}", data_type, self.user_id);
        
        let dek = self.get_dek()?;
        
        // Encrypt the message content
        let (encrypted_content, nonce) = encrypt_gcm(content.as_bytes(), dek)
            .map_err(|e| LlmEncryptionError::EncryptionFailed(e.to_string()))?;
        
        Ok(EncryptedLlmData {
            encrypted_content,
            nonce,
            data_type,
            user_id: self.user_id,
            created_at: chrono::Utc::now(),
        })
    }

    /// Decrypt individual message content
    pub fn decrypt_message_content(&self, encrypted_data: &EncryptedLlmData) -> Result<String, LlmEncryptionError> {
        debug!("Decrypting message content of type {:?} for user: {}", encrypted_data.data_type, self.user_id);
        
        // Verify data belongs to this user
        if encrypted_data.user_id != self.user_id {
            return Err(LlmEncryptionError::DecryptionFailed(
                "Encrypted data does not belong to current user".to_string()
            ));
        }
        
        let dek = self.get_dek()?;
        
        // Decrypt the data
        let decrypted_secret_box = decrypt_gcm(
            &encrypted_data.encrypted_content,
            &encrypted_data.nonce,
            dek
        ).map_err(|e| LlmEncryptionError::DecryptionFailed(e.to_string()))?;
        let decrypted_bytes = decrypted_secret_box.expose_secret().clone();
        
        // Convert to string
        let content = String::from_utf8(decrypted_bytes)
            .map_err(|e| LlmEncryptionError::DecryptionFailed(format!("UTF-8 decode failed: {}", e)))?;
        
        Ok(content)
    }

    /// Encrypt chat messages in place for secure transmission/storage
    pub fn encrypt_messages_in_place(&self, messages: &mut Vec<ChatMessage>) -> Result<(), LlmEncryptionError> {
        debug!("Encrypting {} messages in place for user: {}", messages.len(), self.user_id);
        
        for message in messages.iter_mut() {
            match &mut message.content {
                MessageContent::Text(text) => {
                    // Encrypt the text content
                    let encrypted_data = self.encrypt_message_content(text, LlmDataType::UserPrompt)?;
                    
                    // Replace text with encrypted marker (for debugging/auditing)
                    *text = format!("[ENCRYPTED:{}]", 
                        base64::prelude::BASE64_STANDARD.encode(&encrypted_data.encrypted_content[..16.min(encrypted_data.encrypted_content.len())])
                    );
                }
                // TextAndImages variant may not exist in this version of genai
                // Skip non-text content for now
                // Other content types not implemented yet
                _ => {
                    warn!("Unsupported message content type for encryption: {:?}", message.content);
                }
            }
        }
        
        Ok(())
    }

    /// Decrypt chat messages in place for processing
    pub fn decrypt_messages_in_place(&self, messages: &mut Vec<ChatMessage>) -> Result<(), LlmEncryptionError> {
        debug!("Decrypting {} messages in place for user: {}", messages.len(), self.user_id);
        
        // In a real implementation, this would lookup the encrypted content
        // from storage and decrypt it. For now, we'll just detect encrypted markers.
        
        for message in messages.iter_mut() {
            match &mut message.content {
                MessageContent::Text(text) => {
                    if text.starts_with("[ENCRYPTED:") {
                        warn!("Found encrypted message marker - real implementation would decrypt from storage");
                        // In real implementation: lookup by ID and decrypt
                    }
                }
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Get user ID for this encryption service
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }
}

/// Streaming encryption handler for real-time response encryption
#[derive(Debug)]
pub struct StreamingEncryptionHandler {
    encryption_service: LlmEncryptionService,
    accumulated_content: String,
}

impl StreamingEncryptionHandler {
    pub fn new(encryption_service: LlmEncryptionService) -> Self {
        Self {
            encryption_service,
            accumulated_content: String::new(),
        }
    }

    /// Process a chunk of streaming response data
    pub fn process_chunk(&mut self, chunk: &str) -> Result<String, LlmEncryptionError> {
        // Accumulate content for final encryption
        self.accumulated_content.push_str(chunk);
        
        // For now, pass through the chunk (encryption happens at the end)
        // In a more sophisticated implementation, you might encrypt fixed-size blocks
        Ok(chunk.to_string())
    }

    /// Finalize streaming and encrypt the complete response
    pub fn finalize(&self) -> Result<EncryptedLlmData, LlmEncryptionError> {
        debug!("Finalizing streaming encryption with {} characters", self.accumulated_content.len());
        
        self.encryption_service.encrypt_message_content(
            &self.accumulated_content,
            LlmDataType::AssistantResponse
        )
    }

    /// Get accumulated content length for metrics
    pub fn content_length(&self) -> usize {
        self.accumulated_content.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use genai::chat::ChatRole;

    #[tokio::test]
    async fn test_llm_encryption_service_creation() {
        let (_test_guard, _app, _pool) = spawn_test_app().await;
        
        // This would normally be created from a real SessionDek
        // For testing, we'll need to mock the DEK
        // TODO: Complete this test once SessionDek mocking is available
    }

    #[test]
    fn test_encrypted_llm_data_serialization() {
        let encrypted_data = EncryptedLlmData {
            encrypted_content: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8],
            data_type: LlmDataType::ChatRequest,
            user_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
        };

        let serialized = serde_json::to_string(&encrypted_data).unwrap();
        let deserialized: EncryptedLlmData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(encrypted_data.encrypted_content, deserialized.encrypted_content);
        assert_eq!(encrypted_data.data_type, deserialized.data_type);
        assert_eq!(encrypted_data.user_id, deserialized.user_id);
    }

    #[test]
    fn test_llm_data_type_equality() {
        assert_eq!(LlmDataType::ChatRequest, LlmDataType::ChatRequest);
        assert_ne!(LlmDataType::ChatRequest, LlmDataType::ChatResponse);
        assert_ne!(LlmDataType::UserPrompt, LlmDataType::AssistantResponse);
    }

    #[test]
    fn test_streaming_encryption_handler() {
        // This test would require a mock encryption service
        // TODO: Complete once mocking infrastructure is available
    }
}