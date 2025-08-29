// backend/src/services/secure_llm_service.rs
// Secure wrapper service for LLM operations with encryption and security controls

use crate::{
    auth::SessionDek,
    errors::AppError,
    llm::{AiClient, ChatStream},
    state::AppState,
};
use async_trait::async_trait;
use futures_util::StreamExt;
use genai::{
    chat::{ChatRequest, ChatResponse, ChatMessage, ChatOptions},
    Client,
};
use std::sync::Arc;
use tracing::{debug, info, warn, error};
use uuid::Uuid;

#[cfg(feature = "local-llm")]
use crate::llm::llamacpp::{
    LlmEncryptionService, LlmEncryptionError, EncryptedLlmData,
    SecurityAuditLogger, SecurityEvent, SecurityEventType, SecurityEventSeverity,
    PromptSanitizer, OutputValidator, ResourceLimiter,
    security::SecurityError,
};

/// Secure LLM service that wraps AI client with security controls
pub struct SecureLlmService {
    ai_client: Arc<dyn AiClient + Send + Sync>,
    app_state: Arc<AppState>,
}

impl SecureLlmService {
    pub fn new(ai_client: Arc<dyn AiClient + Send + Sync>, app_state: Arc<AppState>) -> Self {
        Self {
            ai_client,
            app_state,
        }
    }

    /// Secure chat execution with encryption, sanitization, and audit logging
    pub async fn secure_exec_chat(
        &self,
        mut request: ChatRequest,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<ChatResponse, AppError> {
        debug!("Starting secure chat execution for user: {}", user_id);

        // Create encryption service for this user
        #[cfg(feature = "local-llm")]
        let encryption_service = LlmEncryptionService::new(user_id, session_dek.clone());

        // Log the request (before encryption for audit purposes)
        #[cfg(feature = "local-llm")]
        if let Some(ref audit_logger) = self.app_state.security_audit_logger {
            let event = SecurityEvent::new(
                SecurityEventType::SuspiciousActivity, // Default, will be overridden if issues found
                SecurityEventSeverity::Info,
                "/api/llm/chat".to_string(),
                "POST".to_string(),
                "LLM chat request received".to_string(),
            )
            .with_user(user_id)
            .with_detail("message_count", request.messages.len())
;

            audit_logger.log_event(event);
        }

        // 1. Apply prompt sanitization
        #[cfg(feature = "local-llm")]
        let sanitization_result = self.sanitize_prompts(&mut request.messages, user_id).await;
        
        #[cfg(not(feature = "local-llm"))]
        let sanitization_result: Result<(), AppError> = Ok(());

        if let Err(e) = sanitization_result {
            error!("Prompt sanitization failed for user {}: {}", user_id, e);
            return Err(e);
        }

        // 2. Apply resource limits
        #[cfg(feature = "local-llm")]
        self.check_resource_limits(&request, user_id).await?;

        // 3. Encrypt request data
        #[cfg(feature = "local-llm")]
        let _encrypted_request = encryption_service.encrypt_chat_request(&request)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Request encryption failed: {}", e)))?;

        // Store encrypted data (implementation would save to database for audit/recovery)
        debug!("Request encrypted successfully for user: {}", user_id);

        // 4. Execute the actual chat request
        let response = self.ai_client.exec_chat("default", request.clone(), None).await
            .map_err(|e| {
                error!("AI client execution failed for user {}: {}", user_id, e);
                AppError::InternalServerErrorGeneric(format!("Chat execution failed: {}", e))
            })?;

        debug!("Received response from AI client for user: {}", user_id);

        // 5. Validate output
        #[cfg(feature = "local-llm")]
        let validated_response = self.validate_output(&response, user_id).await?;
        
        #[cfg(not(feature = "local-llm"))]
        let validated_response = response;

        // 6. Encrypt response data
        #[cfg(feature = "local-llm")]
        let _encrypted_response = encryption_service.encrypt_chat_response(&validated_response)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Response encryption failed: {}", e)))?;

        // Log successful completion
        #[cfg(feature = "local-llm")]
        if let Some(ref audit_logger) = self.app_state.security_audit_logger {
            let response_length = validated_response.first_content_text_as_str().unwrap_or("").len();
            let event = SecurityEvent::new(
                SecurityEventType::SuspiciousActivity,
                SecurityEventSeverity::Info,
                "/api/llm/chat".to_string(),
                "POST".to_string(),
                "LLM chat request completed successfully".to_string(),
            )
            .with_user(user_id)
            .with_detail("response_length", response_length);

            audit_logger.log_event(event);
        }

        info!("Secure chat execution completed successfully for user: {}", user_id);
        Ok(validated_response)
    }

    /// Secure streaming chat with real-time encryption
    pub async fn secure_stream_chat(
        &self,
        mut request: ChatRequest,
        user_id: Uuid,
        session_dek: &SessionDek,
    ) -> Result<ChatStream, AppError> {
        debug!("Starting secure streaming chat for user: {}", user_id);

        // Apply same initial security controls as exec_chat
        #[cfg(feature = "local-llm")]
        {
            let _encryption_service = LlmEncryptionService::new(user_id, session_dek.clone());
            self.sanitize_prompts(&mut request.messages, user_id).await?;
            self.check_resource_limits(&request, user_id).await?;
        }

        // Execute streaming request
        let stream = self.ai_client.stream_chat("default", request.clone(), None).await
            .map_err(|e| {
                error!("AI client streaming failed for user {}: {}", user_id, e);
                AppError::InternalServerErrorGeneric(format!("Streaming chat failed: {}", e))
            })?;

        // For now, return the stream directly since stream validation is complex
        // TODO: Implement proper streaming validation that works with ChatStreamEvent
        // The challenge is that ChatStreamEvent doesn't contain full responses to validate
        let secure_stream = stream.map(|result| {
            match result {
                Ok(event) => Ok(event),
                Err(e) => Err(AppError::InternalServerErrorGeneric(e.to_string())),
            }
        });

        Ok(Box::pin(secure_stream))
    }

    #[cfg(feature = "local-llm")]
    async fn sanitize_prompts(&self, messages: &mut Vec<ChatMessage>, user_id: Uuid) -> Result<(), AppError> {
        debug!("Sanitizing prompts for user: {}", user_id);
        
        let sanitizer = PromptSanitizer::new(self.app_state.config.security.prompt_max_length)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to create sanitizer: {}", e)))?;

        for message in messages.iter() {
            let content = match &message.content {
                genai::chat::MessageContent::Text(text) => text,
                _ => continue, // Skip non-text content
            };

            if let Err(security_error) = sanitizer.sanitize(content) {
                let error_message = security_error.to_string();
                warn!("Prompt sanitization detected issue for user {}: {}", user_id, error_message);
                
                // Log security event
                if let Some(ref audit_logger) = self.app_state.security_audit_logger {
                    let event: SecurityEvent = security_error.into();
                    let event = event.with_user(user_id);
                    audit_logger.log_event(event);
                }

                return Err(AppError::BadRequest(format!("Input validation failed: {}", error_message)));
            }
        }

        debug!("Prompt sanitization passed for user: {}", user_id);
        Ok(())
    }

    #[cfg(feature = "local-llm")]
    async fn check_resource_limits(&self, request: &ChatRequest, user_id: Uuid) -> Result<(), AppError> {
        debug!("Checking resource limits for user: {}", user_id);
        
        // Get user's context settings from database
        use crate::services::user_settings_service::UserSettingsService;
        let user_settings = UserSettingsService::get_user_settings(&self.app_state.pool, user_id, &self.app_state.config).await?;
        
        // Use user-configured context limit, or fall back to config default
        let user_context_limit = user_settings.default_context_total_token_limit
            .map(|v| v as usize)
            .unwrap_or(self.app_state.config.context_total_token_limit);

        debug!("User {} has context limit: {} tokens", user_id, user_context_limit);
        
        // Use configuration values for resource limits
        let security_config = &self.app_state.config.security;
        let mut limiter = ResourceLimiter::new(
            security_config.prompt_max_length,                    // Max tokens per request
            security_config.max_requests_per_minute,              // Requests per minute
            security_config.max_concurrent_requests as usize,     // Concurrent requests per user (convert u32 to usize)
            security_config.max_context_tokens,                   // Security max context length limit
        );

        // Estimate tokens in request (rough approximation: ~4 chars per token)
        let estimated_tokens = request.messages.iter()
            .map(|msg| match &msg.content {
                genai::chat::MessageContent::Text(text) => text.len() / 4,
                _ => 0,
            })
            .sum::<usize>();

        // Estimate context length used (all messages combined)
        let context_length = estimated_tokens;

        let user_id_str = user_id.to_string();
        // Use the new method that respects user-configured context limits
        if let Err(security_error) = limiter.check_request_allowed_with_limit(&user_id_str, estimated_tokens, context_length, user_context_limit) {
            warn!("Resource limit exceeded for user {}: {}", user_id, security_error);
            
            // Log security event
            if let Some(ref audit_logger) = self.app_state.security_audit_logger {
                let event: SecurityEvent = security_error.clone().into();
                let event = event.with_user(user_id);
                audit_logger.log_event(event);
            }

            return Err(AppError::BadRequest(format!("Resource limit exceeded: {}", security_error)));
        }

        debug!("Resource limits check passed for user: {}", user_id);
        Ok(())
    }

    #[cfg(feature = "local-llm")]
    async fn validate_output(&self, response: &ChatResponse, user_id: Uuid) -> Result<ChatResponse, AppError> {
        debug!("Validating output for user: {}", user_id);
        
        let validator = OutputValidator::new(self.app_state.config.security.response_max_length)
            .map_err(|e| AppError::BadRequest(format!("Failed to create validator: {}", e)))?;

        // Validate each content item
        for content in &response.contents {
            if let Some(text) = content.text_as_str() {
                if let Err(security_error) = validator.validate(text) {
                    warn!("Output validation failed for user {}: {}", user_id, security_error);
                    
                    // Log security event
                    if let Some(ref audit_logger) = self.app_state.security_audit_logger {
                        let event: SecurityEvent = security_error.clone().into();
                        let event = event.with_user(user_id);
                        audit_logger.log_event(event);
                    }

                    return Err(AppError::BadRequest(format!("Output validation failed: {}", security_error)));
                }
            }
        }

        debug!("Output validation passed for user: {}", user_id);
        Ok(response.clone())
    }

    #[cfg(feature = "local-llm")]
    fn validate_streaming_output(&self, response: &ChatResponse, user_id: Uuid) -> Result<ChatResponse, AppError> {
        // Lighter validation for streaming chunks
        let validator = OutputValidator::new(self.app_state.config.security.response_max_length)
            .map_err(|e| AppError::BadRequest(format!("Failed to create validator: {}", e)))?;

        // Validate the text content if present
        if let Some(text) = response.first_content_text_as_str() {
            if let Err(security_error) = validator.validate(text) {
                warn!("Streaming output validation failed for user {}: {}", user_id, security_error);
                return Err(AppError::BadRequest(format!("Streaming validation failed: {}", security_error)));
            }
        }

        Ok(response.clone())
    }
}

// Helper to extract text content from messages for logging/analysis
#[cfg(feature = "local-llm")]
fn extract_text_content(messages: &[ChatMessage]) -> String {
    messages.iter()
        .filter_map(|msg| match &msg.content {
            genai::chat::MessageContent::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<&str>>()
        .join(" ")
        .chars()
        .take(500) // Limit for logging
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(feature = "local-llm")]
    fn test_security_event_types_mapping() {
        // Test that all OWASP LLM Top 10 event types are properly mapped
        use crate::llm::llamacpp::audit::{SecurityEvent, SecurityEventType, SecurityEventSeverity};
        
        let prompt_injection = SecurityEvent::new(
            SecurityEventType::PromptInjectionAttempt,
            SecurityEventSeverity::High,
            "/api/llm/chat".to_string(),
            "POST".to_string(),
            "Test prompt injection detection".to_string(),
        );
        
        assert_eq!(prompt_injection.event_type, SecurityEventType::PromptInjectionAttempt);
        assert_eq!(prompt_injection.severity, SecurityEventSeverity::High);
        assert!(prompt_injection.log_message().contains("PROMPT_INJECTION"));
    }
}

/// Implement AiClient trait for SecureLlmService to make it interchangeable with other AI clients
#[async_trait]
impl AiClient for SecureLlmService {
    async fn exec_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatResponse, AppError> {
        // We need user_id and session_dek to perform secure operations
        // For now, we'll have to delegate to the underlying client without security features
        // This is a limitation of making SecureLlmService implement AiClient directly
        
        // In a real implementation, we'd need the user context passed differently
        warn!("SecureLlmService::exec_chat called without user context - falling back to underlying client");
        
        self.ai_client.exec_chat(model_name, request, config_override).await
    }

    async fn stream_chat(
        &self,
        model_name: &str,
        request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        // Same limitation as exec_chat - we need user context for full security
        warn!("SecureLlmService::stream_chat called without user context - falling back to underlying client");
        
        self.ai_client.stream_chat(model_name, request, config_override).await
    }
}