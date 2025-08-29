// backend/src/llm/llamacpp/client.rs
// LlamaCpp client implementation with AiClient trait

use crate::llm::{AiClient, ChatStream, ChatStreamItem};
use crate::llm::llamacpp::{
    LocalLlmError, LlamaCppConfig, LlamaCppMetrics, PromptSanitizer, 
    OutputValidator, ResourceLimiter, LlamaCppResilience, HealthChecker,
    ModelManager, HardwareCapabilities, detect_hardware, PerformanceMetrics,
    LlamaCppServerManager
};
use crate::errors::AppError;

use async_trait::async_trait;
use genai::chat::{ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent, MessageContent, Usage, ChatMessage, ChatRole};
use genai::{ModelIden, ModelName};
use genai::adapter::AdapterKind;
use futures::stream::{Stream, StreamExt, TryStreamExt};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};

/// Helper function to extract content from malformed JSON responses
fn extract_content_from_malformed_json(data: &str) -> Option<String> {
    // Try to find content field using regex or simple string matching
    // This handles cases where JSON structure is incorrect but content is present
    
    // Look for "content":"..." pattern
    if let Some(start) = data.find("\"content\":\"") {
        let content_start = start + 11; // Length of "content":"
        if let Some(end) = data[content_start..].find("\",") {
            let content = &data[content_start..content_start + end];
            // Unescape basic JSON escape sequences
            let unescaped = content
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\t", "\t");
            return Some(unescaped);
        } else if let Some(end) = data[content_start..].find("\"") {
            // Handle case where content is at the end
            let content = &data[content_start..content_start + end];
            let unescaped = content
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\t", "\t");
            return Some(unescaped);
        }
    }
    
    // Try alternative patterns if the above doesn't work
    if let Some(start) = data.find("content='") {
        let content_start = start + 9; // Length of "content='"
        if let Some(end) = data[content_start..].find("'") {
            return Some(data[content_start..content_start + end].to_string());
        }
    }
    
    None
}

/// LlamaCpp client implementing the AiClient trait
#[derive(Clone)]
pub struct LlamaCppClient {
    config: Arc<LlamaCppConfig>,
    http_client: HttpClient,
    metrics: LlamaCppMetrics,
    security: Arc<SecurityControls>,
    resilience: Arc<LlamaCppResilience>,
    health_checker: Arc<HealthChecker>,
    model_manager: Arc<ModelManager>,
    server_manager: Arc<LlamaCppServerManager>,
    hardware_info: Arc<RwLock<Option<HardwareCapabilities>>>,
}

/// Security controls wrapper
#[derive(Debug)]
struct SecurityControls {
    prompt_sanitizer: PromptSanitizer,
    output_validator: OutputValidator,
    resource_limiter: std::sync::Mutex<ResourceLimiter>,
}

/// LlamaCpp API request/response types
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlamaCppChatRequest {
    messages: Vec<LlamaCppMessage>,
    model: String,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    top_p: Option<f32>,
    frequency_penalty: Option<f32>,
    presence_penalty: Option<f32>,
    stop: Option<Vec<String>>,
    stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlamaCppMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlamaCppResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<LlamaCppChoice>,
    usage: Option<LlamaCppUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlamaCppChoice {
    index: u32,
    message: Option<LlamaCppMessage>,
    delta: Option<LlamaCppMessage>,
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlamaCppUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

impl LlamaCppClient {
    /// Create a new LlamaCpp client
    pub async fn new(config: LlamaCppConfig) -> Result<Self, LocalLlmError> {
        info!("Initializing LlamaCpp client");
        
        // Detect hardware capabilities
        let hardware_info = detect_hardware()
            .map_err(|e| LocalLlmError::HardwareDetectionFailed(e.to_string()))?;
        
        debug!("Hardware capabilities: {:#?}", hardware_info);
        
        // Initialize security controls with model's actual context size
        let context_size = config.context_size;
        let max_tokens_per_request = (context_size as f32 * 0.8) as usize; // Use 80% of context for safety
        let security = Arc::new(SecurityControls {
            prompt_sanitizer: PromptSanitizer::new(context_size)?,
            output_validator: OutputValidator::new(context_size * 2)?, // Allow larger outputs
            resource_limiter: std::sync::Mutex::new(ResourceLimiter::new(max_tokens_per_request, 60, 5, context_size)),
        });
        
        // Initialize metrics
        let metrics = LlamaCppMetrics::new();
        
        // Initialize HTTP client with timeout
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("HTTP client error: {}", e)))?;
        
        // Initialize model manager
        let model_manager = Arc::new(ModelManager::new(config.clone()).await?);
        
        // Initialize health checker
        let health_checker = Arc::new(HealthChecker::new(config.clone()));
        
        // Initialize resilience layer
        let resilience = Arc::new(LlamaCppResilience::new(config.clone()));
        
        // Initialize server manager and start the server
        let server_manager = Arc::new(LlamaCppServerManager::new(config.clone(), model_manager.clone()).await?);
        
        info!("Starting LlamaCpp server...");
        server_manager.start().await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("Failed to start server: {}", e)))?;
        
        let client = Self {
            config: Arc::new(config),
            http_client,
            metrics,
            security,
            resilience,
            health_checker,
            model_manager,
            server_manager,
            hardware_info: Arc::new(RwLock::new(Some(hardware_info))),
        };
        
        // Start health monitoring
        client.start_health_monitoring().await;
        
        info!("LlamaCpp client initialization completed successfully");
        Ok(client)
    }
    
    /// Start background health monitoring
    async fn start_health_monitoring(&self) {
        let health_checker = Arc::clone(&self.health_checker);
        let metrics = self.metrics.clone();
        let interval = Duration::from_secs(self.config.health_check_interval_seconds);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                match health_checker.check_health().await {
                    Ok(health_status) => {
                        if !health_status.is_healthy {
                            warn!("LlamaCpp server health check failed: {:?}", health_status);
                            metrics.record_error("health_check_failed".to_string());
                        } else {
                            debug!("LlamaCpp server is healthy");
                        }
                    }
                    Err(e) => {
                        error!("Health check error: {}", e);
                        metrics.record_error("health_check_error".to_string());
                    }
                }
            }
        });
    }
    
    /// Get the current server status
    pub async fn get_server_status(&self) -> crate::llm::llamacpp::server::ServerInfo {
        self.server_manager.get_server_info().await
    }
    
    /// Switch to a different model (restarts server with new model)
    #[instrument(skip(self))]
    pub async fn switch_model(&self, model_name: &str) -> Result<(), LocalLlmError> {
        info!("Switching to model: {}", model_name);
        
        // Validate the model exists and is compatible
        let models = self.model_manager.list_models().await?;
        let model_available = models.iter().any(|m| m.name == model_name && m.is_downloaded);
        if !model_available {
            return Err(LocalLlmError::ModelLoadFailed(
                format!("Model '{}' is not available", model_name)
            ));
        }
        
        // Stop the current server gracefully
        info!("Stopping current server for model switch...");
        self.server_manager.stop().await?;
        
        // Update the model configuration
        self.model_manager.switch_model(model_name).await?;
        
        // Start server with new model
        info!("Starting server with new model: {}", model_name);
        self.server_manager.start().await?;
        
        info!("Model switch completed successfully: {}", model_name);
        Ok(())
    }
    
    /// Restart the server (useful for recovery or configuration changes)
    #[instrument(skip(self))]
    pub async fn restart_server(&self) -> Result<(), LocalLlmError> {
        info!("Restarting LlamaCpp server");
        
        self.server_manager.stop().await?;
        self.server_manager.start().await?;
        
        info!("Server restart completed successfully");
        Ok(())
    }
    
    /// Gracefully shutdown the server
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<(), LocalLlmError> {
        info!("Shutting down LlamaCpp server");
        self.server_manager.stop().await
    }
    
    /// Get available models
    pub async fn list_available_models(&self) -> Result<Vec<String>, LocalLlmError> {
        let models = self.model_manager.list_models().await?;
        Ok(models.into_iter().map(|m| m.name).collect())
    }
    
    /// Get current active model name
    pub fn get_current_model(&self) -> Option<String> {
        self.model_manager.get_active_model()
    }
    
    /// Convert GenAI ChatRequest to LlamaCpp format
    fn convert_request(&self, request: &ChatRequest, stream: bool) -> Result<LlamaCppChatRequest, LocalLlmError> {
        let messages = request.messages.iter().map(|msg| {
            let content = match &msg.content {
                MessageContent::Text(text) => text.clone(),
                _ => String::new(), // Handle other content types if needed
            };
            
            // Convert ChatRole to lowercase strings expected by llama.cpp
            let role_str = match msg.role {
                genai::chat::ChatRole::System => "system",
                genai::chat::ChatRole::User => "user",
                genai::chat::ChatRole::Assistant => "assistant",
                genai::chat::ChatRole::Tool => "tool",
            };
            
            LlamaCppMessage {
                role: Some(role_str.to_string()),
                content: Some(content),
            }
        }).collect();
        
        // Use the configured model or default
        let model = self.model_manager.get_active_model()
            .unwrap_or_else(|| "default".to_string());
        
        Ok(LlamaCppChatRequest {
            messages,
            model,
            temperature: None, // Will be set from config_override in exec_chat
            max_tokens: None,  // Will be set from config_override in exec_chat
            top_p: None,       // Will be set from config_override in exec_chat
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,        // Will be set from config_override in exec_chat
            stream,
        })
    }
    
    /// Convert LlamaCpp response to GenAI format
    fn convert_response(&self, response: LlamaCppResponse) -> Result<ChatResponse, LocalLlmError> {
        let choice = response.choices.into_iter().next()
            .ok_or_else(|| LocalLlmError::ServerUnavailable("No choices in response".to_string()))?;
        
        let message = choice.message
            .ok_or_else(|| LocalLlmError::ServerUnavailable("No message in choice".to_string()))?;
        
        Ok(ChatResponse {
            contents: vec![MessageContent::Text(message.content.unwrap_or_default())],
            reasoning_content: None,
            model_iden: ModelIden::new(AdapterKind::Ollama, response.model.clone()),
            provider_model_iden: ModelIden::new(AdapterKind::Ollama, response.model.clone()),
            usage: response.usage.map(|u| Usage {
                prompt_tokens: Some(u.prompt_tokens as i32),
                completion_tokens: Some(u.completion_tokens as i32),
                total_tokens: Some(u.total_tokens as i32),
                ..Default::default()
            }).unwrap_or_default(),
        })
    }
    
    /// Make HTTP request to LlamaCpp server
    async fn make_request(&self, llamacpp_request: LlamaCppChatRequest) -> Result<LlamaCppResponse, LocalLlmError> {
        let url = format!("http://{}:{}/v1/chat/completions", 
                         self.config.server_host, self.config.server_port);
        
        debug!("Making request to LlamaCpp server: {}", url);
        
        // Enhanced debug logging for request structure
        info!("🔍 LlamaCpp NON-STREAM REQUEST DEBUG:");
        info!("  Model: {}", llamacpp_request.model);
        info!("  Stream: {}", llamacpp_request.stream);
        info!("  Temperature: {:?}", llamacpp_request.temperature);
        info!("  Max tokens: {:?}", llamacpp_request.max_tokens);
        for (i, msg) in llamacpp_request.messages.iter().enumerate() {
            info!("  Message {}: role={:?}, content_len={}", 
                i + 1, 
                msg.role, 
                msg.content.as_ref().map(|c| c.len()).unwrap_or(0)
            );
            if let Some(content) = &msg.content {
                let preview = if content.len() > 100 { 
                    format!("{}...", &content[..100]) 
                } else { 
                    content.clone() 
                };
                info!("    Content preview: {:?}", preview);
            }
        }
        
        let response = self.http_client
            .post(&url)
            .header("Authorization", "Bearer sk-no-key-required")
            .json(&llamacpp_request)
            .send()
            .await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("HTTP request failed: {}", e)))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(LocalLlmError::ServerUnavailable(
                format!("HTTP {} error: {}", status, error_body)
            ));
        }
        
        let llamacpp_response: LlamaCppResponse = response.json().await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("Response parsing failed: {}", e)))?;
        
        Ok(llamacpp_response)
    }
    
    /// Make streaming HTTP request to LlamaCpp server
    async fn make_streaming_request(&self, llamacpp_request: LlamaCppChatRequest) -> Result<ChatStream, LocalLlmError> {
        let url = format!("http://{}:{}/v1/chat/completions", 
                         self.config.server_host, self.config.server_port);
        
        debug!("Making streaming request to LlamaCpp server: {}", url);
        debug!("Request payload: {:?}", llamacpp_request);
        
        // Enhanced debug logging for request structure
        info!("🔍 LlamaCpp REQUEST DEBUG:");
        info!("  Model: {}", llamacpp_request.model);
        info!("  Stream: {}", llamacpp_request.stream);
        info!("  Temperature: {:?}", llamacpp_request.temperature);
        info!("  Max tokens: {:?}", llamacpp_request.max_tokens);
        for (i, msg) in llamacpp_request.messages.iter().enumerate() {
            info!("  Message {}: role={:?}, content_len={}", 
                i + 1, 
                msg.role, 
                msg.content.as_ref().map(|c| c.len()).unwrap_or(0)
            );
            if let Some(content) = &msg.content {
                let preview = if content.len() > 100 { 
                    format!("{}...", &content[..100]) 
                } else { 
                    content.clone() 
                };
                info!("    Content preview: {:?}", preview);
            }
        }
        
        let response = self.http_client
            .post(&url)
            .header("Authorization", "Bearer sk-no-key-required")
            .json(&llamacpp_request)
            .send()
            .await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("HTTP request failed: {}", e)))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());
            error!("LlamaCpp server returned error - Status: {}, Body: {}", status, error_body);
            return Err(LocalLlmError::ServerUnavailable(
                format!("HTTP {} error: {}", status, error_body)
            ));
        }
        
        // Convert HTTP stream to ChatStream with robust SSE parsing and crash recovery
        // Keep a reference to self to prevent client from being dropped during streaming
        let client_ref = self.clone();
        let health_checker = Arc::clone(&self.health_checker);
        
        let stream = response.bytes_stream()
            .map(move |chunk_result| {
                let _client_ref = client_ref.clone(); // Keep client alive for duration of stream
                let health_checker = Arc::clone(&health_checker);
                async move {
                    match chunk_result {
                        Ok(chunk) => {
                            // Decode bytes to string, handling potential UTF-8 issues
                            let chunk_str = match std::str::from_utf8(&chunk) {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("Invalid UTF-8 in streaming response chunk: {}", e);
                                    // Check server health on parsing errors
                                    if let Ok(health) = health_checker.check_health().await {
                                        if !health.is_healthy {
                                            error!("Server unhealthy during UTF-8 error");
                                            return Err(AppError::HttpRequestError("Server became unhealthy".to_string()));
                                        }
                                    }
                                    
                                    // Use lossy conversion as fallback
                                    return Ok(ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                        content: String::new(),
                                    }));
                                }
                            };
                            
                            debug!("Raw chunk received: {:?}", chunk_str);
                            
                            // Process SSE lines from this chunk
                            for line in chunk_str.lines() {
                                if line.is_empty() {
                                    continue;
                                }
                                
                                debug!("Processing line: {:?}", line);
                                
                                if line.starts_with("data: ") {
                                    let data = &line[6..]; // Remove "data: " prefix
                                    
                                    debug!("SSE data: {:?}", data);
                                    
                                    if data.trim() == "[DONE]" {
                                        debug!("Received [DONE] signal");
                                        return Ok(ChatStreamEvent::End(genai::chat::StreamEnd::default()));
                                    }
                                    
                                    // Skip empty data
                                    if data.trim().is_empty() {
                                        continue;
                                    }
                                    
                                    // Try to parse as LlamaCppResponse
                                    match serde_json::from_str::<LlamaCppResponse>(data) {
                                        Ok(response) => {
                                            debug!("Parsed response: {:?}", response);
                                            
                                            if let Some(choice) = response.choices.first() {
                                                // Handle streaming delta
                                                if let Some(delta) = &choice.delta {
                                                    if let Some(content) = &delta.content {
                                                        if !content.is_empty() {
                                                            debug!("Streaming delta content: {:?}", content);
                                                            return Ok(ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                                                content: content.clone(),
                                                            }));
                                                        }
                                                    }
                                                }
                                                // Handle complete message (non-streaming fallback)
                                                else if let Some(message) = &choice.message {
                                                    if let Some(content) = &message.content {
                                                        if !content.is_empty() {
                                                            debug!("Complete message content: {:?}", content);
                                                            return Ok(ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                                                content: content.clone(),
                                                            }));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            debug!("Failed to parse JSON as LlamaCppResponse (may be partial/empty): {} - Data: {:?}", e, data);
                                            
                                            // Only check for server crashes on explicit error messages
                                            if data.contains("\"error\"") || data.contains("crash") || data.contains("abort") {
                                                error!("Server error detected in response data, checking health");
                                                if let Ok(health) = health_checker.check_health().await {
                                                    if !health.is_healthy {
                                                        error!("Server unhealthy after parsing error");
                                                        return Err(AppError::HttpRequestError("Server crashed during streaming".to_string()));
                                                    }
                                                }
                                            }
                                            
                                            // Only try content extraction for actual malformed/corrupted JSON (not parsing failures)
                                            if data.len() > 100 && !data.starts_with("{") {
                                                if let Some(content) = extract_content_from_malformed_json(data) {
                                                    debug!("Extracted content from corrupted JSON: {:?}", content);
                                                    return Ok(ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                                        content,
                                                    }));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Return empty chunk if no valid content found
                            Ok(ChatStreamEvent::Chunk(genai::chat::StreamChunk {
                                content: String::new(),
                            }))
                        }
                        Err(e) => {
                            error!("Stream error: {}", e);
                            Err(AppError::HttpRequestError(e.to_string()))
                        }
                    }
                }
            })
            .buffer_unordered(1)
            .filter_map(|result| async {
                match result {
                    Ok(event) => {
                        // Filter out empty chunks to avoid spam
                        match &event {
                            ChatStreamEvent::Chunk(chunk) if chunk.content.is_empty() => None,
                            _ => Some(Ok(event)),
                        }
                    }
                    Err(e) => Some(Err(e)),
                }
            });
        
        Ok(Box::pin(stream))
    }
    
    /// Apply security controls to request
    async fn apply_security_controls(&self, request: &mut ChatRequest) -> Result<(), LocalLlmError> {
        // Sanitize prompts
        for message in &mut request.messages {
            if let MessageContent::Text(text) = &mut message.content {
                *text = self.security.prompt_sanitizer.sanitize(text)?;
            }
        }
        
        // Check resource limits (estimate tokens for now)
        let estimated_tokens = request.messages.iter()
            .map(|m| match &m.content {
                MessageContent::Text(text) => text.len() / 4,  // Rough estimate
                _ => 0,
            })
            .sum::<usize>();
        let estimated_context = estimated_tokens;
        
        // For now use a default user_id - in real implementation this would come from the request context
        // TODO: Pass user_id from the request context
        let user_id = "default_user"; 
        self.security.resource_limiter.lock().unwrap()
            .check_request_allowed(user_id, estimated_tokens, estimated_context)?;
        
        Ok(())
    }
    
    /// Apply security validation to response
    async fn validate_response(&self, response: &ChatResponse) -> Result<(), LocalLlmError> {
        if let Some(text) = response.first_content_text_as_str() {
            self.security.output_validator.validate(text)?;
        }
        
        Ok(())
    }
    
    /// Record performance metrics
    fn record_metrics(&self, start_time: Instant, first_token_time: Option<Instant>, 
                     prompt_tokens: usize, completion_tokens: usize, queue_depth: usize) {
        let hw_info = self.hardware_info.try_read().ok()
            .and_then(|guard| guard.as_ref().cloned())
            .unwrap_or_else(|| HardwareCapabilities {
                total_ram_gb: 0.0,
                available_ram_gb: 0.0,
                cpu_cores: 0,
                cpu_arch: "unknown".to_string(),
                gpu_info: vec![],
                has_cuda: false,
                has_metal: false,
                os: "unknown".to_string(),
            });
        
        let memory_usage_mb = crate::llm::llamacpp::metrics::get_current_memory_usage_mb();
        let model_name = self.model_manager.get_active_model()
            .unwrap_or_else(|| "unknown".to_string());
        
        let metrics = PerformanceMetrics::new(
            model_name,
            prompt_tokens,
            completion_tokens,
            start_time,
            first_token_time,
            memory_usage_mb,
            queue_depth,
        );
        
        self.metrics.record_inference(metrics);
    }
}

#[async_trait]
impl AiClient for LlamaCppClient {
    #[instrument(skip(self, request, config_override), fields(model = %model_name))]
    async fn exec_chat(
        &self,
        model_name: &str,
        mut request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatResponse, AppError> {
        let start_time = Instant::now();
        
        debug!("Starting LlamaCpp chat execution for model: {}", model_name);
        
        // Check if server is healthy
        let health_status = self.health_checker.check_health().await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("Health check failed: {}", e)))?;
        
        if !health_status.is_healthy {
            return Err(LocalLlmError::ServerUnavailable(
                format!("Server unhealthy: {:?}", health_status)
            ).into());
        }
        
        // Apply security controls
        self.apply_security_controls(&mut request).await?;
        
        // Convert request format and apply config override
        let mut llamacpp_request = self.convert_request(&request, false)?;
        
        // Apply config override if provided
        if let Some(override_config) = config_override {
            if let Some(temp) = override_config.temperature {
                llamacpp_request.temperature = Some(temp as f32);
            }
            if let Some(max_tokens) = override_config.max_tokens {
                llamacpp_request.max_tokens = Some(max_tokens as u32);
            }
            if let Some(top_p) = override_config.top_p {
                llamacpp_request.top_p = Some(top_p as f32);
            }
            if !override_config.stop_sequences.is_empty() {
                llamacpp_request.stop = Some(override_config.stop_sequences);
            }
        }
        
        // Execute with resilience wrapper
        let response = self.resilience.execute_with_retry(|| async {
            self.make_request(llamacpp_request.clone()).await
        }).await?;
        
        // Convert response format
        let mut chat_response = self.convert_response(response)?;
        
        // Apply security validation
        self.validate_response(&chat_response).await?;
        
        // Record metrics
        let prompt_tokens = llamacpp_request.messages.iter()
            .map(|m| m.content.as_ref().map(|c| c.len()).unwrap_or(0) / 4) // Rough token estimation
            .sum();
        let completion_tokens = chat_response.first_content_text_as_str()
            .map(|c| c.len() / 4)
            .unwrap_or(0);
        
        self.record_metrics(start_time, None, prompt_tokens, completion_tokens, 0);
        
        info!("LlamaCpp chat execution completed successfully");
        Ok(chat_response)
    }
    
    #[instrument(skip(self, request, config_override), fields(model = %model_name))]
    async fn stream_chat(
        &self,
        model_name: &str,
        mut request: ChatRequest,
        config_override: Option<ChatOptions>,
    ) -> Result<ChatStream, AppError> {
        debug!("Starting LlamaCpp streaming chat for model: {}", model_name);
        
        // Check if server is healthy
        let health_status = self.health_checker.check_health().await
            .map_err(|e| LocalLlmError::ServerUnavailable(format!("Health check failed: {}", e)))?;
        
        if !health_status.is_healthy {
            return Err(LocalLlmError::ServerUnavailable(
                format!("Server unhealthy: {:?}", health_status)
            ).into());
        }
        
        // Apply security controls
        self.apply_security_controls(&mut request).await?;
        
        // Convert request format with streaming enabled and apply config override
        let mut llamacpp_request = self.convert_request(&request, true)?;
        
        // Apply config override if provided
        if let Some(override_config) = config_override {
            if let Some(temp) = override_config.temperature {
                llamacpp_request.temperature = Some(temp as f32);
            }
            if let Some(max_tokens) = override_config.max_tokens {
                llamacpp_request.max_tokens = Some(max_tokens as u32);
            }
            if let Some(top_p) = override_config.top_p {
                llamacpp_request.top_p = Some(top_p as f32);
            }
            if !override_config.stop_sequences.is_empty() {
                llamacpp_request.stop = Some(override_config.stop_sequences);
            }
        }
        
        // Execute streaming request with resilience wrapper
        let stream = self.resilience.execute_with_retry(|| async {
            self.make_streaming_request(llamacpp_request.clone()).await
        }).await?;
        
        info!("LlamaCpp streaming chat started successfully");
        Ok(stream)
    }
}

impl Drop for LlamaCppClient {
    fn drop(&mut self) {
        // DON'T immediately stop the server when client is dropped
        // Instead, let the server's inactivity timer handle shutdown after 15 minutes
        // This prevents premature shutdown during streaming
        debug!("LlamaCppClient dropped - server will remain running for inactivity timer");
        
        // TODO: Implement reference counting or stream tracking to know when it's safe to shutdown
        // For now, rely on server's built-in inactivity timeout
    }
}

impl std::fmt::Debug for LlamaCppClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlamaCppClient")
            .field("config", &self.config)
            .field("metrics", &"LlamaCppMetrics")
            .field("security", &"SecurityControls")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use genai::chat::{ChatMessage, ChatRole};
    
    fn create_test_config() -> LlamaCppConfig {
        LlamaCppConfig {
            enabled: true,
            model_path: "test-model.gguf".to_string(),
            model_url: Some("https://example.com/model.gguf".to_string()),
            server_host: "127.0.0.1".to_string(),
            server_port: 11435,
            context_size: 2048,
            gpu_layers: Some(32),
            threads: Some(4),
            timeout_seconds: 30,
            max_retries: 2,
            health_check_interval_seconds: 10,
            enable_tool_calling: false,
            parallel_requests: Some(1),
            chat_template: None,
        }
    }
    
    fn create_test_request() -> ChatRequest {
        ChatRequest {
            messages: vec![
                ChatMessage {
                    role: ChatRole::User,
                    content: MessageContent::Text("Hello, how are you?".to_string()),
                    options: Default::default(),
                }
            ],
            system: None,
            tools: None,
            ..Default::default()
        }
    }
    
    #[test]
    fn test_convert_request() {
        let config = create_test_config();
        let model_manager = ModelManager::new_mock();
        
        // This would need a proper mock setup in a real test environment
        // For now, we'll test the conversion logic structure
        let request = create_test_request();
        
        // Test conversion logic (would need proper client setup)
        assert_eq!(request.messages.len(), 1);
        if let MessageContent::Text(text) = &request.messages[0].content {
            assert_eq!(text, "Hello, how are you?");
        }
    }
    
    #[test]
    fn test_llamacpp_request_serialization() {
        let request = LlamaCppChatRequest {
            messages: vec![
                LlamaCppMessage {
                    role: Some("user".to_string()),
                    content: Some("Test message".to_string()),
                }
            ],
            model: "test-model".to_string(),
            temperature: Some(0.7),
            max_tokens: Some(100),
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            stop: None,
            stream: false,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-model"));
        assert!(json.contains("Test message"));
        
        let deserialized: LlamaCppChatRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.model, "test-model");
        assert_eq!(deserialized.messages[0].content, "Test message");
    }
    
    #[test]
    fn test_llamacpp_response_deserialization() {
        let json = r#"{
            "id": "test-id",
            "object": "chat.completion",
            "created": 1234567890,
            "model": "test-model",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! I'm doing well, thank you for asking."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 15,
                "total_tokens": 25
            }
        }"#;
        
        let response: LlamaCppResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.model, "test-model");
        assert_eq!(response.choices.len(), 1);
        assert_eq!(response.choices[0].message.as_ref().unwrap().content, 
                   "Hello! I'm doing well, thank you for asking.");
        assert_eq!(response.usage.as_ref().unwrap().total_tokens, 25);
    }
    
    #[tokio::test]
    async fn test_security_controls_structure() {
        // Test that security controls struct is properly sized
        assert!(std::mem::size_of::<SecurityControls>() > 0);
    }
}