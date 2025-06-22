use std::sync::Arc;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono;

use crate::{
    auth::session_dek::SessionDek,
    errors::AppError,
    llm::AiClient,
    models::{
        chats::ChatMessage,
        chronicle_event::{ChronicleEvent, EventSource, CreateEventRequest},
    },
    services::{
        ChronicleService,
        tokenizer_service::TokenizerService,
    },
};

// Default extraction model - lightweight for fast processing
const DEFAULT_EXTRACTION_MODEL: &str = "gemini-2.5-flash-lite-preview-06-17";

// Chunking parameters
const DEFAULT_CHUNK_SIZE_MESSAGES: usize = 4;
const DEFAULT_CHUNK_SIZE_TOKENS: usize = 2000;
const CHUNK_OVERLAP_MESSAGES: usize = 1; // Overlap to maintain context

/// Configuration for event extraction
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    pub model_name: String,
    pub chunk_size_messages: usize,
    pub chunk_size_tokens: usize,
    pub chunk_overlap_messages: usize,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            model_name: DEFAULT_EXTRACTION_MODEL.to_string(),
            chunk_size_messages: DEFAULT_CHUNK_SIZE_MESSAGES,
            chunk_size_tokens: DEFAULT_CHUNK_SIZE_TOKENS,
            chunk_overlap_messages: CHUNK_OVERLAP_MESSAGES,
        }
    }
}

/// A chunk of messages to be processed for event extraction
#[derive(Debug, Clone)]
pub struct MessageChunk {
    pub messages: Vec<ChatMessage>,
    pub start_index: usize,
    pub end_index: usize,
    pub estimated_tokens: usize,
}

/// An extracted event before it's saved to the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub summary: String,
    pub participants: Option<Vec<String>>,
    pub location: Option<String>,
    pub details: Option<String>, // Additional context/details
}

/// Response from the LLM for event extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmExtractionResponse {
    pub events: Vec<ExtractedEvent>,
}

/// Helper function to create JSON schema for event extraction structured output
fn get_event_extraction_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "events": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": [
                                "plot.twist.revealed",
                                "character.met",
                                "location.discovered", 
                                "quest.advanced",
                                "conflict.started",
                                "conflict.resolved",
                                "item.acquired",
                                "secret.revealed",
                                "relationship.updated",
                                "character.development",
                                "world.lore.added",
                                "dialogue.key"
                            ]
                        },
                        "summary": {
                            "type": "string"
                        },
                        "participants": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "location": {
                            "type": "string"
                        },
                        "details": {
                            "type": "string"
                        }
                    },
                    "required": ["type", "summary"]
                }
            }
        },
        "required": ["events"]
    })
}

/// Service for extracting chronicle events from chat messages
#[derive(Clone)]
pub struct EventExtractionService {
    ai_client: Arc<dyn AiClient>,
    tokenizer_service: TokenizerService,
    chronicle_service: ChronicleService,
}

impl EventExtractionService {
    #[must_use]
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        tokenizer_service: TokenizerService,
        chronicle_service: ChronicleService,
    ) -> Self {
        Self {
            ai_client,
            tokenizer_service,
            chronicle_service,
        }
    }

    /// Extract events from a range of chat messages
    #[instrument(skip(self, messages, session_dek), fields(message_count = messages.len()))]
    pub async fn extract_events_from_messages(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
        config: ExtractionConfig,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        if messages.is_empty() {
            info!("No messages to extract events from");
            return Ok(vec![]);
        }

        info!(
            "Starting event extraction from {} messages using model {}",
            messages.len(),
            config.model_name
        );

        // Step 1: Chunk the messages intelligently
        let chunks = self.chunk_messages(messages, session_dek, &config).await?;
        info!("Created {} chunks for processing", chunks.len());

        // Step 2: Extract events from each chunk
        let mut all_extracted_events = Vec::new();
        for (chunk_index, chunk) in chunks.iter().enumerate() {
            info!(
                "Processing chunk {} of {} with {} messages (tokens: ~{})",
                chunk_index + 1,
                chunks.len(),
                chunk.messages.len(),
                chunk.estimated_tokens
            );

            match self.extract_events_from_chunk(chunk, session_dek, &config).await {
                Ok(mut events) => {
                    info!(
                        "Successfully extracted {} events from chunk {} of {}",
                        events.len(),
                        chunk_index + 1,
                        chunks.len()
                    );
                    all_extracted_events.append(&mut events);
                }
                Err(e) => {
                    error!(
                        "Failed to extract events from chunk {} of {}: {}",
                        chunk_index + 1,
                        chunks.len(),
                        e
                    );
                    // Continue processing other chunks even if one fails
                }
            }
        }

        // Step 3: Convert extracted events to database models and save them
        let mut saved_events = Vec::new();
        for extracted_event in all_extracted_events {
            match self
                .save_extracted_event(user_id, chronicle_id, extracted_event)
                .await
            {
                Ok(event) => saved_events.push(event),
                Err(e) => {
                    error!("Failed to save extracted event: {}", e);
                    // Continue saving other events even if one fails
                }
            }
        }

        info!(
            "Successfully extracted and saved {} events to chronicle {}",
            saved_events.len(),
            chronicle_id
        );

        Ok(saved_events)
    }

    /// Chunk messages intelligently based on both message count and token limits
    #[instrument(skip(self, messages, session_dek), fields(message_count = messages.len()))]
    async fn chunk_messages(
        &self,
        messages: Vec<ChatMessage>,
        session_dek: &SessionDek,
        config: &ExtractionConfig,
    ) -> Result<Vec<MessageChunk>, AppError> {
        info!("Starting message chunking with {} total messages", messages.len());
        info!("Chunk config: max_messages={}, max_tokens={}, overlap={}", 
            config.chunk_size_messages, config.chunk_size_tokens, config.chunk_overlap_messages);
        
        let mut chunks = Vec::new();
        let mut start_index = 0;

        while start_index < messages.len() {
            info!("Creating chunk starting at message index {}", start_index);
            
            // Determine chunk end based on message count limit
            let mut end_index = std::cmp::min(
                start_index + config.chunk_size_messages,
                messages.len(),
            );

            // Estimate tokens for this chunk and adjust if needed
            let chunk_messages = &messages[start_index..end_index];
            let estimated_tokens = self.estimate_chunk_tokens(chunk_messages, session_dek).await?;
            info!("Initial chunk estimate: {} messages, {} tokens", chunk_messages.len(), estimated_tokens);

            // If chunk exceeds token limit, reduce it
            if estimated_tokens > config.chunk_size_tokens && end_index > start_index + 1 {
                info!("Chunk exceeds token limit, reducing size with binary search");
                // Binary search to find optimal chunk size within token limit
                let mut left = start_index + 1;
                let mut right = end_index;
                
                while left < right {
                    let mid = (left + right + 1) / 2;
                    let test_messages = &messages[start_index..mid];
                    let test_tokens = self.estimate_chunk_tokens(test_messages, session_dek).await?;
                    
                    if test_tokens <= config.chunk_size_tokens {
                        left = mid;
                    } else {
                        right = mid - 1;
                    }
                }
                end_index = left;
                info!("Reduced chunk to {} messages", end_index - start_index);
            }

            let chunk_messages = messages[start_index..end_index].to_vec();
            let final_tokens = self.estimate_chunk_tokens(&chunk_messages, session_dek).await?;

            let chunk = MessageChunk {
                messages: chunk_messages,
                start_index,
                end_index: end_index - 1,
                estimated_tokens: final_tokens,
            };
            
            info!("Created chunk: messages={}, start={}, end={}, tokens={}", 
                chunk.messages.len(), chunk.start_index, chunk.end_index, chunk.estimated_tokens);
            chunks.push(chunk);

            // Move to next chunk with overlap
            let next_start = if end_index >= config.chunk_overlap_messages {
                end_index - config.chunk_overlap_messages
            } else {
                end_index
            };
            
            // Prevent infinite loops - if we're not advancing, break
            if next_start <= start_index {
                info!("Breaking chunking loop to prevent infinite recursion: next_start={}, current_start={}", next_start, start_index);
                break;
            }
            
            start_index = next_start;
            
            if start_index >= messages.len() {
                info!("Reached end of messages, breaking chunking loop");
                break;
            }
        }

        info!("Chunking completed: created {} chunks from {} messages", chunks.len(), messages.len());
        Ok(chunks)
    }

    /// Estimate token count for a slice of messages
    async fn estimate_chunk_tokens(
        &self,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<usize, AppError> {
        let mut total_tokens = 0;
        
        for message in messages {
            // Decrypt the message content to get accurate token count
            let decrypted_content = message.decrypt_content_field(&session_dek.0)
                .unwrap_or_else(|e| {
                    tracing::warn!("Failed to decrypt message {} for token estimation: {}", message.id, e);
                    // Fallback to empty string if decryption fails
                    String::new()
                });
            
            // Rough estimation: ~4 characters per token
            total_tokens += decrypted_content.len() / 4;
        }

        Ok(total_tokens)
    }

    /// Extract events from a single chunk using LLM with structured output
    #[instrument(skip(self, chunk, session_dek), fields(chunk_size = chunk.messages.len()))]
    async fn extract_events_from_chunk(
        &self,
        chunk: &MessageChunk,
        session_dek: &SessionDek,
        config: &ExtractionConfig,
    ) -> Result<Vec<ExtractedEvent>, AppError> {
        info!("Starting event extraction for chunk with {} messages", chunk.messages.len());
        
        // Build the extraction prompt
        info!("Building extraction prompt...");
        let prompt = self.build_extraction_prompt(chunk, session_dek).await?;
        info!("Extraction prompt built successfully, length: {} characters", prompt.len());
        
        // Generate using structured output
        info!("Calling AI with structured output for event extraction...");
        let generated_output = self.generate_with_structured_output(&prompt, &config.model_name).await?;
        
        // Parse the structured output
        let extraction_response: LlmExtractionResponse = serde_json::from_value(generated_output)
            .map_err(|e| {
                error!("Failed to parse structured event extraction output: {}", e);
                AppError::InternalServerErrorGeneric(format!("Failed to parse event extraction output: {}", e))
            })?;

        info!("Successfully extracted {} events from AI response", extraction_response.events.len());

        Ok(extraction_response.events)
    }

    /// Build the prompt for event extraction
    async fn build_extraction_prompt(&self, chunk: &MessageChunk, session_dek: &SessionDek) -> Result<String, AppError> {
        info!("Building extraction prompt for chunk with {} messages", chunk.messages.len());
        
        // Create conversation text representation with decrypted content
        let mut conversation_text = String::new();
        
        for (_i, message) in chunk.messages.iter().enumerate() {
            let role = match message.message_type {
                crate::models::chats::MessageRole::User => "User",
                crate::models::chats::MessageRole::Assistant => "Assistant", 
                crate::models::chats::MessageRole::System => "System",
            };
            
            // Decrypt the message content
            let decrypted_content = message.decrypt_content_field(&session_dek.0)
                .unwrap_or_else(|e| {
                    tracing::warn!("Failed to decrypt message {} for extraction: {}", message.id, e);
                    format!("[Failed to decrypt message: {}]", e)
                });
            
            let message_line = format!(
                "\n{}: {}\n", 
                role, 
                decrypted_content
            );
            
            conversation_text.push_str(&message_line);
        }
        
        info!("Generated conversation text with {} characters", conversation_text.len());

        let prompt = format!(
            r#"Analyze this conversation and extract discrete, meaningful events for a roleplay game chronicle.

CONVERSATION:
{}

EXTRACTION GUIDELINES:
1. Identify significant events, actions, discoveries, character developments, or plot points
2. Focus on events that would be relevant to future roleplay sessions or game integration
3. Each event should be discrete and self-contained
4. Include details that would help a game engine understand the context

EVENT TYPES (choose the most specific):
- plot.twist.revealed: Major story revelations or unexpected developments
- character.met: Introduction of new characters or NPCs
- location.discovered: New places visited or described
- quest.advanced: Progress on missions, goals, or objectives
- conflict.started: Beginning of fights, arguments, or tension
- conflict.resolved: End of conflicts or problems solved
- item.acquired: Discovery or acquisition of objects, artifacts, or tools
- secret.revealed: Hidden information or mysteries uncovered
- relationship.updated: Changes in character relationships or alliances
- character.development: Personal growth, skill gains, or character changes
- world.lore.added: Lore, history, or world background information
- dialogue.key: Important conversations or negotiations

FIELD REQUIREMENTS:
- summary: Brief description of what happened
- participants: Names of characters involved (if any)
- location: Where this took place (if mentioned)
- details: Additional context, consequences, or specifics

Extract 1-3 significant events maximum. If no significant events occurred, return an empty events array."#,
            conversation_text
        );

        Ok(prompt)
    }


    /// Save an extracted event to the database
    #[instrument(skip(self, extracted_event))]
    async fn save_extracted_event(
        &self,
        user_id: Uuid,
        chronicle_id: Uuid,
        extracted_event: ExtractedEvent,
    ) -> Result<ChronicleEvent, AppError> {
        // Create structured event_data following the dual-representation model
        let mut event_data = serde_json::Map::new();
        
        // === The Data Layer (For Game Engines) ===
        
        // Core structured data that games can consume
        if let Some(participants) = &extracted_event.participants {
            if !participants.is_empty() {
                event_data.insert("participants".to_string(), serde_json::json!(participants));
            }
        }
        
        if let Some(location) = &extracted_event.location {
            if !location.is_empty() {
                event_data.insert("location".to_string(), serde_json::json!(location));
            }
        }
        
        if let Some(details) = &extracted_event.details {
            if !details.is_empty() {
                event_data.insert("details".to_string(), serde_json::json!(details));
            }
        }
        
        // Metadata for game integration
        event_data.insert("extraction_source".to_string(), serde_json::json!("ai_chat_analysis"));
        event_data.insert("extracted_at".to_string(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
        
        // Domain-specific data based on event type for game logic
        match extracted_event.event_type.as_str() {
            "character.met" => {
                if let Some(participants) = &extracted_event.participants {
                    if let Some(character_name) = participants.first() {
                        event_data.insert("character_name".to_string(), serde_json::json!(character_name));
                        event_data.insert("action".to_string(), serde_json::json!("met"));
                    }
                }
            },
            "location.discovered" => {
                if let Some(location) = &extracted_event.location {
                    event_data.insert("location_name".to_string(), serde_json::json!(location));
                    event_data.insert("action".to_string(), serde_json::json!("discovered"));
                }
            },
            "item.acquired" => {
                event_data.insert("action".to_string(), serde_json::json!("acquired"));
                // Game engines can parse summary for item names if not structured
            },
            "quest.advanced" => {
                event_data.insert("action".to_string(), serde_json::json!("advanced"));
                // Additional quest data would come from game-specific context
            },
            _ => {
                // Generic action for other event types
                let parts: Vec<&str> = extracted_event.event_type.split('.').collect();
                if parts.len() >= 2 {
                    event_data.insert("domain".to_string(), serde_json::json!(parts[0]));
                    event_data.insert("action".to_string(), serde_json::json!(parts[1]));
                }
            }
        }

        let create_request = CreateEventRequest {
            event_type: extracted_event.event_type,
            summary: extracted_event.summary,
            source: EventSource::AiExtracted,
            event_data: if event_data.is_empty() { None } else { Some(serde_json::Value::Object(event_data)) },
        };

        self.chronicle_service
            .create_event(user_id, chronicle_id, create_request)
            .await
    }

    /// Generate structured output using the AI client with JSON schema
    async fn generate_with_structured_output(
        &self,
        prompt: &str,
        model_name: &str,
    ) -> Result<serde_json::Value, AppError> {
        use genai::chat::{ChatOptions as GenAiChatOptions, HarmBlockThreshold, HarmCategory, SafetySetting, ChatResponseFormat, JsonSchemaSpec, ChatRole, MessageContent};
        
        // Create the user message
        let user_message = genai::chat::ChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(prompt.to_string()),
            options: None,
        };

        // Build chat options for event extraction
        let mut genai_chat_options = GenAiChatOptions::default();
        
        // Set temperature for consistent extraction
        genai_chat_options = genai_chat_options.with_temperature(0.3);
        
        // Set max tokens for event extraction
        genai_chat_options = genai_chat_options.with_max_tokens(4096);
        
        // Add safety settings to allow analysis of any content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        genai_chat_options = genai_chat_options.with_safety_settings(safety_settings);

        // Enable structured output using JSON schema
        let json_schema_spec = JsonSchemaSpec::new(get_event_extraction_schema());
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        genai_chat_options = genai_chat_options.with_response_format(response_format);

        // Create system prompt for event extraction
        let system_prompt = "You are an expert chronicle keeper for a roleplay game. Analyze the conversation and extract discrete, meaningful events that should be recorded in the game's chronicle. Focus on events that would be relevant to future roleplay sessions.";

        // Create chat request
        let chat_req = genai::chat::ChatRequest::new(vec![user_message]).with_system(system_prompt);
        
        info!("Making structured AI call for event extraction with model: {}", model_name);
        
        // Call the AI client
        let response = self.ai_client
            .exec_chat(model_name, chat_req, Some(genai_chat_options))
            .await
            .map_err(|e| {
                error!("AI client call failed during structured event extraction: {}", e);
                AppError::LlmClientError(format!("Structured event extraction failed: {e}"))
            })?;

        info!("AI client call successful, processing structured response...");

        // Process the response to extract JSON value
        self.process_structured_chat_response(response)
    }

    /// Process structured chat response to extract JSON value
    fn process_structured_chat_response(
        &self,
        response: genai::chat::ChatResponse,
    ) -> Result<serde_json::Value, AppError> {
        // Extract the first content as text
        let content = response.first_content_text_as_str().unwrap_or_default();
        info!("Processing structured response, content length: {} characters", content.len());
        
        // The response should already be JSON due to structured output
        // But let's handle it gracefully in case it's wrapped in markdown
        let cleaned_content = if content.trim().starts_with("```json") {
            // Extract content between ```json and ```
            let start = content.find("```json").unwrap() + 7;
            let end = content.rfind("```").unwrap_or(content.len());
            content[start..end].trim()
        } else if content.trim().starts_with("```") {
            // Extract content between ``` and ```
            let start = content.find("```").unwrap() + 3;
            let end = content.rfind("```").unwrap_or(content.len());
            content[start..end].trim()
        } else {
            content.trim()
        };

        // Parse as JSON
        serde_json::from_str(cleaned_content)
            .map_err(|e| {
                error!("Failed to parse structured response as JSON: {}", e);
                debug!("Raw response content: {}", content);
                debug!("Cleaned content: {}", cleaned_content);
                AppError::InternalServerErrorGeneric(format!("Failed to parse structured response: {}", e))
            })
    }
}