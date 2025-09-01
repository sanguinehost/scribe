// backend/src/services/chat/types.rs
use bigdecimal::BigDecimal;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

// Imports needed for the types defined in this file, based on original chat_service.rs
pub use crate::models::chats::{ChatMessage, DbInsertableChatMessage, MessageRole};
pub use crate::services::embeddings::RetrievedChunk;
// User and UserPersona are not directly re-exported here as they were not top-level imports
// in chat_service.rs for general use by other modules. They were used internally.
// Modules like generation.rs will import them directly from crate::models if needed.

// Type alias for the history tuple returned for generation
pub type HistoryForGeneration = Vec<(MessageRole, String)>;

// Type alias for the full data needed for generation, including the model name
// AND the unsaved user message struct
// NOTE: HistoryForGeneration here will now contain the *managed* history.
pub type GenerationDataWithUnsavedUserMessage = (
    Vec<ChatMessage>, // 0: managed_db_history (CHANGED from HistoryForGeneration) - Changed DbChatMessage to ChatMessage
    Option<String>, // 1: system_prompt (this is the final_effective_system_prompt for the builder, from persona/override only)
    Option<Vec<Uuid>>, // 2: active_lorebook_ids_for_search
    Option<Uuid>,   // 3: session_character_id (NEW) - Now optional for non-character chat modes
    Option<String>, // 4: raw_character_system_prompt (NEW - from character_db.system_prompt)
    Option<BigDecimal>, // 5: temperature (was 4)
    Option<i32>,    // 6: max_output_tokens (was 5)
    Option<BigDecimal>, // 7: frequency_penalty (was 6)
    Option<BigDecimal>, // 8: presence_penalty (was 7)
    Option<i32>,    // 9: top_k (was 8)
    Option<BigDecimal>, // 10: top_p (was 9)
    Option<i32>,    // 11: seed (was 13)
    String,         // 12: model_name (Fetched from DB) (was 15)
    Option<String>, // 13: model_provider (NEW - provider type for AI client routing)
    // -- Gemini Specific Options --
    Option<i32>,             // 14: gemini_thinking_budget (was 16)
    Option<bool>,            // 15: gemini_enable_code_execution (was 17)
    DbInsertableChatMessage, // 16: The user message struct, ready to be saved (was 18)
    // -- RAG Context & Recent History Tokens --
    usize,               // 17: actual_recent_history_tokens (NEW) (was 19)
    Vec<RetrievedChunk>, // 18: rag_context_items (NEW) (was 20)
    // History Management Settings (still returned for potential future use/logging)
    String,         // 19: history_management_strategy (was 21)
    i32,            // 20: history_management_limit (was 22)
    Option<String>, // 21: user_persona_name (NEW - for template substitution)
    Option<Uuid>,   // 22: player_chronicle_id (NEW - for narrative processing)
    Option<String>, // 23: agent_mode (NEW - for context enrichment)
);

/// Structured chunk with integrity checking for reliable streaming
#[derive(Debug, Serialize, Deserialize)]
pub struct StreamedChunk {
    pub index: u32,
    pub content: String,
    pub checksum: u32,
}

#[derive(Debug)]
pub enum ScribeSseEvent {
    Content(String), // Now contains JSON-serialized StreamedChunk
    Thinking(String),
    Error(String),
    TokenUsage {
        prompt_tokens: i32,
        completion_tokens: i32,
        model_name: String,
    },
    MessageSaved {
        message_id: String,
    },
}
