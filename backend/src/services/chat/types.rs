// backend/src/services/chat/types.rs
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
    Option<Vec<crate::db::DbId>>, // 2: active_lorebook_ids_for_search
    Option<crate::db::DbId>, // 3: session_character_id (NEW) - Now optional for non-character chat modes
    Option<String>, // 4: raw_character_system_prompt (NEW - from character_db.system_prompt)
    Option<crate::db::DbDecimal>, // 5: temperature (was 4)
    Option<i32>,    // 6: max_output_tokens (was 5)
    Option<crate::db::DbDecimal>, // 7: frequency_penalty (was 6)
    Option<crate::db::DbDecimal>, // 8: presence_penalty (was 7)
    Option<i32>,    // 9: top_k (was 8)
    Option<crate::db::DbDecimal>, // 10: top_p (was 9)
    Option<i32>,    // 11: seed (was 13)
    String,         // 12: model_name (Fetched from DB) (was 15)
    Option<String>, // 13: model_provider (NEW - provider type for AI client routing)
    // -- Gemini Specific Options --
    Option<i32>,             // 14: gemini_thinking_budget
    Option<String>,          // 15: gemini_thinking_level (NEW)
    Option<bool>,            // 16: gemini_enable_code_execution (was 15)
    DbInsertableChatMessage, // 17: The user message struct, ready to be saved (was 16)
    // -- RAG Context & Recent History Tokens --
    usize,               // 18: actual_recent_history_tokens (NEW) (was 17)
    Vec<RetrievedChunk>, // 19: rag_context_items (NEW) (was 18)
    // History Management Settings (still returned for potential future use/logging)
    String,                    // 20: history_management_strategy (was 19)
    i32,                       // 21: history_management_limit (was 20)
    Option<String>,            // 22: user_persona_name (NEW - for template substitution)
    Option<crate::db::DbId>,   // 23: player_chronicle_id (NEW - for narrative processing)
    Option<String>,            // 24: agent_mode (NEW - for context enrichment)
    Option<bool>,              // 25: game_master_mode_enabled (NEW - for Game Master processing)
    Option<serde_json::Value>, // 26: initial_game_state (NEW - for double deduction prevention)
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
        variant_count: i32,
        current_variant_index: i32,
    },
    GameState(serde_json::Value),
}
