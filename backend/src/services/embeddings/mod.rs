// backend/src/services/embeddings/mod.rs

pub mod metadata;
pub mod utils; 
pub mod trait_def;
pub mod service;
pub mod retrieval;

#[cfg(test)]
pub mod tests;

// Re-export the main types and traits for easy access
pub use metadata::{ChatMessageChunkMetadata, LorebookChunkMetadata, LorebookEntryParams};
pub use trait_def::EmbeddingPipelineServiceTrait;
pub use service::EmbeddingPipelineService;
pub use retrieval::{RetrievedMetadata, RetrievedChunk};
pub use utils::{
    extract_string_from_payload, extract_uuid_from_payload, 
    extract_optional_string_from_payload, extract_string_list_from_payload,
    extract_bool_from_payload
};