// backend/src/text_processing/mod.rs

pub mod chunking;

// Re-export key components
pub use chunking::chunk_text;