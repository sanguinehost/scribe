// backend/src/vector_db/mod.rs

pub mod qdrant_client;

// Re-export key components if needed
pub use qdrant_client::QdrantClientService;

#[cfg(feature = "embedded-vector")]
pub use qdrant_client::NoOpQdrantService;
