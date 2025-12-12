// backend/src/vector_db/mod.rs

pub mod qdrant_client;

#[cfg(feature = "embedded-vector")]
pub mod lancedb_client;

// Re-export key components
pub use qdrant_client::QdrantClientService;

// Export LanceDbClient when embedded-vector is enabled
#[cfg(feature = "embedded-vector")]
pub use lancedb_client::LanceDbClient;

// Export NoOpQdrantService only when no vector feature is enabled (fallback)
#[cfg(not(any(feature = "remote-vector", feature = "embedded-vector")))]
pub use qdrant_client::NoOpQdrantService;
