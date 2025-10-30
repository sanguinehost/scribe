// backend/src/vector_db/mod.rs

pub mod qdrant_client;

// Re-export key components if needed
pub use qdrant_client::QdrantClientService;

// Export NoOpQdrantService when embedded-vector is enabled OR when neither vector feature is enabled
#[cfg(any(
    feature = "embedded-vector",
    not(any(feature = "remote-vector", feature = "embedded-vector"))
))]
pub use qdrant_client::NoOpQdrantService;
