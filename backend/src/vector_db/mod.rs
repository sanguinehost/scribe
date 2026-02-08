use crate::errors::AppError;
use async_trait::async_trait;
#[allow(unused_imports)]
use std::sync::Arc;

#[cfg(feature = "embedded-vector")]
pub mod rig_lancedb_adapter;
#[cfg(feature = "remote-vector")]
pub mod rig_qdrant_adapter;
pub mod utils;

/// Unified trait for vector database operations.
/// Implementations can convert the `serde_json::Value` filter to their native filter type.
#[async_trait]
pub trait VectorServiceTrait: Send + Sync {
    async fn ensure_collection_exists(&self) -> Result<(), AppError>;
    async fn ensure_collection_exists_named(&self, collection_name: &str) -> Result<(), AppError>;
    async fn add_document(&self, document: serde_json::Value) -> Result<(), AppError>;
    async fn add_documents(&self, documents: Vec<serde_json::Value>) -> Result<(), AppError>;
    async fn add_document_to_collection(
        &self,
        collection_name: &str,
        document: serde_json::Value,
    ) -> Result<(), AppError>;
    async fn search_values(
        &self,
        query: &str,
        limit: usize,
        filter: Option<::qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<(f32, serde_json::Value)>, AppError>;
    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        text_query: Option<String>,
        text_fields: Vec<String>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn retrieve_points(
        &self,
        filter: Option<::qdrant_client::qdrant::Filter>,
        limit: u64,
        offset: Option<u64>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn delete_points(
        &self,
        ids: Vec<::qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError>;
    async fn delete_by_filter(
        &self,
        filter: ::qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError>;
    async fn delete_by_id(&self, id: &str) -> Result<(), AppError>;
    async fn optimize_collection(&self) -> Result<(), AppError>;
    async fn health_check(&self) -> Result<(), AppError>;
}

pub async fn create_vector_service(
    config: Arc<crate::config::Config>,
    embedding_model: crate::llm::UnifiedEmbeddingModel,
) -> Result<Arc<dyn VectorServiceTrait>, AppError> {
    #[cfg(feature = "remote-vector")]
    {
        Ok(Arc::new(
            rig_qdrant_adapter::RigQdrantService::new(config, embedding_model).await?,
        ))
    }
    #[cfg(feature = "embedded-vector")]
    {
        Ok(Arc::new(
            rig_lancedb_adapter::RigLanceDbService::new(config, embedding_model).await?,
        ))
    }
    #[cfg(not(any(feature = "remote-vector", feature = "embedded-vector")))]
    {
        let _ = config;
        let _ = embedding_model;
        Err(AppError::ConfigError(
            "No vector database feature enabled".to_string(),
        ))
    }
}

pub type VectorService = dyn VectorServiceTrait;

#[async_trait]
pub trait QdrantClientServiceTrait: Send + Sync {
    async fn ensure_collection_exists(&self) -> Result<(), AppError>;
    async fn store_points(
        &self,
        points: Vec<::qdrant_client::qdrant::PointStruct>,
    ) -> Result<(), AppError>;
    async fn store_points_to_collection(
        &self,
        collection_name: &str,
        points: Vec<::qdrant_client::qdrant::PointStruct>,
    ) -> Result<(), AppError>;
    async fn search_points(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn search_points_in_collection(
        &self,
        collection_name: &str,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn search_points_with_threshold(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn hybrid_search(
        &self,
        vector: Option<Vec<f32>>,
        text_query: Option<String>,
        text_fields: Vec<String>,
        limit: u64,
        filter: Option<::qdrant_client::qdrant::Filter>,
        score_threshold: Option<f32>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn retrieve_points(
        &self,
        filter: Option<::qdrant_client::qdrant::Filter>,
        limit: u64,
        offset: Option<u64>,
    ) -> Result<Vec<::qdrant_client::qdrant::ScoredPoint>, AppError>;
    async fn delete_points(
        &self,
        _point_ids: Vec<::qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError>;
    async fn delete_points_by_filter(
        &self,
        filter: ::qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError>;
    async fn delete_points_from_collection(
        &self,
        collection_name: &str,
        points: Vec<::qdrant_client::qdrant::PointId>,
    ) -> Result<(), AppError>;
    async fn delete_points_by_filter_from_collection(
        &self,
        collection_name: &str,
        filter: ::qdrant_client::qdrant::Filter,
    ) -> Result<(), AppError>;
    async fn update_collection_settings(&self) -> Result<(), AppError>;
    async fn get_point_by_id(
        &self,
        point_id: ::qdrant_client::qdrant::PointId,
    ) -> Result<Option<::qdrant_client::qdrant::RetrievedPoint>, AppError>;
    async fn health_check(&self) -> Result<(), AppError>;
    async fn optimize_collection(&self) -> Result<(), AppError>;
    async fn delete_by_id(&self, id: &str) -> Result<(), AppError>;
    async fn ensure_collection_exists_named(&self, collection_name: &str) -> Result<(), AppError>;
}

// Keep old clients for now to avoid massive breakage during transition
#[cfg(feature = "remote-vector")]
pub mod qdrant_client;
#[cfg(feature = "remote-vector")]
pub use qdrant_client::QdrantClientService;
#[cfg(feature = "embedded-vector")]
pub mod lancedb_client;
#[cfg(feature = "embedded-vector")]
pub use lancedb_client::LanceDbClient;
