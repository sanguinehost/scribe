// backend/src/vector_db/qdrant_client.rs

use crate::config::Config;
use crate::errors::AppError;
use qdrant_client::Qdrant; // Use the new top-level Qdrant client struct
use qdrant_client::qdrant::{PointStruct, VectorParams, Distance, CreateCollection, VectorsConfig, Filter, ScoredPoint}; // Remove unused SearchPointsBuilder
use qdrant_client::qdrant::vectors_config::Config as QdrantVectorsConfig; // Alias to avoid naming conflict
use std::sync::Arc;
use tracing::{info, error, instrument, warn};
use uuid::Uuid;

// Constants
const DEFAULT_COLLECTION_NAME: &str = "chat_embeddings";
const EMBEDDING_DIMENSION: u64 = 768; // Dimension for gemini-embedding-001 (or the model you use) - Needs verification for gemini-embedding-exp-03-07

#[derive(Clone)]
pub struct QdrantClientService {
    client: Arc<Qdrant>, // Update client type
    collection_name: String,
    embedding_dimension: u64,
}

impl QdrantClientService {
    #[instrument(skip(config), name = "qdrant_service_new")]
    pub async fn new(config: Arc<Config>) -> Result<Self, AppError> {
        let qdrant_url = config.qdrant_url.as_ref().ok_or_else(|| {
            error!("QDRANT_URL is not configured");
            AppError::ConfigError("QDRANT_URL is not configured".to_string())
        })?;

        info!("Connecting to Qdrant at URL: {}", qdrant_url);

        // Build the Qdrant client
        // Note: Add API key handling if required for Qdrant Cloud or secured instances
        // Use the new Qdrant struct and its builder pattern
        let qdrant_client = Qdrant::from_url(qdrant_url).build().map_err(|e| {
            error!(error = %e, "Failed to build Qdrant client");
            AppError::VectorDbError(format!("Failed to build Qdrant client: {}", e))
        })?;

        let collection_name = config.qdrant_collection_name.clone().unwrap_or_else(|| DEFAULT_COLLECTION_NAME.to_string());
        // TODO: Make embedding dimension configurable or derive from embedding client
        let embedding_dimension = EMBEDDING_DIMENSION;

        let service = Self {
            client: Arc::new(qdrant_client),
            collection_name,
            embedding_dimension,
        };

        // Ensure the collection exists on startup
        service.ensure_collection_exists().await?;

        Ok(service)
    }

    #[instrument(skip(self), name = "qdrant_ensure_collection")]
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        // Use the collection_exist method on the new client (assuming name change, check docs if fails)
        // Correction: Deprecation message confirms method name is still collection_exists
        let collection_exists = self.client.collection_exists(&self.collection_name).await.map_err(|e| {
            error!(error = %e, collection = %self.collection_name, "Failed to check if Qdrant collection exists");
            AppError::VectorDbError(format!("Failed to check Qdrant collection existence: {}", e))
        })?;

        if !collection_exists {
            info!("Collection '{}' does not exist. Creating...", self.collection_name);
            // Use the create_collection method on the new client
            // Pass the CreateCollection struct directly by value
            let create_result = self.client.create_collection(CreateCollection {
                collection_name: self.collection_name.clone(),
                vectors_config: Some(VectorsConfig {
                    config: Some(QdrantVectorsConfig::Params(VectorParams {
                        size: self.embedding_dimension,
                        distance: Distance::Cosine.into(),
                        hnsw_config: None,
                        quantization_config: None,
                        on_disk: None,
                        datatype: None,
                        multivector_config: None,
                    })),
                }),
                ..Default::default()
            }).await;

            match create_result {
                Ok(_) => {
                    // Creation succeeded
                    info!("Successfully created collection '{}'", self.collection_name);
                },
                Err(e) => {
                    // Check if the error is the one we want to ignore
                    let error_string = e.to_string();
                    if error_string.contains("already exists") {
                        warn!(collection = %self.collection_name, "Attempted to create collection, but it already exists (ignoring error).");
                        // Treat as success in the context of ensure_collection_exists
                    } else {
                        // This is a different, unexpected error
                        error!(error = %e, collection = %self.collection_name, "Failed to create Qdrant collection");
                        return Err(AppError::VectorDbError(format!(
                            "Failed to create Qdrant collection '{}': {}",
                            self.collection_name,
                            e
                        )));
                    }
                }
            }
        } else {
            info!("Collection '{}' already exists.", self.collection_name);
            // Optionally: Validate existing collection parameters match expected ones
        }
        Ok(())
    }

    // --- Placeholder for Upsert Operation ---
    #[instrument(skip(self, points), fields(count = points.len()), name = "qdrant_upsert_points")]
    pub async fn upsert_points(&self, points: Vec<PointStruct>) -> Result<(), AppError> {
        if points.is_empty() {
            return Ok(()); // Nothing to do
        }
        info!("Upserting {} points into collection '{}'", points.len(), self.collection_name);
        // Use the upsert_points method (blocking version seems removed/renamed)
        // Construct and pass UpsertPoints struct directly
        self.client
            .upsert_points(qdrant_client::qdrant::UpsertPoints {
                collection_name: self.collection_name.clone(),
                wait: Some(true), // Wait for operation to complete (optional, default false)
                points,
                ordering: None, // Default ordering
                shard_key_selector: None,
            })
            .await
            .map_err(|e| {
                error!(error = %e, collection = %self.collection_name, "Failed to upsert points to Qdrant");
                AppError::VectorDbError(format!("Failed to upsert points: {}", e))
            })?;
        info!("Successfully upserted points.");
        Ok(())
    }


    // --- Search Operation --- 
    #[instrument(skip(self, query_vector, filter), fields(limit), name = "qdrant_search_points")]
    pub async fn search_points(
        &self,
        query_vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        info!(
            limit,
            filter_is_some = filter.is_some(),
            collection = %self.collection_name,
            "Searching points in Qdrant"
        );

        // Build the base search request
        // Note: SearchPointsBuilder might not exist or work this way anymore.
        // Directly constructing SearchPoints is often clearer.
        let mut search_request = qdrant_client::qdrant::SearchPoints {
             collection_name: self.collection_name.clone(),
             vector: query_vector,
             limit,
             with_payload: Some(true.into()), // Request payload
             filter: None, // Initialize filter as None
             // Initialize other fields as needed, using defaults or None
             offset: None,
             score_threshold: None,
             params: None,
             vector_name: None,
             with_vectors: None,
             read_consistency: None,
             timeout: None,
             shard_key_selector: None,
             sparse_indices: None, // Add this if using sparse vectors
        };

        // Conditionally add the filter
        if let Some(f) = filter {
            search_request.filter = Some(f);
        }

        // Use the search_points method on the new client
        let search_result = self
            .client
            // Pass the SearchPoints struct directly by value
            .search_points(search_request)
            .await
            .map_err(|e| {
                error!(error = %e, collection = %self.collection_name, "Failed to search points in Qdrant");
                AppError::VectorDbError(format!("Failed to search points: {}", e))
            })?;

        info!(
            found_points = search_result.result.len(),
            "Qdrant search completed"
        );
        Ok(search_result.result)
    }

    // --- Placeholder for Search Operation ---
    // Add search functionality later as needed by RAG logic
    // pub async fn search(...) -> Result<...> { ... }

}

// --- Helper function to create PointStruct (Example) ---
// This will likely live elsewhere (e.g., in the chunking/embedding pipeline)
pub fn create_qdrant_point(id: Uuid, vector: Vec<f32>, payload: Option<serde_json::Value>) -> Result<PointStruct, AppError> {
    // Convert Option<serde_json::Value> to HashMap<String, qdrant_client::qdrant::Value>
    let qdrant_payload: std::collections::HashMap<String, qdrant_client::qdrant::Value> = match payload {
        Some(json_value) => {
            // Ensure the JSON value is an object before converting
            if !json_value.is_object() {
                 error!("Payload must be a JSON object");
                 return Err(AppError::SerializationError("Payload must be a JSON object".to_string()));
            }
            // Convert serde_json::Value to the target HashMap type
            serde_json::from_value(json_value).map_err(|e| {
                error!(error = %e, "Failed to deserialize JSON payload into Qdrant Value map");
                AppError::SerializationError(format!("Failed to deserialize payload for Qdrant: {}", e))
            })?
        },
        None => Default::default(), // Empty HashMap if no payload provided
    };

    // Convert UUID to string for PointId
    let point_id_str = id.to_string();

    Ok(PointStruct {
        id: Some(point_id_str.into()), // Convert String to Qdrant PointId
        vectors: Some(vector.into()), // Convert Vec<f32> to Qdrant Vectors
        payload: qdrant_payload,
    })
}

// --- Unit/Integration Tests (To be added later) ---
#[cfg(test)]
mod tests {
    // Add tests here
    // - Test connection
    // - Test collection creation
    // - Test point creation helper
    // - Test upsert (requires running Qdrant)
    // - Test search (requires running Qdrant)
}