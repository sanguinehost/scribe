// backend/src/vector_db/qdrant_client.rs

use crate::config::Config;
use crate::errors::AppError;
use qdrant_client::Qdrant; // Use the new top-level Qdrant client struct
use qdrant_client::qdrant::{PointStruct, VectorParams, Distance, CreateCollection, VectorsConfig, Filter, ScoredPoint}; // Remove unused SearchPointsBuilder
use qdrant_client::qdrant::vectors_config::Config as QdrantVectorsConfig; // Alias to avoid naming conflict
use std::sync::Arc;
use tracing::{info, error, instrument, warn};
use uuid::Uuid;
use serde_json::json;
use qdrant_client::qdrant::{PointId, Vectors, Value}; // Added imports
use std::collections::HashMap;

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
    use super::*;
    use serde_json::json;
    use uuid::Uuid;
    use qdrant_client::qdrant::{PointId, Vectors, Value}; // Added imports
    use std::collections::HashMap;

    #[test]
    fn test_create_qdrant_point_with_payload() {
        let id = Uuid::new_v4();
        let vector = vec![0.1, 0.2, 0.3];
        let payload = json!({
            "key": "value",
            "number": 123
        });

        let result = create_qdrant_point(id, vector.clone(), Some(payload));
        assert!(result.is_ok());
        let point = result.unwrap();

        // Check ID
        assert_eq!(point.id, Some(PointId::from(id.to_string())));

        // Check Vector
        assert_eq!(point.vectors, Some(Vectors::from(vector)));

        // Check Payload
        assert!(point.payload.contains_key("key"));
        assert!(point.payload.contains_key("number"));
        assert_eq!(point.payload.get("key").unwrap().kind.as_ref().unwrap(), &Value { kind: Some(qdrant_client::qdrant::value::Kind::StringValue("value".to_string())) }.kind.unwrap());
        assert_eq!(point.payload.get("number").unwrap().kind.as_ref().unwrap(), &Value { kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(123)) }.kind.unwrap());
    }

    #[test]
    fn test_create_qdrant_point_without_payload() {
        let id = Uuid::new_v4();
        let vector = vec![0.4, 0.5];

        let result = create_qdrant_point(id, vector.clone(), None);
        assert!(result.is_ok());
        let point = result.unwrap();

        assert_eq!(point.id, Some(PointId::from(id.to_string())));
        assert_eq!(point.vectors, Some(Vectors::from(vector)));
        assert!(point.payload.is_empty(), "Payload should be an empty map");
    }

    #[test]
    fn test_create_qdrant_point_payload_not_object() {
        let id = Uuid::new_v4();
        let vector = vec![0.6];
        let payload = json!("this is just a string"); // Not a JSON object

        let result = create_qdrant_point(id, vector, Some(payload));
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Payload must be a JSON object"));
            }
            _ => panic!("Expected SerializationError due to non-object payload"),
        }
    }

     #[test]
    fn test_create_qdrant_point_payload_deserialization_error() {
        // This tests the internal serde_json::from_value step.
        // We create a valid JSON object but one that might fail complex struct deserialization
        // if we were using a specific struct type here. Since we deserialize to HashMap<String, Value>,
        // most valid JSON objects should work unless they contain types Value can't represent directly.
        // Let's use a nested structure.
        let id = Uuid::new_v4();
        let vector = vec![0.7, 0.8];
        let payload = json!({
            "nested": { "a": 1 },
            "array": [1, 2, 3]
        });

        let result = create_qdrant_point(id, vector.clone(), Some(payload));
        assert!(result.is_ok()); // Should be Ok because HashMap<String, Value> can handle nested objects/arrays
        let point = result.unwrap();

        // Check payload structure was preserved
        assert!(point.payload.contains_key("nested"));
        assert!(point.payload.contains_key("array"));

        let nested_val = point.payload.get("nested").unwrap();
        assert!(matches!(nested_val.kind, Some(qdrant_client::qdrant::value::Kind::StructValue(_))));

        let array_val = point.payload.get("array").unwrap();
         assert!(matches!(array_val.kind, Some(qdrant_client::qdrant::value::Kind::ListValue(_))));

        // If we were expecting a flat structure, we might add a test that fails here.
        // For now, this confirms the basic conversion handles nested JSON.
    }

    // --- Integration Tests (Require running Qdrant instance) ---
    // Add tests here later for:
    // - Test connection (implicitly done by new)
    // - Test ensure_collection_exists (new and existing)
    // - Test upsert (requires running Qdrant)
    // - Test search (requires running Qdrant)
}