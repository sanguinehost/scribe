// backend/src/vector_db/qdrant_client.rs

use crate::config::Config;
use crate::errors::AppError;
use async_trait::async_trait;
use qdrant_client::Qdrant;
use qdrant_client::qdrant::vectors_config::Config as QdrantVectorsConfig; // Alias to avoid naming conflict
pub use qdrant_client::qdrant::{
    Condition, CreateCollection, CreateFieldIndexCollection, Distance, FieldCondition, FieldType,
    Filter, HnswConfigDiff, Match, OptimizersConfigDiff, PayloadIncludeSelector, PointId,
    PointStruct, ReadConsistency, ReadConsistencyType, ScoredPoint, UpdateCollection, Value,
    VectorParams, VectorsConfig, WalConfigDiff, WithPayloadSelector, condition::ConditionOneOf,
    r#match::MatchValue, point_id::PointIdOptions, value::Kind,
};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

// Constants
pub const DEFAULT_COLLECTION_NAME: &str = "scribe_embeddings";
// Removed hardcoded EMBEDDING_DIMENSION constant

#[derive(Clone)]
pub struct QdrantClientService {
    client: Arc<Qdrant>, // Update client type
    collection_name: String,
    embedding_dimension: u64,
    distance_metric: Distance, // Added from config
    on_disk: Option<bool>,     // Added from config
}

#[async_trait]
pub trait QdrantClientServiceTrait: Send + Sync {
    async fn ensure_collection_exists(&self) -> Result<(), AppError>;
    async fn store_points(&self, points: Vec<PointStruct>) -> Result<(), AppError>;
    async fn search_points(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError>;
    async fn retrieve_points(
        &self,
        filter: Option<Filter>,
        limit: u64,
    ) -> Result<Vec<ScoredPoint>, AppError>; // Added Retrieve Method
    async fn delete_points(&self, _point_ids: Vec<PointId>) -> Result<(), AppError>;
    async fn delete_points_by_filter(&self, filter: Filter) -> Result<(), AppError>;
    async fn update_collection_settings(&self) -> Result<(), AppError>; // Added Update Settings Method
    async fn get_point_by_id(
        &self,
        point_id: PointId,
    ) -> Result<Option<qdrant_client::qdrant::RetrievedPoint>, AppError>;
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

        let collection_name = config.qdrant_collection_name.clone(); // Access directly from config

        // Use embedding dimension from config
        let embedding_dimension = config.embedding_dimension;
        info!(embedding_dimension, "Using embedding dimension from config");

        // Parse distance metric from config
        let distance_metric_str = &config.qdrant_distance_metric;
        let distance_metric = match distance_metric_str.to_lowercase().as_str() {
            "cosine" => Distance::Cosine,
            "euclid" => Distance::Euclid,
            "dot" => Distance::Dot,
            _ => {
                error!(
                    "Invalid QDRANT_DISTANCE_METRIC configured: '{}'. Must be one of 'Cosine', 'Euclid', 'Dot'.",
                    distance_metric_str
                );
                return Err(AppError::ConfigError(format!(
                    "Invalid QDRANT_DISTANCE_METRIC: {}",
                    distance_metric_str
                )));
            }
        };
        info!(?distance_metric, "Using distance metric from config");

        // Get on_disk setting from config
        let on_disk = config.qdrant_on_disk;
        info!(?on_disk, "Using on_disk setting from config");

        let service = Self {
            client: Arc::new(qdrant_client),
            collection_name,
            embedding_dimension,
            distance_metric,
            on_disk,
        };

        // Ensure the collection exists on startup
        service.ensure_collection_exists().await?;

        Ok(service)
    }

    /// Private constructor for creating a dummy instance for tests where
    /// the actual Qdrant service is mocked at a higher level.
    /// Avoids hitting network or requiring config.
    pub fn new_test_dummy() -> Self {
        // NOTE: The Qdrant client here is likely non-functional or will panic if used.
        // This is acceptable ONLY because the AppStateBuilder uses this when the
        // higher-level service (like EmbeddingPipelineService) is mocked, meaning
        // this dummy QdrantClientService won't actually be called.
        Self {
            // Attempt to build a client with a dummy URL. This might still panic
            // if the builder tries to resolve the URL immediately, but it avoids Default::default().
            // If this panics, we might need a more sophisticated mock/dummy approach.
            client: Arc::new(
                Qdrant::from_url("http://localhost:6333")
                    .build()
                    .expect("Failed to build dummy Qdrant client"),
            ),
            collection_name: DEFAULT_COLLECTION_NAME.to_string(), // Keep default for dummy
            embedding_dimension: 768, // Use a reasonable default (e.g., 768) for the dummy instance
            distance_metric: Distance::Cosine, // Default for dummy
            on_disk: None,            // Default for dummy
        }
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
            info!(
                "Collection '{}' does not exist. Creating...",
                self.collection_name
            );
            // Use the create_collection method on the new client
            // Pass the CreateCollection struct directly by value
            let target_hnsw_config = HnswConfigDiff {
                m: Some(0),          // Disable global HNSW
                payload_m: Some(16), // Enable per-group HNSW
                ..Default::default()
            };
            let create_result = self
                .client
                .create_collection(CreateCollection {
                    collection_name: self.collection_name.clone(),
                    vectors_config: Some(VectorsConfig {
                        config: Some(QdrantVectorsConfig::Params(VectorParams {
                            size: self.embedding_dimension,
                            distance: self.distance_metric.into(), // Use configured distance
                            hnsw_config: Some(target_hnsw_config),
                            quantization_config: None,
                            on_disk: self.on_disk, // Use configured on_disk setting
                            datatype: None,
                            multivector_config: None,
                        })),
                    }),
                    ..Default::default()
                })
                .await;

            match create_result {
                Ok(_) => {
                    // Creation succeeded
                    info!("Successfully created collection '{}'", self.collection_name);

                    // Wait for collection to be fully ready with increased timeout
                    for i in 0..20 { // Increased retries
                        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await; // Increased sleep duration
                        match self.client.collection_exists(&self.collection_name).await {
                            Ok(true) => {
                                info!(
                                    "Collection '{}' confirmed ready after {}ms",
                                    self.collection_name,
                                    (i + 1) * 200
                                );
                                break;
                            }
                            Ok(false) => {
                                if i == 19 { // Adjusted for new retry count
                                    return Err(AppError::VectorDbError(format!(
                                        "Collection '{}' was created but is not accessible after {} seconds",
                                        self.collection_name,
                                        (i + 1) * 200 / 1000
                                    )));
                                }
                            }
                            Err(e) => {
                                if i == 19 { // Adjusted for new retry count
                                    return Err(AppError::VectorDbError(format!(
                                        "Failed to verify collection '{}' exists after creation: {}",
                                        self.collection_name, e
                                    )));
                                }
                            }
                        }
                    }
                }
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
                            self.collection_name, e
                        )));
                    }
                }
            }
        } else {
            info!("Collection '{}' already exists.", self.collection_name);
            // Ensure existing collection has the correct HNSW settings
            let target_hnsw_config = HnswConfigDiff {
                m: Some(0),
                payload_m: Some(16),
                ..Default::default()
            };
            info!(
                "Updating HNSW config for existing collection '{}': m=0, payload_m=16",
                self.collection_name
            );
            self.client
                .update_collection(UpdateCollection {
                    collection_name: self.collection_name.clone(),
                    hnsw_config: Some(target_hnsw_config.clone()),
                    ..Default::default()
                })
                .await
                .map_err(|e| {
                    error!(error = %e, collection = %self.collection_name, "Failed to update HNSW config for Qdrant collection");
                    AppError::VectorDbError(format!(
                        "Failed to update HNSW config for Qdrant collection '{}': {}",
                        self.collection_name, e
                    ))
                })?;
            info!(
                "Successfully updated HNSW config for collection '{}'",
                self.collection_name
            );
        }

        // Ensure payload indexes exist for group_id fields
        for field_name in ["user_id", "lorebook_id"].iter() {
            info!(
                "Ensuring payload index exists for field '{}' in collection '{}'",
                field_name, self.collection_name
            );
            // It's possible the index already exists. Qdrant's create_field_index
            // is idempotent if the index already exists with the same parameters.
            // If it exists with different parameters, it might error.
            // We'll log errors but proceed, as the main goal is to *try* to create them.
            let result = self
                .client
                .create_field_index(CreateFieldIndexCollection {
                    collection_name: self.collection_name.clone(),
                    wait: Some(true),
                    field_name: field_name.to_string(),
                    field_type: Some(FieldType::Keyword.into()),
                    field_index_params: None, // Use default index params for keyword
                    ordering: None,
                })
                .await;

            match result {
                Ok(_) => info!(
                    "Successfully ensured payload index for field '{}'",
                    field_name
                ),
                Err(e) => {
                    // Check if the error indicates the index already exists (common case)
                    // Qdrant error for "already exists" might be specific, e.g., involving "Wrong input" if types mismatch
                    // or a more generic "already exists". For now, we log and continue.
                    // A more robust check might involve trying to get collection info and inspect existing indexes.
                    let error_string = e.to_string();
                    if error_string.contains("already exists")
                        || error_string.contains("exists with different parameters")
                    {
                        warn!(error = %e, collection = %self.collection_name, field = %field_name, "Payload index for field may already exist or have different params. Proceeding.");
                    } else {
                        error!(error = %e, collection = %self.collection_name, field = %field_name, "Failed to create payload index for field. This might be an issue if filtering is required on this field.");
                        // Decide if this should be a hard error. For now, let's make it a hard error to be safe.
                        return Err(AppError::VectorDbError(format!(
                            "Failed to create payload index for field '{}': {}",
                            field_name, e
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    // --- Placeholder for Upsert Operation ---
    #[instrument(skip(self, points), fields(count = points.len()), name = "qdrant_upsert_points")]
    pub async fn upsert_points(&self, points: Vec<PointStruct>) -> Result<(), AppError> {
        if points.is_empty() {
            return Ok(()); // Nothing to do
        }
        info!(
            "Upserting {} points into collection '{}'",
            points.len(),
            self.collection_name
        );
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
    #[instrument(
        skip(self, query_vector, filter),
        fields(limit),
        name = "qdrant_search_points"
    )]
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
        // Remove unused `mut`
        let search_request = qdrant_client::qdrant::SearchPoints {
            collection_name: self.collection_name.clone(),
            vector: query_vector,
            limit,
            with_payload: Some(true.into()), // Request payload
            filter,                  // Use the passed-in filter directly
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

    // --- Retrieve Operation (using Scroll API) ---
    #[instrument(
        skip(self, filter),
        fields(limit),
        name = "qdrant_retrieve_points_scroll"
    )]
    pub async fn retrieve_points(
        &self,
        filter: Option<Filter>,
        limit: usize,
    ) -> Result<Vec<qdrant_client::qdrant::RetrievedPoint>, AppError> {
        info!(
            limit,
            filter_is_some = filter.is_some(),
            collection = %self.collection_name,
            "Retrieving points from Qdrant using scroll"
        );

        // Use the client's `scroll` method for retrieving by filter
        let scroll_request = qdrant_client::qdrant::ScrollPoints {
            collection_name: self.collection_name.clone(),
            filter,
            limit: Some(limit as u32), // Scroll API uses u32 for limit
            with_payload: Some(true.into()),
            with_vectors: Some(true.into()), // Include vectors (optional)
            offset: None,                    // Start from the beginning
            read_consistency: None,          // Correct field name
            shard_key_selector: None,
            // Add missing fields required by ScrollPoints
            order_by: None,
            timeout: None,
        };

        let scroll_response = self
            .client
            .scroll(scroll_request) // Pass request by value
            .await
            .map_err(|e| {
                error!(error = %e, collection = %self.collection_name, "Failed to scroll points in Qdrant");
                AppError::VectorDbError(format!("Failed to scroll points: {}", e))
            })?;

        info!(
            found_points = scroll_response.result.len(),
            next_page_offset = ?scroll_response.next_page_offset,
            "Qdrant scroll completed"
        );

        Ok(scroll_response.result)
    }

    // --- Placeholder for Search Operation ---
    // Add search functionality later as needed by RAG logic
    // pub async fn search(...) -> Result<...> { ... }
}

// --- Helper function to create PointStruct (Example) ---
// This will likely live elsewhere (e.g., in the chunking/embedding pipeline)
pub fn create_qdrant_point(
    id: Uuid,
    vector: Vec<f32>,
    payload: Option<serde_json::Value>,
) -> Result<PointStruct, AppError> {
    // Convert Option<serde_json::Value> to HashMap<String, qdrant_client::qdrant::Value>
    let qdrant_payload: std::collections::HashMap<String, Value> = match payload {
        Some(json_value) => {
            // Ensure the JSON value is an object before converting
            if !json_value.is_object() {
                error!("Payload must be a JSON object");
                return Err(AppError::SerializationError(
                    "Payload must be a JSON object".to_string(),
                ));
            }
            // Convert serde_json::Value to the target HashMap type
            serde_json::from_value(json_value).map_err(|e| {
                error!(error = %e, "Failed to deserialize JSON payload into Qdrant Value map");
                AppError::SerializationError(format!(
                    "Failed to deserialize payload for Qdrant: {}",
                    e
                ))
            })?
        }
        None => Default::default(), // Empty HashMap if no payload provided
    };

    // Convert UUID to string for PointId
    let point_id_str = id.to_string();

    Ok(PointStruct {
        id: Some(point_id_str.into()), // Convert String to Qdrant PointId
        vectors: Some(vector.into()),  // Convert Vec<f32> to Qdrant Vectors
        payload: qdrant_payload,
    })
}

// Add a helper function to create a filter for message_id
pub fn create_message_id_filter(message_id: Uuid) -> Filter {
    Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "message_id".to_string(), // Assumes metadata field name
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword(message_id.to_string())),
                }),
                ..Default::default() // Initialize other FieldCondition fields if needed
            })),
        }],
        ..Default::default() // Initialize other Filter fields if needed
    }
}

// --- Unit/Integration Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use dotenvy::dotenv;
    use qdrant_client::qdrant::r#match::MatchValue; // Corrected import
    use qdrant_client::qdrant::point_id::PointIdOptions;
    use qdrant_client::qdrant::{Condition, FieldCondition, Filter, Match, value::Kind};
    use qdrant_client::qdrant::{PointId, Value, Vectors}; // Correct the import path for PointId and Vectors if they are part of the public API
    use serde_json::json; // Moved import here
    use std::sync::Arc; // Removed Once
    use tokio; // Add tokio for async tests
    use uuid::Uuid; // Import for PointId variants
    // Use Rng trait for gen method, StdRng for concrete type, SeedableRng for seeding
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    // Removed: use rustls;
    use tracing::info; // Already used

    // Removed static INIT_RUSTLS_PROVIDER and local ensure_rustls_provider_installed function

    // Helper function to load config and create a real Qdrant client for integration tests
    async fn setup_test_qdrant_client() -> Result<QdrantClientService, AppError> {
        setup_test_qdrant_client_with_name(None).await
    }

    async fn setup_test_qdrant_client_with_name(
        collection_name: Option<String>,
    ) -> Result<QdrantClientService, AppError> {
        crate::test_helpers::ensure_rustls_provider_installed(); // Call public helper

        dotenv().ok(); // Load .env file for QDRANT_URL
        let mut config = Config::load().expect("Failed to load config for integration test");

        // Use a unique collection name for each test to avoid conflicts
        let unique_collection_name = collection_name.unwrap_or_else(|| {
            format!(
                "test_collection_{}",
                Uuid::new_v4().to_string().replace('-', "_")
            )
        });
        config.qdrant_collection_name = unique_collection_name.clone();

        let config = Arc::new(config);

        // Add a small random delay to stagger concurrent test execution
        use rand::random;
        let delay_ms = random::<u64>() % 1000; // 0-999 ms
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

        let service = QdrantClientService::new(config).await?;

        info!("Setting up test collection '{}'", service.collection_name);

        // Ensure the collection exists (create it fresh for the test)
        service.ensure_collection_exists().await?;
        info!("Collection '{}' ready for test.", service.collection_name);

        Ok(service)
    }

    // Helper to cleanup test collection
    async fn cleanup_test_collection(service: &QdrantClientService) {
        info!("Cleaning up test collection '{}'", service.collection_name);
        let _ = service
            .client
            .delete_collection(&service.collection_name)
            .await;
    }

    // Helper to create a simple filter for testing
    fn create_test_filter(key: &str, value: &str) -> Filter {
        Filter {
            must: vec![Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: key.to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(value.to_string())),
                    }),
                    ..Default::default() // Initialize other fields as needed
                })),
            }],
            ..Default::default()
        }
    }

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
        assert_eq!(
            point.payload.get("key").unwrap().kind.as_ref().unwrap(),
            &Value {
                kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                    "value".to_string()
                ))
            }
            .kind
            .unwrap()
        );
        assert_eq!(
            point.payload.get("number").unwrap().kind.as_ref().unwrap(),
            &Value {
                kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(123))
            }
            .kind
            .unwrap()
        );
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
        assert!(matches!(
            nested_val.kind,
            Some(qdrant_client::qdrant::value::Kind::StructValue(_))
        ));

        let array_val = point.payload.get("array").unwrap();
        assert!(matches!(
            array_val.kind,
            Some(qdrant_client::qdrant::value::Kind::ListValue(_))
        ));

        // If we were expecting a flat structure, we might add a test that fails here.
        // For now, this confirms the basic conversion handles nested JSON.
    }

    #[test]
    fn test_new_test_dummy_creation() {
        // This test covers lines 89, 98, 103
        let dummy_service = QdrantClientService::new_test_dummy();
        // Basic assertion to ensure it runs without panic and fields are initialized
        assert_eq!(dummy_service.collection_name, DEFAULT_COLLECTION_NAME);
        assert_eq!(dummy_service.embedding_dimension, 768); // Check against the dummy default
        // We don't assert on the client itself as it's expected to be non-functional.
        drop(dummy_service);
    }
    // --- Integration Tests (Require running Qdrant instance) ---
    // Run these tests with `cargo test -- --ignored`

    #[tokio::test]
    #[ignore] // Re-added as it's an integration test
    async fn test_integration_connection_and_collection() {
        let result = setup_test_qdrant_client().await;
        assert!(
            result.is_ok(),
            "Failed to connect to Qdrant and ensure collection exists: {:?}",
            result.err()
        );
        drop(result);

        let service = setup_test_qdrant_client().await.unwrap();

        // Verify the collection actually exists
        let exists = service
            .client
            .collection_exists(&service.collection_name)
            .await;
        assert!(
            exists.is_ok() && exists.unwrap(),
            "Collection should exist after service initialization"
        );

        // Clean up the test collection
        cleanup_test_collection(&service).await;
        drop(service);
    }

    #[tokio::test]
    #[ignore] // Re-added as it's an integration test
    async fn test_integration_upsert_and_search() {
        let service = setup_test_qdrant_client()
            .await
            .expect("Failed to setup Qdrant client");
        let _collection_name = service.collection_name.clone(); // Prefix unused variable
        let embedding_dim = usize::try_from(service.embedding_dimension).expect("embedding dimension should fit in usize");

        let point_id_1 = Uuid::new_v4();
        // Use slightly more distinct vectors for testing
        let mut rng1 = StdRng::seed_from_u64(42); // Seeded RNG for reproducibility
        // Use rng.gen::<f32>() for f32 which generates [0.0, 1.0)
        let vector_1: Vec<f32> = (0..embedding_dim).map(|_| rng1.random::<f32>()).collect();

        let payload_1 = json!({"test_key": "value1"});
        let point_1 = create_qdrant_point(point_id_1, vector_1.clone(), Some(payload_1.clone()))
            .expect("Failed to create point 1");

        let point_id_2 = Uuid::new_v4();
        // Use a different seed or different generation logic for vector_2
        let mut rng2 = StdRng::seed_from_u64(99);
        let vector_2: Vec<f32> = (0..embedding_dim).map(|_| rng2.random::<f32>()).collect();

        let payload_2 = json!({"test_key": "value2"});
        let point_2 = create_qdrant_point(point_id_2, vector_2.clone(), Some(payload_2.clone()))
            .expect("Failed to create point 2");

        // Upsert points
        let upsert_result = service.upsert_points(vec![point_1, point_2]).await;
        assert!(
            upsert_result.is_ok(),
            "Failed to upsert points: {:?}",
            upsert_result.err()
        );

        // Give Qdrant a moment to index (usually fast, but safer in tests)
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await; // Increased sleep time slightly

        // Search for point 1
        let search_result = service.search_points(vector_1.clone(), 1, None).await;
        assert!(
            search_result.is_ok(),
            "Search failed: {:?}",
            search_result.err()
        );
        let found_points = search_result.unwrap();

        assert_eq!(found_points.len(), 1, "Expected to find 1 point");
        let found_point = &found_points[0];

        // Extract the string ID correctly from PointId before comparing
        let found_id_str = match found_point
            .id
            .as_ref()
            .unwrap()
            .point_id_options
            .as_ref()
            .unwrap()
        {
            PointIdOptions::Uuid(s) => s.clone(),
            PointIdOptions::Num(n) => n.to_string(), // Handle numeric IDs just in case, though we use UUIDs
        };
        assert_eq!(
            found_id_str,
            point_id_1.to_string(),
            "Found point ID does not match"
        );

        // Verify payload. Need to convert qdrant::Value back to serde_json::Value or compare map directly.
        assert!(
            found_point.payload.contains_key("test_key"),
            "Payload key missing"
        );
        assert_eq!(
            found_point.payload.get("test_key").unwrap().kind,
            Some(Kind::StringValue("value1".to_string())),
            "Payload value mismatch"
        );

        // Clean up the test collection
        cleanup_test_collection(&service).await;
        drop(service);
    }

    #[tokio::test]
    #[ignore] // Re-added as it's an integration test
    #[allow(clippy::too_many_lines)]
    async fn test_integration_search_with_filter() {
        const MAX_RETRIES: u32 = 3;

        let service = setup_test_qdrant_client()
            .await
            .expect("Failed to setup Qdrant client");
        let _collection_name = service.collection_name.clone(); // Prefix unused variable
        let embedding_dim = usize::try_from(service.embedding_dimension).expect("embedding dimension should fit in usize");

        let point_id_filter = Uuid::new_v4();
        let mut rng3 = StdRng::seed_from_u64(123);
        let vector_filter: Vec<f32> = (0..embedding_dim).map(|_| rng3.random::<f32>()).collect();

        let payload_filter = json!({"filter_key": "target_value", "other": "data1"});
        let point_filter = create_qdrant_point(
            point_id_filter,
            vector_filter.clone(),
            Some(payload_filter.clone()),
        )
        .expect("Failed to create filter point");

        let point_id_other = Uuid::new_v4();
        let mut rng4 = StdRng::seed_from_u64(456);
        let vector_other: Vec<f32> = (0..embedding_dim).map(|_| rng4.random::<f32>()).collect();

        let payload_other = json!({"filter_key": "different_value", "other": "data2"});
        let point_other = create_qdrant_point(
            point_id_other,
            vector_other.clone(),
            Some(payload_other.clone()),
        )
        .expect("Failed to create other point");

        // Add retry logic for the upsert operation
        let points_to_upsert = vec![point_filter, point_other];
        let mut attempt = 0;

        loop {
            attempt += 1;
            match service.upsert_points(points_to_upsert.clone()).await {
                Ok(()) => break, // Success
                Err(e) => {
                    if let AppError::VectorDbError(msg) = &e {
                        if msg.contains("Collection") && (msg.contains("doesn't exist") || msg.contains("not found")) && attempt < MAX_RETRIES {
                            warn!(
                                "Upsert failed because collection was not found (attempt {}). Ensuring and retrying...",
                                attempt
                            );
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                100 * u64::from(attempt),
                            ))
                            .await; // Exponential backoff
                            service
                                .ensure_collection_exists()
                                .await
                                .expect("Retry ensure_collection_exists failed");
                            continue; // Retry upsert
                        }
                    }
                    // For other errors or max retries reached, panic with the original assertion message
                    panic!(
                        "Failed to upsert points for filter test: {e:?} (attempt {attempt})"
                    );
                }
            }
        }

        // Give Qdrant a moment
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await; // Increased sleep time slightly

        // Create filter
        let filter = create_test_filter("filter_key", "target_value");

        // Search with filter
        let search_result = service
            .search_points(vector_filter.clone(), 5, Some(filter))
            .await; // Search near the target vector
        assert!(
            search_result.is_ok(),
            "Filtered search failed: {:?}",
            search_result.err()
        );
        let found_points = search_result.unwrap();

        assert_eq!(
            found_points.len(),
            1,
            "Expected to find exactly 1 point matching the filter"
        );
        let found_point = &found_points[0];
        // Extract the string ID correctly from PointId before comparing
        let found_id_str_filter = match found_point
            .id
            .as_ref()
            .unwrap()
            .point_id_options
            .as_ref()
            .unwrap()
        {
            PointIdOptions::Uuid(s) => s.clone(),
            PointIdOptions::Num(n) => n.to_string(),
        };
        assert_eq!(
            found_id_str_filter,
            point_id_filter.to_string(),
            "Found point ID does not match the filtered point"
        );
        assert!(
            found_point.payload.contains_key("filter_key"),
            "Payload key missing"
        );
        assert_eq!(
            found_point.payload.get("filter_key").unwrap().kind,
            Some(Kind::StringValue("target_value".to_string())),
            "Payload value mismatch"
        );

        // Clean up the test collection
        cleanup_test_collection(&service).await;
        drop(service);
    }
}

// Implement the QdrantClientServiceTrait for QdrantClientService
#[async_trait]
impl QdrantClientServiceTrait for QdrantClientService {
    async fn ensure_collection_exists(&self) -> Result<(), AppError> {
        // Call the method directly instead of through the trait
        QdrantClientService::ensure_collection_exists(self).await
    }

    async fn store_points(&self, points: Vec<PointStruct>) -> Result<(), AppError> {
        // Rename upsert_points to store_points for the trait, but call the implementation method
        self.upsert_points(points).await
    }

    async fn search_points(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter: Option<Filter>,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Use the implementation's method directly
        QdrantClientService::search_points(self, vector, limit, filter).await
    }

    async fn retrieve_points(
        &self,
        filter: Option<Filter>,
        limit: u64,
    ) -> Result<Vec<ScoredPoint>, AppError> {
        // Call the implementation method which returns RetrievedPoint
        let retrieved_points =
            QdrantClientService::retrieve_points(self, filter, limit as usize).await?;

        // Convert RetrievedPoint to ScoredPoint
        let scored_points = retrieved_points
            .into_iter()
            .map(|rp| ScoredPoint {
                id: rp.id,
                version: 0, // Use a default version
                score: 1.0, // Default score as RetrievedPoint doesn't have a score
                payload: rp.payload,
                vectors: rp.vectors,
                shard_key: rp.shard_key,
                order_value: rp.order_value,
            })
            .collect();

        Ok(scored_points)
    }

    async fn delete_points(&self, _point_ids: Vec<PointId>) -> Result<(), AppError> {
        // Implement delete functionality if needed
        // For now, return success
        Ok(())
    }

    async fn update_collection_settings(&self) -> Result<(), AppError> {
        // Implement update settings functionality if needed
        // For now, return success
        Ok(())
    }

    #[instrument(skip(self, filter), name = "qdrant_delete_points_by_filter")]
    async fn delete_points_by_filter(&self, filter: Filter) -> Result<(), AppError> {
        info!(
            collection = %self.collection_name,
            ?filter,
            "Deleting points from Qdrant by filter"
        );

        let points_selector = qdrant_client::qdrant::PointsSelector {
            points_selector_one_of: Some(
                qdrant_client::qdrant::points_selector::PointsSelectorOneOf::Filter(filter),
            ),
        };

        self.client
            .delete_points(qdrant_client::qdrant::DeletePoints {
                collection_name: self.collection_name.clone(),
                points: Some(points_selector),
                wait: Some(true), // Wait for operation to complete
                ordering: None,
                shard_key_selector: None,
            })
            .await
            .map_err(|e| {
                error!(error = %e, collection = %self.collection_name, "Failed to delete points by filter from Qdrant");
                AppError::VectorDbError(format!("Failed to delete points by filter: {}", e))
            })?;

        info!(
            "Successfully deleted points by filter from collection '{}'",
            self.collection_name
        );
        Ok(())
    }

    #[instrument(skip(self), fields(point_id = ?point_id.point_id_options), name = "qdrant_get_point_by_id_trait")]
    async fn get_point_by_id(
        &self,
        point_id: PointId,
    ) -> Result<Option<qdrant_client::qdrant::RetrievedPoint>, AppError> {
        let point_id_for_log = format!("{:?}", point_id.point_id_options);
        info!(
            collection = %self.collection_name,
            point_id = %point_id_for_log,
            "Trait: Getting point by ID from Qdrant"
        );

        // self.client is Arc<Qdrant>
        let get_points_request = qdrant_client::qdrant::GetPoints {
            collection_name: self.collection_name.clone(),
            ids: vec![point_id],             // Pass the single PointId in a vec
            with_payload: Some(true.into()), // Include payload
            with_vectors: Some(true.into()), // Include vectors
            read_consistency: None,
            shard_key_selector: None,
            timeout: None, // Add missing timeout field
        };

        let response = self.client
            .get_points(get_points_request) // Use get_points
            .await
            .map_err(|e| {
                error!(error = %e, collection = %self.collection_name, point_id = %point_id_for_log, "Failed to get point by ID from Qdrant using get_points");
                AppError::VectorDbError(format!("Failed to get point by ID {:?} using get_points: {}", point_id_for_log, e))
            })?;

        // get_points returns a GetResponse which has a Vec<RetrievedPoint>
        // We expect at most one point.
        Ok(response.result.into_iter().next())
    }
}
