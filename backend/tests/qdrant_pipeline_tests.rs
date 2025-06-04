#![cfg(test)]

use anyhow::Error as AnyhowError;
use dotenvy::dotenv;
use scribe_backend::config::Config;
use scribe_backend::errors::AppError;
use scribe_backend::test_helpers::ensure_rustls_provider_installed;
use scribe_backend::vector_db::qdrant_client::{QdrantClientService, create_qdrant_point}; // Added
// Import necessary types for direct client use in setup
use qdrant_client::Qdrant;
use qdrant_client::qdrant::Match;
use qdrant_client::qdrant::condition::ConditionOneOf;
use qdrant_client::qdrant::r#match::MatchValue;
use qdrant_client::qdrant::{
    Condition, CreateCollection, Distance, FieldCondition, Filter, VectorParams, VectorsConfig,
    vectors_config::Config as QdrantVectorsConfig,
};
use scribe_backend::vector_db::qdrant_client::Kind as ValueKind;
use serde_json::json;
use serial_test::serial;
use std::sync::Arc;
use uuid::Uuid;

// Define a shared collection name
const TEST_COLLECTION_NAME: &str = "sanguine_scribe_integration_test";
// Use the dimension defined in the main service
// Use the dimension constant from the service module - Make local as source is private
// const EMBEDDING_DIMENSION: u64 = qdrant_service::EMBEDDING_DIMENSION; // Use alias
const EMBEDDING_DIMENSION: u64 = 768; // Redefine locally

// Helper function to create a Qdrant client service for testing (uses shared name)
async fn create_test_qdrant_service() -> Result<QdrantClientService, AppError> {
    dotenv().ok(); // Load .env file
    ensure_rustls_provider_installed();

    // Load config from environment
    let base_config = Config::load().map_err(|e| {
        AppError::ConfigError(format!("Failed to load configuration for test: {e}"))
    })?;

    // Ensure qdrant_url is present, otherwise this test setup is invalid.
    if base_config.qdrant_url.is_none() {
        return Err(AppError::ConfigError(
            "QDRANT_URL must be set in the environment for integration tests.".to_string(),
        ));
    }

    // Create a new config for the service, ensuring the test collection name is used.
    // We use the loaded config as a base, then override the collection name.
    let service_config = Config {
        qdrant_collection_name: TEST_COLLECTION_NAME.to_string(),
        ..base_config // Use other values from loaded config (like qdrant_url, api_key if any)
    };

    // NOTE: This will *still* call ensure_collection_exists internally, but because the name
    // is constant, it should just log "already exists" after the first test.
    QdrantClientService::new(Arc::new(service_config)).await
}

// Helper function to delete and recreate the test collection
async fn cleanup_and_prepare_collection() -> Result<(), anyhow::Error> {
    dotenv().ok(); // Load .env file
    ensure_rustls_provider_installed();

    let config = Config::load().map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;
    let qdrant_url = config.qdrant_url.ok_or_else(|| {
        anyhow::anyhow!("QDRANT_URL not set in environment, required for cleanup/prepare.")
    })?;

    // Create a raw client directly using the URL from config
    let client = Qdrant::from_url(&qdrant_url).build()?;

    // Attempt to delete the collection, ignore errors (it might not exist)
    let _ = client.delete_collection(TEST_COLLECTION_NAME).await;
    // Short delay to allow deletion to propagate if needed?
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create the collection
    let create_result = client
        .create_collection(CreateCollection {
            collection_name: TEST_COLLECTION_NAME.to_string(),
            vectors_config: Some(VectorsConfig {
                config: Some(QdrantVectorsConfig::Params(VectorParams {
                    size: EMBEDDING_DIMENSION,
                    distance: Distance::Cosine.into(),
                    hnsw_config: None,
                    quantization_config: None,
                    on_disk: None,
                    datatype: None,
                    multivector_config: None,
                })),
            }),
            ..Default::default()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create test collection: {}", e))?; // Convert error

    // Explicitly drop client to reduce resource contention
    drop(client);
    let _ = create_result; // Use the result to avoid warnings

    Ok(())
}

// Helper for generating test vectors of specific dimension
fn generate_test_vectors(dimension: usize, count: usize) -> Vec<Vec<f32>> {
    let mut vectors = Vec::with_capacity(count);
    for i in 0..count {
        let mut vector = Vec::with_capacity(dimension);
        for j in 0..dimension {
            // Create slightly different values for each vector
            let value = u8::try_from((i + j) % 10).unwrap_or(0);
            vector.push(f32::from(value) * 0.1);
        }
        vectors.push(vector);
    }
    vectors
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_service_creation() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Create a new instance of the Qdrant service with the shared collection name
    let _service = create_test_qdrant_service().await?;
    Ok(())
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_upsert_points() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state

    // Generate test vectors and points
    let test_vectors = generate_test_vectors(768, 3); // 768 is the dimension used in the service
    let mut points = Vec::new();

    for (i, vector) in test_vectors.iter().enumerate() {
        let id = Uuid::new_v4();
        let payload = json!({
            "text": format!("Test text {}", i),
            "metadata": {
                "user_id": Uuid::new_v4().to_string(),
                "chat_id": Uuid::new_v4().to_string(),
                "index": i
            }
        });

        let point = create_qdrant_point(id, vector.clone(), Some(payload))?;
        points.push(point);
    }

    // Upsert the points
    create_test_qdrant_service()
        .await?
        .upsert_points(points)
        .await?;

    // Success is implied by no error being returned
    Ok(())
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_search_points() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Create a new instance of the Qdrant service
    let service = create_test_qdrant_service().await?;

    // Generate test data with a consistent user_id for filtering
    let test_vectors = generate_test_vectors(768, 5);
    let user_id = Uuid::new_v4();
    let chat_id = Uuid::new_v4();
    let mut points = Vec::new();

    for (i, vector) in test_vectors.iter().enumerate() {
        let id = Uuid::new_v4();
        let payload = json!({
            "text": format!("Test text {}", i),
            "metadata": {
                "user_id": user_id.to_string(),
                "chat_id": chat_id.to_string(),
                "index": i
            }
        });

        let point = create_qdrant_point(id, vector.clone(), Some(payload))?;
        points.push(point);
    }

    // Upsert the points
    service.upsert_points(points).await?;

    // Create a filter for the specific user_id and chat_id
    let filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "metadata.user_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(user_id.to_string())),
                    }),
                    range: None,
                    geo_bounding_box: None,
                    geo_radius: None,
                    geo_polygon: None,
                    values_count: None,
                    datetime_range: None,
                    is_empty: None,
                    is_null: None,
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "metadata.chat_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(chat_id.to_string())),
                    }),
                    range: None,
                    geo_bounding_box: None,
                    geo_radius: None,
                    geo_polygon: None,
                    values_count: None,
                    datetime_range: None,
                    is_empty: None,
                    is_null: None,
                })),
            },
        ],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };

    // Search for points using the first vector as query
    let query_vector = test_vectors[0].clone();
    let limit = 3;
    let results = service
        .search_points(query_vector, limit, Some(filter))
        .await?;
    drop(service);

    // Verify that we got results
    assert!(
        !results.is_empty(),
        "Search should return at least one result"
    );
    assert!(
        results.len() <= usize::try_from(limit).unwrap_or(usize::MAX),
        "Search should respect the limit"
    );

    // Verify the payload content for the first result
    let first_result = &results[0];
    assert!(
        first_result.score > f32::EPSILON,
        "Score should be positive"
    );

    // Verify that we can extract the payload
    let text_value = first_result
        .payload
        .get("text")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            ValueKind::StringValue(s) => Some(s),
            _ => None,
        });
    assert!(
        text_value.is_some(),
        "Text payload should exist and be a string"
    );

    Ok(())
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_empty_results() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state

    // Search with a random vector that shouldn't match anything
    let query_vector = generate_test_vectors(768, 1)[0].clone();

    // Create a filter for a non-existent user_id
    let non_existent_id = Uuid::new_v4();
    let filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "metadata.user_id".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword(non_existent_id.to_string())),
                }),
                range: None,
                geo_bounding_box: None,
                geo_radius: None,
                geo_polygon: None,
                values_count: None,
                datetime_range: None,
                is_empty: None,
                is_null: None,
            })),
        }],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };

    // Search for points
    let limit = 10;
    let results = create_test_qdrant_service()
        .await?
        .search_points(query_vector, limit, Some(filter))
        .await?;

    // Verify that we get an empty result set
    assert!(
        results.is_empty(),
        "Search with non-existent ID should return empty results"
    );

    Ok(())
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_update_existing_point() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Create a new instance of the Qdrant service
    let service = create_test_qdrant_service().await?;

    // Create a test point with a fixed UUID
    let point_id = Uuid::new_v4();
    let vector = generate_test_vectors(768, 1)[0].clone();

    // First insertion
    let initial_payload = json!({
        "text": "Initial text",
        "metadata": {
            "user_id": Uuid::new_v4().to_string(),
            "version": 1
        }
    });

    let initial_point = create_qdrant_point(point_id, vector.clone(), Some(initial_payload))?;
    service.upsert_points(vec![initial_point]).await?;

    // Create a filter to find this point
    let filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "metadata.version".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Integer(1)),
                }),
                range: None,
                geo_bounding_box: None,
                geo_radius: None,
                geo_polygon: None,
                values_count: None,
                datetime_range: None,
                is_empty: None,
                is_null: None,
            })),
        }],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };

    // Search to confirm the point exists with version 1
    let search_results = service
        .search_points(vector.clone(), 1, Some(filter))
        .await?;
    assert_eq!(
        search_results.len(),
        1,
        "Should find one point with version 1"
    );

    // Update the point with new payload
    let updated_payload = json!({
        "text": "Updated text",
        "metadata": {
            "user_id": Uuid::new_v4().to_string(),
            "version": 2
        }
    });

    let updated_point = create_qdrant_point(point_id, vector.clone(), Some(updated_payload))?;
    service.upsert_points(vec![updated_point]).await?;

    // Create a filter to find the updated point
    let updated_filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "metadata.version".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Integer(2)),
                }),
                range: None,
                geo_bounding_box: None,
                geo_radius: None,
                geo_polygon: None,
                values_count: None,
                datetime_range: None,
                is_empty: None,
                is_null: None,
            })),
        }],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };

    // Search to confirm the point was updated to version 2
    let updated_results = service
        .search_points(vector.clone(), 1, Some(updated_filter))
        .await?;
    drop(service);
    assert_eq!(
        updated_results.len(),
        1,
        "Should find one point with version 2"
    );

    // Also confirm the text was updated
    let text_value = updated_results[0]
        .payload
        .get("text")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            ValueKind::StringValue(s) => Some(s),
            _ => None,
        });
    assert_eq!(
        text_value,
        Some(&"Updated text".to_string()),
        "Text should be updated to 'Updated text'"
    );

    Ok(())
}

// Add a test for the case when we try to upsert an empty vector
#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_upsert_empty_points() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state

    // Try to upsert an empty vector of points
    let result = create_test_qdrant_service()
        .await?
        .upsert_points(vec![])
        .await;

    // This should succeed silently
    assert!(
        result.is_ok(),
        "Upserting empty points vector should succeed"
    );

    Ok(())
}

use scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait; // Import the trait

#[tokio::test]
#[serial]
#[ignore]
async fn test_qdrant_ensure_collection_already_exists() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // First call creates the collection
    let _service1 = create_test_qdrant_service().await?;
    // Second call should find the existing collection (covers line 165 in qdrant_client.rs)
    let _service2 = create_test_qdrant_service().await?;
    // Check if the collection still exists using the raw client for verification
    dotenvy::dotenv().ok(); // Ensure .env is loaded for this part too
    ensure_rustls_provider_installed(); // Ensure rustls is installed for this client
    let config = Config::load()
        .map_err(|e| anyhow::anyhow!("Failed to load config for verification: {}", e))?;
    let qdrant_url = config.qdrant_url.ok_or_else(|| {
        anyhow::anyhow!("QDRANT_URL not set in environment, required for verification client.")
    })?;
    let client = Qdrant::from_url(&qdrant_url).build()?;
    let exists = client.collection_exists(TEST_COLLECTION_NAME).await?;
    // Explicitly drop client to reduce resource contention
    drop(client);
    assert!(
        exists,
        "Collection should still exist after second service creation"
    );
    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_qdrant_retrieve_points() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    let service = create_test_qdrant_service().await?;

    // Generate and upsert test data
    let test_vectors = generate_test_vectors(768, 2);
    let point_id_1 = Uuid::new_v4();
    let point_id_2 = Uuid::new_v4();
    let payload_1 = json!({"retrieve_key": "value_a"});
    let payload_2 = json!({"retrieve_key": "value_b"});
    let point_1 = create_qdrant_point(point_id_1, test_vectors[0].clone(), Some(payload_1))?;
    let point_2 = create_qdrant_point(point_id_2, test_vectors[1].clone(), Some(payload_2))?;
    service.upsert_points(vec![point_1, point_2]).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Allow indexing

    // Create a filter to retrieve one point
    let filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "retrieve_key".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword("value_a".to_string())),
                }),
                ..Default::default()
            })),
        }],
        ..Default::default()
    };

    // Retrieve points (covers lines 269, 300 in qdrant_client.rs)
    let retrieved_points = service.retrieve_points(Some(filter), 5).await?;
    drop(service);

    assert_eq!(retrieved_points.len(), 1, "Expected to retrieve 1 point");
    let retrieved_point = &retrieved_points[0];

    // Verify ID and payload
    let retrieved_id_str = match retrieved_point
        .id
        .as_ref()
        .unwrap()
        .point_id_options
        .as_ref()
        .unwrap()
    {
        qdrant_client::qdrant::point_id::PointIdOptions::Uuid(s) => s.clone(),
        qdrant_client::qdrant::point_id::PointIdOptions::Num(n) => n.to_string(),
    };
    assert_eq!(retrieved_id_str, point_id_1.to_string());
    assert!(retrieved_point.payload.contains_key("retrieve_key"));
    assert_eq!(
        retrieved_point.payload.get("retrieve_key").unwrap().kind,
        Some(ValueKind::StringValue("value_a".to_string()))
    );
    // Also check vector is retrieved
    assert!(
        retrieved_point.vectors.is_some(),
        "Vectors should be retrieved"
    );

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_qdrant_trait_methods() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Get a trait object
    let trait_service: Arc<dyn QdrantClientServiceTrait> =
        Arc::new(create_test_qdrant_service().await?);

    // --- Test store_points (covers lines 746, 748) ---
    let test_vectors = generate_test_vectors(768, 1);
    let point_id_trait = Uuid::new_v4();
    let payload_trait = json!({"trait_key": "trait_value"});
    let point_trait =
        create_qdrant_point(point_id_trait, test_vectors[0].clone(), Some(payload_trait))?;
    trait_service.store_points(vec![point_trait]).await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // Allow indexing

    // --- Test retrieve_points via trait (covers lines 767, 771, 773-774, 777-780, 784) ---
    let filter_trait = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "trait_key".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword("trait_value".to_string())),
                }),
                ..Default::default()
            })),
        }],
        ..Default::default()
    };
    let retrieved_trait_points = trait_service.retrieve_points(Some(filter_trait), 5).await?;
    assert_eq!(
        retrieved_trait_points.len(),
        1,
        "Expected to retrieve 1 point via trait"
    );
    let retrieved_trait_point = &retrieved_trait_points[0];
    // Verify ID (ScoredPoint has ID directly)
    let retrieved_id_str_trait = match retrieved_trait_point
        .id
        .as_ref()
        .unwrap()
        .point_id_options
        .as_ref()
        .unwrap()
    {
        qdrant_client::qdrant::point_id::PointIdOptions::Uuid(s) => s.clone(),
        qdrant_client::qdrant::point_id::PointIdOptions::Num(n) => n.to_string(),
    };
    assert_eq!(retrieved_id_str_trait, point_id_trait.to_string());
    // Verify payload
    assert!(retrieved_trait_point.payload.contains_key("trait_key"));
    // Verify score (should be default 1.0 from conversion)
    assert!((retrieved_trait_point.score - 1.0).abs() < f32::EPSILON);

    // --- Test delete_points (covers lines 787, 790) ---
    // Note: The current implementation is a no-op, so this just tests it doesn't error.
    let point_id_qdrant = qdrant_client::qdrant::PointId::from(point_id_trait.to_string());
    trait_service.delete_points(vec![point_id_qdrant]).await?;

    // --- Test update_collection_settings (covers lines 793, 796) ---
    // Note: The current implementation is a no-op, so this just tests it doesn't error.
    trait_service.update_collection_settings().await?;

    Ok(())
}
