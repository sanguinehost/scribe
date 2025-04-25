#![cfg(test)]

use anyhow::Error as AnyhowError;
use scribe_backend::config::Config;
use scribe_backend::errors::AppError;
use scribe_backend::vector_db::qdrant_client::{QdrantClientService, create_qdrant_point};
// Import necessary types for direct client use in setup
use qdrant_client::Qdrant;
use qdrant_client::qdrant::{
    CreateCollection, VectorParams, Distance, VectorsConfig,
    vectors_config::Config as QdrantVectorsConfig,
    Condition,
    Filter,
    FieldCondition,
};
// Import MatchValue from its specific module
use qdrant_client::qdrant::r#match::MatchValue;
// Import ConditionOneOf from its specific module
use qdrant_client::qdrant::condition::ConditionOneOf;
// Import Match
use qdrant_client::qdrant::Match;
// Removed duplicate/unused imports from scribe_backend::vector_db::qdrant_client
use scribe_backend::vector_db::qdrant_client::Kind as ValueKind;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
// Add serial_test import
use serial_test::serial;

// Define a shared collection name
const TEST_COLLECTION_NAME: &str = "sanguine_scribe_integration_test";
// Use the dimension defined in the main service
// Use the dimension constant from the service module - Make local as source is private
// const EMBEDDING_DIMENSION: u64 = qdrant_service::EMBEDDING_DIMENSION; // Use alias
const EMBEDDING_DIMENSION: u64 = 768; // Redefine locally

// Helper function to create a Qdrant client service for testing (uses shared name)
async fn create_test_qdrant_service() -> Result<QdrantClientService, AppError> {
    // Set up a test configuration
    let mut config = Config::default();
    config.qdrant_url = Some("http://localhost:6334".to_string());
    // Use the constant test collection name
    config.qdrant_collection_name = Some(TEST_COLLECTION_NAME.to_string());
    
    // Create the service
    // NOTE: This will *still* call ensure_collection_exists internally, but because the name
    // is constant, it should just log "already exists" after the first test.
    QdrantClientService::new(Arc::new(config)).await
}

// Helper function to delete and recreate the test collection
async fn cleanup_and_prepare_collection() -> Result<(), anyhow::Error> {
    // Create a raw client directly
    let client = Qdrant::from_url("http://localhost:6334").build()?;

    // Attempt to delete the collection, ignore errors (it might not exist)
    let _ = client.delete_collection(TEST_COLLECTION_NAME).await;
    // Short delay to allow deletion to propagate if needed?
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create the collection
    client.create_collection(CreateCollection {
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
    }).await.map_err(|e| anyhow::anyhow!("Failed to create test collection: {}", e))?; // Convert error

    Ok(())
}

// Helper for generating test vectors of specific dimension
fn generate_test_vectors(dimension: usize, count: usize) -> Vec<Vec<f32>> {
    let mut vectors = Vec::with_capacity(count);
    for i in 0..count {
        let mut vector = Vec::with_capacity(dimension);
        for j in 0..dimension {
            // Create slightly different values for each vector
            vector.push(((i + j) % 10) as f32 * 0.1);
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
    // Create a new instance of the Qdrant service
    let service = create_test_qdrant_service().await?;
    
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
    service.upsert_points(points).await?;
    
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
                condition_one_of: Some(ConditionOneOf::Field(
                    FieldCondition {
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
                    },
                )),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(
                    FieldCondition {
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
                    },
                )),
            },
        ],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };
    
    // Search for points using the first vector as query
    let query_vector = test_vectors[0].clone();
    let limit = 3;
    let results = service.search_points(query_vector, limit, Some(filter)).await?;
    
    // Verify that we got results
    assert!(!results.is_empty(), "Search should return at least one result");
    assert!(results.len() <= limit as usize, "Search should respect the limit");
    
    // Verify the payload content for the first result
    let first_result = &results[0];
    assert!(first_result.score > 0.0, "Score should be positive");
    
    // Verify that we can extract the payload
    let text_value = first_result.payload.get("text")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            ValueKind::StringValue(s) => Some(s),
            _ => None,
        });
    assert!(text_value.is_some(), "Text payload should exist and be a string");
    
    Ok(())
}

#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_empty_results() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Create a new instance of the Qdrant service
    let service = create_test_qdrant_service().await?;
    
    // Search with a random vector that shouldn't match anything
    let query_vector = generate_test_vectors(768, 1)[0].clone();
    
    // Create a filter for a non-existent user_id
    let non_existent_id = Uuid::new_v4();
    let filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(
                    FieldCondition {
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
                    },
                )),
            },
        ],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };
    
    // Search for points
    let limit = 10;
    let results = service.search_points(query_vector, limit, Some(filter)).await?;
    
    // Verify that we get an empty result set
    assert!(results.is_empty(), "Search with non-existent ID should return empty results");
    
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
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(
                    FieldCondition {
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
                    },
                )),
            },
        ],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };
    
    // Search to confirm the point exists with version 1
    let search_results = service.search_points(vector.clone(), 1, Some(filter)).await?;
    assert_eq!(search_results.len(), 1, "Should find one point with version 1");
    
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
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(
                    FieldCondition {
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
                    },
                )),
            },
        ],
        must_not: vec![],
        should: vec![],
        min_should: None,
    };
    
    // Search to confirm the point was updated to version 2
    let updated_results = service.search_points(vector.clone(), 1, Some(updated_filter)).await?;
    assert_eq!(updated_results.len(), 1, "Should find one point with version 2");
    
    // Also confirm the text was updated
    let text_value = updated_results[0].payload.get("text")
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            ValueKind::StringValue(s) => Some(s),
            _ => None,
        });
    assert_eq!(text_value, Some(&"Updated text".to_string()), "Text should be updated to 'Updated text'");
    
    Ok(())
}

// Add a test for the case when we try to upsert an empty vector
#[tokio::test]
#[serial] // Add serial attribute
#[ignore] // Added ignore for CI
async fn test_qdrant_upsert_empty_points() -> Result<(), AnyhowError> {
    cleanup_and_prepare_collection().await?; // Ensure clean state
    // Create a new instance of the Qdrant service
    let service = create_test_qdrant_service().await?;
    
    // Try to upsert an empty vector of points
    let result = service.upsert_points(vec![]).await;
    
    // This should succeed silently
    assert!(result.is_ok(), "Upserting empty points vector should succeed");
    
    Ok(())
} 