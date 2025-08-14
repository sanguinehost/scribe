use scribe_backend::vector_db::qdrant_client::{
    QdrantClientService, QdrantClientServiceTrait, ScoredPoint, PointId, Value, 
    Filter, Condition, FieldCondition, Match, ConditionOneOf, value::Kind, r#match::MatchValue
};
use scribe_backend::config::Config;
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Requires Qdrant to be running
async fn test_hybrid_search_functionality() {
    // Create config for Qdrant
    let mut config = Config::default();
    config.qdrant_url = Some("http://localhost:6334".to_string());
    config.embedding_dimension = Some(768);
    
    let config = Arc::new(config);
    
    // Create Qdrant client
    let qdrant_client = QdrantClientService::new(config.clone())
        .await
        .expect("Failed to create Qdrant client");
    
    // Ensure collection exists
    qdrant_client.ensure_collection_exists()
        .await
        .expect("Failed to ensure collection exists");
    
    // Create test data points
    let test_points = vec![
        create_test_point(
            "point1",
            "China is a country in East Asia",
            vec!["China", "Asia"],
            generate_random_vector(768)
        ),
        create_test_point(
            "point2",
            "The Great Wall of China is a famous landmark",
            vec!["China", "Great Wall", "landmark"],
            generate_random_vector(768)
        ),
        create_test_point(
            "point3",
            "Quantum computing is advancing rapidly",
            vec!["quantum", "computing", "technology"],
            generate_random_vector(768)
        ),
    ];
    
    // Store the test points
    qdrant_client.store_points(test_points)
        .await
        .expect("Failed to store test points");
    
    // Wait for indexing
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    
    // Test 1: Hybrid search with both vector and text
    let results = qdrant_client.hybrid_search(
        Some(generate_random_vector(768)), // Dummy vector
        Some("China".to_string()),
        vec!["chunk_text".to_string(), "keywords".to_string()],
        10,
        None,
        Some(0.3), // Score threshold
    ).await;
    
    assert!(results.is_ok(), "Hybrid search should succeed");
    let results = results.unwrap();
    
    // Should find entries with "China"
    let china_results: Vec<_> = results.iter().filter(|r| {
        r.payload.get("chunk_text")
            .and_then(|v| match &v.kind {
                Some(Kind::StringValue(s)) => Some(s.contains("China")),
                _ => None,
            })
            .unwrap_or(false)
    }).collect();
    
    assert!(!china_results.is_empty(), "Should find results containing 'China'");
    
    // Test 2: Text-only search
    let results = qdrant_client.hybrid_search(
        None, // No vector
        Some("China".to_string()),
        vec!["chunk_text".to_string(), "keywords".to_string()],
        10,
        None,
        None,
    ).await;
    
    assert!(results.is_ok(), "Text-only search should succeed");
    let results = results.unwrap();
    
    // Should still find China entries
    assert!(!results.is_empty(), "Text search should find results");
    
    // Test 3: Vector-only search (traditional)
    let results = qdrant_client.hybrid_search(
        Some(generate_random_vector(768)),
        None, // No text query
        vec![],
        10,
        None,
        Some(0.4),
    ).await;
    
    assert!(results.is_ok(), "Vector-only search should succeed");
    
    println!("All hybrid search tests passed!");
}

fn create_test_point(
    id: &str,
    text: &str,
    keywords: Vec<&str>,
    vector: Vec<f32>,
) -> qdrant_client::qdrant::PointStruct {
    use qdrant_client::qdrant::{PointStruct, Vectors, vectors::VectorsOptions};
    
    let mut payload = HashMap::new();
    payload.insert(
        "chunk_text".to_string(),
        Value {
            kind: Some(Kind::StringValue(text.to_string())),
        },
    );
    payload.insert(
        "keywords".to_string(),
        Value {
            kind: Some(Kind::ListValue(qdrant_client::qdrant::ListValue {
                values: keywords.iter().map(|k| Value {
                    kind: Some(Kind::StringValue(k.to_string())),
                }).collect(),
            })),
        },
    );
    payload.insert(
        "source_type".to_string(),
        Value {
            kind: Some(Kind::StringValue("test".to_string())),
        },
    );
    
    PointStruct {
        id: Some(PointId::from(id.to_string())),
        payload,
        vectors: Some(Vectors {
            vectors_options: Some(VectorsOptions::Vector(vector)),
        }),
    }
}

fn generate_random_vector(dim: usize) -> Vec<f32> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..dim).map(|_| rng.gen_range(-1.0..1.0)).collect()
}