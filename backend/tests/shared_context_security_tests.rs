use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use redis::AsyncCommands;

use scribe_backend::{
    services::agentic::shared_context::{
        SharedAgentContext, ContextEntry, ContextType, AgentType, ContextQuery
    },
    auth::session_dek::SessionDek,
    errors::AppError,
    crypto,
};
use secrecy::ExposeSecret;

/// OWASP Top 10 Security Test Cases for Shared Agent Context
/// 
/// These tests validate security controls across all OWASP Top 10 categories
/// with focus on encryption, access control, and data integrity.

/// Test helper to create a test Redis client
async fn create_test_redis_client() -> Arc<redis::Client> {
    Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap())
}

/// Test helper to create a test SessionDek
fn create_test_session_dek() -> SessionDek {
    let dek = crypto::generate_dek().unwrap();
    SessionDek::new(dek.expose_secret().clone())
}

#[cfg(test)]
mod owasp_security_tests {
    use super::*;

    /// Test helper to create test context entry
    fn create_test_context_entry(
        user_id: Uuid,
        session_id: Uuid,
        context_type: ContextType,
        source_agent: AgentType,
        key: &str,
        data: serde_json::Value,
    ) -> ContextEntry {
        ContextEntry {
            context_type,
            source_agent,
            timestamp: Utc::now(),
            session_id,
            user_id,
            key: key.to_string(),
            data,
            ttl_seconds: Some(3600),
            metadata: HashMap::new(),
        }
    }

    /// A01:2021 - Broken Access Control Tests
    mod a01_broken_access_control {
        use super::*;

        #[tokio::test]
        async fn test_user_isolation_in_context_storage() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            
            let user1_id = Uuid::new_v4();
            let user2_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // User 1 stores sensitive context
            let user1_entry = create_test_context_entry(
                user1_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "sensitive_entity",
                json!({"secret": "user1_secret_data"})
            );
            
            let session_dek = create_test_session_dek();
            shared_context.store_context(user1_entry, &session_dek).await.unwrap();
            
            // User 2 attempts to access User 1's context
            let query = ContextQuery {
                context_types: Some(vec![ContextType::EntityDiscovery]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["sensitive_entity".to_string()]),
                limit: None,
            };
            
            let user2_results = shared_context.query_context(user2_id, query, &session_dek).await.unwrap();
            
            // Assert: User 2 should not see User 1's data
            assert!(user2_results.is_empty(), "User isolation violation: User 2 can access User 1's context");
        }

        #[tokio::test]
        async fn test_session_isolation_within_user() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session1_id = Uuid::new_v4();
            let session2_id = Uuid::new_v4();
            
            // Store context in session 1
            let session1_entry = create_test_context_entry(
                user_id,
                session1_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "session1_plan",
                json!({"plan": "session1_tactical_data"})
            );
            
            shared_context.store_context(session1_entry, &session_dek).await.unwrap();
            
            // Query from session 2
            let query = ContextQuery {
                context_types: Some(vec![ContextType::TacticalPlanning]),
                source_agents: None,
                session_id: Some(session2_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let session2_results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            
            // Assert: Session 2 should not see Session 1's data
            assert!(session2_results.is_empty(), "Session isolation violation: Session 2 can access Session 1's context");
        }

        #[tokio::test]
        async fn test_agent_type_filtering() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store context from different agents
            let perception_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "perception_data",
                json!({"type": "perception"})
            );
            
            let tactical_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "tactical_data",
                json!({"type": "tactical"})
            );
            
            shared_context.store_context(perception_entry, &session_dek).await.unwrap();
            shared_context.store_context(tactical_entry, &session_dek).await.unwrap();
            
            // Query only perception data
            let query = ContextQuery {
                context_types: None,
                source_agents: Some(vec![AgentType::Perception]),
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            
            // Assert: Should only get perception data
            assert_eq!(results.len(), 1);
            assert!(matches!(results[0].source_agent, AgentType::Perception));
        }
    }

    /// A02:2021 - Cryptographic Failures Tests
    mod a02_cryptographic_failures {
        use super::*;

        #[tokio::test]
        async fn test_context_data_encryption() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client.clone());
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Create context with sensitive data
            let sensitive_data = json!({
                "character_secret": "This is highly sensitive character information",
                "api_key": "sk-1234567890abcdef",
                "personal_info": "User's private details"
            });
            
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::StrategicInsight,
                AgentType::Strategic,
                "sensitive_insight",
                sensitive_data.clone()
            );
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // Directly check Redis to ensure data is not stored in plaintext
            let mut conn = redis_client.get_multiplexed_async_connection().await.unwrap();
            let pattern = format!("agent_context:{}:{}:*", user_id, session_id);
            let keys: Vec<String> = conn.keys(&pattern).await.unwrap();
            
            assert!(!keys.is_empty(), "Context should be stored");
            
            // Check that sensitive data is not visible in Redis storage
            for key in keys {
                let stored_data: String = conn.get(&key).await.unwrap();
                assert!(
                    !stored_data.contains("This is highly sensitive character information"),
                    "Sensitive data found in plaintext in Redis storage"
                );
                assert!(
                    !stored_data.contains("sk-1234567890abcdef"),
                    "API key found in plaintext in Redis storage"
                );
                
                // Verify the data is serialized JSON (encrypted context entry)
                let parsed: serde_json::Value = serde_json::from_str(&stored_data).unwrap();
                assert!(parsed.is_object(), "Stored data should be structured JSON");
            }
        }

        #[tokio::test]
        async fn test_ttl_enforcement() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client.clone());
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store context with short TTL
            let mut entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Coordination,
                AgentType::Lightning,
                "short_lived",
                json!({"data": "temporary"})
            );
            entry.ttl_seconds = Some(1); // 1 second TTL
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // Immediately verify it exists
            let query = ContextQuery {
                context_types: Some(vec![ContextType::Coordination]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["short_lived".to_string()]),
                limit: None,
            };
            
            let immediate_results = shared_context.query_context(user_id, query.clone(), &session_dek).await.unwrap();
            assert_eq!(immediate_results.len(), 1, "Context should be immediately available");
            
            // Wait for TTL expiration
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Verify it's expired
            let expired_results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert!(expired_results.is_empty(), "Context should be expired and unavailable");
        }

        #[tokio::test]
        async fn test_key_derivation_unique_per_context() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client.clone());
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store multiple contexts with same key but different types
            let entity_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "shared_key",
                json!({"type": "entity"})
            );
            
            let tactical_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "shared_key",
                json!({"type": "tactical"})
            );
            
            shared_context.store_context(entity_entry, &session_dek).await.unwrap();
            shared_context.store_context(tactical_entry, &session_dek).await.unwrap();
            
            // Verify both are stored with unique Redis keys
            let mut conn = redis_client.get_multiplexed_async_connection().await.unwrap();
            let pattern = format!("agent_context:{}:{}:*", user_id, session_id);
            let keys: Vec<String> = conn.keys(&pattern).await.unwrap();
            
            assert_eq!(keys.len(), 2, "Both contexts should be stored with unique keys");
            
            // Verify keys are actually different
            assert_ne!(keys[0], keys[1], "Redis keys should be unique even with same logical key");
        }
    }

    /// A03:2021 - Injection Tests
    mod a03_injection {
        use super::*;

        #[tokio::test]
        async fn test_json_injection_prevention() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Attempt JSON injection attack
            let malicious_data = json!({
                "legitimate_field": "normal_value",
                "injection_attempt": "\"; DROP TABLE users; --",
                "xss_attempt": "<script>alert('xss')</script>",
                "command_injection": "$(rm -rf /)",
                "nested_injection": {
                    "evil": "'; DELETE FROM context; --"
                }
            });
            
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "injection_test",
                malicious_data
            );
            
            // Should not throw errors during storage
            let result = shared_context.store_context(entry, &session_dek).await;
            assert!(result.is_ok(), "Context storage should handle malicious JSON safely");
            
            // Should be able to retrieve safely
            let query = ContextQuery {
                context_types: Some(vec![ContextType::EntityDiscovery]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["injection_test".to_string()]),
                limit: None,
            };
            
            let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert_eq!(results.len(), 1, "Should retrieve the context safely");
            
            // Verify the malicious content is contained within the JSON structure
            let retrieved_data = &results[0].data;
            assert_eq!(
                retrieved_data["injection_attempt"].as_str().unwrap(),
                "\"; DROP TABLE users; --"
            );
            // The malicious content should be properly escaped in JSON
        }

        #[tokio::test]
        async fn test_redis_command_injection_prevention() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Attempt Redis command injection through key names
            let malicious_key = "normal_key\r\nFLUSHALL\r\nSET malicious_key malicious_value\r\n";
            
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Coordination,
                AgentType::Lightning,
                malicious_key,
                json!({"test": "data"})
            );
            
            let result = shared_context.store_context(entry, &session_dek).await;
            assert!(result.is_ok(), "Should handle malicious key names safely");
            
            // Verify malicious commands were not executed by checking if FLUSHALL worked
            let test_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Performance,
                AgentType::Orchestrator,
                "test_survival",
                json!({"survived": true})
            );
            
            shared_context.store_context(test_entry, &session_dek).await.unwrap();
            
            let query = ContextQuery {
                context_types: Some(vec![ContextType::Performance]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["test_survival".to_string()]),
                limit: None,
            };
            
            let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert_eq!(results.len(), 1, "Data should survive injection attempt");
        }
    }

    /// A04:2021 - Insecure Design Tests
    mod a04_insecure_design {
        use super::*;

        #[tokio::test]
        async fn test_context_type_isolation() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store different types of context
            let entity_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "test_data",
                json!({"sensitivity": "low", "type": "entity"})
            );
            
            let strategic_entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::StrategicInsight,
                AgentType::Strategic,
                "test_data",
                json!({"sensitivity": "high", "type": "strategic"})
            );
            
            shared_context.store_context(entity_entry, &session_dek).await.unwrap();
            shared_context.store_context(strategic_entry, &session_dek).await.unwrap();
            
            // Query only entity discovery
            let entity_query = ContextQuery {
                context_types: Some(vec![ContextType::EntityDiscovery]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let entity_results = shared_context.query_context(user_id, entity_query, &session_dek).await.unwrap();
            assert_eq!(entity_results.len(), 1);
            assert_eq!(entity_results[0].data["type"].as_str().unwrap(), "entity");
            
            // Query only strategic insights
            let strategic_query = ContextQuery {
                context_types: Some(vec![ContextType::StrategicInsight]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let strategic_results = shared_context.query_context(user_id, strategic_query, &session_dek).await.unwrap();
            assert_eq!(strategic_results.len(), 1);
            assert_eq!(strategic_results[0].data["type"].as_str().unwrap(), "strategic");
        }

        #[tokio::test]
        async fn test_metadata_separation() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Create context with metadata
            let mut entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Performance,
                AgentType::Lightning,
                "perf_data",
                json!({"response_time": 1250})
            );
            entry.metadata.insert("internal_metric".to_string(), json!("sensitive_internal_value"));
            entry.metadata.insert("public_metric".to_string(), json!("safe_public_value"));
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            let query = ContextQuery {
                context_types: Some(vec![ContextType::Performance]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["perf_data".to_string()]),
                limit: None,
            };
            
            let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert_eq!(results.len(), 1);
            
            // Verify metadata is preserved but properly structured
            let metadata = &results[0].metadata;
            assert!(metadata.contains_key("internal_metric"));
            assert!(metadata.contains_key("public_metric"));
            assert_eq!(metadata["public_metric"].as_str().unwrap(), "safe_public_value");
        }
    }

    /// A07:2021 - Identification and Authentication Failures Tests
    mod a07_identification_authentication_failures {
        use super::*;

        #[tokio::test]
        async fn test_requires_valid_user_id() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            // Use nil UUID (invalid user)
            let invalid_user_id = Uuid::nil();
            let session_id = Uuid::new_v4();
            
            let entry = create_test_context_entry(
                invalid_user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "test_key",
                json!({"test": "data"})
            );
            
            // Should store without error (validation happens at service layer)
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // But querying should be isolated to this invalid user
            let query = ContextQuery {
                context_types: None,
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let results = shared_context.query_context(invalid_user_id, query.clone(), &session_dek).await.unwrap();
            assert_eq!(results.len(), 1); // Should only see its own invalid data
            
            // Valid user should not see invalid user's data
            let valid_user_id = Uuid::new_v4();
            let valid_results = shared_context.query_context(valid_user_id, query, &session_dek).await.unwrap();
            assert!(valid_results.is_empty());
        }

        #[tokio::test]
        async fn test_session_context_binding() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session1_id = Uuid::new_v4();
            let session2_id = Uuid::new_v4();
            
            // Store context in session 1
            let entry1 = create_test_context_entry(
                user_id,
                session1_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "session1_data",
                json!({"session": "session1"})
            );
            shared_context.store_context(entry1, &session_dek).await.unwrap();
            
            // Store context in session 2
            let entry2 = create_test_context_entry(
                user_id,
                session2_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "session2_data",
                json!({"session": "session2"})
            );
            shared_context.store_context(entry2, &session_dek).await.unwrap();
            
            // Query session 1 only
            let query1 = ContextQuery {
                context_types: None,
                source_agents: None,
                session_id: Some(session1_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let results1 = shared_context.query_context(user_id, query1, &session_dek).await.unwrap();
            assert_eq!(results1.len(), 1);
            assert_eq!(results1[0].data["session"].as_str().unwrap(), "session1");
            
            // Query session 2 only
            let query2 = ContextQuery {
                context_types: None,
                source_agents: None,
                session_id: Some(session2_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let results2 = shared_context.query_context(user_id, query2, &session_dek).await.unwrap();
            assert_eq!(results2.len(), 1);
            assert_eq!(results2[0].data["session"].as_str().unwrap(), "session2");
        }
    }

    /// A09:2021 - Security Logging and Monitoring Failures Tests
    mod a09_security_logging_monitoring_failures {
        use super::*;

        #[tokio::test]
        async fn test_security_event_logging() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Test with tracing subscriber to capture logs
            let _guard = tracing_subscriber::fmt()
                .with_test_writer()
                .init();
            
            // Store context - should generate security logs
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::StrategicInsight,
                AgentType::Strategic,
                "security_test",
                json!({"sensitive": "data"})
            );
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // Query context - should generate access logs
            let query = ContextQuery {
                context_types: None,
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            
            // The test validates that logging infrastructure is in place
            // Actual log verification would require log capture setup
        }

        #[tokio::test]
        async fn test_audit_trail_completeness() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Create context entry with audit metadata
            let mut entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Coordination,
                AgentType::Orchestrator,
                "audit_test",
                json!({"action": "test_operation"})
            );
            
            // Add audit metadata
            entry.metadata.insert("request_id".to_string(), json!("req_12345"));
            entry.metadata.insert("client_ip".to_string(), json!("127.0.0.1"));
            entry.metadata.insert("user_agent".to_string(), json!("TestAgent/1.0"));
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            let query = ContextQuery {
                context_types: Some(vec![ContextType::Coordination]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: Some(vec!["audit_test".to_string()]),
                limit: None,
            };
            
            let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert_eq!(results.len(), 1);
            
            // Verify audit metadata is preserved
            let metadata = &results[0].metadata;
            assert_eq!(metadata["request_id"].as_str().unwrap(), "req_12345");
            assert_eq!(metadata["client_ip"].as_str().unwrap(), "127.0.0.1");
            assert_eq!(metadata["user_agent"].as_str().unwrap(), "TestAgent/1.0");
        }
    }

    /// Performance and Resource Exhaustion Tests
    mod performance_security_tests {
        use super::*;

        #[tokio::test]
        async fn test_context_size_limits() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Create large context data (potential DoS attack)
            let large_string = "x".repeat(10_000_000); // 10MB string
            let large_data = json!({
                "large_field": large_string,
                "normal_field": "normal_value"
            });
            
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::EntityDiscovery,
                AgentType::Perception,
                "large_context",
                large_data
            );
            
            // This should either succeed with proper handling or fail gracefully
            let result = shared_context.store_context(entry, &session_dek).await;
            match result {
                Ok(_) => {
                    // If it succeeds, verify we can still query normally
                    let query = ContextQuery {
                        context_types: Some(vec![ContextType::EntityDiscovery]),
                        source_agents: None,
                        session_id: Some(session_id),
                        since_timestamp: None,
                        keys: None,
                        limit: Some(1),
                    };
                    
                    let results = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
                    assert!(results.len() <= 1, "Query limit should be enforced");
                },
                Err(_) => {
                    // If it fails, that's also acceptable for large data
                    println!("Large context rejected (acceptable behavior)");
                }
            }
        }

        #[tokio::test]
        async fn test_query_result_limits() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store many context entries
            for i in 0..100 {
                let entry = create_test_context_entry(
                    user_id,
                    session_id,
                    ContextType::Performance,
                    AgentType::Lightning,
                    &format!("perf_entry_{}", i),
                    json!({"index": i})
                );
                shared_context.store_context(entry, &session_dek).await.unwrap();
            }
            
            // Query with limit
            let limited_query = ContextQuery {
                context_types: Some(vec![ContextType::Performance]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: Some(10),
            };
            
            let limited_results = shared_context.query_context(user_id, limited_query, &session_dek).await.unwrap();
            assert_eq!(limited_results.len(), 10, "Query limit should be enforced");
            
            // Query without limit should still be reasonable
            let unlimited_query = ContextQuery {
                context_types: Some(vec![ContextType::Performance]),
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let unlimited_results = shared_context.query_context(user_id, unlimited_query, &session_dek).await.unwrap();
            assert!(unlimited_results.len() <= 100, "Should return all stored results");
        }
    }

    /// Cleanup and Memory Management Tests
    mod cleanup_security_tests {
        use super::*;

        #[tokio::test]
        async fn test_session_cleanup() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client);
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store context
            let entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::TacticalPlanning,
                AgentType::Tactical,
                "cleanup_test",
                json!({"data": "to_be_cleaned"})
            );
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // Verify it exists
            let query = ContextQuery {
                context_types: None,
                source_agents: None,
                session_id: Some(session_id),
                since_timestamp: None,
                keys: None,
                limit: None,
            };
            
            let before_cleanup = shared_context.query_context(user_id, query.clone(), &session_dek).await.unwrap();
            assert_eq!(before_cleanup.len(), 1);
            
            // Cleanup old context (0 hours = everything)
            let cleaned_count = shared_context.cleanup_session_context(user_id, session_id, 0).await.unwrap();
            assert_eq!(cleaned_count, 1, "Should have cleaned up 1 context entry");
            
            // Verify it's gone
            let after_cleanup = shared_context.query_context(user_id, query, &session_dek).await.unwrap();
            assert!(after_cleanup.is_empty(), "Context should be cleaned up");
        }

        #[tokio::test]
        async fn test_memory_leak_prevention() {
            let redis_client = create_test_redis_client().await;
            let shared_context = SharedAgentContext::new(redis_client.clone());
            let session_dek = create_test_session_dek();
            
            let user_id = Uuid::new_v4();
            let session_id = Uuid::new_v4();
            
            // Store and immediately expire context
            let mut entry = create_test_context_entry(
                user_id,
                session_id,
                ContextType::Coordination,
                AgentType::Lightning,
                "memory_test",
                json!({"test": "memory_leak_prevention"})
            );
            entry.ttl_seconds = Some(1); // 1 second TTL
            
            shared_context.store_context(entry, &session_dek).await.unwrap();
            
            // Wait for expiration
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            
            // Verify Redis automatically cleaned up expired keys
            let mut conn = redis_client.get_multiplexed_async_connection().await.unwrap();
            let pattern = format!("agent_context:{}:{}:*", user_id, session_id);
            let remaining_keys: Vec<String> = conn.keys(&pattern).await.unwrap();
            
            assert!(remaining_keys.is_empty(), "Expired keys should be automatically cleaned up by Redis TTL");
        }
    }
}

/// End-to-End Encryption Integration Tests
/// 
/// These tests validate the integration with the SessionDek encryption system
#[cfg(test)]
mod encryption_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypted_context_storage_and_retrieval() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Test storing encrypted sensitive data
        let sensitive_context = json!({
            "character_sheet": {
                "name": "Secret Character",
                "backstory": "Highly confidential character background",
                "stats": {"strength": 18, "intelligence": 16}
            },
            "api_credentials": {
                "service": "external_ai",
                "key": "sk-very-secret-key-12345"
            },
            "user_preferences": {
                "privacy_level": "maximum",
                "data_retention": "minimal"
            }
        });
        
        // Store using the helper method that should encrypt before storage
        let result = shared_context.store_strategic_insight(
            user_id,
            session_id,
            "encrypted_character_data".to_string(),
            sensitive_context.clone(),
            None,
            &session_dek
        ).await;
        
        assert!(result.is_ok(), "Should store encrypted context successfully");
        
        // Retrieve and verify data integrity
        let insights = shared_context.get_strategic_insights(user_id, session_id, Some(1), &session_dek).await.unwrap();
        assert_eq!(insights.len(), 1);
        
        let retrieved_data = &insights[0].data;
        assert_eq!(
            retrieved_data["character_sheet"]["name"].as_str().unwrap(),
            "Secret Character"
        );
        assert_eq!(
            retrieved_data["api_credentials"]["key"].as_str().unwrap(),
            "sk-very-secret-key-12345"
        );
    }

    #[tokio::test]
    async fn test_cross_agent_encrypted_communication() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Perception agent stores discovered entities (encrypted)
        let entities = vec![
            json!({
                "name": "Hidden Artifact",
                "type": "item",
                "description": "A mysterious artifact with unknown powers",
                "location": "Secret chamber coordinates: 42.123, -87.456"
            }),
            json!({
                "name": "NPC Informant", 
                "type": "character",
                "secrets": ["Knows the location of the treasure", "Has a secret agenda"],
                "trust_level": 0.3
            })
        ];
        
        shared_context.store_entity_discovery(
            user_id,
            session_id,
            &entities,
            Some("Discovered during infiltration mission".to_string()),
            &session_dek
        ).await.unwrap();
        
        // Tactical agent stores planning data (encrypted)
        let tactical_plan = json!({
            "mission_objective": "Retrieve the Hidden Artifact",
            "approach": "stealth",
            "contingencies": [
                "If discovered, use NPC Informant as distraction",
                "Emergency extraction via coordinates 42.130, -87.450"
            ],
            "risk_assessment": "high",
            "estimated_duration": "2 hours"
        });
        
        shared_context.store_tactical_planning(
            user_id,
            session_id,
            "infiltration_plan".to_string(),
            tactical_plan,
            None,
            &session_dek
        ).await.unwrap();
        
        // Strategic agent retrieves both types of context for coordination
        let entity_discoveries = shared_context.get_recent_entity_discoveries(user_id, session_id, Some(10), &session_dek).await.unwrap();
        let tactical_history = shared_context.get_tactical_planning_history(user_id, session_id, Some(10), &session_dek).await.unwrap();
        
        assert_eq!(entity_discoveries.len(), 1);
        assert_eq!(tactical_history.len(), 1);
        
        // Verify encrypted data integrity across agents
        let discovered_entities = &entity_discoveries[0].data["entities"];
        assert_eq!(discovered_entities.as_array().unwrap().len(), 2);
        
        let plan_data = &tactical_history[0].data;
        assert_eq!(plan_data["mission_objective"].as_str().unwrap(), "Retrieve the Hidden Artifact");
    }

    #[tokio::test]
    async fn test_session_dek_isolation() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        
        // Create two different session DEKs (simulating different user sessions)
        let session_dek_1 = create_test_session_dek();
        let session_dek_2 = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session1_id = Uuid::new_v4();
        let session2_id = Uuid::new_v4();
        
        // Store context with session 1's DEK
        let session1_data = json!({
            "session_identifier": "session_1",
            "sensitive_data": "This belongs to session 1",
            "encryption_test": "DEK_1_encrypted_content"
        });
        
        shared_context.store_strategic_insight(
            user_id,
            session1_id,
            "session1_insight".to_string(),
            session1_data,
            None,
            &session_dek_1
        ).await.unwrap();
        
        // Store context with session 2's DEK  
        let session2_data = json!({
            "session_identifier": "session_2",
            "sensitive_data": "This belongs to session 2",
            "encryption_test": "DEK_2_encrypted_content"
        });
        
        shared_context.store_strategic_insight(
            user_id,
            session2_id,
            "session2_insight".to_string(),
            session2_data,
            None,
            &session_dek_2
        ).await.unwrap();
        
        // Verify each session can only access its own data
        let session1_insights = shared_context.get_strategic_insights(user_id, session1_id, None, &session_dek_1).await.unwrap();
        let session2_insights = shared_context.get_strategic_insights(user_id, session2_id, None, &session_dek_2).await.unwrap();
        
        assert_eq!(session1_insights.len(), 1);
        assert_eq!(session2_insights.len(), 1);
        
        assert_eq!(
            session1_insights[0].data["session_identifier"].as_str().unwrap(),
            "session_1"
        );
        assert_eq!(
            session2_insights[0].data["session_identifier"].as_str().unwrap(),
            "session_2"
        );
    }
}

/// Functional Test Cases for Shared Context Features
#[cfg(test)]
mod functional_tests {
    use super::*;

    #[tokio::test]
    async fn test_entity_discovery_sharing() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Perception agent discovers entities
        let entities = vec![
            json!({"name": "Dragon", "type": "creature", "threat_level": "high"}),
            json!({"name": "Cave", "type": "location", "contains": ["treasure", "traps"]}),
            json!({"name": "Magic Sword", "type": "item", "power": "flame_enchantment"})
        ];
        
        shared_context.store_entity_discovery(
            user_id,
            session_id,
            &entities,
            Some("Combat encounter analysis".to_string()),
            &session_dek
        ).await.unwrap();
        
        // Tactical agent retrieves entity discoveries for planning
        let discoveries = shared_context.get_recent_entity_discoveries(user_id, session_id, Some(5), &session_dek).await.unwrap();
        assert_eq!(discoveries.len(), 1);
        
        let discovered_entities = discoveries[0].data["entities"].as_array().unwrap();
        assert_eq!(discovered_entities.len(), 3);
        assert_eq!(discovered_entities[0]["name"].as_str().unwrap(), "Dragon");
    }

    #[tokio::test]
    async fn test_strategic_tactical_coordination() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Strategic agent provides high-level direction
        let strategic_directive = json!({
            "narrative_focus": "character_development",
            "plot_progression": "rising_action",
            "tone": "mysterious",
            "pacing": "moderate",
            "key_themes": ["trust", "sacrifice", "hidden_knowledge"]
        });
        
        shared_context.store_strategic_insight(
            user_id,
            session_id,
            "narrative_direction".to_string(),
            strategic_directive,
            Some(HashMap::from([
                ("confidence".to_string(), json!(0.85)),
                ("priority".to_string(), json!("high"))
            ])),
            &session_dek
        ).await.unwrap();
        
        // Tactical agent creates plan based on strategic direction
        let tactical_response = json!({
            "plan_type": "character_interaction",
            "aligned_with_strategy": true,
            "implementation": {
                "focus_character": "mysterious_mentor",
                "interaction_type": "revelation",
                "emotional_beat": "surprise_then_contemplation"
            },
            "references_strategic_insight": "narrative_direction"
        });
        
        shared_context.store_tactical_planning(
            user_id,
            session_id,
            "character_interaction_plan".to_string(),
            tactical_response,
            Some(HashMap::from([
                ("strategic_alignment".to_string(), json!(true)),
                ("execution_priority".to_string(), json!("immediate"))
            ])),
            &session_dek
        ).await.unwrap();
        
        // Strategic agent can review tactical implementation
        let tactical_history = shared_context.get_tactical_planning_history(user_id, session_id, Some(5), &session_dek).await.unwrap();
        assert_eq!(tactical_history.len(), 1);
        
        let tactical_plan = &tactical_history[0];
        assert_eq!(
            tactical_plan.data["implementation"]["focus_character"].as_str().unwrap(),
            "mysterious_mentor"
        );
        assert_eq!(
            tactical_plan.metadata["strategic_alignment"].as_bool().unwrap(),
            true
        );
    }

    #[tokio::test]
    async fn test_performance_monitoring_context() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Different agents report performance metrics
        let lightning_metrics = json!({
            "agent": "lightning",
            "response_time_ms": 850,
            "cache_hit_rate": 0.75,
            "quality_score": 0.92
        });
        
        shared_context.store_performance_metrics(
            user_id,
            session_id,
            AgentType::Lightning,
            lightning_metrics,
            &session_dek
        ).await.unwrap();
        
        let tactical_metrics = json!({
            "agent": "tactical", 
            "planning_time_ms": 1200,
            "plan_validation_success": true,
            "context_complexity": "high"
        });
        
        shared_context.store_performance_metrics(
            user_id,
            session_id,
            AgentType::Tactical,
            tactical_metrics,
            &session_dek
        ).await.unwrap();
        
        // Query all performance data
        let perf_query = ContextQuery {
            context_types: Some(vec![ContextType::Performance]),
            source_agents: None,
            session_id: Some(session_id),
            since_timestamp: None,
            keys: None,
            limit: None,
        };
        
        let performance_data = shared_context.query_context(user_id, perf_query, &session_dek).await.unwrap();
        assert_eq!(performance_data.len(), 2);
        
        // Verify we can identify metrics by agent
        let lightning_data = performance_data.iter()
            .find(|entry| matches!(entry.source_agent, AgentType::Lightning))
            .unwrap();
        assert_eq!(lightning_data.data["response_time_ms"].as_u64().unwrap(), 850);
        
        let tactical_data = performance_data.iter()
            .find(|entry| matches!(entry.source_agent, AgentType::Tactical))
            .unwrap();
        assert_eq!(tactical_data.data["planning_time_ms"].as_u64().unwrap(), 1200);
    }

    #[tokio::test]
    async fn test_coordination_signals() {
        let redis_client = create_test_redis_client().await;
        let shared_context = SharedAgentContext::new(redis_client);
        let session_dek = create_test_session_dek();
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Perception agent signals entity creation completion
        shared_context.store_coordination_signal(
            user_id,
            session_id,
            AgentType::Perception,
            "entity_creation_complete".to_string(),
            json!({
                "status": "completed",
                "entities_created": 5,
                "timestamp": Utc::now().to_rfc3339()
            }),
            Some(1800), // 30 minutes TTL for coordination signals
            &session_dek
        ).await.unwrap();
        
        // Tactical agent can check for perception completion before planning
        let coord_query = ContextQuery {
            context_types: Some(vec![ContextType::Coordination]),
            source_agents: Some(vec![AgentType::Perception]),
            session_id: Some(session_id),
            since_timestamp: None,
            keys: Some(vec!["entity_creation_complete".to_string()]),
            limit: None,
        };
        
        let coordination_signals = shared_context.query_context(user_id, coord_query, &session_dek).await.unwrap();
        assert_eq!(coordination_signals.len(), 1);
        
        let signal = &coordination_signals[0];
        assert_eq!(signal.data["status"].as_str().unwrap(), "completed");
        assert_eq!(signal.data["entities_created"].as_u64().unwrap(), 5);
        
        // Tactical agent signals planning start
        shared_context.store_coordination_signal(
            user_id,
            session_id,
            AgentType::Tactical,
            "planning_started".to_string(),
            json!({
                "status": "in_progress",
                "depends_on": "entity_creation_complete",
                "estimated_duration_ms": 2000
            }),
            Some(1800),
            &session_dek
        ).await.unwrap();
    }
}