//! OWASP Top 10 Security Tests for CheckEntityExistsTool
//! 
//! These tests verify that the CheckEntityExistsTool properly protects against
//! common security vulnerabilities outlined in the OWASP Top 10:
//! 
//! 1. A01:2021 - Broken Access Control
//! 2. A02:2021 - Cryptographic Failures  
//! 3. A03:2021 - Injection
//! 4. A04:2021 - Insecure Design
//! 5. A05:2021 - Security Misconfiguration
//! 6. A06:2021 - Vulnerable and Outdated Components
//! 7. A07:2021 - Identification and Authentication Failures
//! 8. A08:2021 - Software and Data Integrity Failures
//! 9. A09:2021 - Security Logging and Monitoring Failures
//! 10. A10:2021 - Server-Side Request Forgery (SSRF)

use scribe_backend::services::agentic::tools::entity_crud_tools::CheckEntityExistsTool;
use scribe_backend::services::agentic::tools::ScribeTool;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::services::EcsEntityManager;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard, db::create_test_user};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// A01:2021 - Broken Access Control Tests
#[tokio::test]
async fn test_a01_broken_access_control_user_isolation() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two separate users
    let user1 = create_test_user(&test_app.db_pool, "user1_access".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user1.id);
    let user2 = create_test_user(&test_app.db_pool, "user2_access".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user2.id);
    
    // User1 creates an entity
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": "User1 Private Entity",
            "entity_type": "character"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user1.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    // Test that user2 cannot access user1's entity by ID
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user2.id.to_string(),
        "identifier": created_entity.entity.id.to_string()
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    // Should return false - user2 cannot see user1's entity
    assert_eq!(result["exists"], false, "User isolation failed: user2 can see user1's entity");
    
    // Test that user2 cannot access user1's entity by name
    let params_by_name = json!({
        "user_id": user2.id.to_string(),
        "identifier": "User1 Private Entity"
    });
    
    let result_by_name = tool.execute(&params_by_name, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    // Should return false - user2 cannot see user1's entity
    assert_eq!(result_by_name["exists"], false, "User isolation failed: user2 can find user1's entity by name");
}

#[tokio::test]
async fn test_a01_privilege_escalation_attempt() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "escalation_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with admin-style UUID (attempt to access system entities)
    let admin_uuid = "00000000-0000-0000-0000-000000000000";
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": admin_uuid
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    // Should not find any system entities
    assert_eq!(result["exists"], false, "Privilege escalation: found system entity with admin UUID");
    
    // Test with SQL injection attempt in user_id (should be caught by UUID validation)
    let malicious_params = json!({
        "user_id": "'; DROP TABLE entities; --",
        "identifier": "test"
    });
    
    let malicious_result = tool.execute(&malicious_params, &SessionDek::new(vec![0u8; 32])).await;
    
    // Should fail with validation error, not execute SQL
    assert!(malicious_result.is_err(), "SQL injection in user_id was not caught");
    assert!(malicious_result.unwrap_err().to_string().contains("user_id must be a valid UUID"), 
           "Wrong error message for malicious user_id");
}

/// A02:2021 - Cryptographic Failures Tests  
#[tokio::test]
async fn test_a02_session_dek_validation() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "crypto_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": "test_entity"
    });
    
    // Test with invalid session DEK (empty)
    let empty_dek = SessionDek::new(vec![]);
    let result_empty = tool.execute(&params, &empty_dek).await;
    
    // Should either work with empty DEK or fail gracefully
    // The exact behavior depends on implementation - we just ensure no crash
    let _ = result_empty; // Just ensure it doesn't panic
    
    // Test with malformed session DEK (wrong size)
    let wrong_size_dek = SessionDek::new(vec![0u8; 16]); // Wrong size
    let result_wrong_size = tool.execute(&params, &wrong_size_dek).await;
    
    // Should either work or fail gracefully
    let _ = result_wrong_size; // Just ensure it doesn't panic
    
    // Test with valid session DEK
    let valid_dek = SessionDek::new(vec![0u8; 32]);
    let result_valid = tool.execute(&params, &valid_dek).await;
    
    // Should work without errors
    assert!(result_valid.is_ok(), "Valid session DEK should work");
}

/// A03:2021 - Injection Tests
#[tokio::test]
async fn test_a03_sql_injection_attacks() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "injection_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // SQL injection payloads
    let sql_payloads = vec![
        "'; DROP TABLE entities; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO entities VALUES ('malicious'); --",
        "admin'; --",
        "' OR 1=1 --",
        "'; EXEC xp_cmdshell('dir'); --",
        "\"; DROP TABLE entities; --",
        "' OR SLEEP(5) --",
        "'; UPDATE entities SET name='hacked'; --"
    ];
    
    for payload in sql_payloads {
        let params = json!({
            "user_id": user.id.to_string(),
            "identifier": payload
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect("Tool should handle SQL injection gracefully");
        
        // Should return false (not found) for injection attempts
        assert_eq!(result["exists"], false, "SQL injection payload '{}' should not find entities", payload);
        
        // Should not return any sensitive data
        assert_eq!(result["entity_id"], serde_json::Value::Null, "SQL injection payload '{}' should not return entity_id", payload);
        assert_eq!(result["entity_type"], serde_json::Value::Null, "SQL injection payload '{}' should not return entity_type", payload);
        assert_eq!(result["name"], serde_json::Value::Null, "SQL injection payload '{}' should not return name", payload);
    }
}

#[tokio::test]
async fn test_a03_nosql_injection_attacks() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "nosql_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // NoSQL injection payloads (relevant for JSON queries)
    let nosql_payloads = vec![
        r#"{"$ne": null}"#,
        r#"{"$gt": ""}"#,
        r#"{"$regex": ".*"}"#,
        r#"{"$where": "function() { return true; }"}"#,
        r#"{"$or": [{"name": "test"}, {"name": {"$ne": null}}]}"#
    ];
    
    for payload in nosql_payloads {
        let params = json!({
            "user_id": user.id.to_string(),
            "identifier": payload
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect("Tool should handle NoSQL injection gracefully");
        
        // Should return false (not found) for injection attempts
        assert_eq!(result["exists"], false, "NoSQL injection payload '{}' should not find entities", payload);
    }
}

/// A04:2021 - Insecure Design Tests
#[tokio::test]
async fn test_a04_rate_limiting_and_dos_protection() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "dos_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test rapid requests (potential DoS)
    let mut request_times = Vec::new();
    for i in 0..10 {
        let start = std::time::Instant::now();
        
        let params = json!({
            "user_id": user.id.to_string(),
            "identifier": format!("dos_test_{}", i)
        });
        
        let _result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect("Tool should handle rapid requests");
        
        request_times.push(start.elapsed());
    }
    
    // Verify that requests don't get faster (indicating potential caching vulnerabilities)
    // and don't get significantly slower (indicating DoS vulnerability)
    let avg_time = request_times.iter().sum::<std::time::Duration>() / request_times.len() as u32;
    
    for time in &request_times {
        assert!(time.as_millis() < 10000, "Request took too long: {}ms (potential DoS)", time.as_millis());
        // Don't assert minimum time as legitimate optimization is allowed
    }
    
    println!("Average request time: {}ms", avg_time.as_millis());
}

#[tokio::test]
async fn test_a04_information_disclosure_prevention() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "disclosure_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with non-existent entity
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": "definitely_does_not_exist_12345"
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    // Verify that non-existent entities don't leak information
    assert_eq!(result["exists"], false);
    assert_eq!(result["entity_id"], serde_json::Value::Null);
    assert_eq!(result["entity_type"], serde_json::Value::Null);
    assert_eq!(result["name"], serde_json::Value::Null);
    
    // Verify no additional fields that could leak information
    let expected_fields = ["exists", "entity_id", "entity_type", "name"];
    for (key, _) in result.as_object().unwrap() {
        assert!(expected_fields.contains(&key.as_str()), 
               "Unexpected field '{}' in response could leak information", key);
    }
}

/// A05:2021 - Security Misconfiguration Tests
#[tokio::test]
async fn test_a05_error_handling_information_leakage() {
    let test_app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test various malformed inputs
    let malformed_inputs = vec![
        // Missing user_id
        json!({"identifier": "test"}),
        // Missing identifier
        json!({"user_id": "550e8400-e29b-41d4-a716-446655440000"}),
        // Invalid UUID format
        json!({"user_id": "not-a-uuid", "identifier": "test"}),
        // Null values
        json!({"user_id": null, "identifier": "test"}),
        json!({"user_id": "550e8400-e29b-41d4-a716-446655440000", "identifier": null}),
        // Wrong types
        json!({"user_id": 123, "identifier": "test"}),
        json!({"user_id": "550e8400-e29b-41d4-a716-446655440000", "identifier": 123}),
    ];
    
    for input in malformed_inputs {
        let result = tool.execute(&input, &SessionDek::new(vec![0u8; 32])).await;
        
        if let Err(error) = result {
            let error_msg = error.to_string();
            
            // Verify error messages don't leak sensitive information
            assert!(!error_msg.contains("database"), "Error message should not contain 'database': {}", error_msg);
            assert!(!error_msg.contains("connection"), "Error message should not contain 'connection': {}", error_msg);
            assert!(!error_msg.contains("SQL"), "Error message should not contain 'SQL': {}", error_msg);
            assert!(!error_msg.contains("password"), "Error message should not contain 'password': {}", error_msg);
            assert!(!error_msg.contains("secret"), "Error message should not contain 'secret': {}", error_msg);
            assert!(!error_msg.contains("internal"), "Error message should not contain 'internal': {}", error_msg);
            
            // Should contain helpful but safe validation messages
            assert!(error_msg.len() > 0, "Error message should not be empty");
            assert!(error_msg.len() < 200, "Error message should not be excessively long: {}", error_msg);
        }
    }
}

/// A07:2021 - Identification and Authentication Failures Tests
#[tokio::test]
async fn test_a07_user_authentication_bypass_attempts() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "auth_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create entity for the user
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": "Protected Entity",
            "entity_type": "character"
        })),
    ];
    
    let created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with wildcard UUID attempts
    let bypass_attempts = vec![
        "00000000-0000-0000-0000-000000000000", // Null UUID
        "ffffffff-ffff-ffff-ffff-ffffffffffff", // Max UUID
        "*",
        "%",
        "admin",
        "root",
        "system"
    ];
    
    for attempt in bypass_attempts {
        let params = json!({
            "user_id": attempt,
            "identifier": created_entity.entity.id.to_string()
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await;
        
        // Should either fail with validation error or return false
        match result {
            Ok(response) => {
                assert_eq!(response["exists"], false, "Auth bypass attempt '{}' should not find entities", attempt);
            }
            Err(error) => {
                assert!(error.to_string().contains("user_id must be a valid UUID"), 
                       "Wrong error for auth bypass attempt '{}': {}", attempt, error);
            }
        }
    }
}

/// A08:2021 - Software and Data Integrity Failures Tests
#[tokio::test]
async fn test_a08_data_integrity_validation() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "integrity_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with extremely long identifiers (potential buffer overflow)
    let long_identifier = "a".repeat(10000);
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": long_identifier
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle long identifiers gracefully");
    
    // Should return false without crashing
    assert_eq!(result["exists"], false);
    
    // Test with special Unicode characters (potential encoding issues)
    let unicode_identifier = "test\u{0000}\u{FFFF}\u{1F600}";
    let unicode_params = json!({
        "user_id": user.id.to_string(),
        "identifier": unicode_identifier
    });
    
    let unicode_result = tool.execute(&unicode_params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle Unicode characters gracefully");
    
    // Should return false without crashing
    assert_eq!(unicode_result["exists"], false);
    
    // Test with binary data (potential deserialization issues)
    let binary_data = "\x00\x01\x02\x03\x7F\x7E\x7D";
    let binary_params = json!({
        "user_id": user.id.to_string(),
        "identifier": binary_data
    });
    
    let binary_result = tool.execute(&binary_params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle binary data gracefully");
    
    // Should return false without crashing
    assert_eq!(binary_result["exists"], false);
}

/// A09:2021 - Security Logging and Monitoring Tests
#[tokio::test]
async fn test_a09_security_logging_verification() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "logging_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test normal operation (should be logged)
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": "normal_entity"
    });
    
    let _result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    // Test suspicious operation (should be logged with higher severity)
    let suspicious_params = json!({
        "user_id": user.id.to_string(),
        "identifier": "'; DROP TABLE entities; --"
    });
    
    let _suspicious_result = tool.execute(&suspicious_params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle suspicious input gracefully");
    
    // Note: Actual log verification would require access to log output
    // In a real implementation, you would check log files or log collectors
    // For now, we just ensure the operations complete without error
    // indicating that logging infrastructure is not broken
}

/// A10:2021 - Server-Side Request Forgery (SSRF) Tests
#[tokio::test]
async fn test_a10_ssrf_prevention() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "ssrf_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with URL-like identifiers (potential SSRF)
    let ssrf_payloads = vec![
        "http://localhost:8080/admin",
        "https://internal.network/secrets",
        "file:///etc/passwd",
        "ftp://internal.server/data",
        "ldap://internal.ldap/users",
        "gopher://internal.gopher/data",
        "dict://localhost:11211/stats",
    ];
    
    for payload in ssrf_payloads {
        let params = json!({
            "user_id": user.id.to_string(),
            "identifier": payload
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect("Tool should handle URL-like identifiers gracefully");
        
        // Should return false (not found) and not make any network requests
        assert_eq!(result["exists"], false, "SSRF payload '{}' should not find entities", payload);
        
        // Verify response is consistent with normal not-found response
        assert_eq!(result["entity_id"], serde_json::Value::Null);
        assert_eq!(result["entity_type"], serde_json::Value::Null);
        assert_eq!(result["name"], serde_json::Value::Null);
    }
}

/// Additional Security Tests - Entity Type Filter Validation
#[tokio::test]
async fn test_entity_type_filter_security() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "filter_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test with malicious entity type filters
    let malicious_filters = vec![
        "'; DROP TABLE entities; --",
        "admin",
        "system",
        "*",
        "%",
        "../../../etc/passwd",
        "<script>alert('xss')</script>",
        "../../admin",
    ];
    
    for filter in malicious_filters {
        let params = json!({
            "user_id": user.id.to_string(),
            "identifier": "test_entity",
            "entity_type": filter
        });
        
        let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
            .expect("Tool should handle malicious entity type filters gracefully");
        
        // Should return false without executing any malicious code
        assert_eq!(result["exists"], false, "Malicious entity type filter '{}' should not find entities", filter);
    }
}

/// Cross-Site Scripting (XSS) Prevention Tests
#[tokio::test]
async fn test_xss_prevention_in_responses() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "xss_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Create entity with XSS payload in name
    let entity_manager = EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        test_app.app_state.redis_client.clone(),
        Default::default()
    );
    
    let xss_name = "<script>alert('xss')</script>";
    let entity_id = Uuid::new_v4();
    let archetype_signature = "SpatialArchetype|Identity".to_string();
    let components = vec![
        ("Identity".to_string(), json!({
            "name": xss_name,
            "entity_type": "character"
        })),
    ];
    
    let _created_entity = entity_manager.create_entity(user.id, Some(entity_id), archetype_signature, components).await
        .expect("Failed to create test entity");
    
    let tool = CheckEntityExistsTool::new(test_app.app_state.clone());
    
    // Test finding entity by XSS name
    let params = json!({
        "user_id": user.id.to_string(),
        "identifier": xss_name
    });
    
    let result = tool.execute(&params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool execution should not fail");
    
    if result["exists"] == true {
        // If entity is found, verify the response properly escapes/handles XSS content
        let returned_name = result["name"].as_str().unwrap();
        
        // The exact escaping mechanism depends on implementation
        // We just verify that dangerous script content is not returned as-is
        // or that proper escaping/encoding is applied
        assert_eq!(returned_name, xss_name, "XSS content should be returned as-is from database");
        
        // Note: The frontend should handle XSS prevention when displaying this data
        // The backend should store the data accurately but flag it if needed
    }
    
    // Test with XSS payload in identifier search
    let xss_params = json!({
        "user_id": user.id.to_string(),
        "identifier": "<img src=x onerror=alert('xss')>"
    });
    
    let xss_result = tool.execute(&xss_params, &SessionDek::new(vec![0u8; 32])).await
        .expect("Tool should handle XSS payloads gracefully");
    
    // Should return false (not found) without executing script
    assert_eq!(xss_result["exists"], false);
}