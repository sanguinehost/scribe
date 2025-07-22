use scribe_backend::services::agentic::{
    HierarchicalAgentPipeline, 
    hierarchical_pipeline::HierarchicalPipelineConfig,
};
use scribe_backend::services::agent_prompt_templates::PromptTemplateVersion;
use scribe_backend::test_helpers::*;
use scribe_backend::models::chats::{ChatMessageForClient, MessageRole};
use scribe_backend::auth::session_dek::SessionDek;
use uuid::Uuid;
use chrono::Utc;

/// Create test chat history for pipeline testing
fn create_pipeline_test_chat_history(user_id: Uuid) -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I slowly draw my sword as the ancient dragon awakens from its slumber.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "The dragon's massive golden eyes snap open, fixing upon you with ancient intelligence. Its scales shimmer in the dim light of the cavern as it begins to rise, wings unfurling like massive sails.".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I take a defensive stance and call out, 'Great one, I seek passage through your domain, not conflict.'".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_hierarchical_pipeline_full_execution() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_pipeline_test_chat_history(user_id);
    let current_message = "I prepare to negotiate with the dragon for safe passage.";

    // Create hierarchical pipeline with extended timeout for tests
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000, // 60 seconds for tests
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    // Execute the full pipeline
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        current_message,
    ).await;

    // Pipeline should complete successfully
    if let Err(e) = &result {
        eprintln!("Pipeline execution failed: {:?}", e);
    }
    assert!(result.is_ok());
    let pipeline_result = result.unwrap();

    // Verify response is generated
    assert!(!pipeline_result.response.is_empty());
    assert!(pipeline_result.response.len() > 10); // Should be substantial

    // Verify strategic directive was created
    assert!(!pipeline_result.strategic_directive.directive_type.is_empty());
    assert!(!pipeline_result.strategic_directive.narrative_arc.is_empty());

    // Verify enriched context was assembled
    assert!(pipeline_result.enriched_context.strategic_directive.is_some());
    assert!(!pipeline_result.enriched_context.validated_plan.steps.is_empty() || 
           pipeline_result.enriched_context.validated_plan.preconditions_met);

    // Verify metrics are reasonable
    assert!(pipeline_result.metrics.total_execution_time_ms > 0);
    assert!(pipeline_result.metrics.strategic_time_ms > 0);
    assert!(pipeline_result.metrics.tactical_time_ms > 0);
    assert!(pipeline_result.metrics.operational_time_ms > 0);
    assert!(pipeline_result.metrics.total_tokens_used > 0);
    assert!(pipeline_result.metrics.total_ai_calls >= 2); // At least strategic and operational (planning may use cache)
    assert!(pipeline_result.metrics.confidence_score >= 0.0);
    assert!(pipeline_result.metrics.confidence_score <= 1.0);

    println!("✅ Full hierarchical pipeline executed successfully");
    println!("   📋 Strategic directive: {}", pipeline_result.strategic_directive.directive_type);
    println!("   ⏱️  Total execution time: {}ms", pipeline_result.metrics.total_execution_time_ms);
    println!("   🎯 Confidence score: {:.2}", pipeline_result.metrics.confidence_score);
    println!("   🤖 AI calls made: {}", pipeline_result.metrics.total_ai_calls);
    println!("   📝 Response length: {} chars", pipeline_result.response.len());
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_hierarchical_pipeline_with_different_template_versions() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_pipeline_test_chat_history(user_id);
    let current_message = "I attempt to communicate with the dragon.";

    // Test V1 template
    let config_v1 = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V1,
        max_pipeline_time_ms: 60000, // 60 seconds for tests
        ..Default::default()
    };
    let pipeline_v1 = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config_v1));
    
    let result_v1 = pipeline_v1.execute(
        &chat_history,
        user_id,
        &session_dek,
        current_message,
    ).await;
    
    assert!(result_v1.is_ok());
    let response_v1 = result_v1.unwrap().response;

    // Test V2 template
    let config_v2 = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::V2,
        max_pipeline_time_ms: 60000, // 60 seconds for tests
        ..Default::default()
    };
    let pipeline_v2 = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config_v2));
    
    let result_v2 = pipeline_v2.execute(
        &chat_history,
        user_id,
        &session_dek,
        current_message,
    ).await;
    
    assert!(result_v2.is_ok());
    let response_v2 = result_v2.unwrap().response;

    // Responses should be different (different template versions)
    assert_ne!(response_v1, response_v2);
    assert!(!response_v1.is_empty());
    assert!(!response_v2.is_empty());

    println!("✅ Pipeline tested with different template versions");
    println!("   📝 V1 response length: {} chars", response_v1.len());
    println!("   📝 V2 response length: {} chars", response_v2.len());
}

#[tokio::test]
async fn test_hierarchical_pipeline_error_handling() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, None);

    // Test with empty chat history
    let empty_history: Vec<ChatMessageForClient> = vec![];
    let result = pipeline.execute(
        &empty_history,
        user_id,
        &session_dek,
        "Test message",
    ).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Chat history cannot be empty"));

    // Test with invalid user ID
    let chat_history = create_pipeline_test_chat_history(user_id);
    let result = pipeline.execute(
        &chat_history,
        Uuid::nil(), // Invalid user ID
        &session_dek,
        "Test message",
    ).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Invalid user ID"));

    println!("✅ Pipeline error handling validated");
}

#[tokio::test]
async fn test_hierarchical_pipeline_timeout_configuration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let chat_history = create_pipeline_test_chat_history(user_id);

    // Test with very short timeout
    let short_timeout_config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 1, // 1ms - too short
        ..Default::default()
    };
    
    let pipeline = HierarchicalAgentPipeline::from_app_state(
        &app.app_state, 
        Some(short_timeout_config)
    );
    
    // Validation should fail for too short timeout
    let validation_result = pipeline.validate_configuration();
    assert!(validation_result.is_err());
    assert!(validation_result.unwrap_err().to_string().contains("too short"));

    // Test with reasonable timeout
    let reasonable_config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 30000, // 30 seconds
        ..Default::default()
    };
    
    let pipeline_reasonable = HierarchicalAgentPipeline::from_app_state(
        &app.app_state, 
        Some(reasonable_config)
    );
    
    let validation_result = pipeline_reasonable.validate_configuration();
    assert!(validation_result.is_ok());

    println!("✅ Pipeline timeout configuration validated");
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_hierarchical_pipeline_metrics_tracking() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_pipeline_test_chat_history(user_id);
    let current_message = "I observe the dragon's reaction carefully.";

    // Create pipeline with extended timeout for tests
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000, // 60 seconds for tests
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));
    
    let result = pipeline.execute(
        &chat_history,
        user_id,
        &session_dek,
        current_message,
    ).await;

    assert!(result.is_ok());
    let metrics = result.unwrap().metrics;

    // Verify time distribution makes sense
    let layer_time_sum = metrics.strategic_time_ms + 
                         metrics.tactical_time_ms + 
                         metrics.operational_time_ms;
    
    // Total time should be at least the sum of layer times (plus some overhead)
    assert!(metrics.total_execution_time_ms >= layer_time_sum);
    
    // Each layer should take some measurable time
    assert!(metrics.strategic_time_ms > 0);
    assert!(metrics.tactical_time_ms > 0);
    assert!(metrics.operational_time_ms > 0);

    // Verify resource usage tracking
    assert!(metrics.total_tokens_used > 0);
    assert!(metrics.total_ai_calls >= 2); // At least strategic and operational (planning may use cache)
    assert!(metrics.confidence_score >= 0.0 && metrics.confidence_score <= 1.0);

    println!("✅ Pipeline metrics tracking validated");
    println!("   ⏱️  Strategic: {}ms, Tactical: {}ms, Operational: {}ms", 
             metrics.strategic_time_ms, metrics.tactical_time_ms, metrics.operational_time_ms);
    println!("   🎯 Confidence: {:.2}, Tokens: {}, AI calls: {}", 
             metrics.confidence_score, metrics.total_tokens_used, metrics.total_ai_calls);
}

#[tokio::test]
async fn test_hierarchical_pipeline_health_check() {
    let app = spawn_app(false, false, false).await;
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, None);

    // Health check should pass for properly configured pipeline
    let health_result = pipeline.health_check().await;
    assert!(health_result.is_ok());

    // Test with invalid configuration
    let invalid_config = HierarchicalPipelineConfig {
        response_generation_model: "".to_string(), // Empty model name
        ..Default::default()
    };
    
    let invalid_pipeline = HierarchicalAgentPipeline::from_app_state(
        &app.app_state, 
        Some(invalid_config)
    );
    
    let health_result = invalid_pipeline.health_check().await;
    assert!(health_result.is_err());
    assert!(health_result.unwrap_err().to_string().contains("not configured"));

    println!("✅ Pipeline health check validated");
}

#[tokio::test]
#[ignore = "Requires real AI API calls"]
async fn test_hierarchical_pipeline_different_narrative_scenarios() {
    let app = spawn_app(true, true, true).await;
    let user_id = Uuid::new_v4();
    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Create pipeline with extended timeout for tests
    let config = HierarchicalPipelineConfig {
        max_pipeline_time_ms: 60000, // 60 seconds for tests
        ..Default::default()
    };
    let pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, Some(config));

    // Scenario 1: Combat encounter
    let combat_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I charge at the orc with my battle axe raised!".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let combat_result = pipeline.execute(
        &combat_history,
        user_id,
        &session_dek,
        "I swing my axe with all my might!",
    ).await;

    assert!(combat_result.is_ok());
    let combat_response = combat_result.unwrap();
    assert!(!combat_response.response.is_empty());

    // Scenario 2: Social interaction
    let social_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I approach the merchant with a friendly smile and inquire about his wares.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let social_result = pipeline.execute(
        &social_history,
        user_id,
        &session_dek,
        "I ask about the rare gemstones he mentioned.",
    ).await;

    assert!(social_result.is_ok());
    let social_response = social_result.unwrap();
    assert!(!social_response.response.is_empty());

    // Different scenarios should potentially produce different strategic directives
    // (Though this depends on AI behavior and isn't guaranteed)
    println!("✅ Pipeline tested across different narrative scenarios");
    println!("   ⚔️  Combat directive: {}", combat_response.strategic_directive.directive_type);
    println!("   💬 Social directive: {}", social_response.strategic_directive.directive_type);
}

#[tokio::test]
async fn test_hierarchical_pipeline_configuration_options() {
    let app = spawn_app(false, false, false).await;

    // Test default configuration
    let default_pipeline = HierarchicalAgentPipeline::from_app_state(&app.app_state, None);
    assert_eq!(default_pipeline.get_config().prompt_template_version, PromptTemplateVersion::V1);
    assert_eq!(default_pipeline.get_config().response_generation_model, "gemini-2.5-flash");
    assert!(default_pipeline.get_config().enable_optimizations);
    assert_eq!(default_pipeline.get_config().max_pipeline_time_ms, 30000);

    // Test custom configuration
    let custom_config = HierarchicalPipelineConfig {
        prompt_template_version: PromptTemplateVersion::Experimental,
        response_generation_model: "custom-model".to_string(),
        enable_optimizations: false,
        max_pipeline_time_ms: 60000,
        enable_parallel_agents: true,
        enable_progressive_response: true,
    };

    let custom_pipeline = HierarchicalAgentPipeline::from_app_state(
        &app.app_state, 
        Some(custom_config.clone())
    );

    assert_eq!(custom_pipeline.get_config().prompt_template_version, PromptTemplateVersion::Experimental);
    assert_eq!(custom_pipeline.get_config().response_generation_model, "custom-model");
    assert!(!custom_pipeline.get_config().enable_optimizations);
    assert_eq!(custom_pipeline.get_config().max_pipeline_time_ms, 60000);

    println!("✅ Pipeline configuration options validated");
}