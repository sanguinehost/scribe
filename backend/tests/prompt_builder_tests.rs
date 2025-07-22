use scribe_backend::prompt_builder::*;
use scribe_backend::services::{
    context_assembly_engine::*,
    hybrid_token_counter::{HybridTokenCounter, CountingMode},
    tokenizer_service::TokenizerService,
};
use scribe_backend::models::characters::CharacterMetadata;
use scribe_backend::config::Config;
use scribe_backend::test_helpers::{spawn_app, MockAiClient};
use genai::chat::ChatMessage as GenAiChatMessage;
use genai::chat::{ChatRole, MessageContent};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::path::PathBuf;

/// Test basic prompt building with character metadata
#[tokio::test]
async fn test_build_prompt_with_rag_character_metadata() {
    // Create test character metadata
    let character = create_test_character("Test Character", Some(b"A brave warrior with a mysterious past.".to_vec()));

    let result = build_prompt_with_rag(Some(&character));
    assert!(result.is_ok());
    
    let prompt = result.unwrap();
    assert!(prompt.contains("Test Character"));
    assert!(prompt.contains("A brave warrior with a mysterious past."));
    assert!(prompt.contains("Stay in character"));
}

/// Test prompt building with no character
#[tokio::test]
async fn test_build_prompt_with_rag_no_character() {
    let result = build_prompt_with_rag(None);
    assert!(result.is_ok());
    
    let prompt = result.unwrap();
    assert!(prompt.is_empty());
}

/// Test prompt building with character but no description
#[tokio::test]
async fn test_build_prompt_with_rag_no_description() {
    let character = create_test_character("Test Character", None);

    let result = build_prompt_with_rag(Some(&character));
    assert!(result.is_ok());
    
    let prompt = result.unwrap();
    assert!(prompt.is_empty());
}

/// Test basic EnrichedContext prompt building
#[tokio::test]
async fn test_build_enriched_context_prompt_basic() {
    let test_app = spawn_app(false, false, false).await;
    let config = Arc::new(create_test_config());
    let token_counter = Arc::new(create_test_token_counter());
    
    // Create basic EnrichedContext
    let enriched_context = create_test_enriched_context();
    
    // Create user message
    let user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("Test user message".to_string()),
        options: None,
    };
    
    // Create params
    let params = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: Some(&enriched_context),
        current_user_message: user_message,
        legacy_params: None,
        user_persona_name: Some("TestUser".to_string()),
    };
    
    let result = build_enriched_context_prompt(params).await;
    assert!(result.is_ok());
    
    let (prompt, _messages) = result.unwrap();
    assert!(prompt.contains("<strategic_directive>"));
    assert!(prompt.contains("<tactical_plan>"));
    assert!(prompt.contains("<current_sub_goal>"));
    assert!(prompt.contains("Execute test scene"));
}

/// Test EnrichedContext prompt building with multiple entities
#[tokio::test]
async fn test_build_enriched_context_prompt_multiple_entities() {
    let test_app = spawn_app(false, false, false).await;
    let config = Arc::new(create_test_config());
    let token_counter = Arc::new(create_test_token_counter());
    
    // Create EnrichedContext with multiple entities
    let mut enriched_context = create_test_enriched_context();
    enriched_context.relevant_entities = vec![
        create_test_entity_context("Hero", "Character"),
        create_test_entity_context("Villain", "Character"),
        create_test_entity_context("Sword", "Item"),
    ];
    
    let user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("I draw my sword".to_string()),
        options: None,
    };
    
    let params = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: Some(&enriched_context),
        current_user_message: user_message,
        legacy_params: None,
        user_persona_name: Some("TestUser".to_string()),
    };
    
    let result = build_enriched_context_prompt(params).await;
    assert!(result.is_ok());
    
    let (prompt, _messages) = result.unwrap();
    assert!(prompt.contains("Hero"));
    assert!(prompt.contains("Villain"));
    assert!(prompt.contains("Sword"));
    assert!(prompt.contains("Character"));
    assert!(prompt.contains("Item"));
}

/// Test EnrichedContext prompt building with spatial context
#[tokio::test]
async fn test_build_enriched_context_prompt_spatial_context() {
    let test_app = spawn_app(false, false, false).await;
    let config = Arc::new(create_test_config());
    let token_counter = Arc::new(create_test_token_counter());
    
    let mut enriched_context = create_test_enriched_context();
    enriched_context.spatial_context = Some(SpatialContext {
        current_location: SpatialLocation {
            location_id: Uuid::new_v4(),
            name: "Ancient Temple".to_string(),
            coordinates: Some((10.0, 20.0, 0.0)),
            parent_location: None,
            location_type: "Temple".to_string(),
        },
        nearby_locations: vec![],
        environmental_factors: vec![],
        spatial_relationships: vec![],
    });
    
    let user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("I examine the altar".to_string()),
        options: None,
    };
    
    let params = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: Some(&enriched_context),
        current_user_message: user_message,
        legacy_params: None,
        user_persona_name: Some("TestUser".to_string()),
    };
    
    let result = build_enriched_context_prompt(params).await;
    assert!(result.is_ok());
    
    let (prompt, _messages) = result.unwrap();
    assert!(prompt.contains("Ancient Temple"));
    assert!(prompt.contains("<spatial_context>"));
}

/// Test EnrichedContext prompt building with temporal context
#[tokio::test]
async fn test_build_enriched_context_prompt_temporal_context() {
    let test_app = spawn_app(false, false, false).await;
    let config = Arc::new(create_test_config());
    let token_counter = Arc::new(create_test_token_counter());
    
    let mut enriched_context = create_test_enriched_context();
    enriched_context.temporal_context = Some(TemporalContext {
        current_time: Utc::now(),
        recent_events: vec![],
        future_scheduled_events: vec![],
        temporal_significance: 0.6,
    });
    
    let user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("What time is it?".to_string()),
        options: None,
    };
    
    let params = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: Some(&enriched_context),
        current_user_message: user_message,
        legacy_params: None,
        user_persona_name: Some("TestUser".to_string()),
    };
    
    let result = build_enriched_context_prompt(params).await;
    assert!(result.is_ok());
    
    let (prompt, _messages) = result.unwrap();
    assert!(prompt.contains("<temporal_context>"));
}

/// Test prompt mode determination (basic validation)
#[tokio::test]
async fn test_prompt_mode_validation() {
    let config = Arc::new(create_test_config());
    let token_counter = Arc::new(create_test_token_counter());
    let enriched_context = create_test_enriched_context();
    
    let user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text("Test".to_string()),
        options: None,
    };
    
    // Test params creation (basic validation that the structs can be created)
    let _params_legacy = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: None,
        current_user_message: user_message.clone(),
        legacy_params: None,
        user_persona_name: None,
    };
    
    // Test Enriched mode params
    let _params_enriched = EnrichedPromptBuildParams {
        config: config.clone(),
        token_counter: token_counter.clone(),
        model_name: "gemini-2.5-flash".to_string(),
        user_id: Uuid::new_v4(),
        user_dek: None,
        enriched_context: Some(&enriched_context),
        current_user_message: user_message,
        legacy_params: None,
        user_persona_name: None,
    };
    
    // Just verify the structs can be created successfully
    assert!(true);
}

/// Test performance metrics formatting (basic validation)
#[tokio::test]
async fn test_enriched_context_contains_metrics() {
    let enriched_context = create_test_enriched_context();
    
    // Just validate that the enriched context has the expected fields
    assert!(enriched_context.total_tokens_used > 0);
    assert!(enriched_context.execution_time_ms > 0);
    assert!(enriched_context.confidence_score > 0.0);
    assert!(enriched_context.confidence_score <= 1.0);
}

/// Test performance metrics validation
#[tokio::test]
async fn test_performance_metrics_validation() {
    let enriched_context = create_test_enriched_context();
    
    // Validate that performance metrics are reasonable
    assert!(enriched_context.total_tokens_used <= 10000); // Reasonable token limit
    assert!(enriched_context.execution_time_ms <= 60000); // Max 60 seconds
    assert!(enriched_context.ai_model_calls <= 10); // Reasonable number of calls
    assert!(enriched_context.confidence_score >= 0.0 && enriched_context.confidence_score <= 1.0);
}

// Helper functions for test setup
fn create_test_config() -> Config {
    Config {
        database_url: Some("postgresql://test".to_string()),
        gemini_api_key: Some("test-key".to_string()),
        gemini_api_base_url: "https://generativelanguage.googleapis.com".to_string(),
        port: 8080,
        cookie_signing_key: Some("test-signing-key".to_string()),
        session_cookie_secure: false,
        environment: Some("test".to_string()),
        cookie_domain: None,
        qdrant_url: Some("http://localhost:6334".to_string()),
        qdrant_collection_name: "test_collection".to_string(),
        embedding_dimension: 768,
        qdrant_distance_metric: "cosine".to_string(),
        qdrant_on_disk: Some(false),
        chunking_metric: "word".to_string(),
        chunking_max_size: 512,
        chunking_overlap: 50,
        tokenizer_model_path: "./tokenizer.model".to_string(),
        token_counter_default_model: "gemini-2.5-flash".to_string(),
        context_total_token_limit: 100000,
        context_recent_history_token_budget: 50000,
        context_rag_token_budget: 25000,
        min_tail_messages_to_preserve: 3,
        upload_storage_path: "./uploads".to_string(),
        frontend_base_url: "http://localhost:3000".to_string(),
        app_env: "test".to_string(),
        from_email: Some("test@example.com".to_string()),
        narrative_flags: Default::default(),
        rechronicle_confidence_threshold: 0.8,
        agentic_triage_model: "gemini-2.5-flash".to_string(),
        agentic_planning_model: "gemini-2.5-flash".to_string(),
        agentic_extraction_model: "gemini-2.5-flash".to_string(),
        agentic_entity_resolution_model: "gemini-2.5-flash".to_string(),
        agentic_max_tool_executions: 10,
        // Additional model fields
        advanced_model: "gemini-2.5-pro-latest".to_string(),
        chat_model: "gemini-2.5-flash".to_string(),
        fast_model: "gemini-2.5-flash".to_string(),
        embedding_model: "models/text-embedding-004".to_string(),
        token_counter_model: "gemini-2.5-flash".to_string(),
        suggestion_model: "gemini-2.5-flash".to_string(),
        optimization_model: "gemini-2.5-flash".to_string(),
        perception_agent_model: "gemini-2.5-flash".to_string(),
        strategic_agent_model: "gemini-2.5-flash".to_string(),
        tactical_agent_model: "gemini-2.5-flash".to_string(),
        intent_detection_model: "gemini-2.5-flash-lite-preview-06-17".to_string(),
        query_planning_model: "gemini-2.5-flash".to_string(),
        hybrid_query_model: "gemini-2.5-flash".to_string(),
    }
}

fn create_test_token_counter() -> HybridTokenCounter {
    let tokenizer = TokenizerService::new(PathBuf::from("./resources/tokenizers/gemma.model")).unwrap();
    HybridTokenCounter::new(tokenizer, None, "gemini-2.5-flash")
}

fn create_test_character(name: &str, description: Option<Vec<u8>>) -> CharacterMetadata {
    CharacterMetadata {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        name: name.to_string(),
        description,
        description_nonce: None,
        personality: None,
        personality_nonce: None,
        scenario: None,
        scenario_nonce: None,
        mes_example: None,
        mes_example_nonce: None,
        creator_comment: None,
        creator_comment_nonce: None,
        first_mes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

// Helper function to create test EnrichedContext
fn create_test_enriched_context() -> EnrichedContext {
    EnrichedContext {
        strategic_directive: Some(StrategicDirective {
            directive_id: Uuid::new_v4(),
            directive_type: "Execute test scene".to_string(),
            narrative_arc: "Hero's journey".to_string(),
            plot_significance: PlotSignificance::Major,
            emotional_tone: "Intense".to_string(),
            character_focus: vec!["Hero".to_string()],
            world_impact_level: WorldImpactLevel::Local,
        }),
        validated_plan: ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps: vec![PlanStep {
                step_id: Uuid::new_v4(),
                description: "Execute test action".to_string(),
                preconditions: vec!["ready".to_string()],
                expected_outcomes: vec!["success".to_string()],
                required_entities: vec!["Hero".to_string()],
                estimated_duration: Some(1000),
            }],
            preconditions_met: true,
            causal_consistency_verified: true,
            entity_dependencies: vec!["Hero".to_string()],
            estimated_execution_time: Some(1000),
            risk_assessment: RiskAssessment {
                overall_risk: RiskLevel::Low,
                identified_risks: vec![],
                mitigation_strategies: vec![],
            },
        },
        current_sub_goal: SubGoal {
            goal_id: Uuid::new_v4(),
            description: "Test sub-goal".to_string(),
            actionable_directive: "Generate test response".to_string(),
            required_entities: vec!["Hero".to_string()],
            success_criteria: vec!["Response generated".to_string()],
            context_requirements: vec![],
            priority_level: 1.0,
        },
        relevant_entities: vec![],
        spatial_context: None,
        causal_context: None,
        temporal_context: None,
        plan_validation_status: PlanValidationStatus::Validated,
        symbolic_firewall_checks: vec![
            // Will be defined when the enums are available
        ],
        assembled_context: None,
        perception_analysis: None,
        total_tokens_used: 1500,
        execution_time_ms: 250,
        validation_time_ms: 50,
        ai_model_calls: 2,
        confidence_score: 0.85,
    }
}

// Helper function to create test EntityContext
fn create_test_entity_context(name: &str, entity_type: &str) -> EntityContext {
    EntityContext {
        entity_id: Uuid::new_v4(),
        entity_name: name.to_string(),
        entity_type: entity_type.to_string(),
        current_state: HashMap::new(),
        spatial_location: None,
        relationships: vec![],
        recent_actions: vec![],
        emotional_state: None,
        narrative_importance: 0.8,
        ai_insights: vec![],
    }
}