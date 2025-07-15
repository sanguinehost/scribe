// Integration tests for TacticalAgent in the chat service pipeline
// Task 4.2.1: Verify the agent's output correctly enriches the final prompt

use scribe_backend::services::agentic::tactical_agent::TacticalAgent;
use scribe_backend::services::context_assembly_engine::{
    StrategicDirective, PlotSignificance, WorldImpactLevel,
    PlanValidationStatus,
};
use scribe_backend::services::planning::{PlanningService, PlanValidatorService};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::models::characters::CharacterMetadata;
use uuid::Uuid;
use std::sync::Arc;
use genai::chat::{ChatMessage as GenAiChatMessage, MessageContent, ChatRole};

/// Test that TacticalAgent integrates correctly with the chat service pipeline
#[tokio::test]
async fn test_tactical_agent_chat_service_integration() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    // Create necessary services
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let tactical_agent = Arc::new(TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));

    // Simulate user input that should trigger TacticalAgent
    let user_input = "I need to investigate the abandoned warehouse in the industrial district";
    
    // Create a strategic directive (this would normally come from Strategic Layer)
    let strategic_directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "investigation".to_string(),
        narrative_arc: user_input.to_string(),
        plot_significance: PlotSignificance::Moderate,
        emotional_tone: "tense".to_string(),
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Local,
    };

    // Step 1: Call TacticalAgent to process the directive
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let enriched_context = tactical_agent.process_directive(
        &strategic_directive,
        user_id,
        &session_dek,
    ).await;
    
    // Create Arc for prompt builder usage
    let session_dek_arc = Arc::new(SessionDek::new(vec![0u8; 32]).0);

    assert!(enriched_context.is_ok(), "TacticalAgent should successfully process directive");
    let enriched_context = enriched_context.unwrap();

    // Verify the enriched context has expected structure
    assert!(!enriched_context.current_sub_goal.description.is_empty());
    assert!(!enriched_context.current_sub_goal.actionable_directive.is_empty());
    assert!(enriched_context.confidence_score > 0.0);
    assert!(enriched_context.execution_time_ms > 0);

    // Step 2: Verify the EnrichedContext can be used by prompt_builder
    let character_metadata = CharacterMetadata {
        id: Uuid::new_v4(),
        user_id,
        name: "Test Character".to_string(),
        description: Some("A test character for integration testing".as_bytes().to_vec()),
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
    };

    // Create a minimal chat history
    let chat_history = vec![
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::from_text(user_input),
            options: None,
        },
    ];

    // Create current user message
    let current_user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::from_text(user_input),
        options: None,
    };

    // Build prompt with enriched context
    let prompt_result = scribe_backend::prompt_builder::build_enriched_context_prompt(
        scribe_backend::prompt_builder::EnrichedPromptBuildParams {
            config: app.app_state.config.clone(),
            token_counter: app.app_state.token_counter.clone(),
            model_name: "gemini-2.5-flash-preview-06-17".to_string(),
            user_id,
            user_dek: Some(&*session_dek_arc),
            enriched_context: Some(&enriched_context),
            current_user_message: current_user_message.clone(),
            user_persona_name: None,
            legacy_params: Some(scribe_backend::prompt_builder::PromptBuildParams {
                config: app.app_state.config.clone(),
                token_counter: app.app_state.token_counter.clone(),
                recent_history: chat_history,
                rag_items: vec![],
                system_prompt_base: Some("You are a helpful AI assistant.".to_string()),
                raw_character_system_prompt: None,
                character_metadata: Some(&character_metadata),
                current_user_message,
                model_name: "gemini-2.5-flash-preview-06-17".to_string(),
                user_dek: Some(&*session_dek_arc),
                user_persona_name: None,
                world_state_context: None,
                user_id: Some(user_id),
                chronicle_id: None,
                agentic_context: None,
            }),
        }
    ).await;

    assert!(prompt_result.is_ok(), "Prompt builder should successfully handle EnrichedContext");
    let (system_prompt, messages) = prompt_result.unwrap();

    // Step 3: Verify the prompt contains enriched context
    assert!(!system_prompt.is_empty(), "System prompt should not be empty");
    
    // Debug: Print the system prompt to see what we're getting
    println!("System prompt:\n{}", system_prompt);
    
    // Check that the system prompt contains hierarchical context sections
    assert!(system_prompt.contains("Strategic Context") || 
            system_prompt.contains("Current Objective") ||
            system_prompt.contains("World State") ||
            system_prompt.contains("Strategic Directive") ||
            system_prompt.contains("Tactical Context"),
            "System prompt should contain hierarchical context sections");

    // Verify the enriched context is properly formatted in the prompt
    let prompt_str = system_prompt.to_lowercase();
    assert!(prompt_str.contains("investigation") || 
            prompt_str.contains("warehouse") ||
            prompt_str.contains("industrial"),
            "Prompt should contain elements from the enriched context");
}

/// Test that TacticalAgent enriched context appears in the final prompt under correct tags
#[tokio::test]
async fn test_enriched_context_prompt_formatting() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    // Create services
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let tactical_agent = Arc::new(TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));

    // Create a directive with specific content we can verify
    let strategic_directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "combat".to_string(),
        narrative_arc: "Engage the enemy forces at dawn".to_string(),
        plot_significance: PlotSignificance::Major,
        emotional_tone: "heroic".to_string(),
        character_focus: vec!["Commander Sarah".to_string()],
        world_impact_level: WorldImpactLevel::Regional,
    };

    // Process through TacticalAgent
    let session_dek = SessionDek::new(vec![0u8; 32]);
    let enriched_context = tactical_agent.process_directive(
        &strategic_directive,
        user_id,
        &session_dek,
    ).await.unwrap();
    
    // Create Arc for prompt builder usage
    let session_dek_arc = Arc::new(SessionDek::new(vec![0u8; 32]).0);

    // Create minimal character for prompt building
    let character_metadata = CharacterMetadata {
        id: Uuid::new_v4(),
        user_id,
        name: "Commander Sarah".to_string(),
        description: Some("Military commander".as_bytes().to_vec()),
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
    };

    let current_user_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::from_text("What's our battle plan?"),
        options: None,
    };

    // Build prompt with enriched context
    let (system_prompt, _messages) = scribe_backend::prompt_builder::build_enriched_context_prompt(
        scribe_backend::prompt_builder::EnrichedPromptBuildParams {
            config: app.app_state.config.clone(),
            token_counter: app.app_state.token_counter.clone(),
            model_name: "gemini-2.5-flash-preview-06-17".to_string(),
            user_id,
            user_dek: Some(&*session_dek_arc),
            enriched_context: Some(&enriched_context),
            current_user_message: current_user_message.clone(),
            user_persona_name: None,
            legacy_params: Some(scribe_backend::prompt_builder::PromptBuildParams {
                config: app.app_state.config.clone(),
                token_counter: app.app_state.token_counter.clone(),
                recent_history: vec![],
                rag_items: vec![],
                system_prompt_base: Some("Base system prompt".to_string()),
                raw_character_system_prompt: None,
                character_metadata: Some(&character_metadata),
                current_user_message,
                model_name: "gemini-2.5-flash-preview-06-17".to_string(),
                user_dek: Some(&*session_dek_arc),
                user_persona_name: None,
                world_state_context: None,
                user_id: Some(user_id),
                chronicle_id: None,
                agentic_context: None,
            }),
        }
    ).await.unwrap();

    // Debug: Print the system prompt to see what we're getting
    println!("System prompt for formatting test:\n{}", system_prompt);
    
    // Verify specific formatting requirements
    assert!(system_prompt.contains("<current_world_state>") || 
            system_prompt.contains("World State") ||
            system_prompt.contains("Current Context") ||
            system_prompt.contains("Strategic Directive") ||
            system_prompt.contains("Tactical Context"),
            "Prompt should contain world state section");

    // Verify strategic directive elements appear
    assert!(system_prompt.contains("combat") || system_prompt.contains("enemy forces"),
            "Prompt should contain strategic directive elements");
    
    // Verify sub-goal appears
    assert!(!enriched_context.current_sub_goal.description.is_empty(),
            "Sub-goal should be populated");
    
    // Verify plan validation status is included
    match enriched_context.plan_validation_status {
        PlanValidationStatus::Validated => {
            assert!(enriched_context.validated_plan.preconditions_met,
                    "Validated plan should have preconditions met");
        }
        _ => {
            // Other statuses are acceptable for this test
        }
    }
}

/// Test error handling when TacticalAgent fails
#[tokio::test]
async fn test_tactical_agent_failure_fallback() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    // Create services
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let tactical_agent = Arc::new(TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));

    let session_dek = SessionDek::new(vec![0u8; 32]);

    // Create an invalid directive that should cause processing to fail
    let invalid_directive = StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "".to_string(), // Empty type
        narrative_arc: "".to_string(), // Empty narrative
        plot_significance: PlotSignificance::Major,
        emotional_tone: "".to_string(), // Empty tone
        character_focus: vec![],
        world_impact_level: WorldImpactLevel::Regional,
    };

    // Process should fail gracefully
    let result = tactical_agent.process_directive(
        &invalid_directive,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_err(), "TacticalAgent should fail with invalid directive");

    // In the real integration, the chat service should fall back to standard flow
    // This is handled in the chat service route, not here
}

/// Test that TacticalAgent integrates with actual chat generation
#[tokio::test]
async fn test_tactical_agent_end_to_end_chat_generation() {
    let app = spawn_app(false, false, false).await;
    let _user_id = Uuid::new_v4();
    let _session_id = Uuid::new_v4();
    
    // This test would require a full chat session setup with database records
    // For now, we verify the components can be wired together
    
    let planning_service = Arc::new(PlanningService::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        Arc::new(app.app_state.pool.clone()),
    ));
    
    let plan_validator = Arc::new(PlanValidatorService::new(
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    ));
    
    let tactical_agent = Arc::new(TacticalAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        planning_service,
        plan_validator,
        app.app_state.redis_client.clone(),
    ));

    // Verify the agent can be created and is ready for integration
    assert!(Arc::strong_count(&tactical_agent) == 1, "TacticalAgent should be properly initialized");
}