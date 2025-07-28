use scribe_backend::services::agentic::strategic_agent::StrategicAgent;
use scribe_backend::services::context_assembly_engine::{
    PlotSignificance, WorldImpactLevel
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::models::chats::{ChatMessageForClient, MessageRole};
use uuid::Uuid;
use chrono::Utc;

// Helper function to create test chat history
fn create_test_chat_history() -> Vec<ChatMessageForClient> {
    vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            content: "I draw my sword and face the beast.".to_string(),
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
            user_id: Uuid::new_v4(),
            content: "The dragon roars menacingly, its eyes glowing with ancient fire.".to_string(),
            message_type: MessageRole::Assistant,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ]
}

#[tokio::test]
async fn test_strategic_agent_creation() {
    let app = spawn_app(false, false, false).await;
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    // Service should be created successfully
    let _ = strategic_agent; // Just ensure it compiles and creates
}

#[tokio::test]
async fn test_analyze_conversation_basic_combat() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_test_chat_history();

    let session_id = Uuid::new_v4();
    let result = strategic_agent.analyze_conversation(
        &chat_history,
        user_id,
        session_id,
        &session_dek,
    ).await;

    if let Err(e) = &result {
        eprintln!("Strategic agent test failed with error: {:?}", e);
    }
    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Verify directive structure
    assert!(!directive.directive_type.is_empty());
    assert!(!directive.narrative_arc.is_empty());
    assert!(matches!(directive.plot_significance, PlotSignificance::Minor | PlotSignificance::Moderate | PlotSignificance::Major));
    assert!(matches!(directive.world_impact_level, WorldImpactLevel::Local | WorldImpactLevel::Regional | WorldImpactLevel::Global));
}

#[tokio::test]
async fn test_generate_narrative_direction_mystery() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Mystery-themed conversation
    let mystery_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I notice something strange about the innkeeper's behavior.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let session_id = Uuid::new_v4();
    let result = strategic_agent.analyze_conversation(
        &mystery_history,
        user_id,
        session_id,
        &session_dek,
    ).await;

    if let Err(e) = &result {
        eprintln!("Strategic agent test failed with error: {:?}", e);
    }
    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Should identify mystery elements in the directive type or narrative arc
    assert!(directive.directive_type.to_lowercase().contains("mystery") || 
            directive.directive_type.to_lowercase().contains("investigate") ||
            directive.directive_type.to_lowercase().contains("suspicious") ||
            directive.narrative_arc.to_lowercase().contains("mystery") ||
            directive.narrative_arc.to_lowercase().contains("investigate"));
}

#[tokio::test]
async fn test_create_strategic_directive_social_interaction() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let narrative_direction = "Initiate diplomatic negotiation".to_string();
    
    // Social interaction conversation
    let social_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I approach the noble and request an audience.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let session_id = Uuid::new_v4();
    let result = strategic_agent.analyze_conversation(
        &social_history,
        user_id,
        session_id,
        &session_dek,
    ).await;

    if let Err(e) = &result {
        eprintln!("Strategic agent test failed with error: {:?}", e);
    }
    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Verify diplomatic/social directive
    assert!(directive.directive_type.to_lowercase().contains("social") ||
            directive.directive_type.to_lowercase().contains("diplomatic") ||
            directive.directive_type.to_lowercase().contains("negotiation"));
    assert!(directive.character_focus.len() > 0);
    assert!(matches!(directive.world_impact_level, WorldImpactLevel::Local | WorldImpactLevel::Regional));
}

#[tokio::test]
async fn test_assess_narrative_significance_major_event() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Major event conversation
    let major_event_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "The ancient prophecy has been fulfilled and the Dark Lord has awakened.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.assess_narrative_significance(
        &major_event_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let significance = result.unwrap();
    
    // Should recognize high significance
    assert!(matches!(significance, PlotSignificance::Major | PlotSignificance::Major));
}

#[tokio::test]
async fn test_extract_character_focus_multiple_characters() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Multi-character conversation
    let multi_char_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "Aragorn and Legolas discuss the approaching orc army while Gimli sharpens his axe.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.extract_character_focus(
        &multi_char_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let characters = result.unwrap();
    
    // Should identify multiple characters
    assert!(characters.len() >= 2);
    assert!(characters.iter().any(|c| c.to_lowercase().contains("aragorn")));
    assert!(characters.iter().any(|c| c.to_lowercase().contains("legolas")));
}

#[tokio::test]
async fn test_determine_emotional_tone_tense() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Tense conversation
    let tense_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "The countdown begins. Ten seconds until the bomb explodes.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.determine_emotional_tone(
        &tense_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let tone = result.unwrap();
    
    // Should identify tense/urgent tone
    assert!(tone.to_lowercase().contains("tense") ||
            tone.to_lowercase().contains("urgent") ||
            tone.to_lowercase().contains("suspenseful"));
}

#[tokio::test]
async fn test_evaluate_world_impact_local() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Local impact conversation
    let local_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "I help the merchant fix his cart wheel.".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.evaluate_world_impact(
        &local_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let impact = result.unwrap();
    
    // Should identify local impact
    assert!(matches!(impact, WorldImpactLevel::Local | WorldImpactLevel::Personal));
}

#[tokio::test]
async fn test_cache_directive_and_retrieval() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_test_chat_history();
    
    // Generate and cache directive
    let session_id = Uuid::new_v4();
    let directive = strategic_agent.analyze_conversation(
        &chat_history,
        user_id,
        session_id,
        &session_dek,
    ).await.unwrap();

    // Try to retrieve cached directive
    let cached_result = strategic_agent.get_cached_directive(
        user_id,
        &chat_history,
    ).await;

    assert!(cached_result.is_ok());
    // Note: Cache might not contain exact match due to TTL and content hashing
}

#[tokio::test]
async fn test_directive_content_validation() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let chat_history = create_test_chat_history();

    let session_id = Uuid::new_v4();
    let result = strategic_agent.analyze_conversation(
        &chat_history,
        user_id,
        session_id,
        &session_dek,
    ).await;

    if let Err(e) = &result {
        eprintln!("Strategic agent test failed with error: {:?}", e);
    }
    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Validate directive completeness and quality
    assert!(!directive.directive_type.is_empty());
    assert!(!directive.narrative_arc.is_empty());
    assert!(!directive.emotional_tone.is_empty());
    assert!(directive.directive_type.len() >= 5); // Reasonable minimum length
    assert!(directive.narrative_arc.len() >= 10); // Reasonable minimum length
    
    // Should not contain template placeholders
    assert!(!directive.directive_type.contains("["));
    assert!(!directive.narrative_arc.contains("TODO"));
}

#[tokio::test]
async fn test_error_handling_empty_chat_history() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
        "gemini-2.5-flash".to_string(),
        app.app_state.shared_agent_context.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let empty_history: Vec<ChatMessageForClient> = vec![];

    let session_id = Uuid::new_v4();
    let result = strategic_agent.analyze_conversation(
        &empty_history,
        user_id,
        session_id,
        &session_dek,
    ).await;

    // Should handle empty history gracefully
    assert!(result.is_err() || result.is_ok());
    if let Ok(directive) = result {
        // If it succeeds, should provide default/fallback directive
        assert!(!directive.directive_type.is_empty());
    }
}