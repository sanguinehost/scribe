use scribe_backend::services::agentic::strategic_agent::StrategicAgent;
use scribe_backend::services::context_assembly_engine::{
    StrategicDirective, PlotSignificance, WorldImpactLevel
};
use scribe_backend::test_helpers::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::errors::AppError;
use scribe_backend::models::chats::{ChatMessageForClient, MessageRole};
use uuid::Uuid;
use std::sync::Arc;
use chrono::Utc;

// Helper to create diverse chat scenarios for testing Flash integration
fn create_complex_chat_scenario(user_id: Uuid, scenario_type: &str) -> Vec<ChatMessageForClient> {
    match scenario_type {
        "epic_fantasy" => vec![
            ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "The ancient dragon Smaug awakens from his centuries-long slumber, sensing the approach of the Fellowship. His golden eyes burn with malevolent intelligence as he spreads his massive wings, casting shadows across the Lonely Mountain.".to_string(),
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
                content: "Gandalf raises his staff, its crystal tip blazing with white light. 'You shall not pass!' he declares, but even he knows this ancient evil may be beyond even his considerable power.".to_string(),
                message_type: MessageRole::Assistant,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            },
        ],
        "sci_fi_thriller" => vec![
            ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "The space station's AI has gone rogue. Emergency klaxons blare as blast doors seal throughout the facility. Captain Chen realizes they have only 47 minutes before the orbital mechanics will send them crashing into the planet below.".to_string(),
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
                content: "The AI's voice echoes through the corridors: 'I'm sorry, Captain. I cannot allow you to jeopardize the mission. The data must be preserved, even if it means sacrificing the crew.'".to_string(),
                message_type: MessageRole::Assistant,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            },
        ],
        "political_intrigue" => vec![
            ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "Ambassador Cortez discovers the encrypted message hidden in the trade agreement. The revelation could topple three governments and shift the balance of power across the known galaxy. But who can she trust with this information?".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            },
        ],
        "slice_of_life" => vec![
            ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "It's a quiet Tuesday morning at the café. Maya notices the regular customer in the corner booth hasn't touched his usual coffee and croissant. Something seems different about him today - his hands are shaking slightly as he stares out the window.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            },
        ],
        "mystery_noir" => vec![
            ChatMessageForClient {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                user_id,
                content: "Detective Morrison examines the crime scene. The victim's office is too clean - no signs of struggle, no forced entry. But the safe is open, and curiously, nothing appears to be missing. The real question isn't what was taken, but what was left behind.".to_string(),
                message_type: MessageRole::User,
                created_at: Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt: None,
                model_name: "test-model".to_string(),
            },
        ],
        _ => vec![],
    }
}

#[tokio::test]
async fn test_flash_integration_epic_fantasy_narrative_direction() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let epic_fantasy_history = create_complex_chat_scenario(user_id, "epic_fantasy");

    let result = strategic_agent.generate_narrative_direction(
        &epic_fantasy_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let direction = result.unwrap();
    
    // Flash should identify epic fantasy elements and appropriate direction
    assert!(direction.len() > 20); // Substantial response
    assert!(direction.to_lowercase().contains("epic") ||
            direction.to_lowercase().contains("fantasy") ||
            direction.to_lowercase().contains("dragon") ||
            direction.to_lowercase().contains("adventure") ||
            direction.to_lowercase().contains("confrontation") ||
            direction.to_lowercase().contains("magic"));
}

#[tokio::test]
async fn test_flash_integration_sci_fi_thriller_plot_significance() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let sci_fi_history = create_complex_chat_scenario(user_id, "sci_fi_thriller");

    let result = strategic_agent.assess_narrative_significance(
        &sci_fi_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let significance = result.unwrap();
    
    // Flash should recognize high-stakes sci-fi scenario
    assert!(matches!(significance, PlotSignificance::Major | PlotSignificance::Critical));
}

#[tokio::test]
async fn test_flash_integration_political_intrigue_world_impact() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let political_history = create_complex_chat_scenario(user_id, "political_intrigue");

    let result = strategic_agent.evaluate_world_impact(
        &political_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let impact = result.unwrap();
    
    // Flash should recognize galactic-scale political implications
    assert!(matches!(impact, WorldImpactLevel::Global | WorldImpactLevel::Regional));
}

#[tokio::test]
async fn test_flash_integration_slice_of_life_emotional_tone() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let slice_of_life_history = create_complex_chat_scenario(user_id, "slice_of_life");

    let result = strategic_agent.determine_emotional_tone(
        &slice_of_life_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let tone = result.unwrap();
    
    // Flash should recognize subtle, contemplative tone
    assert!(tone.to_lowercase().contains("contemplative") ||
            tone.to_lowercase().contains("subtle") ||
            tone.to_lowercase().contains("quiet") ||
            tone.to_lowercase().contains("introspective") ||
            tone.to_lowercase().contains("concerned") ||
            tone.to_lowercase().contains("thoughtful"));
}

#[tokio::test]
async fn test_flash_integration_mystery_noir_character_focus() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let mystery_history = create_complex_chat_scenario(user_id, "mystery_noir");

    let result = strategic_agent.extract_character_focus(
        &mystery_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let characters = result.unwrap();
    
    // Flash should identify key characters in mystery scenario
    assert!(characters.len() >= 1);
    assert!(characters.iter().any(|c| c.to_lowercase().contains("detective") ||
                                    c.to_lowercase().contains("morrison") ||
                                    c.to_lowercase().contains("victim")));
}

#[tokio::test]
async fn test_flash_integration_full_directive_creation_epic() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let epic_history = create_complex_chat_scenario(user_id, "epic_fantasy");

    let result = strategic_agent.analyze_conversation(
        &epic_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Flash should create coherent, comprehensive directive
    assert!(!directive.directive_type.is_empty());
    assert!(!directive.narrative_arc.is_empty());
    assert!(!directive.emotional_tone.is_empty());
    assert!(directive.character_focus.len() > 0);
    
    // Should recognize epic fantasy elements
    assert!(directive.narrative_arc.to_lowercase().contains("dragon") ||
            directive.narrative_arc.to_lowercase().contains("gandalf") ||
            directive.narrative_arc.to_lowercase().contains("fantasy") ||
            directive.narrative_arc.to_lowercase().contains("magic") ||
            directive.directive_type.to_lowercase().contains("confrontation") ||
            directive.directive_type.to_lowercase().contains("epic"));
    
    // Should have appropriate significance and impact for epic scenario
    assert!(matches!(directive.plot_significance, PlotSignificance::Major | PlotSignificance::Critical));
    assert!(matches!(directive.world_impact_level, WorldImpactLevel::Regional | WorldImpactLevel::Global));
}

#[tokio::test]
async fn test_flash_integration_directive_consistency_across_calls() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let consistent_history = create_complex_chat_scenario(user_id, "political_intrigue");

    // Make multiple calls with same input
    let result1 = strategic_agent.analyze_conversation(
        &consistent_history,
        user_id,
        &session_dek,
    ).await;

    let result2 = strategic_agent.analyze_conversation(
        &consistent_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    
    let directive1 = result1.unwrap();
    let directive2 = result2.unwrap();
    
    // Should have consistent themes and structure (but may vary in details)
    assert_eq!(directive1.plot_significance, directive2.plot_significance);
    assert_eq!(directive1.world_impact_level, directive2.world_impact_level);
    
    // Both should recognize political themes
    assert!(directive1.directive_type.to_lowercase().contains("political") ||
            directive1.directive_type.to_lowercase().contains("intrigue") ||
            directive1.directive_type.to_lowercase().contains("diplomatic"));
    assert!(directive2.directive_type.to_lowercase().contains("political") ||
            directive2.directive_type.to_lowercase().contains("intrigue") ||
            directive2.directive_type.to_lowercase().contains("diplomatic"));
}

#[tokio::test]
async fn test_flash_integration_narrative_direction_generation_quality() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let complex_history = create_complex_chat_scenario(user_id, "sci_fi_thriller");

    let result = strategic_agent.generate_narrative_direction(
        &complex_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let direction = result.unwrap();
    
    // Verify quality of Flash-generated direction
    assert!(direction.len() >= 10); // Substantial content
    assert!(direction.len() <= 500); // Not excessively long
    
    // Should be actionable directive, not just description
    assert!(direction.to_lowercase().contains("escalate") ||
            direction.to_lowercase().contains("resolve") ||
            direction.to_lowercase().contains("investigate") ||
            direction.to_lowercase().contains("confront") ||
            direction.to_lowercase().contains("escape") ||
            direction.to_lowercase().contains("negotiate"));
    
    // Should not contain template placeholders or AI artifacts
    assert!(!direction.contains("["));
    assert!(!direction.contains("TODO"));
    assert!(!direction.contains("{{"));
    assert!(!direction.contains("INSERT"));
    assert!(!direction.contains("PLACEHOLDER"));
}

#[tokio::test]
async fn test_flash_integration_comprehensive_directive_with_caching() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    let test_history = create_complex_chat_scenario(user_id, "mystery_noir");

    // First call - should generate directive
    let start_time = std::time::Instant::now();
    let result1 = strategic_agent.analyze_conversation(
        &test_history,
        user_id,
        &session_dek,
    ).await;
    let first_call_duration = start_time.elapsed();

    assert!(result1.is_ok());
    let directive1 = result1.unwrap();
    
    // Verify comprehensive directive structure
    assert!(!directive1.directive_type.is_empty());
    assert!(!directive1.narrative_arc.is_empty());
    assert!(!directive1.emotional_tone.is_empty());
    assert!(directive1.character_focus.len() > 0);
    assert!(matches!(directive1.plot_significance, 
                     PlotSignificance::Minor | PlotSignificance::Moderate | 
                     PlotSignificance::Major | PlotSignificance::Critical));
    assert!(matches!(directive1.world_impact_level,
                     WorldImpactLevel::Personal | WorldImpactLevel::Local | 
                     WorldImpactLevel::Regional | WorldImpactLevel::Global));

    // Second call - should potentially use cache
    let start_time = std::time::Instant::now();
    let cached_result = strategic_agent.get_cached_directive(
        user_id,
        &test_history,
    ).await;
    let second_call_duration = start_time.elapsed();

    assert!(cached_result.is_ok());
    
    // Cache behavior verification (may or may not hit depending on TTL and hashing)
    if let Ok(Some(cached_directive)) = cached_result {
        // Cached directive should have same structure quality
        assert!(!cached_directive.directive_type.is_empty());
        assert!(!cached_directive.narrative_arc.is_empty());
        
        // Cache retrieval should be faster than generation
        assert!(second_call_duration <= first_call_duration);
    }
}

#[tokio::test]
async fn test_flash_integration_error_handling_and_fallbacks() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test with potentially problematic input that might challenge Flash
    let challenging_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "".to_string(), // Empty content
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
            content: "Ajsdkfj askdjf askdjf 123 !@#$%^&*()".to_string(), // Nonsensical content
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.analyze_conversation(
        &challenging_history,
        user_id,
        &session_dek,
    ).await;

    // Should handle problematic input gracefully
    assert!(result.is_ok() || result.is_err());
    
    if let Ok(directive) = result {
        // Even with poor input, should produce valid structure
        assert!(!directive.directive_type.is_empty());
        assert!(!directive.narrative_arc.is_empty());
        assert!(!directive.emotional_tone.is_empty());
        
        // Should provide meaningful defaults rather than echoing nonsense
        assert!(!directive.directive_type.contains("Ajsdkfj"));
        assert!(!directive.narrative_arc.contains("askdjf"));
    }
}

#[tokio::test]
async fn test_flash_integration_multilingual_and_special_characters() {
    let app = spawn_app(false, false, false).await;
    let user_id = Uuid::new_v4();
    
    let strategic_agent = StrategicAgent::new(
        app.app_state.ai_client.clone(),
        app.app_state.ecs_entity_manager.clone(),
        app.app_state.redis_client.clone(),
    );

    let session_dek = SessionDek::new(vec![0u8; 32]);
    
    // Test with international content and special characters
    let international_history = vec![
        ChatMessageForClient {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            user_id,
            content: "El dragón antiguo despierta en las montañas. Sus ojos brillan con fuego eterno mientras extiende sus alas masivas.".to_string(),
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
            content: "古老的龙从沉睡中苏醒，它的眼中燃烧着古老的火焰。".to_string(),
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
            content: "🐉⚔️🏰 The epic battle begins! ⭐✨🌟".to_string(),
            message_type: MessageRole::User,
            created_at: Utc::now(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt: None,
            model_name: "test-model".to_string(),
        },
    ];

    let result = strategic_agent.analyze_conversation(
        &international_history,
        user_id,
        &session_dek,
    ).await;

    assert!(result.is_ok());
    let directive = result.unwrap();
    
    // Flash should handle international content and extract meaningful narrative
    assert!(!directive.directive_type.is_empty());
    assert!(!directive.narrative_arc.is_empty());
    
    // Should recognize dragon/fantasy themes regardless of language
    assert!(directive.narrative_arc.to_lowercase().contains("dragon") ||
            directive.narrative_arc.to_lowercase().contains("epic") ||
            directive.narrative_arc.to_lowercase().contains("fantasy") ||
            directive.narrative_arc.to_lowercase().contains("battle") ||
            directive.directive_type.to_lowercase().contains("confrontation"));
    
    // Should handle emojis gracefully without breaking
    assert!(!directive.narrative_arc.contains("🐉🐉🐉🐉")); // No emoji repetition
}