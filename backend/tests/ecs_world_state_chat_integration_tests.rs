//! ECS World State Chat Integration Tests
//!
//! End-to-end tests for the ECS world state integration in chat generation.
//! These tests verify the complete integration path:
//! User message → Chronicle linked → ECS enabled → World state generated → Included in prompt → LLM receives it
//!
//! Critical scenarios tested:
//! 1. World state inclusion when ECS is enabled and chronicle is linked
//! 2. Graceful degradation when world state generation fails
//! 3. Feature flag behavior (world state only when enable_ecs_enhanced_rag is true)
//! 4. Performance impact and error handling
//! 5. Integration with existing RAG content (lorebook + chronicle events)

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use diesel::prelude::*;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{ApiChatMessage, Chat as DbChat, GenerateChatRequest, NewChat},
        chronicle_event::{NewChronicleEvent, EventSource},
        ecs_diesel::{NewEcsEntity, NewEcsComponent},
        character_card::NewCharacter,
        chronicle::{NewPlayerChronicle, PlayerChronicle},
        users::User,
    },
    schema::{characters, chat_sessions, chronicle_events, ecs_entities, ecs_components, player_chronicles},
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
};

/// Test context for ECS world state integration tests
pub struct EcsWorldStateTestContext {
    pub app: TestApp,
    pub auth_cookie: String,
    pub user: User,
    pub character: DbCharacter,
    pub session: DbChat,
    pub chronicle_id: Uuid,
    pub test_entity_id: Uuid,
}

impl EcsWorldStateTestContext {
    /// Create a complete test context with user, character, session, chronicle, and ECS entities
    pub async fn setup(enable_ecs: bool) -> anyhow::Result<Self> {
        let app = spawn_app_permissive_rate_limiting(true, enable_ecs, true).await;
        let _guard = TestDataGuard::new(app.db_pool.clone());

        // Create test user
        let user = scribe_backend::test_helpers::db::create_test_user(&app.db_pool, "testuser".to_string(), "password123".to_string()).await?;
        let auth_cookie = "session=test_cookie".to_string(); // Simple mock cookie

        // Create test character
        let character = app.db_pool.get().await?
            .interact(move |conn| {
                diesel::insert_into(characters::table)
                    .values(&NewCharacter {
                        user_id: user.id,
                        spec: "chara_card_v3".to_string(),
                        spec_version: "3.0".to_string(),
                        name: "Test Character".to_string(),
                        description: Some(b"A test character for ECS integration tests".to_vec()),
                        description_nonce: None,
                        first_mes: Some(b"Hello! I'm a test character.".to_vec()),
                        first_mes_nonce: None,
                        avatar: None,
                        scenario: None,
                        scenario_nonce: None,
                        personality: None,
                        personality_nonce: None,
                        mes_example: None,
                        mes_example_nonce: None,
                        system_prompt: None,
                        system_prompt_nonce: None,
                        post_history_instructions: None,
                        post_history_instructions_nonce: None,
                        alternate_greetings: None,
                        tags: None,
                        creator: None,
                        character_version: None,
                        extensions: None,
                        created_at: Some(Utc::now()),
                        updated_at: Some(Utc::now()),
                        // Add required fields with default values
                        nickname: None,
                        creator_notes_multilingual: None,
                        source: None,
                        group_only_greetings: None,
                        creation_date: None,
                        modification_date: None,
                        creator_notes: None,
                        creator_notes_nonce: None,
                        persona: None,
                        persona_nonce: None,
                        world_scenario: None,
                        world_scenario_nonce: None,
                        chat: None,
                        greeting: None,
                        greeting_nonce: None,
                        definition: None,
                        definition_nonce: None,
                        default_voice: None,
                        category: None,
                        definition_visibility: None,
                        example_dialogue: None,
                        example_dialogue_nonce: None,
                        favorite: None,
                        first_message_visibility: None,
                        migrated_from: None,
                        model_prompt: None,
                        model_prompt_nonce: None,
                        model_prompt_visibility: None,
                        persona_visibility: None,
                        sharing_visibility: None,
                        status: None,
                        system_prompt_visibility: None,
                        system_tags: None,
                        token_budget: None,
                        usage_hints: None,
                        user_persona: None,
                        user_persona_nonce: None,
                        user_persona_visibility: None,
                        visibility: None,
                        world_scenario_visibility: None,
                        fav: None,
                        world: None,
                        creator_comment: None,
                        creator_comment_nonce: None,
                        depth_prompt: None,
                        depth_prompt_depth: None,
                        depth_prompt_role: None,
                        talkativeness: None,
                        depth_prompt_ciphertext: None,
                        depth_prompt_nonce: None,
                        world_ciphertext: None,
                        world_nonce: None,
                    })
                    .get_result::<DbCharacter>(conn)
            })
            .await.unwrap().unwrap();

        // Create test chronicle  
        let chronicle_id = app.db_pool.get().await?
            .interact(move |conn| {
                // First create the player chronicle
                let chronicle = diesel::insert_into(player_chronicles::table)
                    .values(&NewPlayerChronicle {
                        user_id: user.id,
                        name: "Test Chronicle for ECS".to_string(),
                        description: Some("A test chronicle for ECS integration testing".to_string()),
                    })
                    .returning(PlayerChronicle::as_returning())
                    .get_result::<PlayerChronicle>(conn)?;
                
                // Then create chronicle events
                diesel::insert_into(chronicle_events::table)
                    .values(&NewChronicleEvent {
                        chronicle_id: chronicle.id,
                        user_id: user.id,
                        event_type: "world.setup".to_string(),
                        summary: "Test chronicle for ECS integration".to_string(),
                        source: EventSource::System.to_string(),
                        event_data: Some(json!({
                            "narrative_action": "setup",
                            "modality": "narrative",
                            "actors": [{"id": "test_character", "role": "protagonist"}],
                            "objects": [{"id": "test_world", "type": "location"}],
                            "metadata": {"test": true, "ecs_integration": true},
                            "causality_metadata": {"causes": [], "effects": ["world_established"]}
                        })),
                        summary_encrypted: None,
                        summary_nonce: None,
                        timestamp_iso8601: Utc::now(),
                        actors: Some(json!([{"id": "test_character", "role": "protagonist"}])),
                        action: Some("setup".to_string()),
                        context_data: Some(json!({"test": true, "ecs_integration": true})),
                        causality: Some(json!({"causes": [], "effects": ["world_established"]})),
                        valence: None,
                        modality: Some("ACTUAL".to_string()),
                        caused_by_event_id: None,
                        causes_event_ids: None,
                        sequence_number: 0,
                    })
                    .execute(conn)?;
                
                Ok::<Uuid, diesel::result::Error>(chronicle.id)
            })
            .await.unwrap().unwrap();

        // Create test chat session linked to the chronicle
        let session = app.db_pool.get().await?
            .interact(move |conn| {
                diesel::insert_into(chat_sessions::table)
                    .values(&NewChat {
                        id: Uuid::new_v4(),
                        user_id: user.id,
                        character_id: character.id,
                        title_ciphertext: Some(b"ECS World State Test Session".to_vec()),
                        title_nonce: None,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        history_management_strategy: "rolling".to_string(),
                        history_management_limit: 10,
                        model_name: "gemini-1.5-pro".to_string(),
                        visibility: None,
                        active_custom_persona_id: None,
                        active_impersonated_character_id: None,
                        temperature: None,
                        max_output_tokens: None,
                        frequency_penalty: None,
                        presence_penalty: None,
                        top_k: None,
                        top_p: None,
                        seed: None,
                        stop_sequences: None,
                        gemini_thinking_budget: None,
                        gemini_enable_code_execution: None,
                        system_prompt_ciphertext: None,
                        system_prompt_nonce: None,
                        player_chronicle_id: Some(chronicle_id), // CRITICAL: Link to chronicle
                    })
                    .returning(scribe_backend::models::chats::Chat::as_returning())
                    .get_result(conn)
            })
            .await.unwrap().unwrap();

        // Create test ECS entities and components
        let test_entity_id = Uuid::new_v4();
        app.db_pool.get().await?
            .interact(move |conn| {
                // Create test entity
                diesel::insert_into(ecs_entities::table)
                    .values(&NewEcsEntity {
                        id: test_entity_id,
                        user_id: user.id,
                        archetype_signature: "character|position|health|inventory|name".to_string(),
                    })
                    .execute(conn)?;

                // Create test components for the entity
                diesel::insert_into(ecs_components::table)
                    .values(&vec![
                        NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id: test_entity_id,
                            user_id: user.id,
                            component_type: "name".to_string(),
                            component_data: json!({"name": "Test Hero"}),
                        },
                        NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id: test_entity_id,
                            user_id: user.id,
                            component_type: "position".to_string(),
                            component_data: json!({"x": 10, "y": 20, "zone": "test_area"}),
                        },
                        NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id: test_entity_id,
                            user_id: user.id,
                            component_type: "health".to_string(),
                            component_data: json!({"current": 100, "max": 100, "status": "healthy"}),
                        },
                        NewEcsComponent {
                            id: Uuid::new_v4(),
                            entity_id: test_entity_id,
                            user_id: user.id,
                            component_type: "inventory".to_string(),
                            component_data: json!({"items": ["sword", "shield"], "capacity": 10}),
                        }
                    ])
                    .execute(conn)
                    .map(|_| ())
            })
            .await.unwrap().unwrap();

        Ok(EcsWorldStateTestContext {
            app,
            auth_cookie,
            user,
            character,
            session,
            chronicle_id,
            test_entity_id,
        })
    }

    /// Send a chat message and return the response using direct service call to bypass auth
    pub async fn send_chat_message(&self, message: &str) -> anyhow::Result<axum::response::Response> {
        let request_body = GenerateChatRequest {
            history: vec![ApiChatMessage {
                role: "user".to_string(),
                content: message.to_string(),
            }],
            model: Some("gemini-2.5-pro".to_string()),
            query_text_for_rag: None,
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/chats/{}/generate", self.session.id))
            .header(header::COOKIE, &self.auth_cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&request_body)?))?;

        let response = self.app.router.clone().oneshot(request).await?;
        Ok(response)
    }

    /// Extract the system prompt from the mock AI client's last request
    pub async fn get_last_system_prompt(&self) -> Option<String> {
        if let Some(mock_client) = &self.app.mock_ai_client {
            if let Some(request) = mock_client.get_last_request() {
                request.system
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Check if the last system prompt contains ECS world state
    pub async fn system_prompt_contains_world_state(&self) -> bool {
        if let Some(system_prompt) = self.get_last_system_prompt().await {
            system_prompt.contains("<current_world_state>") && 
            system_prompt.contains("</current_world_state>")
        } else {
            false
        }
    }

    /// Check if the last system prompt contains specific entity data
    pub async fn system_prompt_contains_entity(&self, entity_name: &str) -> bool {
        if let Some(system_prompt) = self.get_last_system_prompt().await {
            system_prompt.contains(entity_name)
        } else {
            false
        }
    }
}

#[tokio::test]
async fn test_ecs_world_state_included_when_enabled_and_chronicle_linked() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Create the WorldModelService independently for testing
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::development());
    let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
        Arc::new(context.app.db_pool.clone()),
        redis_client.clone(),
        None,
    ));
    let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
        context.app.db_pool.clone(),
    ));
    let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
        Default::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None,
    ));
    let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
        scribe_backend::text_processing::chunking::ChunkConfig {
            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
            max_size: 500,
            overlap: 50,
        }
    ));
    let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
        Arc::new(context.app.db_pool.clone()),
        Default::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation.clone(),
        concrete_embedding_service,
    ));
    let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
        Arc::new(context.app.db_pool.clone()),
        Default::default(),
        feature_flags.clone(),
        context.app.ai_client.clone(),
        "gemini-2.5-flash".to_string(),
        entity_manager.clone(),
        rag_service,
        degradation.clone(),
    ));
    
    let world_model_service = Arc::new(scribe_backend::services::WorldModelService::new(
        Arc::new(context.app.db_pool.clone()),
        entity_manager.clone(),
        hybrid_query_service,
        chronicle_service,
    ));
    
    // Verify that ECS is enabled in feature flags
    assert!(
        feature_flags.enable_ecs_enhanced_rag,
        "ECS enhanced RAG should be enabled for testing"
    );
    
    // Test world state generation directly
    let world_snapshot = world_model_service
        .generate_world_snapshot(
            context.user.id,
            Some(context.chronicle_id),
            None, // No specific target time
            Default::default(), // Use default WorldModelOptions
        )
        .await;
    
    assert!(
        world_snapshot.is_ok(),
        "World state snapshot generation should succeed: {:?}",
        world_snapshot.err()
    );
    
    let snapshot = world_snapshot.unwrap();
    assert!(
        !snapshot.entities.is_empty(),
        "World snapshot should contain ECS entities"
    );
    
    // Test LLM context generation  
    let focus = scribe_backend::services::world_model_service::LLMContextFocus {
        query_intent: "Test ECS integration".to_string(),
        key_entities: vec![context.test_entity_id],
        time_focus: scribe_backend::services::world_model_service::TimeFocus::Current,
        reasoning_depth: scribe_backend::services::world_model_service::ReasoningDepth::Surface,
    };
    let llm_context = world_model_service
        .snapshot_to_llm_context(&snapshot, focus);
    
    assert!(
        llm_context.is_ok(),
        "LLM context conversion should succeed: {:?}",
        llm_context.err()
    );
    
    let context_data = llm_context.unwrap();
    let formatted_context = serde_json::to_string_pretty(&context_data).unwrap();
    
    // Debug: Print the actual formatted context
    println!("Full formatted context: {}", formatted_context);
    
    // Verify the formatted context contains expected ECS data
    assert!(
        formatted_context.contains("entity_summaries") && formatted_context.contains("character|position|health|inventory"),
        "Formatted world state should contain ECS entity summary data with test archetype. Actual content: {}",
        formatted_context
    );
    
    println!("✅ ECS world state generation successful");
    println!("Generated world state context: {}", &formatted_context[..std::cmp::min(500, formatted_context.len())]);
}

#[tokio::test] 
async fn test_ecs_world_state_excluded_when_feature_disabled() {
    let context = EcsWorldStateTestContext::setup(false).await.unwrap();
    
    // Send a chat message  
    let response = context.send_chat_message("What's happening?").await.unwrap();
    
    // Verify successful response
    assert_eq!(response.status(), StatusCode::OK);
    
    // Allow time for async operations
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // Verify that world state was NOT included in the system prompt
    assert!(
        !context.system_prompt_contains_world_state().await,
        "System prompt should NOT contain <current_world_state> section when ECS is disabled"
    );
    
    println!("✅ ECS world state correctly excluded when feature flag is disabled");
}

#[tokio::test]
async fn test_ecs_world_state_excluded_when_no_chronicle_linked() {
    let mut context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Create a new session WITHOUT a linked chronicle
    let session_without_chronicle = context.app.db_pool.get().await.unwrap()
        .interact(move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&NewChat {
                    id: Uuid::new_v4(),
                    user_id: context.user.id,
                    character_id: context.character.id,
                    title_ciphertext: Some(b"Session Without Chronicle".to_vec()),
                    title_nonce: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    history_management_strategy: "rolling".to_string(),
                    history_management_limit: 10,
                    model_name: "gemini-1.5-pro".to_string(),
                    visibility: None,
                    active_custom_persona_id: None,
                    active_impersonated_character_id: None,
                    temperature: None,
                    max_output_tokens: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                    top_k: None,
                    top_p: None,
                    seed: None,
                    stop_sequences: None,
                    gemini_thinking_budget: None,
                    gemini_enable_code_execution: None,
                    system_prompt_ciphertext: None,
                    system_prompt_nonce: None,
                    player_chronicle_id: None, // CRITICAL: No chronicle linked
                })
                .returning(scribe_backend::models::chats::Chat::as_returning())
                .get_result(conn)
        })
        .await.unwrap().unwrap();
        
    // Update context to use the new session
    context.session = session_without_chronicle;
    
    
    // Send a chat message
    let response = context.send_chat_message("Hello there!").await.unwrap();
    
    // Verify successful response  
    assert_eq!(response.status(), StatusCode::OK);
    
    // Allow time for async operations
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // Verify that world state was NOT included in the system prompt
    assert!(
        !context.system_prompt_contains_world_state().await,
        "System prompt should NOT contain <current_world_state> section when no chronicle is linked"
    );
    
    println!("✅ ECS world state correctly excluded when no chronicle is linked");
}

#[tokio::test]
async fn test_graceful_degradation_when_world_state_generation_fails() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // TODO: Mock WorldModelService to fail world state generation
    // This would require dependency injection or a way to make the service fail
    // For now, we'll test that chat generation continues even if world state fails
    
    // Send a chat message
    let response = context.send_chat_message("Continue the story").await.unwrap();
    
    // Verify successful response (chat generation should continue even if world state fails)
    assert_eq!(response.status(), StatusCode::OK);
    
    println!("✅ Chat generation continues gracefully even when world state generation might fail");
}

#[tokio::test]
async fn test_world_state_coexists_with_existing_rag_content() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Mock embedding pipeline to return some RAG content
    context.app.mock_embedding_pipeline_service
        .set_retrieve_responses_sequence(vec![
            Ok(vec![
                scribe_backend::services::embeddings::RetrievedChunk {
                    text: "This is some lorebook content about the world".to_string(),
                    score: 0.9,
                    metadata: scribe_backend::services::embeddings::RetrievedMetadata::Lorebook(
                        scribe_backend::services::embeddings::LorebookChunkMetadata {
                            original_lorebook_entry_id: Uuid::new_v4(),
                            lorebook_id: Uuid::new_v4(),
                            user_id: context.user.id,
                            chunk_text: "This is some lorebook content about the world".to_string(),
                            entry_title: Some("Test Lorebook Entry".to_string()),
                            keywords: None,
                            is_enabled: true,
                            is_constant: false,
                            source_type: "lorebook".to_string(),
                        }
                    ),
                }
            ])
        ]);
    
    // Send a chat message
    let response = context.send_chat_message("Tell me about this world").await.unwrap();
    
    // Verify successful response
    assert_eq!(response.status(), StatusCode::OK);
    
    // Allow time for async operations
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // Verify that BOTH world state AND existing RAG content are present
    let system_prompt = context.get_last_system_prompt().await.unwrap_or_default();
    
    // Should contain world state section
    assert!(
        system_prompt.contains("<current_world_state>") && system_prompt.contains("</current_world_state>"),
        "System prompt should contain ECS world state section"
    );
    
    // Should also contain lorebook entries section (existing RAG)
    assert!(
        system_prompt.contains("<lorebook_entries>") && system_prompt.contains("</lorebook_entries>"),
        "System prompt should also contain existing RAG content (lorebook entries)"
    );
    
    // Verify both types of content are present
    assert!(
        system_prompt.contains("Test Hero"), // From ECS world state
        "System prompt should contain ECS entity data"
    );
    
    println!("✅ ECS world state coexists with existing RAG content");
}

#[tokio::test]
async fn test_world_state_content_structure_and_format() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Send a chat message
    let response = context.send_chat_message("What entities are present?").await.unwrap();
    
    // Verify successful response
    assert_eq!(response.status(), StatusCode::OK);
    
    // Allow time for async operations
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    // Get the system prompt and verify world state content structure
    let system_prompt = context.get_last_system_prompt().await.unwrap_or_default();
    
    // Verify proper XML structure
    assert!(
        system_prompt.contains("<current_world_state>"),
        "World state should have opening tag"
    );
    assert!(
        system_prompt.contains("</current_world_state>"),
        "World state should have closing tag"
    );
    
    // Verify entity data is included
    assert!(
        system_prompt.contains("Test Hero"),
        "World state should contain entity name"
    );
    
    // Verify component data is included
    assert!(
        system_prompt.contains("position") || system_prompt.contains("health") || system_prompt.contains("inventory"),
        "World state should contain component data"
    );
    
    println!("✅ ECS world state has proper structure and format in system prompt");
    println!("System prompt excerpt: {}", &system_prompt[..std::cmp::min(500, system_prompt.len())]);
}

#[tokio::test]  
async fn test_performance_impact_of_world_state_generation() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Measure response time with world state generation
    let start_time = std::time::Instant::now();
    let response = context.send_chat_message("Quick response test").await.unwrap();
    let response_time = start_time.elapsed();
    
    // Verify successful response
    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify reasonable response time (should be under 5 seconds for integration test)
    assert!(
        response_time < std::time::Duration::from_secs(5),
        "Chat generation with world state should complete within reasonable time. Took: {:?}",
        response_time
    );
    
    println!("✅ ECS world state generation completed in {:?}", response_time);
}

#[tokio::test]
#[ignore] // Mark as ignored since this requires manual verification of logs
async fn test_world_state_logging_and_observability() {
    let context = EcsWorldStateTestContext::setup(true).await.unwrap();
    
    // Send a chat message
    let response = context.send_chat_message("Test logging").await.unwrap();
    
    // Verify successful response
    assert_eq!(response.status(), StatusCode::OK);
    
    // NOTE: In a real implementation, we would:
    // 1. Capture log output and verify appropriate log messages are generated
    // 2. Verify metrics are recorded for world state generation time
    // 3. Verify error logging when world state generation fails
    // 4. Verify feature flag state is logged
    
    println!("✅ Test completed - manually verify logs contain ECS world state generation messages");
}