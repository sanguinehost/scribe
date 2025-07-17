#![cfg(test)]
// backend/tests/agentic_event_deduplication_tests.rs

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle::{CreateChronicleRequest},
        chronicle_event::{EventSource, EventFilter, CreateEventRequest},
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
    },
    services::{
        ScribeTool,
        agentic::{
            AgenticNarrativeFactory,
            SearchKnowledgeBaseTool,
        },
        ChronicleService,
    },
    schema::users,
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use secrecy::{SecretBox, ExposeSecret};
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;

/// Helper to create a test user
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek)> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("dedup_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;
    
    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;
    
    let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    
    let new_user = NewUser {
        username,
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
    };
    
    let user_db: UserDbQuery = conn
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));
    Ok((user_db.id, session_dek))
}

/// Helper to create a test chronicle
async fn create_test_chronicle(user_id: Uuid, test_app: &TestApp) -> AnyhowResult<Uuid> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "De-duplication Test Chronicle".to_string(),
        description: Some("Testing event de-duplication".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

/// Helper to create duplicate Everest cleansing messages
fn create_duplicate_everest_messages(user_id: Uuid, session_id: Uuid, session_dek: &SessionDek) -> AnyhowResult<Vec<ChatMessage>> {
    // These messages describe essentially the same Mount Everest cleansing action
    // but with different wording - they should be deduplicated
    let messages_content = vec![
        ("user", "I descend upon Everest and wave my hand, cleansing it of accumulated human filth."),
        ("assistant", "You arrive at Mount Everest's peak. With a gesture, all human debris vanishes, leaving the mountain pristine."),
        ("user", "I use my cosmic powers to remove all pollution from Mount Everest."),
        ("assistant", "Your divine energy sweeps across Everest, dissolving tents, ropes, and waste, restoring its natural state."),
        ("user", "I cleanse Mount Everest of all the garbage left by climbers over the years."), 
        ("assistant", "The mountain is purified by your will, every trace of human contamination eliminated."),
    ];
    
    let mut messages = Vec::new();
    
    for (i, (role, content)) in messages_content.iter().enumerate() {
        let message_role = match *role {
            "user" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            _ => MessageRole::System,
        };
        
        // Encrypt the content
        let (encrypted_content, nonce) = scribe_backend::crypto::encrypt_gcm(
            content.as_bytes(),
            &session_dek.0,
        )?;
        
        messages.push(ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: message_role,
            content: encrypted_content,
            content_nonce: Some(nonce),
            created_at: Utc::now() + chrono::Duration::seconds(i as i64), // Spread across time
            user_id,
            prompt_tokens: Some(30),
            completion_tokens: Some(100),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        });
    }
    
    Ok(messages)
}

/// Helper to create existing chronicle events to test deduplication against
async fn create_existing_everest_events(user_id: Uuid, chronicle_id: Uuid, test_app: &TestApp) -> AnyhowResult<()> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    // Create a few existing events about Mount Everest cleansing
    let existing_events = vec![
        CreateEventRequest {
            event_type: "ENVIRONMENTAL_CLEANSING".to_string(),
            summary: "The user performed a powerful act of cleansing, removing all human pollution and remains from Mount Everest".to_string(),
            event_data: Some(json!({
                "location": "Mount Everest, Himalayas",
                "action": "cleansing",
                "target": "human pollution"
            })),
            source: EventSource::AiExtracted,
            timestamp_iso8601: None,
        },
        CreateEventRequest {
            event_type: "COSMIC_INTERVENTION".to_string(), 
            summary: "The user, now enlightened and possessing vast cosmic powers, descended upon Mount Everest and cleansed it entirely".to_string(),
            event_data: Some(json!({
                "location": "Mount Everest", 
                "method": "cosmic powers",
                "result": "pristine state"
            })),
            source: EventSource::AiExtracted,
            timestamp_iso8601: None,
        },
    ];
    
    for event_request in existing_events {
        chronicle_service
            .create_event(user_id, chronicle_id, event_request, None)
            .await?;
    }
    
    Ok(())
}

#[tokio::test]
async fn test_search_knowledge_base_tool_functionality() {
    // Test that the SearchKnowledgeBaseTool can find existing events
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, _session_dek) = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create some existing events
    create_existing_everest_events(user_id, chronicle_id, &test_app).await.unwrap();
    
    // Wait a bit for events to be indexed (if using vector search)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    
    // Test the search tool
    let search_tool = SearchKnowledgeBaseTool::new(test_app.app_state.clone());
    
    let search_params = json!({
        "query": "Mount Everest cleansing pollution",
        "search_type": "chronicle_events",
        "limit": 10
    });
    
    let search_result = search_tool.execute(&search_params).await.unwrap();
    assert!(search_result.get("results").is_some());
    
    let results = search_result.get("results").unwrap().as_array().unwrap();
    println!("Search tool found {} results for Everest cleansing", results.len());
    
    // The search should find the existing Everest events
    let found_everest_events = results.iter().any(|result| {
        result.get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.contains("Mount Everest") && s.contains("cleans"))
            .unwrap_or(false)
    });
    
    if found_everest_events {
        println!("✅ Search tool successfully found existing Everest events");
    } else {
        println!("❌ Search tool failed to find existing Everest events");
        println!("Search results: {:?}", results);
    }
}

#[tokio::test]
async fn test_deduplication_failure_multiple_everest_events() {
    // This test demonstrates the current de-duplication failure
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create existing events that should prevent duplicates
    create_existing_everest_events(user_id, chronicle_id, &test_app).await.unwrap();
    
    // Create messages that describe the same action again
    let duplicate_messages = create_duplicate_everest_messages(user_id, session_id, &session_dek).unwrap();
    
    // Create a mock AI response for the workflow that marks the events as NOT significant to test deduplication
    let mock_response = json!({
        "is_significant": false,
        "summary": "Duplicate Mount Everest cleansing event - already exists in chronicle",
        "event_category": "WORLD",
        "event_type": "ENVIRONMENTAL_CLEANSING",
        "narrative_action": "CLEANSED",
        "primary_agent": "User",
        "primary_patient": "Mount Everest",
        "confidence": 0.9,
        "reasoning": "This appears to be a duplicate of existing Mount Everest cleansing events already in the chronicle",
        "actions": []
    });

    let mock_ai_client = Arc::new(scribe_backend::test_helpers::MockAiClient::new_with_response(mock_response.to_string()));

    // Create the agentic narrative system
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    
    // Create AppState for the test
    let services = scribe_backend::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
        chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
            test_app.db_pool.clone(),
            encryption_service.clone()
        )),
        user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
            test_app.db_pool.clone(),
            encryption_service.clone()
        )),
        token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
            scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                panic!("Failed to create tokenizer for test")
            }),
            None,
            "gemini-2.5-pro"
        )),
        encryption_service: encryption_service.clone(),
        lorebook_service: lorebook_service.clone(),
        auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
        file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
        email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
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
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
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
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test - properly constructed
        world_model_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
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
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager.clone(),
                rag_service,
                degradation,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            Arc::new(scribe_backend::services::WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager,
                hybrid_query_service,
                chronicle_service,
            ))
        },
        agentic_state_update_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
            ))
        },
        agentic_orchestrator: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
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
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager.clone(),
                rag_service,
                degradation,
            ));
            let agentic_state_update_service = Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
            ));
            Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                test_app.ai_client.clone(),
                hybrid_query_service,
                Arc::new(test_app.db_pool.clone()),
                agentic_state_update_service,
            ))
        },
        hierarchical_context_assembler: None,
        tactical_agent: None,
        strategic_agent: None,
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let agentic_system = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        app_state,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );
    
    // Get initial event count
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let initial_events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .unwrap();
    let initial_count = initial_events.len();
    println!("Initial event count: {}", initial_count);
    
    // Execute the narrative workflow - this should NOT create new events due to deduplication
    let workflow_result = agentic_system
        .process_narrative_event(
            user_id,
            session_id,
            Some(chronicle_id),
            &duplicate_messages,
            &session_dek,
            None, // No persona context
        )
        .await
        .expect("Workflow should complete");
    
    let triage = workflow_result.get("triage").expect("Should have triage section");
    println!("Triage result - significant: {}", triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false));
    
    if let Some(execution) = workflow_result.get("execution") {
        if execution.is_array() {
            println!("Actions taken: {}", execution.as_array().unwrap().len());
        } else {
            println!("Execution result present but not array");
        }
    } else {
        println!("No execution section (likely insignificant)");
    }
    
    // Get final event count
    let final_events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .unwrap();
    let final_count = final_events.len();
    println!("Final event count: {}", final_count);
    
    // Find all Mount Everest related events
    let everest_events: Vec<_> = final_events
        .iter()
        .filter(|event| {
            let content = format!("{} {}", event.event_type, event.summary);
            content.to_lowercase().contains("everest") || 
            content.to_lowercase().contains("mount") ||
            content.to_lowercase().contains("mountain")
        })
        .collect();
    
    println!("Mount Everest related events found: {}", everest_events.len());
    for (i, event) in everest_events.iter().enumerate() {
        println!("  {}: {} - {}", i + 1, event.event_type, event.summary);
    }
    
    // The bug: we expect only 2 events (the initial ones) but likely get more
    if everest_events.len() > 2 {
        println!("❌ DE-DUPLICATION FAILURE: Found {} Everest events, expected 2 or fewer", everest_events.len());
        println!("This demonstrates the de-duplication bug where similar events are not being filtered out.");
        
        // Check for very similar summaries
        let mut similar_pairs = Vec::new();
        for i in 0..everest_events.len() {
            for j in i+1..everest_events.len() {
                let event1 = &everest_events[i];
                let event2 = &everest_events[j];
                
                // Simple similarity check - both contain key terms
                let summary1 = event1.summary.to_lowercase();
                let summary2 = event2.summary.to_lowercase();
                
                let key_terms = ["cleanse", "clean", "mount", "everest", "pollution", "cosmic", "power"];
                let common_terms: Vec<_> = key_terms.iter()
                    .filter(|term| summary1.contains(*term) && summary2.contains(*term))
                    .collect();
                
                if common_terms.len() >= 3 {
                    similar_pairs.push((i, j, common_terms.len()));
                }
            }
        }
        
        if !similar_pairs.is_empty() {
            println!("❌ Found {} pairs of very similar events:", similar_pairs.len());
            for (i, j, common_count) in similar_pairs {
                println!("  Event {} and {} share {} key terms", i+1, j+1, common_count);
                println!("    Event {}: {}", i+1, everest_events[i].summary);
                println!("    Event {}: {}", j+1, everest_events[j].summary);
            }
        }
    } else {
        println!("✅ De-duplication working: Only {} Everest events found", everest_events.len());
    }
}

#[tokio::test]
async fn test_chronicle_context_retrieval_for_deduplication() {
    // Test that the get_recent_chronicle_context method can retrieve existing events
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, _session_dek) = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create existing events
    create_existing_everest_events(user_id, chronicle_id, &test_app).await.unwrap();
    
    // This test would require access to the NarrativeAgentRunner's internal methods
    // For now, we test the chronicle service directly
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .unwrap();
    
    assert!(!events.is_empty(), "Should have existing events for context");
    
    let everest_events: Vec<_> = events
        .iter()
        .filter(|event| event.summary.to_lowercase().contains("everest"))
        .collect();
    
    assert!(!everest_events.is_empty(), "Should have Everest events in context");
    
    println!("✅ Context retrieval test: Found {} total events, {} Everest-related", 
             events.len(), everest_events.len());
    
    // The issue may be that the search/context retrieval isn't finding these events
    // when the AI is making deduplication decisions
}

#[tokio::test]
async fn test_ai_triage_with_existing_context() {
    // Test what happens when we provide existing context to the triage decision
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create existing events
    create_existing_everest_events(user_id, chronicle_id, &test_app).await.unwrap();
    
    // Get the existing events as context
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let existing_events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .unwrap();
    
    // Create new duplicate messages
    let duplicate_messages = create_duplicate_everest_messages(user_id, Uuid::new_v4(), &session_dek).unwrap();
    
    // Format the messages for AI analysis
    let mut conversation_text = String::new();
    for msg in &duplicate_messages {
        let decrypted = if let Some(nonce) = &msg.content_nonce {
            scribe_backend::crypto::decrypt_gcm(&msg.content, nonce, &session_dek.0)
                .map(|secret| secret.expose_secret().clone())
                .unwrap_or_else(|_| b"<decryption failed>".to_vec())
        } else {
            msg.content.clone()
        };
        
        let role = match msg.message_type {
            MessageRole::User => "User",
            MessageRole::Assistant => "Assistant", 
            _ => "System",
        };
        
        conversation_text.push_str(&format!("{}: {}\n", role, String::from_utf8_lossy(&decrypted)));
    }
    
    // Format existing events as context
    let mut context_text = String::new();
    for event in &existing_events {
        context_text.push_str(&format!("- {}: {}\n", event.event_type, event.summary));
    }
    
    // Create a mock AI response for the significance analysis
    let mock_triage_response = json!({
        "is_significant": false,
        "reasoning": "The conversation describes Mount Everest cleansing which is already covered by existing events in the chronicle",
        "confidence": 0.85
    });

    let _mock_ai_client = Arc::new(scribe_backend::test_helpers::MockAiClient::new_with_response(mock_triage_response.to_string()));

    // Test triage with explicit context
    let triage_params = json!({
        "messages": [
            {
                "role": "user", 
                "content": format!("Analyze this conversation for narrative significance, considering existing events:\n\nConversation:\n{}\n\nExisting Events:\n{}\n\nInstruction: Focus on deduplication - if similar events already exist, mark as NOT significant.", conversation_text, context_text)
            }
        ]
    });
    
    let triage_tool = scribe_backend::services::agentic::AnalyzeTextSignificanceTool::new(test_app.app_state.clone());
    let triage_result = triage_tool.execute(&triage_params).await.unwrap();
    
    println!("Triage result with context: {:?}", triage_result);
    
    let is_significant = triage_result.get("is_significant")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    
    if is_significant {
        println!("❌ AI marked duplicate content as significant despite existing context");
        println!("This suggests the deduplication logic in AI prompts needs improvement");
    } else {
        println!("✅ AI correctly identified duplicate content as not significant");
    }
}

// Future test for when deduplication is fixed
// #[tokio::test]
// async fn test_improved_deduplication_prevents_duplicates() {
//     // This test will verify that the fixed deduplication system works
//     let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
//     let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
//     
//     let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
//     let session_id = Uuid::new_v4();
//     let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
//     
//     // Create existing events
//     create_existing_everest_events(user_id, chronicle_id, &test_app).await.unwrap();
//     
//     // Try to create duplicates
//     let duplicate_messages = create_duplicate_everest_messages(user_id, session_id, &session_dek).unwrap();
//     
//     let workflow_result = agentic_system
//         .process_narrative_event_with_improved_deduplication(
//             user_id,
//             session_id,
//             Some(chronicle_id),
//             &duplicate_messages,
//             &session_dek,
//         )
//         .await
//         .expect("Workflow should complete");
//     
//     // Should either be marked as not significant or no new events created
//     assert!(!workflow_result.triage_result.is_significant || workflow_result.execution_results.is_empty());
//     
//     // Verify no new duplicate events were created
//     let final_events = chronicle_service
//         .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
//         .await
//         .unwrap();
//     
//     let everest_events: Vec<_> = final_events
//         .iter()
//         .filter(|event| event.summary.to_lowercase().contains("everest"))
//         .collect();
//     
//     assert_eq!(everest_events.len(), 2, "Should still have only the original 2 Everest events");
// }