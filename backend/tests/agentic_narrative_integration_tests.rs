#![cfg(test)]
// backend/tests/agentic_narrative_integration_tests.rs

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle::{CreateChronicleRequest},
        chronicle_event::{EventSource, EventFilter},
        users::{NewUser, UserRole, AccountStatus, SerializableSecretDek, UserDbQuery},
    },
    services::{
        agentic::{
            AgenticNarrativeFactory,
            AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
            CreateChronicleEventTool, SearchKnowledgeBaseTool, ScribeTool,
        },
        ChronicleService, LorebookService,
    },
    schema::users,
    test_helpers::{TestDataGuard, TestApp, spawn_app_permissive_rate_limiting},
};
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use secrecy::{SecretString, SecretBox, ExposeSecret};
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;
use hex;

/// Helper to create a test user in the database
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek)> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("agentic_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys following the working pattern
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

/// Helper to create test chat messages with realistic roleplay content
fn create_roleplay_messages(user_id: Uuid, session_id: Uuid, session_dek: &SessionDek) -> AnyhowResult<Vec<ChatMessage>> {
    let messages_content = vec![
        ("user", "I approach the ancient temple, looking for signs of the lost artifact."),
        ("assistant", "As you step through the crumbling doorway, you notice intricate carvings depicting a forgotten god named Valdris. The air feels heavy with ancient magic."),
        ("user", "I examine the carvings more closely and search for any hidden mechanisms."),
        ("assistant", "Your investigation reveals a hidden compartment behind Valdris's eye. Inside, you discover the Shard of Eternity, a crystal that pulses with otherworldly light. Suddenly, the temple guardian - a stone golem - awakens!"),
        ("user", "I grab the shard and prepare to fight the golem!"),
        ("assistant", "The golem attacks with crushing fists, but you manage to defeat it using the shard's power. The temple begins to collapse as you escape with your prize."),
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
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(20),
            completion_tokens: Some(50),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        });
    }
    
    Ok(messages)
}

/// Helper to create a test chronicle
async fn create_test_chronicle(user_id: Uuid, test_app: &TestApp) -> AnyhowResult<Uuid> {
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    let create_request = CreateChronicleRequest {
        name: "Test Adventure Chronicle".to_string(),
        description: Some("A chronicle for testing the agentic narrative system".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

/// Helper to get first available lorebook for user (or skip if none)
async fn get_test_lorebook(_user_id: Uuid, _test_app: &TestApp) -> AnyhowResult<Option<Uuid>> {
    // For testing, we'll skip lorebook retrieval since it requires auth session
    // In a real integration, the agentic system would create lorebooks as needed
    Ok(None)
}

/*
#[tokio::test]
#[ignore] // Requires real AI calls - run with RUN_INTEGRATION_TESTS=true
async fn test_agentic_narrative_end_to_end_real_ai() {
    // This test validates the complete agentic workflow with real AI calls
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Setup test data
    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    let _lorebook_id = get_test_lorebook(user_id, &test_app).await.unwrap();
    
    // Create realistic roleplay messages
    let messages = create_roleplay_messages(user_id, session_id, &session_dek).unwrap();
    
    // Use the test app's existing app_state
    let app_state = test_app.app_state.clone();

    // Create the agentic narrative system with development config
    let agentic_system = AgenticNarrativeFactory::create_system(
        test_app.ai_client.clone(),
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        Arc::new(LorebookService::new(
            test_app.db_pool.clone(),
            test_app.app_state.encryption_service.clone(),
            test_app.qdrant_service.clone(),
        )),
        app_state,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );
    
    // Execute the complete agentic workflow
    let workflow_result = agentic_system
        .process_narrative_event(
            user_id,
            session_id,
            Some(chronicle_id),
            &messages,
            &session_dek,
        )
        .await
        .expect("Agentic workflow should complete successfully");
    
    // Validate the triage result
    assert!(workflow_result.triage_result.is_significant, "The roleplay conversation should be deemed significant");
    assert!(workflow_result.triage_result.confidence > 0.5, "Confidence should be reasonably high");
    
    // Validate that actions were planned and executed
    assert!(!workflow_result.actions_taken.is_empty(), "The agent should have planned at least one action");
    assert_eq!(
        workflow_result.actions_taken.len(),
        workflow_result.execution_results.len(),
        "All planned actions should have execution results"
    );
    
    // Check that at least one action was successful
    let successful_executions = workflow_result
        .execution_results
        .iter()
        .filter(|result| result.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    
    assert!(successful_executions > 0, "At least one tool execution should be successful");
    
    // Validate that chronicle events were actually created in the database
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .expect("Should be able to retrieve events");
    
    let ai_extracted_events: Vec<_> = events
        .iter()
        .filter(|event| event.source == EventSource::AiExtracted.to_string())
        .collect();
    
    if !ai_extracted_events.is_empty() {
        println!("✅ Created {} AI-extracted chronicle events", ai_extracted_events.len());
        for event in &ai_extracted_events {
            println!("  - {}: {}", event.event_type, event.summary);
        }
    }
    
    // Note: Lorebook validation is simplified for integration test
    // The agentic system is designed to create lorebook entries as needed
    let total_entries = 0; // Placeholder - lorebook creation would happen via agentic workflow
    println!("✅ Total lorebook entries in system: {}", total_entries);
    
    // At minimum, we should have created chronicle events or lorebook entries
    assert!(
        !ai_extracted_events.is_empty() || total_entries > 0,
        "The agentic system should have created either chronicle events or lorebook entries"
    );
    
    println!("✅ End-to-end agentic narrative workflow completed successfully!");
}
*/

#[tokio::test]
async fn test_agentic_tools_with_mock_ai() {
    // Test individual tools with mock AI to ensure they work without external dependencies
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let _session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create encryption service and AppState for the test
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    
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
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    // Test messages that should trigger significance
    let messages = json!({
        "messages": [
            {"role": "user", "content": "I found the legendary sword"},
            {"role": "assistant", "content": "The blade glows with ancient power"}
        ]
    });
    
    // Test 1: Analyze Text Significance Tool with real AI
    let triage_tool = AnalyzeTextSignificanceTool::new(test_app.ai_client.clone());
    let triage_result = triage_tool.execute(&messages).await.unwrap();
    
    assert!(triage_result.get("is_significant").is_some());
    assert!(triage_result.get("confidence").is_some());
    println!("✅ Triage tool working: {:?}", triage_result);
    
    // Test 2: Extract Temporal Events Tool with real AI  
    let events_tool = ExtractTemporalEventsTool::new(test_app.ai_client.clone());
    let events_result = events_tool.execute(&messages).await.unwrap();
    
    assert!(events_result.get("events").is_some());
    println!("✅ Events extraction tool working: {:?}", events_result);
    
    // Test 3: Extract World Concepts Tool with real AI
    let concepts_tool = ExtractWorldConceptsTool::new(test_app.ai_client.clone());
    let concepts_result = concepts_tool.execute(&messages).await.unwrap();
    
    assert!(concepts_result.get("concepts").is_some());
    println!("✅ Concepts extraction tool working: {:?}", concepts_result);
    
    // Test 4: Search Knowledge Base Tool 
    let search_tool = SearchKnowledgeBaseTool::new(
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
    );
    
    let search_params = json!({
        "query": "legendary sword",
        "search_type": "all",
        "limit": 5
    });
    
    let search_result = search_tool.execute(&search_params).await.unwrap();
    assert!(search_result.get("results").is_some());
    println!("✅ Knowledge search tool working: {:?}", search_result);
    
    // Test 5: Create Chronicle Event Tool
    let create_event_tool = CreateChronicleEventTool::new(
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        app_state.clone()
    );
    
    // Hex-encode the session_dek for the tool parameter
    let session_dek_hex = hex::encode(session_dek.0.expose_secret());
    
    let event_params = json!({
        "user_id": user_id.to_string(),
        "chronicle_id": chronicle_id.to_string(),
        "event_category": "WORLD",
        "event_type": "DISCOVERY", 
        "event_subtype": "ITEM_ACQUISITION",
        "summary": "Found the legendary sword of testing",
        "subject": "Test Hero",
        "session_dek": session_dek_hex,
        "event_data": {
            "participants": ["Test Hero"],
            "location": "Test Dungeon",
            "details": "A magnificent blade discovered during integration testing"
        }
    });
    
    let create_result = create_event_tool.execute(&event_params).await.unwrap();
    assert_eq!(create_result.get("success").unwrap(), true);
    println!("✅ Chronicle event creation tool working: {:?}", create_result);
    
    // Verify the event was actually created in the database
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, Default::default())
        .await
        .unwrap();
    
    let test_events: Vec<_> = events
        .iter()
        .filter(|e| e.summary.contains("testing"))
        .collect();
    
    assert!(!test_events.is_empty(), "Test event should be created in database");
    println!("✅ Verified event in database: {}", test_events[0].summary);
}

/*
#[tokio::test]
async fn test_workflow_orchestration() {
    // Test the complete workflow orchestration without requiring significant events
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create non-significant messages
    let mundane_messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Hello there".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(5),
            completion_tokens: Some(5),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "Hello! How are you?".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(10),
            completion_tokens: Some(10),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        },
    ];
    
    // Use the test app's existing app_state
    let app_state = test_app.app_state.clone();

    // Create the agentic system
    let agentic_system = AgenticNarrativeFactory::create_system(
        test_app.ai_client.clone(),
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        Arc::new(LorebookService::new(
            test_app.db_pool.clone(),
            test_app.app_state.encryption_service.clone(),
            test_app.qdrant_service.clone(),
        )),
        app_state,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );
    
    // Execute workflow with mundane messages
    let workflow_result = agentic_system
        .process_narrative_event(
            user_id,
            session_id,
            Some(chronicle_id),
            &mundane_messages,
            &session_dek,
        )
        .await
        .expect("Workflow should complete even for non-significant events");
    
    // For non-significant events, the workflow should stop early
    if !workflow_result.triage_result.is_significant {
        assert!(workflow_result.actions_taken.is_empty(), "No actions should be taken for non-significant events");
        assert!(workflow_result.execution_results.is_empty(), "No execution results for non-significant events");
        println!("✅ Workflow correctly filtered out non-significant conversation");
    }
}
*/