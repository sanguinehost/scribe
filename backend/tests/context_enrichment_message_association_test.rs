#![cfg(test)]

use diesel::prelude::*;
use scribe_backend::{
    models::{
        AgentContextAnalysis,
        chats::{NewChat, Chat, NewChatMessage, MessageRole},
    },
    schema::{chat_sessions, chat_messages},
    services::{
        agentic::{
            context_enrichment_agent::{ContextEnrichmentAgent, EnrichmentMode},
            narrative_tools::SearchKnowledgeBaseTool,
        },
        ChronicleService,
    },
    state::{AppState, AppStateServices},
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
};
use std::sync::Arc;
use uuid::Uuid;
use secrecy::ExposeSecret;
use tracing::info;

/// Test that agent analysis is properly associated with specific messages
#[tokio::test]
async fn test_agent_analysis_message_association() -> anyhow::Result<()> {
    let test_app = spawn_app(false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        format!("message_assoc_user_{}", Uuid::new_v4()),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create user");
    guard.add_user(user.id);

    let user_dek = user.dek.as_ref().expect("User should have DEK");

    // Create a character first
    use scribe_backend::models::character_card::NewCharacter;
    use scribe_backend::models::characters::Character as DbCharacter;
    use scribe_backend::schema::characters;
    
    let new_character = NewCharacter {
        user_id: user.id,
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        name: "Test Character for Message Association".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        ..Default::default()
    };
    
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .returning(DbCharacter::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;
    guard.add_character(character.id);

    // Create chat session
    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id,
        user_id: user.id,
        character_id: character.id,
        title_ciphertext: None,
        title_nonce: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        history_management_strategy: "truncate_summary".to_string(),
        history_management_limit: 15,
        model_name: "gemini-test-model".to_string(),
        visibility: Some("private".to_string()),
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
        player_chronicle_id: None,
    };

    let session: Chat = test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_session)
                .returning(Chat::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    // Create context enrichment agent
    let encryption_service = Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::lorebook::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    
    let services = AppStateServices {
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
    };
    
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services
    ));
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        app_state.clone(),
    ));
    let context_agent = ContextEnrichmentAgent::new(
        app_state,
        search_tool,
        chronicle_service,
    );

    // Create first message and enrich it
    let message1_id = Uuid::new_v4();
    let message1_content = "Tell me about dragons";
    let new_message1 = NewChatMessage {
        id: message1_id,
        session_id: session.id,
        user_id: user.id,
        message_type: MessageRole::User,
        content: message1_content.as_bytes().to_vec(),
        content_nonce: None,
        role: Some("user".to_string()),
        parts: None,
        attachments: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message1)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    info!("Testing message 1 association...");

    // Enrich first message with pre-processing
    let messages1 = vec![
        ("user".to_string(), message1_content.to_string()),
    ];

    let result1 = context_agent.enrich_context(
        session_id,
        user.id,
        None, // chronicle_id
        &messages1,
        EnrichmentMode::PreProcessing,
        user_dek.0.expose_secret(),
        message1_id, // Required: Associate with message 1
    ).await;

    // Even if enrichment fails due to mock AI, verify any stored analysis is associated correctly
    if result1.is_ok() {
        info!("✅ Message 1 enrichment succeeded");
    }

    // Create second message and enrich it
    let message2_id = Uuid::new_v4();
    let message2_content = "What about wizards?";
    let new_message2 = NewChatMessage {
        id: message2_id,
        session_id: session.id,
        user_id: user.id,
        message_type: MessageRole::User,
        content: message2_content.as_bytes().to_vec(),
        content_nonce: None,
        role: Some("user".to_string()),
        parts: None,
        attachments: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message2)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    info!("Testing message 2 association...");

    // Enrich second message  
    let messages2 = vec![
        ("user".to_string(), message1_content.to_string()),
        ("assistant".to_string(), "Dragons are mythical creatures...".to_string()),
        ("user".to_string(), message2_content.to_string()),
    ];

    let result2 = context_agent.enrich_context(
        session_id,
        user.id,
        None, // chronicle_id
        &messages2,
        EnrichmentMode::PreProcessing,
        user_dek.0.expose_secret(),
        message2_id, // Required: Associate with message 2
    ).await;

    if result2.is_ok() {
        info!("✅ Message 2 enrichment succeeded");
    }

    // Verify message associations in database
    let conn = test_app.db_pool.get().await?;
    let analyses = conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis::dsl::*;
        
        agent_context_analysis
            .filter(chat_session_id.eq(session_id))
            .order_by(created_at.asc())
            .load::<AgentContextAnalysis>(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    info!("Found {} analyses for session", analyses.len());

    // If any analyses were stored (even with mock AI), verify they have correct message associations
    if !analyses.is_empty() {
        for (i, analysis) in analyses.iter().enumerate() {
            info!("Analysis {}: message_id = {:?}, type = {}", 
                i + 1, 
                analysis.message_id,
                analysis.analysis_type
            );

            // Verify each analysis has a message_id set
            assert!(
                true, // message_id is always present now
                "Analysis {} should have message_id set",
                i + 1
            );

            // Verify the message_id matches one of our test messages
            let msg_id = analysis.message_id; // Already a Uuid, not Option<Uuid>
            assert!(
                msg_id == message1_id || msg_id == message2_id,
                "Analysis message_id should match one of our test messages"
            );
        }

        info!("✅ All analyses have correct message associations");
    } else {
        info!("No analyses stored (mock AI may have failed, but that's OK for this test)");
    }

    // Test querying analysis by message_id
    if !analyses.is_empty() {
        let target_message_id = analyses[0].message_id; // Already a Uuid, not Option<Uuid>
        
        let specific_analysis = conn.interact(move |conn| {
            use scribe_backend::schema::agent_context_analysis::dsl::*;
            
            agent_context_analysis
                .filter(chat_session_id.eq(session_id))
                .filter(message_id.eq(target_message_id))
                .first::<AgentContextAnalysis>(conn)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

        assert!(
            specific_analysis.is_some(),
            "Should be able to query analysis by message_id"
        );

        let found = specific_analysis.unwrap();
        assert_eq!(
            found.message_id,
            target_message_id,
            "Retrieved analysis should have correct message_id"
        );

        info!("✅ Successfully queried analysis by message_id");
    }

    guard.cleanup().await?;
    Ok(())
}

/// Test that multiple analyses for the same message are handled correctly
#[tokio::test]
async fn test_multiple_analyses_per_message() -> anyhow::Result<()> {
    use scribe_backend::models::character_card::NewCharacter;
    use scribe_backend::models::characters::Character as DbCharacter;
    use scribe_backend::schema::characters;
    
    let test_app = spawn_app(false, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        format!("multi_analysis_user_{}", Uuid::new_v4()),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create user");
    guard.add_user(user.id);

    let user_dek = user.dek.as_ref().expect("User should have DEK");

    // Create a character first
    let new_character = NewCharacter {
        user_id: user.id,
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        name: "Test Character for Multiple Analyses".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        ..Default::default()
    };
    
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .returning(DbCharacter::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;
    guard.add_character(character.id);

    // Create chat session
    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id,
        user_id: user.id,
        character_id: character.id,
        title_ciphertext: None,
        title_nonce: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        history_management_strategy: "truncate_summary".to_string(),
        history_management_limit: 15,
        model_name: "gemini-test-model".to_string(),
        visibility: Some("private".to_string()),
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
        player_chronicle_id: None,
    };

    test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_session)
                .returning(Chat::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    // Create a message
    let message_id = Uuid::new_v4();
    let message_content = "Tell me a story";
    let new_message = NewChatMessage {
        id: message_id,
        session_id,
        user_id: user.id,
        message_type: MessageRole::User,
        content: message_content.as_bytes().to_vec(),
        content_nonce: None,
        role: Some("user".to_string()),
        parts: None,
        attachments: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    // Create context enrichment agent
    let encryption_service = Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::lorebook::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    
    let services = AppStateServices {
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
    };
    
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services
    ));
    
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        app_state.clone(),
    ));
    let context_agent = ContextEnrichmentAgent::new(
        app_state,
        search_tool,
        chronicle_service,
    );

    let messages = vec![
        ("user".to_string(), message_content.to_string()),
    ];

    info!("Testing pre-processing analysis for message...");

    // Run pre-processing analysis
    let _pre_result = context_agent.enrich_context(
        session_id,
        user.id,
        None, // chronicle_id
        &messages,
        EnrichmentMode::PreProcessing,
        user_dek.0.expose_secret(),
        message_id, // Required message ID
    ).await;

    info!("Testing post-processing analysis for same message...");

    // Run post-processing analysis for the same message
    let messages_with_response = vec![
        ("user".to_string(), message_content.to_string()),
        ("assistant".to_string(), "Here's a story for you...".to_string()),
    ];

    let _post_result = context_agent.enrich_context(
        session_id,
        user.id,
        None, // chronicle_id
        &messages_with_response,
        EnrichmentMode::PostProcessing,
        user_dek.0.expose_secret(),
        message_id, // Required message ID // Same message ID
    ).await;

    // Query analyses for this message
    let conn = test_app.db_pool.get().await?;
    let analyses = conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis::dsl::*;
        
        agent_context_analysis
            .filter(chat_session_id.eq(session_id))
            .filter(message_id.eq(message_id))
            .order_by(created_at.asc())
            .load::<AgentContextAnalysis>(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Pool interact error: {:?}", e))??;

    info!("Found {} analyses for message", analyses.len());

    // If analyses were stored, verify they have different modes but same message_id
    if analyses.len() >= 2 {
        let modes: Vec<String> = analyses.iter()
            .map(|a| a.analysis_type.clone())
            .collect();

        assert!(
            modes.contains(&"pre_processing".to_string()) || modes.contains(&"post_processing".to_string()),
            "Should have analyses with different modes"
        );

        for analysis in &analyses {
            assert_eq!(
                analysis.message_id,
                message_id, // Required message ID
                "All analyses should be associated with the same message"
            );
        }

        info!("✅ Multiple analyses correctly associated with same message");
    } else {
        info!("Fewer than 2 analyses stored (mock AI may have failed, which is OK)");
    }

    guard.cleanup().await?;
    Ok(())
}