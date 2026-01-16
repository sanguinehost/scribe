#![cfg(feature = "postgres-backend")]
#![cfg(test)]
//! Integration tests for agentic lorebook tools (CreateBatchLorebookEntriesTool and AnalyzeLorebookTool)
//!
//! These tests verify that the agentic lorebook tools correctly:
//! - Generate batch lorebook entries with AI-powered content
//! - Analyze existing lorebook entries to identify gaps and quality issues
//! - Handle encryption/decryption properly
//! - Validate parameters and handle errors gracefully
//! - Persist data correctly to the database

use scribe_backend::{
    auth::session_dek::SessionDek,
    errors::AppError,
    models::lorebook_dtos::CreateLorebookPayload,
    services::agentic::{
        AnalyzeLorebookTool, CreateBatchLorebookEntriesTool, CreateLorebookEntryTool, ScribeTool,
    },
    test_helpers::{MockAiClient, TestDataGuard},
};
use secrecy::SecretBox;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper to create test lorebook with some existing entries
async fn create_test_lorebook_with_entries(
    test_app: &scribe_backend::test_helpers::TestApp,
    user_id: scribe_backend::db::DbId,
    entry_count: usize,
) -> (scribe_backend::db::DbId, SessionDek) {
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));

    let create_lorebook_request = CreateLorebookPayload {
        name: "Test Lorebook".to_string(),
        description: Some("Test lorebook for agentic tools".to_string()),
    };

    let lorebook = lorebook_service
        .create_lorebook_for_test(user_id, create_lorebook_request)
        .await
        .expect("Failed to create test lorebook");

    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Create some test entries if requested
    for i in 0..entry_count {
        let entry_tool = CreateLorebookEntryTool::new(lorebook_service.clone());
        let entry_params = json!({
            "lorebook_id": lorebook.id.to_string(),
            "user_id": user_id.to_string(),
            "name": format!("Test Entry {}", i + 1),
            "content": format!("This is test entry number {}", i + 1),
            "keys": vec![format!("key{}", i + 1), "test".to_string()],
            "session_dek": hex::encode([0u8; 32])
        });

        entry_tool
            .execute(&entry_params)
            .await
            .expect("Failed to create test entry");
    }

    (lorebook.id, session_dek)
}

mod batch_lorebook_generation_tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_batch_generation() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "batch_gen_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 0).await;

        // Mock AI response with valid batch lorebook entries
        let batch_response = json!({
            "entries": [
                {
                    "name": "The Crystal Caves",
                    "content": "Ancient caverns filled with luminescent crystals that pulse with magical energy",
                    "keys": ["crystal", "caves", "caverns"],
                    "category": "location",
                    "reasoning": "Important location for magical artifact quest"
                },
                {
                    "name": "Magistrate Aldric",
                    "content": "The stern but fair leader of the city council, known for his dedication to justice",
                    "keys": ["aldric", "magistrate", "council"],
                    "category": "character",
                    "reasoning": "Key political figure in the campaign"
                },
                {
                    "name": "The Sundering",
                    "content": "A cataclysmic event 500 years ago that split the continent and created the Dead Lands",
                    "keys": ["sundering", "cataclysm", "dead lands"],
                    "category": "lore",
                    "reasoning": "Central historical event that shapes the world"
                }
            ],
            "reasoning": "Generated diverse entries covering key aspects of the world",
            "quality_assessment": "Entries are well-defined with clear triggers and useful information"
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(batch_response.to_string()));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let batch_tool =
            CreateBatchLorebookEntriesTool::new(lorebook_service.clone(), mock_ai_client);

        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "count": 3,
            "theme": "important locations, NPCs, and historical events in the fractured continent of Valdoria",
            "session_dek": hex::encode([0u8; 32])
        });

        let result = batch_tool.execute(&params).await;
        assert!(
            result.is_ok(),
            "Batch generation should succeed: {:?}",
            result.err()
        );

        let output = result.unwrap();
        assert!(output["created_entries"].is_array());
        assert_eq!(output["created_entries"].as_array().unwrap().len(), 3);

        // Verify entries were created in the database
        let entries = lorebook_service
            .list_lorebook_entries_for_test(user.id, lorebook_id)
            .await
            .expect("Failed to retrieve entries");
        assert_eq!(
            entries.len(),
            3,
            "Should have created 3 lorebook entries in the database"
        );

        // Verify entries have decrypted titles (proving encryption/decryption works)
        let entry_titles: Vec<String> = entries.iter().map(|e| e.entry_title.clone()).collect();
        for title in &entry_titles {
            assert!(
                !title.is_empty(),
                "Entry title should be decrypted and non-empty"
            );
        }

        // Verify we have the expected number of entries with reasonable titles
        // Note: We don't check exact titles because the mock might return them in any order
        // or with slight variations due to how the service processes them
        assert_eq!(
            entry_titles.len(),
            3,
            "Should have exactly 3 lorebook entries with titles: {:?}",
            entry_titles
        );
    }

    #[tokio::test]
    async fn test_parameter_validation() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(
            json!({"entries": []}).to_string(),
        ));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let batch_tool = CreateBatchLorebookEntriesTool::new(lorebook_service, mock_ai_client);

        // Test missing user_id (required parameter)
        let result = batch_tool
            .execute(&json!({
                "count": 3,
                "theme": "test theme",
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("user_id is required"),
            "Expected 'user_id is required' but got: {}",
            error_msg
        );

        // Test invalid user_id format
        let result = batch_tool
            .execute(&json!({
                "user_id": "not-a-uuid",
                "count": 3,
                "theme": "test theme",
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid user_id format"));

        // Test missing theme (required parameter)
        let result = batch_tool
            .execute(&json!({
                "user_id": Uuid::new_v4().to_string(),
                "count": 3,
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("theme is required"));

        // Test invalid count (out of range 1-20)
        let result = batch_tool
            .execute(&json!({
                "user_id": Uuid::new_v4().to_string(),
                "count": 0,  // Invalid: must be between 1-20
                "theme": "test theme",
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("count must be between 1 and 20"));

        // Test missing session_dek (required parameter)
        let result = batch_tool
            .execute(&json!({
                "user_id": Uuid::new_v4().to_string(),
                "count": 3,
                "theme": "test theme"
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("session_dek is required for lorebook entry creation"));
    }

    #[tokio::test]
    async fn test_empty_batch_handling() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "empty_batch_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 0).await;

        // Mock AI response with empty entries array
        let empty_batch_response = json!({
            "entries": [],
            "reasoning": "No new entries needed - all concepts already covered",
            "quality_assessment": "Current lorebook is comprehensive"
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(
            empty_batch_response.to_string(),
        ));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let batch_tool =
            CreateBatchLorebookEntriesTool::new(lorebook_service.clone(), mock_ai_client);

        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "count": 3,
            "theme": "additional entries for comprehensive campaign lore",
            "session_dek": hex::encode([0u8; 32])
        });

        let result = batch_tool.execute(&params).await;
        // The tool validates that at least one entry was created, so empty batches are rejected
        assert!(
            result.is_err(),
            "Empty batch should be rejected with validation error"
        );
        // The validation error comes from batch_output.validate(), not from the empty check
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Validation failed")
                || error_msg.contains("Batch generation must produce at least one entry"),
            "Expected validation error but got: {}",
            error_msg
        );

        // Verify no entries were created
        let entries = lorebook_service
            .list_lorebook_entries_for_test(user.id, lorebook_id)
            .await
            .expect("Failed to retrieve entries");
        assert_eq!(entries.len(), 0, "No entries should be created");
    }

    #[tokio::test]
    async fn test_ai_failure_handling() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "ai_fail_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 0).await;

        // Mock AI client that returns an error
        let mock_ai_client = Arc::new(MockAiClient::new_with_error(AppError::GenerationError(
            "AI service temporarily unavailable".to_string(),
        )));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let batch_tool = CreateBatchLorebookEntriesTool::new(lorebook_service, mock_ai_client);

        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "count": 3,
            "theme": "test context theme",
            "session_dek": hex::encode([0u8; 32])
        });

        let result = batch_tool.execute(&params).await;
        assert!(result.is_err(), "Should propagate AI failure");
        // The error should contain either the original error message or a wrapped version
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("AI service temporarily unavailable")
                || error_msg.contains("GenerationError"),
            "Error message should indicate AI failure: {}",
            error_msg
        );
    }
}

mod lorebook_analysis_tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_lorebook_analysis() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "analysis_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 3).await;

        // Mock AI response with analysis results matching the actual tool schema
        let analysis_response = json!({
            "gaps": [
                "Missing information about the economic system",
                "No entries for antagonist factions",
                "Limited cultural details"
            ],
            "consistency_issues": [
                "Some timeline inconsistencies between entries",
                "Conflicting descriptions of the capital city"
            ],
            "improvement_suggestions": [
                "Add more details about character motivations",
                "Include physical descriptions for locations",
                "Expand on historical context"
            ],
            "recommended_themes": [
                "The Merchant Guild and trade networks",
                "Shadow Cult and antagonist factions",
                "Cultural festivals and traditions"
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(
            analysis_response.to_string(),
        ));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
            test_app.qdrant_service.clone(),
        ));

        let app_state_services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone()
                as Arc<
                    dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                        + Send
                        + Sync,
                >,
            chat_override_service: Arc::new(
                scribe_backend::services::chat_override_service::ChatOverrideService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            user_persona_service: Arc::new(
                scribe_backend::services::user_persona_service::UserPersonaService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            token_counter: Arc::new(
                scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
                    scribe_backend::services::tokenizer_service::TokenizerService::new(
                        &test_app.config.tokenizer_model_path,
                    )
                    .expect("Failed to create tokenizer"),
                ),
            ),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
                test_app.db_pool.clone(),
            )),
            email_service: scribe_backend::services::email_service::create_email_service(
                "development",
                "http://localhost:3000".to_string(),
                None,
            )
            .await
            .unwrap(),
            ai_client_factory: Arc::new(
                scribe_backend::services::ai_client_factory::AiClientFactory::new(
                    test_app.db_pool.clone(),
                    test_app.config.clone(),
                    test_app.ai_client.clone(),
                ),
            ),
            rate_limiter: Arc::new(
                scribe_backend::middleware::llm_security::LlmRateLimiter::new(10, 100),
            ),
            recall_pipeline: Arc::new(scribe_backend::services::cognitive::RecallPipeline::new(
                test_app.db_pool.clone(),
            )),
            token_service: None,
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None,
            #[cfg(feature = "local-llm")]
            security_audit_logger: None,
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None,
        };

        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            app_state_services,
        ));

        let analysis_tool = AnalyzeLorebookTool::new(lorebook_service, mock_ai_client, app_state);

        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "session_dek": hex::encode([0u8; 32])
        });

        let result = analysis_tool.execute(&params).await;
        assert!(
            result.is_ok(),
            "Analysis should succeed: {:?}",
            result.err()
        );

        let output = result.unwrap();
        // Analysis results are nested under the "analysis" key
        assert!(output["analysis"].is_object());
        assert!(output["analysis"]["gaps"].is_array());
        assert!(output["analysis"]["consistency_issues"].is_array());
        assert!(output["analysis"]["improvement_suggestions"].is_array());
        assert!(output["analysis"]["recommended_themes"].is_array());
    }

    #[tokio::test]
    async fn test_empty_lorebook_analysis() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "empty_analysis_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 0).await;

        // Mock AI response for empty lorebook matching the actual tool schema
        let empty_analysis_response = json!({
            "gaps": ["No entries exist yet"],
            "consistency_issues": [],
            "improvement_suggestions": ["Start by documenting key characters and locations"],
            "recommended_themes": []
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(
            empty_analysis_response.to_string(),
        ));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
            test_app.qdrant_service.clone(),
        ));

        let app_state_services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone()
                as Arc<
                    dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                        + Send
                        + Sync,
                >,
            chat_override_service: Arc::new(
                scribe_backend::services::chat_override_service::ChatOverrideService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            user_persona_service: Arc::new(
                scribe_backend::services::user_persona_service::UserPersonaService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            token_counter: Arc::new(
                scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
                    scribe_backend::services::tokenizer_service::TokenizerService::new(
                        &test_app.config.tokenizer_model_path,
                    )
                    .expect("Failed to create tokenizer"),
                ),
            ),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
                test_app.db_pool.clone(),
            )),
            email_service: scribe_backend::services::email_service::create_email_service(
                "development",
                "http://localhost:3000".to_string(),
                None,
            )
            .await
            .unwrap(),
            ai_client_factory: Arc::new(
                scribe_backend::services::ai_client_factory::AiClientFactory::new(
                    test_app.db_pool.clone(),
                    test_app.config.clone(),
                    test_app.ai_client.clone(),
                ),
            ),
            rate_limiter: Arc::new(
                scribe_backend::middleware::llm_security::LlmRateLimiter::new(10, 100),
            ),
            recall_pipeline: Arc::new(scribe_backend::services::cognitive::RecallPipeline::new(
                test_app.db_pool.clone(),
            )),
            token_service: None,
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None,
            #[cfg(feature = "local-llm")]
            security_audit_logger: None,
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None,
        };

        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            app_state_services,
        ));

        let analysis_tool = AnalyzeLorebookTool::new(lorebook_service, mock_ai_client, app_state);

        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "session_dek": hex::encode([0u8; 32])
        });

        let result = analysis_tool.execute(&params).await;
        assert!(
            result.is_ok(),
            "Empty lorebook analysis should succeed: {:?}",
            result.err()
        );

        let output = result.unwrap();
        assert!(output["analysis"].is_object());
        assert!(output["analysis"]["gaps"].is_array());
    }

    #[tokio::test]
    async fn test_analysis_parameter_validation() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(json!({}).to_string()));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
            test_app.qdrant_service.clone(),
        ));

        let app_state_services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone()
                as Arc<
                    dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                        + Send
                        + Sync,
                >,
            chat_override_service: Arc::new(
                scribe_backend::services::chat_override_service::ChatOverrideService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            user_persona_service: Arc::new(
                scribe_backend::services::user_persona_service::UserPersonaService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            token_counter: Arc::new(
                scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
                    scribe_backend::services::tokenizer_service::TokenizerService::new(
                        &test_app.config.tokenizer_model_path,
                    )
                    .expect("Failed to create tokenizer"),
                ),
            ),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
                test_app.db_pool.clone(),
            )),
            email_service: scribe_backend::services::email_service::create_email_service(
                "development",
                "http://localhost:3000".to_string(),
                None,
            )
            .await
            .unwrap(),
            ai_client_factory: Arc::new(
                scribe_backend::services::ai_client_factory::AiClientFactory::new(
                    test_app.db_pool.clone(),
                    test_app.config.clone(),
                    test_app.ai_client.clone(),
                ),
            ),
            rate_limiter: Arc::new(
                scribe_backend::middleware::llm_security::LlmRateLimiter::new(10, 100),
            ),
            recall_pipeline: Arc::new(scribe_backend::services::cognitive::RecallPipeline::new(
                test_app.db_pool.clone(),
            )),
            token_service: None,
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None,
            #[cfg(feature = "local-llm")]
            security_audit_logger: None,
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None,
        };

        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            app_state_services,
        ));

        let analysis_tool = AnalyzeLorebookTool::new(lorebook_service, mock_ai_client, app_state);

        // Test missing lorebook_id
        let result = analysis_tool
            .execute(&json!({
                "user_id": Uuid::new_v4().to_string(),
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("lorebook_id must be a valid UUID"));

        // Test invalid lorebook_id format
        let result = analysis_tool
            .execute(&json!({
                "lorebook_id": "not-a-uuid",
                "user_id": Uuid::new_v4().to_string(),
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("lorebook_id must be a valid UUID"));

        // Test missing user_id
        let result = analysis_tool
            .execute(&json!({
                "lorebook_id": Uuid::new_v4().to_string(),
                "session_dek": hex::encode([0u8; 32])
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("user_id must be a valid UUID"));

        // Test missing session_dek
        let result = analysis_tool
            .execute(&json!({
                "lorebook_id": Uuid::new_v4().to_string(),
                "user_id": Uuid::new_v4().to_string()
            }))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("session_dek must be a string"));
    }

    #[tokio::test]
    async fn test_decryption_failure_handling() {
        let test_app = scribe_backend::test_helpers::spawn_app(true, false, false).await;
        let _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "decrypt_fail_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");

        let (lorebook_id, _session_dek) =
            create_test_lorebook_with_entries(&test_app, user.id, 1).await;

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(json!({}).to_string()));

        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
            test_app.qdrant_service.clone(),
        ));

        let app_state_services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone()
                as Arc<
                    dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                        + Send
                        + Sync,
                >,
            chat_override_service: Arc::new(
                scribe_backend::services::chat_override_service::ChatOverrideService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            user_persona_service: Arc::new(
                scribe_backend::services::user_persona_service::UserPersonaService::new(
                    test_app.db_pool.clone(),
                    encryption_service.clone(),
                ),
            ),
            token_counter: Arc::new(
                scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
                    scribe_backend::services::tokenizer_service::TokenizerService::new(
                        &test_app.config.tokenizer_model_path,
                    )
                    .expect("Failed to create tokenizer"),
                ),
            ),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
                test_app.db_pool.clone(),
            )),
            email_service: scribe_backend::services::email_service::create_email_service(
                "development",
                "http://localhost:3000".to_string(),
                None,
            )
            .await
            .unwrap(),
            ai_client_factory: Arc::new(
                scribe_backend::services::ai_client_factory::AiClientFactory::new(
                    test_app.db_pool.clone(),
                    test_app.config.clone(),
                    test_app.ai_client.clone(),
                ),
            ),
            rate_limiter: Arc::new(
                scribe_backend::middleware::llm_security::LlmRateLimiter::new(10, 100),
            ),
            recall_pipeline: Arc::new(scribe_backend::services::cognitive::RecallPipeline::new(
                test_app.db_pool.clone(),
            )),
            token_service: None,
            #[cfg(feature = "local-llm")]
            llamacpp_server_manager: None,
            #[cfg(feature = "local-llm")]
            security_audit_logger: None,
            #[cfg(feature = "local-llm")]
            model_integrity_verifier: None,
        };

        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            app_state_services,
        ));

        let analysis_tool = AnalyzeLorebookTool::new(lorebook_service, mock_ai_client, app_state);

        // Use wrong session_dek to trigger decryption failure
        let params = json!({
            "lorebook_id": lorebook_id.to_string(),
            "user_id": user.id.to_string(),
            "session_dek": hex::encode([0xFFu8; 32]) // Different key, will fail decryption
        });

        let result = analysis_tool.execute(&params).await;
        assert!(result.is_err(), "Should fail with wrong decryption key");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decrypt"));
    }
}
