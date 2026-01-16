#![cfg(feature = "postgres-backend")]
#![cfg(test)]
// backend/tests/structured_output_real_llm_test.rs
//
// Integration tests to verify structured outputs work with real Gemini LLM.
// These tests are marked with #[ignore] and should be run explicitly:
//
// cargo test -- --ignored
//

use chrono::Utc;
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto::{encrypt_gcm, generate_dek},
    db::DbId,
    models::chats::{ChatMessage, MessageRole},
    services::{
        agentic::{
            AnalyzeTextSignificanceTool, NarrativeAgentRunner, NarrativeWorkflowConfig, ScribeTool,
            ToolRegistry,
        },
        chronicle_service::ChronicleService,
        hybrid_token_counter::HybridTokenCounter,
        tokenizer_service::TokenizerService,
    },
    test_helpers::spawn_app_with_options,
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Test that AnalyzeTextSignificanceTool works with real Gemini API using structured outputs
///
/// This test verifies that the conversion from brittle JSON parsing to Gemini 2.5+ structured
/// outputs works correctly with the actual Gemini API.
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored test_analyze_text_significance_with_real_llm
async fn test_analyze_text_significance_with_real_llm() {
    // This test requires GEMINI_API_KEY environment variable
    if std::env::var("GEMINI_API_KEY").is_err() {
        eprintln!("⚠️  Skipping test: GEMINI_API_KEY not set");
        return;
    }

    println!("\n🧪 Testing AnalyzeTextSignificanceTool with real Gemini API...");
    println!("   This verifies structured outputs work correctly (Phase 2.1 conversion)\n");

    // Spawn test app with real AI client (use_real_ai=true)
    let test_app = spawn_app_with_options(
        false, // multi_thread
        true,  // use_real_ai <-- KEY: Use real Gemini API
        false, // use_real_qdrant
        false, // use_real_embedding_pipeline
    )
    .await;

    // Create tool with real AI client
    let tool = AnalyzeTextSignificanceTool::new(test_app.ai_client.clone());

    // Create test input with narratively significant content
    let test_input = json!({
        "messages": [
            {
                "role": "user",
                "content": "The dragon Smaug attacked the village of Laketown, burning everything in sight."
            },
            {
                "role": "assistant",
                "content": "The villagers fled in terror as the dragon's flames consumed their homes. This was a dark day that would be remembered for generations."
            }
        ]
    });

    // Execute the tool (calls call_ai_for_triage() which uses structured outputs)
    println!("📤 Sending analysis request to Gemini API with JsonSchemaSpec...");
    let result = tool.execute(&test_input).await;

    // Verify the result
    match result {
        Ok(analysis_result) => {
            println!("✅ Analysis succeeded with real Gemini API!");
            println!("   Response: {:?}\n", analysis_result);

            // Verify the structured output contains expected fields from get_text_significance_triage_schema()
            assert!(
                analysis_result.get("is_significant").is_some(),
                "Structured output should contain 'is_significant' field"
            );
            assert!(
                analysis_result.get("confidence").is_some(),
                "Structured output should contain 'confidence' field"
            );
            assert!(
                analysis_result.get("reason").is_some(),
                "Structured output should contain 'reason' field"
            );
            assert!(
                analysis_result.get("suggested_categories").is_some(),
                "Structured output should contain 'suggested_categories' field"
            );

            let is_significant = analysis_result
                .get("is_significant")
                .and_then(|v| v.as_bool())
                .expect("is_significant should be a boolean");
            let confidence = analysis_result
                .get("confidence")
                .and_then(|v| v.as_f64())
                .expect("confidence should be a number");
            let reason = analysis_result
                .get("reason")
                .and_then(|v| v.as_str())
                .expect("reason should be a string");

            println!("   ✓ Is Significant: {}", is_significant);
            println!("   ✓ Confidence: {:.2}", confidence);
            println!("   ✓ Reason: {}", reason);

            // Basic sanity checks
            assert!(
                confidence >= 0.0 && confidence <= 1.0,
                "Confidence should be between 0.0 and 1.0"
            );
            assert!(!reason.is_empty(), "Reason should not be empty");

            println!("\n✅ Structured output schema enforced correctly by Gemini 2.5+");
            println!("   No markdown fence stripping needed!");
            println!("   No JSON repair logic needed!");
        }
        Err(e) => {
            panic!("❌ Analysis failed with real Gemini API: {}", e);
        }
    }
}

/// Test that generate_chronicle_name_from_messages() works with real Gemini API using structured outputs
///
/// This test verifies the Phase 1 conversion (agent_runner.rs: get_chronicle_naming_schema) works with real LLM.
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored test_chronicle_naming_with_real_llm
async fn test_chronicle_naming_with_real_llm() {
    // This test requires GEMINI_API_KEY environment variable
    if std::env::var("GEMINI_API_KEY").is_err() {
        eprintln!("⚠️  Skipping test: GEMINI_API_KEY not set");
        return;
    }

    println!("\n🧪 Testing generate_chronicle_name_from_messages() with real Gemini API...");
    println!("   This verifies structured outputs work correctly (Phase 1: chronicle naming)\n");

    // Spawn test app with real AI client
    let test_app = spawn_app_with_options(
        false, // multi_thread
        true,  // use_real_ai <-- KEY: Use real Gemini API
        false, // use_real_qdrant
        false, // use_real_embedding_pipeline
    )
    .await;

    // Create a test DEK for message encryption
    let test_dek = generate_dek().expect("Failed to generate test DEK");
    let session_dek = SessionDek(SecretBox::new(Box::new(test_dek.expose_secret().to_vec())));

    // Create test messages with roleplay content
    let test_messages = vec![
        {
            let content =
                "Welcome to the Crimson Empire. You stand before the gates of the Imperial Palace.";
            let (encrypted_content, content_nonce) =
                encrypt_gcm(content.as_bytes(), &test_dek).expect("Failed to encrypt content");

            ChatMessage {
                id: Uuid::new_v4().into(),
                session_id: Uuid::new_v4().into(),
                user_id: DbId::new(),
                message_type: MessageRole::System,
                content: encrypted_content,
                content_nonce: Some(content_nonce),
                created_at: Utc::now().into(),
                model_name: "test".to_string(),
                status: "completed".to_string(),
                variant_count: 1,
                current_variant_index: 0,
                ..Default::default()
            }
        },
        {
            let content = "I approach the palace gates, requesting an audience with the Empress.";
            let (encrypted_content, content_nonce) =
                encrypt_gcm(content.as_bytes(), &test_dek).expect("Failed to encrypt content");

            ChatMessage {
                id: Uuid::new_v4().into(),
                session_id: Uuid::new_v4().into(),
                user_id: DbId::new(),
                message_type: MessageRole::User,
                content: encrypted_content,
                content_nonce: Some(content_nonce),
                created_at: Utc::now().into(),
                model_name: "test".to_string(),
                status: "completed".to_string(),
                variant_count: 1,
                current_variant_index: 0,
                ..Default::default()
            }
        },
    ];

    // Set up required services for NarrativeAgentRunner
    let chronicle_service = Arc::new(ChronicleService::new(
        test_app.db_pool.clone(),
        test_app.ai_client.clone(),
    ));

    let tokenizer = TokenizerService::new(&test_app.config.tokenizer_model_path)
        .expect("Failed to create tokenizer");
    let token_counter = Arc::new(HybridTokenCounter::new(
        tokenizer,
        None,
        "gemini-2.5-flash-lite",
    ));

    let tool_registry = Arc::new(ToolRegistry::new());
    let config = NarrativeWorkflowConfig::default();

    // Create AppState for the runner
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));

    let services = scribe_backend::state::AppStateServices {
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
        chat_override_service: Arc::new(scribe_backend::services::ChatOverrideService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        )),
        user_persona_service: Arc::new(scribe_backend::services::UserPersonaService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        )),
        token_counter: token_counter.clone(),
        encryption_service: encryption_service.clone(),
        lorebook_service: lorebook_service.clone(),
        auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
            test_app.db_pool.clone(),
        )),
        email_service: scribe_backend::services::email_service::create_email_service(
            &"development".to_string(),
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
        services,
    ));

    // Create agent runner with real AI client
    let agent = NarrativeAgentRunner::new(
        test_app.ai_client.clone(),
        tool_registry,
        config,
        chronicle_service,
        test_app.mock_embedding_pipeline_service.clone()
            as Arc<
                dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                    + Send
                    + Sync,
            >,
        app_state,
        token_counter,
    );

    // Call generate_chronicle_name_from_messages() which uses structured outputs
    println!("📤 Sending chronicle naming request to Gemini API with JsonSchemaSpec...");
    let result = agent
        .generate_chronicle_name_from_messages(
            &test_messages,
            &session_dek,
            Some("Empress Valeria".to_string()),
        )
        .await;

    // Verify the result
    match result {
        Ok(chronicle_name) => {
            println!("✅ Chronicle naming succeeded with real Gemini API!");
            println!("   Generated name: {:?}\n", chronicle_name);

            // Verify the name is valid
            assert!(
                !chronicle_name.is_empty(),
                "Chronicle name should not be empty"
            );
            assert!(
                chronicle_name.len() <= 100,
                "Chronicle name should not be too long"
            );
            assert!(
                chronicle_name != "Untitled Chronicle" && chronicle_name != "New Chronicles",
                "Should generate a meaningful name, not fallback"
            );

            println!("   ✓ Chronicle name: {}", chronicle_name);
            println!("\n✅ Structured output schema enforced correctly by Gemini 2.5+");
            println!("   No markdown fence stripping needed!");
            println!("   No JSON repair logic needed!");
        }
        Err(e) => {
            panic!("❌ Chronicle naming failed with real Gemini API: {}", e);
        }
    }
}
