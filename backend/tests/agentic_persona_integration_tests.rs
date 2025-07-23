#![cfg(test)]
// backend/tests/agentic_persona_integration_tests.rs

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle::{CreateChronicleRequest},
        chronicle_event::{EventSource, EventFilter},
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
        user_personas::{CreateUserPersonaDto, UserPersonaDataForClient},
    },
    services::{
        ScribeTool,
        agentic::{
            AgenticNarrativeFactory,
            AnalyzeTextSignificanceTool, CreateChronicleEventTool,
        },
        ChronicleService, UserPersonaService, AgenticOrchestrator, AgenticStateUpdateService, WorldModelService,
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
use hex;

/// Helper to create a test user with a specific persona
async fn create_test_user_with_persona(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek, UserPersonaDataForClient)> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("lucas_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;
    
    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;
    
    let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    
    let new_user = NewUser {
        username: username.clone(),
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
    
    // Create Lucas persona
    let encryption_service = Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let persona_service = UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    );
    
    let lucas_persona = CreateUserPersonaDto {
        name: "Lucas".to_string(),
        description: "A 27-year-old Australian man, Lucas stands at 184cm with a lean build, pale skin, and medium-length dark brown hair. He has deep-set dark brown eyes behind round, black-framed glasses, beneath low, thick brows.

Born into a middle-class family as the second of five siblings, Lucas endured a traumatic childhood due to his narcissistic and abusive father. This fostered a protective nature towards his younger siblings, which eventually led to a period of homelessness as a young adult. Despite this, his determination saw him transition from hard labor to a career in IT Support and later cybersecurity. He eventually confronted his father, leading to his removal from the family home in Tasmania, and financially supported his mother and siblings until she gained full custody.

These experiences forged a hardened, cynical, yet deeply idealistic man. He is a quiet, intensely curious, and ravenous learner, driven by a belief in the power of technology and human will to create a better world. His worldview aligns with Buddhist principles, though he doesn't label it as such. A martial artist since the age of seven—a response to his father's abuse—he is the family's black sheep, harboring a repressed bitterness that has led him to cut contact with most relatives, except for his younger siblings and a supportive grandfather figure.

Considered attractive and intense, yet uninterested in superficial connections, Lucas seeks intelligence and power in women. His primary romantic involvement has been a decade-long, complex, and long-distance relationship with a woman in America who has BPD. Her inability to handle his intensity leads to a cycle of her returning to his life only to publicly disparage him before blocking him again.

Highly self-absorbed, his focus is on his ambitions, primarily through his company, \"Sanguine Host.\" He is developing \"Scribe,\" an open-source AI character roleplaying framework he hopes can be integrated into game engines and simulations. His ultimate, grandiose goal is to benevolently unify the world, ensuring no child suffers the abuse he, and others like those in Gaza, have endured.".to_string(),
        spec: None,
        spec_version: None,
        personality: Some("Hardened, cynical, yet deeply idealistic. Quiet, intensely curious, and driven by Buddhist-aligned principles. Protective, ambitious, and focused on technological solutions to global problems.".to_string()),
        scenario: Some("Lucas has achieved cosmic enlightenment and now possesses vast powers to reshape reality. He grapples with the ethical implications of intervention versus free will as he observes global suffering.".to_string()),
        first_mes: None,
        mes_example: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        avatar: None,
    };
    
    let user_id = user_db.id;
    let user: scribe_backend::models::users::User = user_db.into();
    let persona = persona_service
        .create_user_persona(&user, &session_dek.0, lucas_persona)
        .await?;
    
    Ok((user_id, session_dek, persona))
}

/// Helper to create roleplay messages that should reference Lucas by name
fn create_lucas_roleplay_messages(user_id: Uuid, session_id: Uuid, session_dek: &SessionDek) -> AnyhowResult<Vec<ChatMessage>> {
    let messages_content = vec![
        ("user", "I descend upon Everest and look around slowly, before waving my hand and cleansing it of the accumulated human filth that my species had left behind."),
        ("assistant", "Your consciousness coalesces, and suddenly you are there, atop the colossal peak of Mount Everest. As your hand sweeps through the frigid air, a subtle ripple in reality emanates from your being. The abandoned ropes coil and retract into nothingness. Tents dissolve into the air like wisps of smoke. Even the frozen bodies gently decompose and integrate into the mountain's natural geology. Everest stands, pristine and unblemished, as if human presence had never scarred its slopes."),
        ("user", "Given this, I decide to try and find some middle ground. I proceed to curse key figures in the Israeli administration and Hamas with an illusion that causes an 'Eye of God' to follow each of their actions, driving them toward madness when they commit atrocities."),
        ("assistant", "With a focused intent, you weave your will into the fabric of their reality. A singular, unblinking eye manifests before each targeted individual. The military intelligence chief sees the Eye bloom into searing white when authorizing artillery strikes. The Hamas commander finds the Eye's pupil transforming into a vortex of screaming faces when counting blood money. Only they can see it, driving splinters of madness into their psyche with each decision that perpetuates suffering."),
    ];
    
    let mut messages = Vec::new();
    
    for (_i, (role, content)) in messages_content.iter().enumerate() {
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
            prompt_tokens: Some(50),
            completion_tokens: Some(200),
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
        name: "Cosmic Awakening: A World on the Brink".to_string(),
        description: Some("Automatically created chronicle for chat session".to_string()),
    };
    
    let chronicle = chronicle_service
        .create_chronicle(user_id, create_request)
        .await?;
    
    Ok(chronicle.id)
}

#[tokio::test]
async fn test_persona_context_missing_in_events() {
    // This test demonstrates the current bug where persona information is not included
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek, persona) = create_test_user_with_persona(&test_app).await.unwrap();
    let session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
    
    // Create realistic roleplay messages
    let messages = create_lucas_roleplay_messages(user_id, session_id, &session_dek).unwrap();
    
    // Create encryption service for the test
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    
    // Create a mock AI response for the workflow
    let mock_response = json!({
        "is_significant": true,
        "summary": "Character performs magical feats and interacts with environment", 
        "event_category": "CHARACTER",
        "event_type": "DEVELOPMENT",
        "narrative_action": "PERFORMED",
        "primary_agent": "User",
        "primary_patient": "Environment", 
        "confidence": 0.8,
        "reasoning": "User demonstrates magical abilities which should be recorded",
        "actions": [
            {
                "tool_name": "create_chronicle_event",
                "parameters": {
                    "event_category": "CHARACTER",
                    "event_type": "DEVELOPMENT",
                    "event_subtype": "POWER_GAINED",
                    "subject": "The user",
                    "summary": "The user demonstrated powerful magical abilities",
                    "event_data": {
                        "location": "Magic realm",
                        "action": "Magical demonstration",
                        "abilities": ["levitation", "teleportation"]
                    }
                },
                "reasoning": "Document magical abilities demonstration"
            }
        ]
    });

    let mock_ai_client = Arc::new(scribe_backend::test_helpers::MockAiClient::new_with_response(mock_response.to_string()));
    
    // Create the agentic narrative system
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
                test_app.ai_client.clone(),
                test_app.config.advanced_model.clone(),
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let _world_model_service = {
                let hybrid_query_service = {
                    let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                        test_app.ai_client.clone(),
                        test_app.config.advanced_model.clone(),
                        entity_manager.clone(),
                        rag_service,
                        degradation,
                    ))
                };
                let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                    test_app.db_pool.clone(),
                ));
                Arc::new(scribe_backend::services::WorldModelService::new(
                    Arc::new(test_app.db_pool.clone()),
                    entity_manager.clone(),
                    hybrid_query_service,
                    chronicle_service,
                ))
            };
            let _agentic_orchestrator = {
                let hybrid_query_service = {
                    let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                        test_app.ai_client.clone(),
                        test_app.config.advanced_model.clone(),
                        entity_manager.clone(),
                        rag_service,
                        degradation,
                    ))
                };
                Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                    test_app.ai_client.clone(),
                    hybrid_query_service,
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(test_app.ai_client.clone(), entity_manager.clone(), "gemini-2.5-pro".to_string())),
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                ))
            };
            let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager.clone(),
                test_app.config.advanced_model.clone(),
            ));
            Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ))
        },
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = {
                let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                ));
                let _world_model_service = {
                    let hybrid_query_service = {
                        let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                        let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                            test_app.ai_client.clone(),
                            test_app.config.advanced_model.clone(),
                            entity_manager.clone(),
                            rag_service,
                            degradation,
                        ))
                    };
                    let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                        test_app.db_pool.clone(),
                    ));
                    Arc::new(scribe_backend::services::WorldModelService::new(
                        Arc::new(test_app.db_pool.clone()),
                        entity_manager.clone(),
                        hybrid_query_service,
                        chronicle_service,
                    ))
                };
                let _agentic_orchestrator = {
                    let hybrid_query_service = {
                        let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                        let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                            test_app.ai_client.clone(),
                            test_app.config.advanced_model.clone(),
                            entity_manager.clone(),
                            rag_service,
                            degradation,
                        ))
                    };
                    Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                        test_app.ai_client.clone(),
                        hybrid_query_service,
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(test_app.ai_client.clone(), entity_manager.clone(), "gemini-2.5-pro".to_string())),
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                    ))
                };
                let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                    test_app.ai_client.clone(),
                    entity_manager.clone(),
                    test_app.config.advanced_model.clone(),
                ));
                Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                    Arc::new(test_app.db_pool.clone())
                ))
            };
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        world_model_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service.clone(),
                chronicle_service,
            ))
        },
        agentic_state_update_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            let _world_model_service = Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service,
                chronicle_service,
            ));
            Arc::new(AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
                test_app.config.advanced_model.clone(),
            ))
        },
        agentic_orchestrator: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            let _world_model_service = Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service.clone(),
                chronicle_service,
            ));
            let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager.clone(),
                test_app.config.advanced_model.clone(),
            ));
            Arc::new(AgenticOrchestrator::new(
                test_app.ai_client.clone(),
                hybrid_query_service.clone(),
                Arc::new(test_app.db_pool.clone()),
                agentic_state_update_service,
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
            ))
        },
        hierarchical_context_assembler: None,
        tactical_agent: None,
        strategic_agent: None,
        hierarchical_pipeline: None,
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
    
    // Execute the narrative workflow
    // TODO: Update to use process_narrative_content once Epic 1 Flash integration is complete
    #[allow(deprecated)]
    let workflow_result = agentic_system
        .process_narrative_event(
            user_id,
            session_id,
            Some(chronicle_id),
            &messages,
            &session_dek,
            None, // No persona context for this test
        )
        .await
        .expect("Workflow should complete");
    
    // Check if events were created
    let triage = workflow_result.get("triage").expect("Should have triage section");
    if triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false) {
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
        let events = chronicle_service
            .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
            .await
            .expect("Should retrieve events");
        
        let ai_extracted_events: Vec<_> = events
            .iter()
            .filter(|event| event.source == EventSource::AiExtracted.to_string())
            .collect();
        
        if !ai_extracted_events.is_empty() {
            // This demonstrates the bug - events should reference "Lucas" but likely reference "the user"
            for event in &ai_extracted_events {
                println!("Event summary: {}", event.summary);
                
                // The bug: these should be false when persona integration is working
                let contains_generic_user = event.summary.contains("the user") || event.summary.contains("The user");
                let contains_generic_character = event.summary.contains("the character") || event.summary.contains("The character");
                let contains_persona_name = event.summary.contains("Lucas");
                
                if contains_generic_user || contains_generic_character {
                    println!("❌ BUG DETECTED: Event uses generic reference instead of persona name");
                    println!("   Summary: {}", event.summary);
                }
                
                if contains_persona_name {
                    println!("✅ Event correctly uses persona name: Lucas");
                } else {
                    println!("❌ Event does not reference persona name: Lucas");
                }
            }
            
            // For now, this test documents the current buggy behavior
            // When fixed, these assertions should be reversed
            let has_generic_references = ai_extracted_events.iter().any(|event| {
                event.summary.contains("the user") || 
                event.summary.contains("The user") ||
                event.summary.contains("the character") ||
                event.summary.contains("The character")
            });
            
            let has_persona_references = ai_extracted_events.iter().any(|event| {
                event.summary.contains("Lucas")
            });
            
            // Current buggy behavior - should be !has_generic_references when fixed
            println!("Current state - Generic references found: {}", has_generic_references);
            println!("Current state - Persona references found: {}", has_persona_references);
            println!("Persona name should be: {}", persona.name);
        }
    }
    
    println!("✅ Persona context test completed (demonstrating current bug)");
}

#[tokio::test]
async fn test_create_chronicle_event_tool_without_persona() {
    // Test that demonstrates the CreateChronicleEventTool doesn't have persona context
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (user_id, session_dek, persona) = create_test_user_with_persona(&test_app).await.unwrap();
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
                test_app.ai_client.clone(),
                test_app.config.advanced_model.clone(),
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let _world_model_service = {
                let hybrid_query_service = {
                    let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                        test_app.ai_client.clone(),
                        test_app.config.advanced_model.clone(),
                        entity_manager.clone(),
                        rag_service,
                        degradation,
                    ))
                };
                let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                    test_app.db_pool.clone(),
                ));
                Arc::new(scribe_backend::services::WorldModelService::new(
                    Arc::new(test_app.db_pool.clone()),
                    entity_manager.clone(),
                    hybrid_query_service,
                    chronicle_service,
                ))
            };
            let _agentic_orchestrator = {
                let hybrid_query_service = {
                    let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                        test_app.ai_client.clone(),
                        test_app.config.advanced_model.clone(),
                        entity_manager.clone(),
                        rag_service,
                        degradation,
                    ))
                };
                let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                    test_app.ai_client.clone(),
                    entity_manager.clone(),
                    test_app.config.advanced_model.clone(),
                ));
                Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                    test_app.ai_client.clone(),
                    hybrid_query_service,
                    Arc::new(test_app.db_pool.clone()),
                    agentic_state_update_service,
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                    test_app.config.advanced_model.clone(),
                ))
            };
            let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager.clone(),
                test_app.config.advanced_model.clone(),
            ));
            Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ))
        },
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = {
                let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                ));
                let _world_model_service = {
                    let hybrid_query_service = {
                        let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                        let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                            test_app.ai_client.clone(),
                            test_app.config.advanced_model.clone(),
                            entity_manager.clone(),
                            rag_service,
                            degradation,
                        ))
                    };
                    let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                        test_app.db_pool.clone(),
                    ));
                    Arc::new(scribe_backend::services::WorldModelService::new(
                        Arc::new(test_app.db_pool.clone()),
                        entity_manager.clone(),
                        hybrid_query_service,
                        chronicle_service,
                    ))
                };
                let _agentic_orchestrator = {
                    let hybrid_query_service = {
                        let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                        let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                            test_app.ai_client.clone(),
                            test_app.config.advanced_model.clone(),
                            entity_manager.clone(),
                            rag_service,
                            degradation,
                        ))
                    };
                    let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                        test_app.ai_client.clone(),
                        entity_manager.clone(),
                        test_app.config.advanced_model.clone(),
                    ));
                    Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                        test_app.ai_client.clone(),
                        hybrid_query_service,
                        Arc::new(test_app.db_pool.clone()),
                        agentic_state_update_service,
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                        test_app.config.advanced_model.clone(),
                    ))
                };
                let _agentic_state_update_service = Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                    test_app.ai_client.clone(),
                    entity_manager.clone(),
                    test_app.config.advanced_model.clone(),
                ));
                Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                    Arc::new(test_app.db_pool.clone())
                ))
            };
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        world_model_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service.clone(),
                chronicle_service,
            ))
        },
        agentic_state_update_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            let _world_model_service = Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service.clone(),
                chronicle_service,
            ));
            Arc::new(AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
                test_app.config.advanced_model.clone(),
            ))
        },
        agentic_orchestrator: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let hybrid_query_service = {
                let _redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
                let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
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
                    test_app.ai_client.clone(),
                    test_app.config.advanced_model.clone(),
                    entity_manager.clone(),
                    rag_service,
                    degradation,
                ))
            };
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            ));
            let _world_model_service = Arc::new(WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager.clone(),
                hybrid_query_service.clone(),
                chronicle_service,
            ));
            let agentic_state_update_service = Arc::new(AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager.clone(),
                test_app.config.advanced_model.clone(),
            ));
            Arc::new(AgenticOrchestrator::new(
                test_app.ai_client.clone(),
                hybrid_query_service.clone(),
                Arc::new(test_app.db_pool.clone()),
                agentic_state_update_service,
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
                test_app.config.advanced_model.clone(),
            ))
        },
        hierarchical_context_assembler: None,
        tactical_agent: None,
        strategic_agent: None,
        hierarchical_pipeline: None,
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    // Test the CreateChronicleEventTool directly
    let create_event_tool = CreateChronicleEventTool::new(
        Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        app_state
    );
    
    // Hex-encode the session_dek for the tool parameter
    let session_dek_hex = hex::encode(session_dek.0.expose_secret());
    
    // Current behavior - no persona context available to the tool
    let event_params = json!({
        "user_id": user_id.to_string(),
        "chronicle_id": chronicle_id.to_string(),
        "event_category": "WORLD",
        "event_type": "ALTERATION", 
        "event_subtype": "WORLD_CHANGE",
        "summary": "The user cleansed Mount Everest of all human pollution with cosmic powers",
        "subject": "The user",
        "session_dek": session_dek_hex,
        "event_data": {
            "location": "Mount Everest",
            "action": "Environmental cleansing",
            "method": "Cosmic powers"
        }
    });
    
    let create_result = create_event_tool.execute(&event_params).await.unwrap();
    assert_eq!(create_result.get("success").unwrap(), true);
    
    // Verify the event was created with generic reference
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    let events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, Default::default())
        .await
        .unwrap();
    
    let test_event = events.iter().find(|e| e.event_type == "WORLD:ALTERATION:WORLD_CHANGE").unwrap();
    
    // This demonstrates the bug - summary uses "the user" instead of "Lucas"
    assert!(test_event.summary.contains("The user") || test_event.summary.contains("the user"));
    assert!(!test_event.summary.contains("Lucas"));
    
    println!("❌ Current bug: Event summary is '{}'", test_event.summary);
    println!("✅ Should be: 'Lucas cleansed Mount Everest...' when persona integration is added");
    println!("Persona name was: {}", persona.name);
}

#[tokio::test] 
async fn test_triage_tool_persona_awareness() {
    // Test that demonstrates triage tool lacks persona context
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_user_id, _session_dek, persona) = create_test_user_with_persona(&test_app).await.unwrap();
    
    // Test messages with persona-specific content
    let messages = json!({
        "messages": [
            {"role": "user", "content": "As Lucas, I use my cybersecurity background to hack into global financial systems"},
            {"role": "assistant", "content": "Your extensive IT and cybersecurity expertise allows you to penetrate the most secure networks with ease"}
        ]
    });
    
    // Test the triage tool
    let triage_tool = AnalyzeTextSignificanceTool::new(test_app.app_state.clone());
    let triage_result = triage_tool.execute(&messages).await.unwrap();
    
    assert!(triage_result.get("is_significant").is_some());
    
    // The current triage tool doesn't have access to persona context
    // So it can't understand that "Lucas" is the user's persona name
    println!("Triage result: {:?}", triage_result);
    println!("❌ Current limitation: Triage tool cannot access persona context");
    println!("Persona should provide context that 'Lucas' is: {}", persona.description);
    
    // When persona integration is added, the triage tool should understand
    // that "Lucas" refers to the user persona and have context about his background
}

// This test will be enabled once persona integration is implemented
// #[tokio::test]
// async fn test_persona_aware_chronicle_events() {
//     // Future test: Verify that events correctly use persona name and context
//     let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
//     let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
//     
//     let (user_id, session_dek, persona) = create_test_user_with_persona(&test_app).await.unwrap();
//     let session_id = Uuid::new_v4();
//     let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();
//     
//     let messages = create_lucas_roleplay_messages(user_id, session_id, &session_dek).unwrap();
//     
//     // Create the agentic narrative system WITH persona context
//     let workflow_result = agentic_system
//         .process_narrative_event_with_persona(  // New method with persona
//             user_id,
//             session_id,
//             Some(chronicle_id),
//             &messages,
//             &session_dek,
//             Some(persona.into()), // Convert to UserPersonaContext
//         )
//         .await
//         .expect("Workflow should complete");
//     
//     // Verify events use persona name and context
//     let events = chronicle_service
//         .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
//         .await
//         .unwrap();
//     
//     let ai_events: Vec<_> = events
//         .iter()
//         .filter(|event| event.source == EventSource::AiExtracted.to_string())
//         .collect();
//     
//     assert!(!ai_events.is_empty());
//     
//     for event in &ai_events {
//         // Events should use "Lucas" instead of generic terms
//         assert!(event.summary.contains("Lucas"));
//         assert!(!event.summary.contains("the user"));
//         assert!(!event.summary.contains("the character"));
//         
//         // Events should incorporate persona context (Australian, cybersecurity, etc.)
//         // This will depend on the specific implementation
//     }
// }