use scribe_backend::models::agent_context_analysis::{AgentContextAnalysis, AnalysisType, AnalysisStatus};
use scribe_backend::test_helpers;
use uuid::Uuid;
use diesel::prelude::*;

#[tokio::test]
async fn test_agent_analysis_error_handling() {
    // Setup test application (multi_thread=true, use_real_ai=false, use_real_qdrant=false)
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create a test user
    let username = format!("test_user_{}", Uuid::new_v4());
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.clone(),
        "password123".to_string(),
    )
    .await
    .unwrap();

    let user_id = user.id;
    
    // Create a chat session
    let session_id = Uuid::new_v4();
    let conn = test_app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        use scribe_backend::schema::chat_sessions;
        use scribe_backend::models::chats::ChatMode;
        
        diesel::insert_into(chat_sessions::table)
            .values((
                chat_sessions::id.eq(session_id),
                chat_sessions::user_id.eq(user_id),
                chat_sessions::model_name.eq("gemini-2.5-flash"),
                chat_sessions::chat_mode.eq(ChatMode::Character.to_string()), // Use Character mode
                chat_sessions::history_management_strategy.eq("sliding_window"),
                chat_sessions::history_management_limit.eq(50),
                chat_sessions::created_at.eq(diesel::dsl::now),
                chat_sessions::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    // Create a message first (since message_id has a foreign key constraint)
    let message_id = Uuid::new_v4();
    let conn = test_app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        // Use raw SQL to insert message since the enum handling is complex
        diesel::sql_query(
            "INSERT INTO chat_messages (id, session_id, user_id, message_type, content, model_name, created_at, updated_at) 
             VALUES ($1, $2, $3, 'User', $4, $5, NOW(), NOW())"
        )
        .bind::<diesel::sql_types::Uuid, _>(message_id)
        .bind::<diesel::sql_types::Uuid, _>(session_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Bytea, _>(b"Test message".to_vec())
        .bind::<diesel::sql_types::Text, _>("gemini-2.5-flash")
        .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();
    
    // Test 1: Create a pending analysis
    let analysis_id = Uuid::new_v4();
    
    let conn = test_app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis;
        
        diesel::insert_into(agent_context_analysis::table)
            .values((
                agent_context_analysis::id.eq(analysis_id),
                agent_context_analysis::chat_session_id.eq(session_id),
                agent_context_analysis::user_id.eq(user_id),
                agent_context_analysis::analysis_type.eq(AnalysisType::PreProcessing.to_string()),
                agent_context_analysis::message_id.eq(message_id),
                agent_context_analysis::status.eq(AnalysisStatus::Pending.to_string()),
                agent_context_analysis::retry_count.eq(0),
                agent_context_analysis::created_at.eq(diesel::dsl::now),
                agent_context_analysis::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    // Test 2: Mark the analysis as failed
    let conn = test_app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        AgentContextAnalysis::update_status(
            conn,
            analysis_id,
            AnalysisStatus::Failed,
            Some("Model overloaded (503)".to_string()),
        )
    })
    .await
    .unwrap()
    .unwrap();

    // Test 3: Verify the failed analysis is marked correctly
    let conn = test_app.db_pool.get().await.unwrap();
    let failed_analysis = conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis::dsl::*;
        
        agent_context_analysis
            .find(analysis_id)
            .first::<AgentContextAnalysis>(conn)
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(failed_analysis.status, "failed");
    assert_eq!(failed_analysis.error_message, Some("Model overloaded (503)".to_string()));

    // Test 4: Supersede failed analyses
    let conn = test_app.db_pool.get().await.unwrap();
    let count = conn.interact(move |conn| {
        AgentContextAnalysis::supersede_failed_analyses(
            conn,
            session_id,
            AnalysisType::PreProcessing,
        )
    })
    .await
    .unwrap()
    .unwrap();

    assert_eq!(count, 1);

    // Test 5: Verify the failed analysis is now superseded
    let conn = test_app.db_pool.get().await.unwrap();
    let superseded_analysis = conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis::dsl::*;
        
        agent_context_analysis
            .find(analysis_id)
            .first::<AgentContextAnalysis>(conn)
    })
    .await
    .unwrap()
    .unwrap();

    assert!(superseded_analysis.superseded_at.is_some());

    // Test 6: Verify that superseded analyses are not returned by get_for_session
    let conn = test_app.db_pool.get().await.unwrap();
    let active_analysis = conn.interact(move |conn| {
        AgentContextAnalysis::get_for_session(
            conn,
            session_id,
            AnalysisType::PreProcessing,
        )
    })
    .await
    .unwrap()
    .unwrap();

    assert!(active_analysis.is_none(), "Superseded analysis should not be returned");

    // Test 7: Create a new successful analysis to replace the failed one
    let new_analysis_id = Uuid::new_v4();
    
    let conn = test_app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        use scribe_backend::schema::agent_context_analysis;
        
        diesel::insert_into(agent_context_analysis::table)
            .values((
                agent_context_analysis::id.eq(new_analysis_id),
                agent_context_analysis::chat_session_id.eq(session_id),
                agent_context_analysis::user_id.eq(user_id),
                agent_context_analysis::analysis_type.eq(AnalysisType::PreProcessing.to_string()),
                agent_context_analysis::message_id.eq(message_id),
                agent_context_analysis::status.eq(AnalysisStatus::Success.to_string()),
                agent_context_analysis::retry_count.eq(1), // This was a retry
                agent_context_analysis::analysis_summary.eq(Some("Test successful analysis".to_string())),
                agent_context_analysis::created_at.eq(diesel::dsl::now),
                agent_context_analysis::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
    })
    .await
    .unwrap()
    .unwrap();

    // Test 8: Verify the new successful analysis is returned
    let conn = test_app.db_pool.get().await.unwrap();
    let new_active_analysis = conn.interact(move |conn| {
        AgentContextAnalysis::get_for_session(
            conn,
            session_id,
            AnalysisType::PreProcessing,
        )
    })
    .await
    .unwrap()
    .unwrap();

    assert!(new_active_analysis.is_some());
    let analysis = new_active_analysis.unwrap();
    assert_eq!(analysis.id, new_analysis_id);
    assert_eq!(analysis.status, "success");
    assert_eq!(analysis.retry_count, 1);
}