use axum::http::StatusCode;
use scribe_backend::models::lorebook_dtos::{
    CreateLorebookEntryPayload, CreateLorebookPayload, LorebookEntryResponse, LorebookResponse,
};
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use uuid::Uuid;

#[tokio::test]
async fn test_delete_lorebook_entry_cleans_up_qdrant() {
    // 1. Setup app with mock Qdrant
    let test_app = spawn_app(false, false, false).await;
    let _test_data_guard =
        TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    let user_credentials = ("delete_test@example.com", "password123");
    let _user_data = scribe_backend::test_helpers::db::create_test_user(
        &test_app.db_pool,
        user_credentials.0.to_string(),
        user_credentials.1.to_string(),
    )
    .await
    .expect("Failed to create user");

    let (auth_client, _) = scribe_backend::test_helpers::login_user_via_api(
        &test_app,
        user_credentials.0,
        user_credentials.1,
    )
    .await;

    // 2. Create a lorebook
    let lorebook_payload = CreateLorebookPayload {
        name: "Test Lorebook".to_string(),
        description: Some("Test Description".to_string()),
    };

    let response = auth_client
        .post(format!("{}/api/lorebooks", test_app.address))
        .json(&lorebook_payload)
        .send()
        .await
        .expect("Failed to create lorebook");

    assert_eq!(response.status(), StatusCode::CREATED);
    let lorebook: LorebookResponse = response.json().await.expect("Failed to parse lorebook");

    // 3. Create a lorebook entry
    let entry_payload = CreateLorebookEntryPayload {
        entry_title: "Test Entry".to_string(),
        keys_text: Some("test, entry".to_string()),
        content: "Test Content".to_string(),
        comment: None,
        is_enabled: Some(true),
        is_constant: Some(false),
        insertion_order: Some(100),
        placement_hint: Some("after_prompt".to_string()),
    };

    let response = auth_client
        .post(format!(
            "{}/api/lorebooks/{}/entries",
            test_app.address, lorebook.id
        ))
        .json(&entry_payload)
        .send()
        .await
        .expect("Failed to create lorebook entry");

    assert_eq!(response.status(), StatusCode::CREATED);
    let entry: LorebookEntryResponse = response.json().await.expect("Failed to parse entry");

    // 4. Delete the lorebook entry
    let response = auth_client
        .delete(format!(
            "{}/api/lorebooks/{}/entries/{}",
            test_app.address, lorebook.id, entry.id
        ))
        .send()
        .await
        .expect("Failed to delete lorebook entry");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 5. Verify Qdrant cleanup was called
    let mock_qdrant = test_app
        .mock_qdrant_service
        .expect("Mock Qdrant service not found");
    let delete_calls = mock_qdrant.get_delete_points_by_filter_calls();

    assert!(
        !delete_calls.is_empty(),
        "delete_points_by_filter should have been called"
    );

    // Check if any of the calls match our entry_id
    let entry_id_str = entry.id.to_string();
    let found_match = delete_calls.iter().any(|filter| {
        filter.must.iter().any(|condition| {
            if let Some(scribe_backend::vector_db::qdrant_client::ConditionOneOf::Field(
                field_cond,
            )) = &condition.condition_one_of
            {
                if field_cond.key == "original_lorebook_entry_id" {
                    if let Some(m) = &field_cond.r#match {
                        if let Some(
                            scribe_backend::vector_db::qdrant_client::MatchValue::Keyword(val),
                        ) = &m.match_value
                        {
                            return val == &entry_id_str;
                        }
                    }
                }
            }
            false
        })
    });

    assert!(
        found_match,
        "Should have called Qdrant delete with original_lorebook_entry_id = {}",
        entry_id_str
    );
}
