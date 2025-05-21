// backend/tests/user_persona_service_tests.rs

#![cfg(test)]

use anyhow::Result as AnyhowResult;
use std::sync::Arc;
use uuid::Uuid;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use scribe_backend::{
    services::{
        UserPersonaService,
        EncryptionService,
    },
    models::{
        users::User,
        user_personas::{CreateUserPersonaDto, UpdateUserPersonaDto},
    },
    test_helpers::{self, TestDataGuard},
    errors::AppError,
    // state::DbPool, // Marked as unused
};

// Helper to set up the service and a test user
struct TestContext {
    service: UserPersonaService,
    user: User,
    dek: SecretBox<Vec<u8>>,
    _guard: TestDataGuard, // To clean up DB entries
}

async fn setup_service_test() -> AnyhowResult<TestContext> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = TestDataGuard::new(test_app.db_pool.clone());

    let username = "testpersonauser";
    let password = "password123";
    let dek_value = "0123456789abcdef0123456789abcdef"; // 32 chars/bytes
    let plaintext_dek_secret_string = SecretString::new(dek_value.to_string().into_boxed_str());

    let (user, _session_cookie) = test_helpers::create_user_with_dek_in_session(
        &test_app.router,
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
        Some(plaintext_dek_secret_string.clone()),
    )
    .await?;
    guard.add_user(user.id);

    let dek_bytes = plaintext_dek_secret_string.expose_secret().as_bytes().to_vec();
    let dek_secret_box = SecretBox::new(Box::new(dek_bytes)); 

    let encryption_service = Arc::new(EncryptionService::new());
    let user_persona_service = UserPersonaService::new(test_app.db_pool.clone(), encryption_service);

    Ok(TestContext {
        service: user_persona_service,
        user, // User object from create_user_with_dek_in_session
        dek: dek_secret_box, // The reconstructed DEK
        _guard: guard,
    })
}

// TODO: Add tests for UserPersonaService CRUD methods
// - test_create_user_persona_success
// - test_get_user_persona_success_and_forbidden
// - test_list_user_personas_success
// - test_update_user_persona_success_and_forbidden
// - test_delete_user_persona_success_and_forbidden
// - ... and error cases (not found, validation etc.) 

#[tokio::test]
async fn test_update_user_persona_success() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;

    // 1. Create initial persona
    let initial_create_dto = CreateUserPersonaDto {
        name: "Initial Name".to_string(),
        description: "Initial description.".to_string(),
        spec: Some("spec_v1".to_string()),
        personality: Some("Initial personality.".to_string()),
        scenario: None, // Start with scenario as None
        ..Default::default()
    };
    let mut current_persona_state = ctx.service.create_user_persona(&ctx.user, &ctx.dek, initial_create_dto.clone()).await?;
    let persona_id = current_persona_state.id;

    // 2. Test Case: Update name and spec (non-encrypted)
    let update_dto_name_spec = UpdateUserPersonaDto {
        name: Some("Updated Name".to_string()),
        spec: Some("spec_v2".to_string()),
        ..Default::default()
    };
    let updated_name_spec_result = ctx.service.update_user_persona(&ctx.user, &ctx.dek, persona_id, update_dto_name_spec.clone()).await?;
    assert_eq!(updated_name_spec_result.name, update_dto_name_spec.name.unwrap());
    assert_eq!(updated_name_spec_result.spec, update_dto_name_spec.spec);
    assert_eq!(updated_name_spec_result.description, initial_create_dto.description); // Should be unchanged
    assert_eq!(updated_name_spec_result.personality, initial_create_dto.personality); // Should be unchanged
    current_persona_state = updated_name_spec_result;
    let original_updated_at = current_persona_state.updated_at;

    // Short delay to ensure updated_at changes if an update occurs
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // 3. Test Case: Update description (encrypted) and set scenario (None to Some, encrypted)
    let update_dto_desc_scenario = UpdateUserPersonaDto {
        description: Some("Updated description.".to_string()),
        scenario: Some("New scenario added.".to_string()),
        ..Default::default()
    };
    let updated_desc_scenario_result = ctx.service.update_user_persona(&ctx.user, &ctx.dek, persona_id, update_dto_desc_scenario.clone()).await?;
    assert_eq!(updated_desc_scenario_result.name, current_persona_state.name); // Should be from previous update
    assert_eq!(updated_desc_scenario_result.description, update_dto_desc_scenario.description.unwrap());
    assert_eq!(updated_desc_scenario_result.scenario, update_dto_desc_scenario.scenario);
    assert_eq!(updated_desc_scenario_result.personality, current_persona_state.personality); // Should be unchanged
    assert!(updated_desc_scenario_result.updated_at > original_updated_at, "updated_at should change after modification");
    current_persona_state = updated_desc_scenario_result;
    let previous_updated_at = current_persona_state.updated_at;
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // 4. Test Case: Update personality (Some to SomeOther, encrypted) and clear scenario (Some to None/empty)
    // Service logic for clearing: sending empty string for an optional field might be treated as "clear"
    // or `None` in DTO means no change. `UpdateUserPersonaDto` uses `Option<String>`. 
    // The service method `encrypt_optional_string_for_db` treats `Some("")` as `(None, None)` for DB.
    // So, to clear `scenario`, we'd send `Some("".to_string())` in DTO, or if DTO has `Option<Option<String>>`, then `Some(None)`.
    // Current DTO is `Option<String>`. The service handles `Some(empty_string)` as clear.
    // Let's test service behavior: if `update_dto.scenario = Some("".to_string())` clears it.
    // Based on current `user_persona_service.rs`, the `update_optional_encrypted_field` macro takes `Option<String>`.
    // If it's `Some(value)`, it encrypts. If `value` is empty, it sets field and nonce to `None`.
    // If it's `None`, it does nothing.
    // So to clear `scenario` (which is `Option<String>`), we need to send `Some("".to_string())` in the DTO.

    let update_dto_pers_clear_scenario = UpdateUserPersonaDto {
        personality: Some("Updated personality again.".to_string()),
        scenario: Some("".to_string()), // Attempt to clear scenario
        ..Default::default()
    };
    let updated_pers_clear_scenario_result = ctx.service.update_user_persona(&ctx.user, &ctx.dek, persona_id, update_dto_pers_clear_scenario.clone()).await?;
    assert_eq!(updated_pers_clear_scenario_result.personality, update_dto_pers_clear_scenario.personality);
    assert!(updated_pers_clear_scenario_result.scenario.is_none() || updated_pers_clear_scenario_result.scenario == Some("".to_string()), "Scenario should be cleared to None or empty string");
    // The `into_data_for_client` would convert a decrypted empty string back to `Some("")` or `None` based on its logic
    // `decrypt_optional_field_async` maps empty decrypted bytes to `Some("")` if `ct` and `n` were non-empty originally (convention for empty encrypted)
    // The service's `encrypt_optional_string_for_db` sets db fields to (None,None) if input is empty. So this should decrypt to None.
    assert!(updated_pers_clear_scenario_result.scenario.is_none(), "Scenario should decrypt to None after being set to empty string update.");
    assert!(updated_pers_clear_scenario_result.updated_at > previous_updated_at);
    current_persona_state = updated_pers_clear_scenario_result;
    let last_updated_at = current_persona_state.updated_at;

    // 5. Verify by fetching again
    let fetched_after_updates = ctx.service.get_user_persona(&ctx.user, Some(&ctx.dek), persona_id).await?;
    assert_eq!(fetched_after_updates.name, "Updated Name");
    assert_eq!(fetched_after_updates.spec, Some("spec_v2".to_string()));
    assert_eq!(fetched_after_updates.description, "Updated description.");
    assert_eq!(fetched_after_updates.personality, Some("Updated personality again.".to_string()));
    assert!(fetched_after_updates.scenario.is_none());
    assert_eq!(fetched_after_updates.updated_at, last_updated_at);

    Ok(())
}

#[tokio::test]
async fn test_update_user_persona_no_changes() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let create_dto = CreateUserPersonaDto {
        name: "No Change Persona".to_string(),
        description: "This persona will not change.".to_string(),
        ..Default::default()
    };
    let created_persona = ctx.service.create_user_persona(&ctx.user, &ctx.dek, create_dto).await?;
    let original_updated_at = created_persona.updated_at;

    // Short delay to ensure updated_at would change IF an update occurs
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let update_dto_empty = UpdateUserPersonaDto { ..Default::default() };
    let result = ctx.service.update_user_persona(&ctx.user, &ctx.dek, created_persona.id, update_dto_empty).await?;

    assert_eq!(result.name, created_persona.name);
    assert_eq!(result.description, created_persona.description);
    // The service *will* update `updated_at` even if no fields change because it re-saves the model.
    // This is because `changed` flag is set to `true` then the model is saved which updates the `updated_at` via DB trigger.
    // Let's read the service again. The service has a `changed` boolean.
    // If `changed` is false, it returns early *before* saving. So updated_at should NOT change.
    assert_eq!(result.updated_at, original_updated_at, "updated_at should not change if DTO is empty and no fields are modified.");

    Ok(())
}

#[tokio::test]
async fn test_update_user_persona_not_found() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let random_uuid = Uuid::new_v4();
    let update_dto = UpdateUserPersonaDto { name: Some("New Name".to_string()), ..Default::default() };

    let result = ctx.service.update_user_persona(&ctx.user, &ctx.dek, random_uuid, update_dto).await;
    assert!(matches!(result, Err(AppError::NotFound(_))), "Expected NotFound, got {:?}", result);

    Ok(())
}

#[tokio::test]
async fn test_update_user_persona_forbidden() -> AnyhowResult<()> {
    let ctx1 = setup_service_test().await?; 
    let test_app_for_ctx2 = test_helpers::spawn_app(true, false, false).await;
    let mut guard2 = TestDataGuard::new(test_app_for_ctx2.db_pool.clone());

    let user2_username = "updateforbiddenuser";
    let user2_password = "password1011";
    let user2_dek_value = "dek-for-update-test-user2-32b"; // Ensure 32 bytes
    let user2_plaintext_dek = SecretString::new(user2_dek_value.to_string().into_boxed_str());

    let (user2, _session_id2) = test_helpers::create_user_with_dek_in_session(
        &test_app_for_ctx2.router,
        &test_app_for_ctx2.db_pool,
        user2_username.to_string(),
        user2_password.to_string(),
        Some(user2_plaintext_dek.clone()),
    ).await?;
    guard2.add_user(user2.id.clone());
    let dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    let dek2 = SecretBox::new(Box::new(dek2_bytes));

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1 Update Test".to_string(),
        description: "Belongs to user1.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1.service.create_user_persona(&ctx1.user, &ctx1.dek, create_dto).await?;

    let update_dto = UpdateUserPersonaDto { name: Some("Attempted Update by User2".to_string()), ..Default::default() };
    let result = ctx1.service.update_user_persona(&user2, &dek2, persona_for_user1.id, update_dto).await;
    assert!(matches!(result, Err(AppError::Forbidden)), "Expected Forbidden, got {:?}", result);

    Ok(())
}

#[tokio::test]
async fn test_delete_user_persona_success() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let create_dto = CreateUserPersonaDto {
        name: "Persona to Delete".to_string(),
        description: "This persona will be deleted.".to_string(),
        ..Default::default()
    };
    let created_persona = ctx.service.create_user_persona(&ctx.user, &ctx.dek, create_dto).await?;

    // Delete the persona
    let delete_result = ctx.service.delete_user_persona(&ctx.user, created_persona.id).await;
    assert!(delete_result.is_ok(), "delete_user_persona failed: {:?}", delete_result.err());

    // Try to get the deleted persona
    let get_result = ctx.service.get_user_persona(&ctx.user, Some(&ctx.dek), created_persona.id).await;
    assert!(matches!(get_result, Err(AppError::NotFound(_))), "Expected NotFound after delete, got {:?}", get_result);

    Ok(())
}

#[tokio::test]
async fn test_delete_user_persona_not_found() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let random_uuid = Uuid::new_v4();

    let delete_result = ctx.service.delete_user_persona(&ctx.user, random_uuid).await;
    // The service first tries to fetch the persona. If not found, it returns NotFound.
    assert!(matches!(delete_result, Err(AppError::NotFound(_))), "Expected NotFound when deleting non-existent persona, got {:?}", delete_result);

    Ok(())
}

#[tokio::test]
async fn test_delete_user_persona_forbidden() -> AnyhowResult<()> {
    let ctx1 = setup_service_test().await?;
    let test_app_for_ctx2 = test_helpers::spawn_app(true, false, false).await;
    let mut guard2 = TestDataGuard::new(test_app_for_ctx2.db_pool.clone());

    let user2_username = "deleteforbiddenuser";
    let user2_password = "password1213";
    // For delete test, user2's DEK isn't strictly used by the service for the check, but good practice to have it if creating user this way.
    let user2_dek_value = "dek-for-delete-test-user2-32b"; // Ensure 32 bytes
    let user2_plaintext_dek = SecretString::new(user2_dek_value.to_string().into_boxed_str());

    let (user2, _session_id2) = test_helpers::create_user_with_dek_in_session(
        &test_app_for_ctx2.router,
        &test_app_for_ctx2.db_pool,
        user2_username.to_string(),
        user2_password.to_string(),
        Some(user2_plaintext_dek.clone()), // Pass DEK, though not strictly needed for delete forbidden check
    ).await?;
    guard2.add_user(user2.id.clone());
    // let _dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    // let _dek2 = SecretBox::new(Box::new(_dek2_bytes)); // _dek2 is not used in this test

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1 Delete Test".to_string(),
        description: "Belongs to user1, user2 cannot delete.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1.service.create_user_persona(&ctx1.user, &ctx1.dek, create_dto).await?;

    let delete_result = ctx1.service.delete_user_persona(&user2, persona_for_user1.id).await;
    assert!(matches!(delete_result, Err(AppError::Forbidden)), "Expected Forbidden, got {:?}", delete_result);

    // Verify persona still exists for user1
    let get_result = ctx1.service.get_user_persona(&ctx1.user, Some(&ctx1.dek), persona_for_user1.id).await;
    assert!(get_result.is_ok(), "Persona should still exist for user1 after forbidden delete attempt.");

    Ok(())
}

#[tokio::test]
async fn test_get_user_persona_forbidden() -> AnyhowResult<()> {
    let ctx1 = setup_service_test().await?; // User 1 and their service/DEK
    let test_app_for_ctx2 = test_helpers::spawn_app(true, false, false).await;
    let mut guard2 = TestDataGuard::new(test_app_for_ctx2.db_pool.clone());

    let user2_username = "forbiddenuser";
    let user2_password = "password456";
    let user2_dek_value = "another-dek-for-user2-32bytes0"; // Ensure 32 bytes
    let user2_plaintext_dek = SecretString::new(user2_dek_value.to_string().into_boxed_str());

    let (user2, _session_id2) = test_helpers::create_user_with_dek_in_session(
        &test_app_for_ctx2.router,
        &test_app_for_ctx2.db_pool,
        user2_username.to_string(),
        user2_password.to_string(),
        Some(user2_plaintext_dek.clone()),
    ).await?;
    guard2.add_user(user2.id.clone());
    let dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    let dek2 = SecretBox::new(Box::new(dek2_bytes));

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1".to_string(),
        description: "This persona belongs to user1.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1.service.create_user_persona(&ctx1.user, &ctx1.dek, create_dto).await?;

    let result = ctx1.service.get_user_persona(&user2, Some(&dek2), persona_for_user1.id).await;
    assert!(matches!(result, Err(AppError::Forbidden)), "Expected Forbidden, got {:?}", result);

    Ok(())
}