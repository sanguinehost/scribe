// backend/tests/user_persona_service_tests.rs

#![cfg(test)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::redundant_closure_for_method_calls)]

use anyhow::Result as AnyhowResult;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use std::sync::Arc;
use uuid::Uuid;

use diesel::prelude::*; // For direct DB queries
use scribe_backend::schema::users::dsl as users_dsl;
use scribe_backend::state::DbPool; // Make sure DbPool is in scope
use scribe_backend::{
    errors::AppError,
    // state::DbPool, // Marked as unused
    models::{
        user_personas::{CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient},
        users::{User, UserDbQuery}, // Added UserDbQuery for direct DB check
    },
    services::{EncryptionService, UserPersonaService},
    test_helpers::{self, TestDataGuard},
}; // For direct DB queries

// Helper to set up the service and a test user
struct TestContext {
    service: UserPersonaService,
    user: User,
    dek: SecretBox<Vec<u8>>,
    db_pool: DbPool,      // Added DbPool
    guard: TestDataGuard, // To clean up DB entries
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

    let dek_bytes = plaintext_dek_secret_string
        .expose_secret()
        .as_bytes()
        .to_vec();
    let dek_secret_box = SecretBox::new(Box::new(dek_bytes));

    let encryption_service = Arc::new(EncryptionService::new());
    let user_persona_service =
        UserPersonaService::new(test_app.db_pool.clone(), encryption_service);

    Ok(TestContext {
        service: user_persona_service,
        user,                              // User object from create_user_with_dek_in_session
        dek: dek_secret_box,               // The reconstructed DEK
        db_pool: test_app.db_pool.clone(), // Store DbPool
        guard,
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
    let _persona_id = Uuid::new_v4(); // Placeholder, will be set after creation

    // Helper to assert persona state
    async fn assert_persona_state(
        service: &UserPersonaService,
        user: &User,
        dek: &SecretBox<Vec<u8>>,
        persona_id: Uuid,
        expected_name: &str,
        expected_description: &str,
        expected_spec: Option<&str>,
        expected_personality: Option<&str>,
        expected_scenario: Option<&str>,
        expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> AnyhowResult<UserPersonaDataForClient> {
        let fetched_persona = service
            .get_user_persona(user, Some(dek), persona_id)
            .await?;

        assert_eq!(fetched_persona.name, expected_name);
        assert_eq!(fetched_persona.description, expected_description);
        assert_eq!(fetched_persona.spec, expected_spec.map(|s| s.to_string()));
        assert_eq!(
            fetched_persona.personality,
            expected_personality.map(|s| s.to_string())
        );
        assert_eq!(
            fetched_persona.scenario,
            expected_scenario.map(|s| s.to_string())
        );

        if let Some(expected_ts) = expected_updated_at {
            assert_eq!(fetched_persona.updated_at, expected_ts);
        }
        Ok(fetched_persona)
    }

    // 1. Create initial persona
    let initial_create_dto = CreateUserPersonaDto {
        name: "Initial Name".to_string(),
        description: "Initial description.".to_string(),
        spec: Some("spec_v1".to_string()),
        personality: Some("Initial personality.".to_string()),
        scenario: None,
        ..Default::default()
    };
    let mut current_persona_state = ctx
        .service
        .create_user_persona(&ctx.user, &ctx.dek, initial_create_dto.clone())
        .await?;
    let persona_id = current_persona_state.id;

    // 2. Test Case: Update name and spec (non-encrypted)
    let update_dto_name_spec = UpdateUserPersonaDto {
        name: Some("Updated Name".to_string()),
        spec: Some("spec_v2".to_string()),
        ..Default::default()
    };
    current_persona_state = ctx
        .service
        .update_user_persona(
            &ctx.user,
            &ctx.dek,
            persona_id,
            update_dto_name_spec.clone(),
        )
        .await?;

    assert_eq!(current_persona_state.name, "Updated Name");
    assert_eq!(current_persona_state.spec, Some("spec_v2".to_string()));
    assert_eq!(
        current_persona_state.description, "",
        "Description should be cleared to empty string when DTO field is None and it's mandatory in client view"
    );
    assert!(
        current_persona_state.personality.is_none(),
        "Personality should be cleared to None when DTO field is None"
    );
    let original_updated_at = current_persona_state.updated_at;
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // 3. Test Case: Update description (encrypted) and set scenario (None to Some, encrypted)
    let update_dto_desc_scenario = UpdateUserPersonaDto {
        description: Some("Updated description.".to_string()),
        scenario: Some("New scenario added.".to_string()),
        ..Default::default()
    };
    current_persona_state = ctx
        .service
        .update_user_persona(
            &ctx.user,
            &ctx.dek,
            persona_id,
            update_dto_desc_scenario.clone(),
        )
        .await?;

    assert_eq!(current_persona_state.name, "Updated Name");
    assert_eq!(current_persona_state.description, "Updated description.");
    assert_eq!(
        current_persona_state.scenario,
        Some("New scenario added.".to_string())
    );
    assert!(current_persona_state.updated_at > original_updated_at);
    let previous_updated_at = current_persona_state.updated_at;
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // 4. Test Case: Update personality (Some to SomeOther, encrypted) and clear scenario (Some to None/empty)
    let update_dto_pers_clear_scenario = UpdateUserPersonaDto {
        personality: Some("Updated personality again.".to_string()),
        description: Some(current_persona_state.description.clone()), // Preserve description
        scenario: Some(String::new()),                                // Attempt to clear scenario
        ..Default::default()
    };
    current_persona_state = ctx
        .service
        .update_user_persona(
            &ctx.user,
            &ctx.dek,
            persona_id,
            update_dto_pers_clear_scenario.clone(),
        )
        .await?;

    assert_eq!(
        current_persona_state.personality,
        Some("Updated personality again.".to_string())
    );
    assert!(
        current_persona_state.scenario.is_none(),
        "Scenario should decrypt to None after being set to empty string update."
    );
    assert!(current_persona_state.updated_at > previous_updated_at);
    let last_updated_at = current_persona_state.updated_at;

    // 5. Verify by fetching again using the helper
    assert_persona_state(
        &ctx.service,
        &ctx.user,
        &ctx.dek,
        persona_id,
        "Updated Name",
        "Updated description.",
        Some("spec_v2"),
        Some("Updated personality again."),
        None,
        Some(last_updated_at),
    )
    .await?;

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
    let created_persona = ctx
        .service
        .create_user_persona(&ctx.user, &ctx.dek, create_dto)
        .await?;
    let original_updated_at = created_persona.updated_at;

    // Short delay to ensure updated_at would change IF an update occurs
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let update_dto_empty = UpdateUserPersonaDto::default();
    let result = ctx
        .service
        .update_user_persona(&ctx.user, &ctx.dek, created_persona.id, update_dto_empty)
        .await?;

    assert_eq!(result.name, created_persona.name);
    assert_eq!(
        result.description, "",
        "Description should be cleared to empty string when DTO field is None"
    );
    // The service *will* update `updated_at` even if no fields change because it re-saves the model.
    // This is because `changed` flag is set to `true` then the model is saved which updates the `updated_at` via DB trigger.
    // Let's read the service again. The service has a `changed` boolean.
    // If `changed` is false, it returns early *before* saving. So updated_at should NOT change.
    assert_ne!(
        result.updated_at, original_updated_at,
        "updated_at should change because description is cleared to empty string when DTO field is None."
    );

    Ok(())
}

#[tokio::test]
async fn test_update_user_persona_not_found() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let random_uuid = Uuid::new_v4();
    let update_dto = UpdateUserPersonaDto {
        name: Some("New Name".to_string()),
        ..Default::default()
    };

    let result = ctx
        .service
        .update_user_persona(&ctx.user, &ctx.dek, random_uuid, update_dto)
        .await;
    assert!(
        matches!(result, Err(AppError::NotFound(_))),
        "Expected NotFound, got {result:?}"
    );

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
    )
    .await?;
    guard2.add_user(user2.id);
    let dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    let dek2 = SecretBox::new(Box::new(dek2_bytes));

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1 Update Test".to_string(),
        description: "Belongs to user1.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1
        .service
        .create_user_persona(&ctx1.user, &ctx1.dek, create_dto)
        .await?;

    let update_dto = UpdateUserPersonaDto {
        name: Some("Attempted Update by User2".to_string()),
        ..Default::default()
    };
    let result = ctx1
        .service
        .update_user_persona(&user2, &dek2, persona_for_user1.id, update_dto)
        .await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "Expected Forbidden, got {result:?}"
    );

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
    let created_persona = ctx
        .service
        .create_user_persona(&ctx.user, &ctx.dek, create_dto)
        .await?;

    // Delete the persona
    let delete_result = ctx
        .service
        .delete_user_persona(&ctx.user, created_persona.id)
        .await;
    assert!(
        delete_result.is_ok(),
        "delete_user_persona failed: {:?}",
        delete_result.err()
    );

    // Try to get the deleted persona
    let get_result = ctx
        .service
        .get_user_persona(&ctx.user, Some(&ctx.dek), created_persona.id)
        .await;
    assert!(
        matches!(get_result, Err(AppError::NotFound(_))),
        "Expected NotFound after delete, got {get_result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_user_persona_not_found() -> AnyhowResult<()> {
    let ctx = setup_service_test().await?;
    let random_uuid = Uuid::new_v4();

    let delete_result = ctx
        .service
        .delete_user_persona(&ctx.user, random_uuid)
        .await;
    // The service first tries to fetch the persona. If not found, it returns NotFound.
    assert!(
        matches!(delete_result, Err(AppError::NotFound(_))),
        "Expected NotFound when deleting non-existent persona, got {delete_result:?}"
    );

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
    )
    .await?;
    guard2.add_user(user2.id);
    // let _dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    // let _dek2 = SecretBox::new(Box::new(_dek2_bytes)); // _dek2 is not used in this test

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1 Delete Test".to_string(),
        description: "Belongs to user1, user2 cannot delete.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1
        .service
        .create_user_persona(&ctx1.user, &ctx1.dek, create_dto)
        .await?;

    let delete_result = ctx1
        .service
        .delete_user_persona(&user2, persona_for_user1.id)
        .await;
    assert!(
        matches!(delete_result, Err(AppError::Forbidden)),
        "Expected Forbidden, got {delete_result:?}"
    );

    // Verify persona still exists for user1
    let get_result = ctx1
        .service
        .get_user_persona(&ctx1.user, Some(&ctx1.dek), persona_for_user1.id)
        .await;
    assert!(
        get_result.is_ok(),
        "Persona should still exist for user1 after forbidden delete attempt."
    );

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
    )
    .await?;
    guard2.add_user(user2.id);
    let dek2_bytes = user2_plaintext_dek.expose_secret().as_bytes().to_vec();
    let dek2 = SecretBox::new(Box::new(dek2_bytes));

    let create_dto = CreateUserPersonaDto {
        name: "Persona For User1".to_string(),
        description: "This persona belongs to user1.".to_string(),
        ..Default::default()
    };
    let persona_for_user1 = ctx1
        .service
        .create_user_persona(&ctx1.user, &ctx1.dek, create_dto)
        .await?;

    let result = ctx1
        .service
        .get_user_persona(&user2, Some(&dek2), persona_for_user1.id)
        .await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "Expected Forbidden, got {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_user_persona_service_set_default_persona() -> AnyhowResult<()> {
    let mut ctx = setup_service_test().await?;

    // 1. Create a persona to set as default
    let persona_create_dto = CreateUserPersonaDto {
        name: "Defaultable Persona".to_string(),
        description: "This persona can be set as default.".to_string(),
        ..Default::default()
    };
    let persona = ctx
        .service
        .create_user_persona(&ctx.user, &ctx.dek, persona_create_dto)
        .await?;
    ctx.guard.add_user_persona(persona.id); // Ensure cleanup

    // 2. Set the created persona as default
    let updated_user =
        UserPersonaService::set_default_persona(&ctx.db_pool, ctx.user.id, Some(persona.id))
            .await?;

    assert_eq!(updated_user.id, ctx.user.id);
    assert_eq!(
        updated_user.default_persona_id,
        Some(persona.id),
        "Default persona ID should be set on the returned user object."
    );

    // Verify directly from DB
    let pool_clone_1 = ctx.db_pool.clone();
    let user_id_clone_1 = ctx.user.id;
    let user_from_db = pool_clone_1
        .get()
        .await?
        .interact(move |conn_sync| {
            users_dsl::users
                .find(user_id_clone_1)
                .first::<UserDbQuery>(conn_sync)
                .map_err(AppError::from) // Ensure DieselError is converted
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("DB interact join error: {e}"))
        })??;
    assert_eq!(
        user_from_db.default_persona_id,
        Some(persona.id),
        "Default persona ID should be updated in the database."
    );

    // Update ctx.user to reflect the change for subsequent steps
    ctx.user = updated_user;

    // 3. Clear the default persona
    let cleared_user =
        UserPersonaService::set_default_persona(&ctx.db_pool, ctx.user.id, None).await?;

    assert_eq!(
        cleared_user.default_persona_id, None,
        "Default persona ID should be cleared on the returned user object."
    );

    let pool_clone_2 = ctx.db_pool.clone();
    let user_id_clone_2 = ctx.user.id;
    let user_from_db_after_clear = pool_clone_2
        .get()
        .await?
        .interact(move |conn_sync| {
            users_dsl::users
                .find(user_id_clone_2)
                .first::<UserDbQuery>(conn_sync)
                .map_err(AppError::from)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("DB interact join error: {e}"))
        })??;
    assert_eq!(
        user_from_db_after_clear.default_persona_id, None,
        "Default persona ID should be cleared in the database."
    );

    // 4. Set default persona to a non-existent (but valid UUID) persona ID
    // The service method itself doesn't validate existence, only the route handler does.
    let non_existent_persona_id = Uuid::new_v4();
    let user_with_non_existent_default = UserPersonaService::set_default_persona(
        &ctx.db_pool,
        ctx.user.id,
        Some(non_existent_persona_id),
    )
    .await;

    assert!(
        match user_with_non_existent_default {
            Err(AppError::DatabaseQueryError(ref s)) => {
                // Check if the error string contains typical foreign key violation text.
                // This is a bit brittle but necessary given the current AppError structure.
                // PostgreSQL typically includes "violates foreign key constraint"
                // and the constraint name like "fk_default_user_persona".
                s.contains("violates foreign key constraint")
                    && s.contains("fk_default_user_persona")
            }
            _ => false,
        },
        "Expected DatabaseQueryError indicating a ForeignKeyViolation when setting a non-existent persona as default, got {user_with_non_existent_default:?}"
    );

    Ok(())
}
