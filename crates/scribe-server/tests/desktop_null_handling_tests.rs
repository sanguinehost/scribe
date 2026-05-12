#![cfg(feature = "sqlite-backend")]

use scribe_backend::{
    models::user_personas::CreateUserPersonaDto,
    services::UserPersonaService,
    test_helpers::{db::create_test_user, spawn_app},
};

#[tokio::test]
async fn test_create_persona_null_handling() {
    let app = spawn_app(false, false, false).await;

    let user = create_test_user(&app.db_pool, "testuser".to_string(), "password".to_string())
        .await
        .expect("Failed to create test user");

    let encryption_service = app.state.encryption_service.clone();
    let service = UserPersonaService::new(app.db_pool.clone(), encryption_service);

    let create_dto = CreateUserPersonaDto {
        name: "Test Persona".to_string(),
        description: "A test persona description".to_string(),
        spec: None,
        spec_version: None,
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: Some(vec![]),
        avatar: None,
    };

    let result = service
        .create_user_persona(&user, &user.dek.as_ref().unwrap().0, create_dto)
        .await;

    if let Err(e) = &result {
        println!("Failed to create persona: {:?}", e);
    }

    assert!(
        result.is_ok(),
        "Expected persona creation to succeed, but it failed"
    );
}
