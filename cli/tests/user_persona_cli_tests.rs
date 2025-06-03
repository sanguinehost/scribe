#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_borrow)]

use assert_cmd::Command;
use predicates::prelude::*;
use regex::Regex;
use reqwest::cookie::Jar;
use scribe_backend::models::users::User;
use scribe_backend::test_helpers::{TestApp, create_user_with_dek_in_session, spawn_app};
use scribe_cli::{
    PersonaCreateArgs, PersonaDeleteArgs, PersonaGetArgs, PersonaUpdateArgs,
    client::{HttpClient, ReqwestClientWrapper},
    error::CliError,
    handlers::user_personas::{
        handle_persona_create_action, handle_persona_delete_action, handle_persona_get_action,
        handle_persona_list_action, handle_persona_update_action,
    },
    test_helpers::MockIoHandler,
};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;

// Helper function to create an authenticated HTTP client for tests
async fn get_authenticated_client(
    app: &TestApp,
) -> Result<(ReqwestClientWrapper, User), Box<dyn std::error::Error>> {
    let (user, auth_cookie) = create_user_with_dek_in_session(
        &app.router,
        &app.db_pool,
        format!("testuser_{}", Uuid::new_v4()),
        "password123".to_string(),
        None,
    )
    .await?;

    let cookie_jar = Arc::new(Jar::default());
    let url = app.address.parse::<Url>()?;
    cookie_jar.add_cookie_str(&auth_cookie, &url);

    let reqwest_native_client = reqwest::Client::builder()
        .cookie_provider(cookie_jar.clone())
        .danger_accept_invalid_certs(true)
        .build()?;

    let http_client = ReqwestClientWrapper::new(reqwest_native_client, url.clone());
    Ok((http_client, user))
}

// Updated helper function to use handler and authenticated client
async fn create_persona_and_get_id(
    http_client: &impl HttpClient, // Use trait object
    io_handler: &mut MockIoHandler,
    name: &str,
    description: &str,
    system_prompt: &str,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let create_args = PersonaCreateArgs {
        name: name.to_string(),
        description: description.to_string(),
        system_prompt: Some(system_prompt.to_string()),
        spec: None,
        spec_version: None,
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        post_history_instructions: None,
        tags: None,
        avatar: None,
    };

    handle_persona_create_action(http_client, io_handler, create_args)
        .await
        .map_err(|e| format!("Create persona handler failed: {}", e))?;

    // Extract ID from io_handler's output
    let output_str = io_handler.get_all_output().join(
        "
",
    );
    let re = Regex::new(
        r"ID: ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    )?;
    let caps = re
        .captures(&output_str)
        .ok_or("Could not find ID in handler output")?;
    let id_str = caps
        .get(1)
        .ok_or("Could not capture ID from handler output")?
        .as_str();
    Ok(Uuid::parse_str(id_str)?)
}

#[tokio::test]
async fn persona_cli_create_success() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();

    let persona_name = format!("Test Persona {}", Uuid::new_v4());
    let persona_description = "A description for CLI testing.";
    let persona_system_prompt = "System prompt for create test.";

    let create_args = PersonaCreateArgs {
        name: persona_name.clone(),
        description: persona_description.to_string(),
        system_prompt: Some(persona_system_prompt.to_string()),
        ..Default::default()
    };

    let result = handle_persona_create_action(&http_client, &mut mock_io, create_args).await;
    assert!(result.is_ok(), "Handler failed: {:?}", result.err());

    let output_str = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str.contains("Successfully created persona"));
    assert!(output_str.contains(&persona_name));
    assert!(output_str.contains(&persona_description));
    assert!(output_str.contains(&persona_system_prompt));

    let re = Regex::new(
        r"ID: ([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    )?;
    assert!(
        re.is_match(&output_str),
        "Expected to find persona ID in output: {}",
        output_str
    );

    Ok(())
}

#[tokio::test]
async fn persona_cli_create_missing_name() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    // For this test, we are testing clap's behavior, so direct CLI invocation is still appropriate.
    // No authentication is needed as clap should fail before hitting the backend.

    let persona_description = "A description for CLI testing.";
    let persona_system_prompt = "System prompt for missing name test.";

    let mut cmd = Command::cargo_bin("scribe-cli")?;
    cmd.arg("--base-url")
        .arg(&app.address)
        .arg("persona")
        .arg("create")
        .arg("--description")
        .arg(&persona_description)
        .arg("--system-prompt")
        .arg(&persona_system_prompt);

    cmd.assert().failure().stderr(
        predicate::str::contains(
            "the following required arguments were not provided:
  --name <NAME>",
        )
        .or(predicate::str::contains("Usage: scribe-cli persona create")),
    ); // Adjusted clap error

    Ok(())
}

#[tokio::test]
async fn persona_cli_list_success() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io_create = MockIoHandler::default(); // Separate mock_io for creation

    let persona_name1 = format!("List Test Persona {}", Uuid::new_v4());
    let persona_desc1 = "First persona for list test";
    let persona_sp1 = "System prompt for first list item";
    let id1 = create_persona_and_get_id(
        &http_client,
        &mut mock_io_create,
        &persona_name1,
        &persona_desc1,
        &persona_sp1,
    )
    .await?;
    mock_io_create.clear_output(); // Clear after creation

    let persona_name2 = format!("List Test Persona {}", Uuid::new_v4());
    let persona_desc2 = "Second persona for list test";
    let persona_sp2 = "System prompt for second list item";
    let id2 = create_persona_and_get_id(
        &http_client,
        &mut mock_io_create,
        &persona_name2,
        &persona_desc2,
        &persona_sp2,
    )
    .await?;

    let mut mock_io_list = MockIoHandler::default(); // New mock_io for list
    let list_result = handle_persona_list_action(&http_client, &mut mock_io_list).await;
    assert!(
        list_result.is_ok(),
        "List handler failed: {:?}",
        list_result.err()
    );

    let output_str = mock_io_list.get_all_output().join("\n");
    // Check for persona 1
    assert!(
        output_str.contains(&format!("- Name: {}", persona_name1)),
        "Output should contain name for persona 1. Output: {}",
        output_str
    );
    assert!(
        output_str.contains(&format!("  ID: {}", id1)),
        "Output should contain ID for persona 1. Output: {}",
        output_str
    );

    // Check for persona 2
    assert!(
        output_str.contains(&format!("- Name: {}", persona_name2)),
        "Output should contain name for persona 2. Output: {}",
        output_str
    );
    assert!(
        output_str.contains(&format!("  ID: {}", id2)),
        "Output should contain ID for persona 2. Output: {}",
        output_str
    );

    Ok(())
}

#[tokio::test]
async fn persona_cli_get_success() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io_create = MockIoHandler::default();

    let persona_name = format!("Get Test Persona {}", Uuid::new_v4());
    let persona_desc = "Persona for get test";
    let persona_system_prompt = "System prompt for get test";
    let persona_id = create_persona_and_get_id(
        &http_client,
        &mut mock_io_create,
        &persona_name,
        &persona_desc,
        &persona_system_prompt,
    )
    .await?;

    let mut mock_io_get = MockIoHandler::default();
    let get_args = PersonaGetArgs { id: persona_id };
    let get_result = handle_persona_get_action(&http_client, &mut mock_io_get, get_args).await;
    assert!(
        get_result.is_ok(),
        "Get handler failed: {:?}",
        get_result.err()
    );

    let output_str = mock_io_get.get_all_output().join(
        "
",
    );
    assert!(output_str.contains(&format!("--- Persona Details: {} ---", persona_name)));
    assert!(output_str.contains(&format!("ID: {}", persona_id)));
    assert!(output_str.contains(&format!("Description: {}", persona_desc)));
    assert!(output_str.contains(&format!("System Prompt: {}", persona_system_prompt)));

    Ok(())
}

#[tokio::test]
async fn persona_cli_update_success() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();

    let initial_name = format!("Initial Name {}", Uuid::new_v4());
    let initial_desc = "Initial description.";
    let initial_sp = "Initial system prompt.";
    let persona_id = create_persona_and_get_id(
        &http_client,
        &mut mock_io,
        &initial_name,
        &initial_desc,
        &initial_sp,
    )
    .await?;
    mock_io.clear_output(); // Clear after creation

    let updated_name = format!("Updated Name {}", Uuid::new_v4());
    let updated_desc = "Updated description.";
    let updated_sp = "Updated system prompt.";

    let update_args = PersonaUpdateArgs {
        id: persona_id,
        name: Some(updated_name.clone()),
        description: Some(updated_desc.to_string()),
        system_prompt: Some(updated_sp.to_string()),
        ..Default::default()
    };

    let update_result = handle_persona_update_action(&http_client, &mut mock_io, update_args).await;
    assert!(
        update_result.is_ok(),
        "Update handler failed: {:?}",
        update_result.err()
    );

    let output_str_update = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str_update.contains("Successfully updated persona"));
    // The update handler now calls print_persona_details, so we check its output format
    assert!(output_str_update.contains(&format!("--- Persona Details: {} ---", updated_name)));
    assert!(output_str_update.contains(&format!("ID: {}", persona_id)));
    assert!(output_str_update.contains(&format!("Description: {}", updated_desc)));
    assert!(output_str_update.contains(&format!("System Prompt: {}", updated_sp)));

    mock_io.clear_output(); // Clear before subsequent get

    // Verify with a subsequent 'get' action
    let get_args = PersonaGetArgs { id: persona_id };
    let get_result = handle_persona_get_action(&http_client, &mut mock_io, get_args).await;
    assert!(
        get_result.is_ok(),
        "Subsequent Get handler failed: {:?}",
        get_result.err()
    );

    let output_str_get = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str_get.contains(&format!("--- Persona Details: {} ---", updated_name)));
    assert!(output_str_get.contains(&format!("Description: {}", updated_desc)));
    assert!(output_str_get.contains(&format!("System Prompt: {}", updated_sp)));

    Ok(())
}

#[tokio::test]
async fn persona_cli_update_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();
    let non_existent_id = Uuid::new_v4();

    let update_args = PersonaUpdateArgs {
        id: non_existent_id,
        name: Some("Attempt Update".to_string()),
        ..Default::default()
    };

    let result = handle_persona_update_action(&http_client, &mut mock_io, update_args).await;
    assert!(
        result.is_err(),
        "Update handler should have failed for non-existent ID"
    );

    if let Some(CliError::ApiError { status, message }) = result.err() {
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND); // Or whatever status the API returns
        assert!(message.to_lowercase().contains("not found"));
    } else {
        panic!("Expected CliError::ApiError for not found");
    }
    // The mock_io output will contain the error message printed by the handler
    let output_str = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str.to_lowercase().contains("not found"));

    Ok(())
}

#[tokio::test]
async fn persona_cli_delete_success() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();

    let persona_name = format!("Delete Test Persona {}", Uuid::new_v4());
    let persona_desc = "Persona for delete test";
    let persona_sp = "System prompt for delete";
    let persona_id = create_persona_and_get_id(
        &http_client,
        &mut mock_io,
        &persona_name,
        &persona_desc,
        &persona_sp,
    )
    .await?;
    mock_io.clear_output();

    let delete_args = PersonaDeleteArgs { id: persona_id };
    let delete_result = handle_persona_delete_action(&http_client, &mut mock_io, delete_args).await;
    assert!(
        delete_result.is_ok(),
        "Delete handler failed: {:?}",
        delete_result.err()
    );

    let output_str_delete = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str_delete.contains(&format!(
        "Successfully deleted persona with ID: {}",
        persona_id
    )));

    mock_io.clear_output();

    // Verify with a subsequent 'get' command that it's not found
    let get_args = PersonaGetArgs { id: persona_id };
    let get_result = handle_persona_get_action(&http_client, &mut mock_io, get_args).await;
    assert!(
        get_result.is_err(),
        "Get handler should have failed for deleted ID"
    );

    if let Some(CliError::ApiError { status, message }) = get_result.err() {
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(message.to_lowercase().contains("not found"));
    } else {
        panic!("Expected CliError::ApiError for not found after delete");
    }
    let output_str_get = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str_get.to_lowercase().contains("not found"));

    Ok(())
}

#[tokio::test]
async fn persona_cli_delete_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();
    let non_existent_id = Uuid::new_v4();

    let delete_args = PersonaDeleteArgs {
        id: non_existent_id,
    };
    let result = handle_persona_delete_action(&http_client, &mut mock_io, delete_args).await;
    assert!(
        result.is_err(),
        "Delete handler should have failed for non-existent ID"
    );

    if let Some(CliError::ApiError { status, message }) = result.err() {
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(message.to_lowercase().contains("not found"));
    } else {
        panic!("Expected CliError::ApiError for not found");
    }
    let output_str = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str.to_lowercase().contains("not found"));

    Ok(())
}

#[tokio::test]
async fn persona_cli_get_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let app = spawn_app(false, false, false).await;
    let (http_client, _user) = get_authenticated_client(&app).await?;
    let mut mock_io = MockIoHandler::default();
    let non_existent_id = Uuid::new_v4();

    let get_args = PersonaGetArgs {
        id: non_existent_id,
    };
    let result = handle_persona_get_action(&http_client, &mut mock_io, get_args).await;
    assert!(
        result.is_err(),
        "Get handler should have failed for non-existent ID"
    );

    if let Some(CliError::ApiError { status, message }) = result.err() {
        assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
        assert!(message.to_lowercase().contains("not found"));
    } else {
        panic!("Expected CliError::ApiError for not found");
    }
    let output_str = mock_io.get_all_output().join(
        "
",
    );
    assert!(output_str.to_lowercase().contains("not found"));

    Ok(())
}
