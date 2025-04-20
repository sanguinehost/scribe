#![cfg(test)]

use anyhow::Error as AnyhowError; // For manual cleanup test return type
use axum::extract::State;
 // <-- Add import for Json extractor/response type
use axum::response::IntoResponse; // <-- ADD THIS IMPORT
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::result::Error as DieselError; // Keep alias for test_transaction test
use dotenvy::dotenv;
use scribe_backend::errors::AppError; // Import AppError
use scribe_backend::models::characters::{Character, NewCharacter};
use scribe_backend::models::chat::{ChatMessage, NewChatMessage};
use scribe_backend::models::users::{NewUser, User};
use scribe_backend::routes::characters::list_characters_handler; // Updated handler name
use scribe_backend::schema::{self, characters, users}; // Added schema imports
use scribe_backend::state::AppState;
use std::env;
use uuid::Uuid; // For manual cleanup test assertion
use scribe_backend::models::chat::{
    ChatSession, MessageType, NewChatSession,
};
use scribe_backend::schema::{chat_messages, chat_sessions};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use bigdecimal::BigDecimal; // Add this import
use std::str::FromStr; // Add this import
use deadpool_diesel::postgres::Manager as DeadpoolManager;
use deadpool_diesel::{Pool as DeadpoolPool, Runtime as DeadpoolRuntime};
use axum::http::StatusCode;
use http_body_util::BodyExt;

// --- DbPool Type ---
use scribe_backend::state::DbPool;

// Embed migrations for the test context
// NOTE: This assumes the test binary is run with the working directory
// at the root of the `scribe-backend` crate, like `cargo test` does.
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

// Helper function to establish a test database connection (used by test_transaction test)
fn establish_connection() -> PgConnection {
    dotenv().ok(); // Load .env file if present

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url).expect(&format!("Error connecting to {}", database_url))
}

// --- Test Helper Functions ---

// Updated helper to create a deadpool pool for tests - made public
pub fn create_test_pool() -> DbPool {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = DeadpoolManager::new(&database_url, DeadpoolRuntime::Tokio1);
    let pool = DeadpoolPool::builder(manager)
        // .max_size(5) // Example: configure max size
        .build()
        .expect("Failed to create test DB pool.");
    pool // Return the pool directly (it's Clone)
}

// Helper to insert a unique test user (returns Result) - kept private
fn insert_test_user(conn: &mut PgConnection, prefix: &str) -> Result<User, DieselError> {
    let test_username = format!("{}_{}", prefix, Uuid::new_v4());
    let new_user = NewUser {
        username: test_username.clone(),
        password_hash: "test_hash",
    };
    diesel::insert_into(schema::users::table)
        .values(&new_user)
        .get_result(conn)
    // .expect(&format!("Error inserting test user {}", test_username)) // Use Result instead
}

// Helper to insert a test character (returns Result)
fn insert_test_character(
    conn: &mut PgConnection,
    user_id: Uuid,
    name: &str,
) -> Result<Character, DieselError> {
    let new_character = NewCharacter {
        user_id,
        spec: Some("test_spec".to_string()),
        spec_version: Some("1.0".to_string()),
        name: name.to_string(),
        description: None,
        personality: None,
        first_mes: None,
        mes_example: None,
        scenario: None,
        system_prompt: None,
        creator_notes: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
    };
    diesel::insert_into(schema::characters::table)
        .values(new_character)
        .get_result(conn)
    // .expect(&format!("Error inserting test character {}", name)) // Use Result instead
}

// Helper struct to manage test data cleanup (copied from other file)
struct TestDataGuard {
    pool: DbPool,
    user_ids: Vec<Uuid>,
    character_ids: Vec<Uuid>,
}

impl TestDataGuard {
    fn new(pool: DbPool) -> Self {
        TestDataGuard {
            pool,
            user_ids: Vec::new(),
            character_ids: Vec::new(),
        }
    }

    fn add_user(&mut self, user_id: Uuid) {
        self.user_ids.push(user_id);
    }

    fn add_character(&mut self, character_id: Uuid) {
        self.character_ids.push(character_id);
    }
}

// Implement Drop asynchronously
// #[async_trait] // Would require adding async_trait dependency
impl Drop for TestDataGuard {
    fn drop(&mut self) {
        // WARNING: drop() cannot be async. Using block_on for cleanup.
        // This can block the thread dropping the guard. Consider alternatives.
        let pool_clone = self.pool.clone();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                // Get the actual deadpool object
                let obj = pool_clone.get().await.expect("Failed to get DB conn for cleanup in drop");

                if !self.character_ids.is_empty() {
                    let ids = self.character_ids.clone(); // Clone IDs for the interact closure
                    let delete_chars_result = obj.interact(move |conn| { // Force move
                        diesel::delete(
                            characters::table.filter(characters::id.eq_any(ids)),
                        )
                        .execute(conn) // Execute uses the conn passed by interact
                    }).await; // await the interact future

                    if let Err(e) = delete_chars_result {
                        eprintln!("Error cleaning up characters: {:?}", e);
                    } else {
                        println!("Cleaned up {} characters.", self.character_ids.len());
                    }
                }

                if !self.user_ids.is_empty() {
                    let ids = self.user_ids.clone(); // Clone IDs for the interact closure
                    let delete_users_result = obj.interact(move |conn| { // Force move
                        diesel::delete(users::table.filter(users::id.eq_any(ids)))
                        .execute(conn) // Execute uses the conn passed by interact
                    }).await; // await the interact future

                    if let Err(e) = delete_users_result {
                        eprintln!("Error cleaning up users: {:?}", e);
                    } else {
                        println!("Cleaned up {} users.", self.user_ids.len());
                    }
                }
            }); // End block_on
        println!("--- Integration cleanup complete ---");
    }
}

// --- Tests ---

#[test]
fn test_user_character_insert_and_query() {
    let mut conn = establish_connection();

    // Start a transaction
    conn.test_transaction::<_, DieselError, _>(|conn| {
        // --- Insert User ---
        let test_username = format!("test_user_{}", Uuid::new_v4());
        let test_password_hash = "test_hash"; // Use a real hash in practice

        let new_user = NewUser {
            username: test_username.clone(),
            password_hash: test_password_hash,
        };

        let inserted_user: User = diesel::insert_into(schema::users::table)
            .values(&new_user)
            .get_result(conn)?; // Use ? for error propagation

        assert_eq!(inserted_user.username, test_username);

        // --- Insert Character ---
        let test_char_name = format!("Test Character {}", Uuid::new_v4());

        let new_character = NewCharacter {
            user_id: inserted_user.id, // Use the ID from the inserted user
            name: test_char_name.clone(),
            spec: Some("test_spec".to_string()),
            spec_version: Some("1.0".to_string()),
            description: None,
            personality: None,
            first_mes: None,
            mes_example: None,
            scenario: None,
            system_prompt: None,
            creator_notes: None,
            tags: None,
            creator: None,
            character_version: None,
            alternate_greetings: None,
            nickname: None,
            source: None,
            group_only_greetings: None,
            creation_date: None,
            modification_date: None,
        };

        let inserted_character: Character = diesel::insert_into(schema::characters::table)
            .values(new_character)
            .get_result(conn)?; // Use ?

        assert_eq!(inserted_character.name, test_char_name);
        assert_eq!(inserted_character.user_id, inserted_user.id);

        // --- Query Character ---
        let found_character: Character = schema::characters::table
            .find(inserted_character.id) // Find by the ID we got back
            .first(conn)?; // Use ?

        assert_eq!(found_character.id, inserted_character.id);
        assert_eq!(found_character.name, test_char_name);
        assert_eq!(found_character.user_id, inserted_user.id);

        println!("Successfully inserted and queried user and character.");
        Ok(())
    });
}

// Refactored test using manual cleanup
#[tokio::test]
async fn test_list_characters_endpoint_manual_cleanup() -> Result<(), AnyhowError> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    // Get connection object from pool
    let obj = pool.get().await?; // Use await?

    // --- Setup Test Data ---
    // Clean first (optional but safer)
    // Run deletes within interact
    let delete_chars_result = obj.interact(|conn| diesel::delete(characters::table).execute(conn)).await;
    match delete_chars_result {
        Ok(Ok(_)) => (), // Success
        Ok(Err(e)) => return Err(AnyhowError::new(AppError::DatabaseError(e))), // Map Diesel error
        Err(e) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact Error deleting chars: {:?}", e)))), // Map InteractError
    };

    let delete_users_result = obj.interact(|conn| diesel::delete(users::table).execute(conn)).await;
    match delete_users_result {
        Ok(Ok(_)) => (), // Success
        Ok(Err(e)) => return Err(AnyhowError::new(AppError::DatabaseError(e))),
        Err(e) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact Error deleting users: {:?}", e)))),
    };

    // Insert a user
    // Use interact to insert user
    let insert_user_result = obj.interact(|conn| insert_test_user(conn, "list_user")).await;
    let user = match insert_user_result {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => return Err(AnyhowError::new(AppError::DatabaseError(e))),
        Err(e) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact Error inserting user: {:?}", e)))),
    };
    guard.add_user(user.id); // Register for cleanup

    // Insert two characters for this user
    let user_id_clone1 = user.id; // Clone user ID for the closure
    let insert_char1_result = obj.interact(move |conn| insert_test_character(conn, user_id_clone1, "List Test 1")).await;
    let char1 = match insert_char1_result {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(AnyhowError::new(AppError::DatabaseError(e))),
        Err(e) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact Error inserting char1: {:?}", e)))),
    };
    guard.add_character(char1.id);

    let user_id_clone2 = user.id; // Clone user ID again for the second closure
    let insert_char2_result = obj.interact(move |conn| insert_test_character(conn, user_id_clone2, "List Test 2")).await;
    let char2 = match insert_char2_result {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(AnyhowError::new(AppError::DatabaseError(e))),
        Err(e) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact Error inserting char2: {:?}", e)))),
    };
    guard.add_character(char2.id);

    // Prepare state and user extension for handler call
    let app_state = AppState { pool };
    // Create a dummy User extension - the real middleware would populate this
    // let user_extension = axum::Extension(user.clone()); // Assuming user data needed via Extension

    // Call the handler directly with State
    // FIXME: The handler likely gets user_id from Claims provided by middleware,
    // not directly from an Extension<User>.
    // Adjust this call based on the actual `list_characters` signature and auth mechanism.
    let result = list_characters_handler(State(app_state)).await; // REMOVED user_extension argument

    // Assert success and parse response
    let response = result.into_response();

    // --- Assertions ---
    assert_eq!(response.status(), StatusCode::OK, "Expected OK status code");

    // Extract and deserialize the body on success
    let body_bytes = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return Err(AnyhowError::new(e).context("Failed to collect response body")),
    };
    
    match serde_json::from_slice::<Vec<Character>>(&body_bytes) {
        Ok(characters) => {
            assert_eq!(characters.len(), 2);
            let mut names: Vec<String> = characters.into_iter().map(|c| c.name).collect();
            names.sort(); // Sort for consistent comparison
            assert_eq!(names, vec!["List Test 1", "List Test 2"]);
            println!("Successfully listed characters via handler.");
        }
        Err(e) => {
            // Body wasn't the expected Vec<Character>
            return Err(AnyhowError::new(e).context(format!(
                "Failed to deserialize OK response body: {}",
                String::from_utf8_lossy(&body_bytes)
            )));
        }
    }
    
    Ok(())
    // Guard will automatically clean up when it goes out of scope here
}

// --- New Tests ---

#[test]
fn test_migrations_run_cleanly() {
    let mut conn = establish_connection();
    // Attempt to run migrations within a test transaction.
    // This doesn't guarantee all migrations *were* run previously,
    // but checks if the current set applies cleanly to the DB state.
    conn.test_transaction::<_, Box<dyn std::error::Error + Send + Sync>, _>(|conn| {
        match conn.run_pending_migrations(MIGRATIONS) {
            Ok(versions) => {
                println!("Applied migrations in test: {:?}", versions);
                Ok(())
            }
            Err(e) => {
                eprintln!("Failed to run migrations in test: {:?}", e);
                Err(e)
                // Manually fail the test if migrations fail
                // panic!("Migration test failed: {:?}", e);
            }
        }
    });
}

#[test]
fn test_chat_session_insert_and_query() {
    let mut conn = establish_connection();
    conn.test_transaction::<_, DieselError, _>(|conn| {
        // --- Setup: Insert User and Character ---
        let user = insert_test_user(conn, "session_user")?;
        let character = insert_test_character(conn, user.id, "Session Character")?;

        // --- Insert Chat Session ---
        let new_session = NewChatSession {
            user_id: user.id,
            character_id: character.id,
            // Optional fields can be None or set
            system_prompt: Some("Test System Prompt".to_string()),
            temperature: Some(BigDecimal::from_str("0.8").unwrap()), // Convert float to BigDecimal
            max_output_tokens: Some(256),
            title: None, // Add missing title field
        };

        let inserted_session: ChatSession = diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .get_result(conn)?;

        assert_eq!(inserted_session.user_id, user.id);
        assert_eq!(inserted_session.character_id, character.id);
        assert_eq!(inserted_session.system_prompt, new_session.system_prompt);
        assert_eq!(inserted_session.temperature, new_session.temperature);
        assert_eq!(
            inserted_session.max_output_tokens,
            new_session.max_output_tokens
        );

        // --- Query Chat Session ---
        let found_session: ChatSession = chat_sessions::table
            .find(inserted_session.id)
            .first(conn)?;

        assert_eq!(found_session.id, inserted_session.id);
        assert_eq!(found_session.user_id, user.id);
        assert_eq!(found_session.character_id, character.id);

        println!("Successfully inserted and queried chat session.");
        Ok(())
    });
}

// Test chat message insertion and querying - Updated to async
#[tokio::test]
async fn test_chat_message_insert_and_query() -> Result<(), AnyhowError> {
    let pool = create_test_pool();
    let obj = pool.get().await?;
    let mut guard = TestDataGuard::new(pool.clone());

    // Start a transaction (using interact)
    let interact_result = obj.interact(move |conn| {
        // Note: test_transaction doesn't work well inside interact.
        // We'll perform operations directly and rely on guard for cleanup.

        // --- Setup: Insert User and Character ---
        let user = insert_test_user(conn, "chat_msg_user")?;
        guard.add_user(user.id);

        let character = insert_test_character(conn, user.id, "Chat Message Character")?;
        guard.add_character(character.id);

        let session = {
            let new_session = NewChatSession {
                user_id: user.id,
                character_id: character.id,
                ..Default::default()
            };
            diesel::insert_into(chat_sessions::table)
                .values(&new_session)
                .get_result::<ChatSession>(conn)?
        };

        let session_id = session.id;

        // --- Insert Chat Message ---
        let user_message = NewChatMessage {
            session_id,
            message_type: MessageType::User,
            content: "Hello, character!".to_string(),
            rag_embedding_id: None,
        };

        let inserted_user_msg: ChatMessage = diesel::insert_into(chat_messages::table)
            .values(&user_message)
            .get_result(conn)?;

        // --- Query Messages ---
        let messages: Vec<ChatMessage> = chat_messages::table
            .filter(chat_messages::session_id.eq(session_id))
            .order(chat_messages::created_at.asc())
            .load(conn)?;

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, "Hello, character!");
        assert_eq!(messages[0].message_type, MessageType::User);
        assert_eq!(messages[1].content, "Hello, user!");
        assert_eq!(messages[1].message_type, MessageType::Ai);

        Ok(()) // Return Ok from closure
    }).await; // Get Result<Result<_, DieselError>, InteractError>

    // Explicitly handle errors to satisfy AnyhowError + Sync requirements
    match interact_result {
        Ok(Ok(())) => (), // Inner closure succeeded
        Ok(Err(diesel_error)) => return Err(AnyhowError::new(AppError::DatabaseError(diesel_error))),
        Err(interact_error) => return Err(AnyhowError::new(AppError::InternalServerError(anyhow::anyhow!("Interact error: {:?}", interact_error)))),
    };

    Ok(())
}

// TODO: Add tests for assets, lorebooks, entries, chat etc.
// TODO: Implement proper transaction management for test isolation. (Consider TestDataGuard sufficient for now)
// TODO: Use a dedicated TEST_DATABASE_URL.
