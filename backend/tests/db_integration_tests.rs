use anyhow::Error as AnyhowError; // For manual cleanup test return type
use axum::extract::State;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::result::Error as DieselError; // Keep alias for test_transaction test
use dotenvy::dotenv;
use scribe_backend::models::character_card::{Character, NewCharacter};
use scribe_backend::models::users::{NewUser, User};
use scribe_backend::routes::characters::list_characters;
use scribe_backend::schema::{self, characters, users}; // Added schema imports
use scribe_backend::state::AppState;
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use uuid::Uuid; // For manual cleanup test assertion
use scribe_backend::models::chat::{
    ChatSession, MessageType, NewChatMessage, NewChatSession, ChatMessage,
};
use scribe_backend::schema::{chat_messages, chat_sessions};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use bigdecimal::BigDecimal; // Add this import
use std::str::FromStr; // Add this import

// --- DbPool Type ---
pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

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

// Helper to create a pool for tests
fn create_test_pool() -> DbPool {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .test_on_check_out(true)
        .max_size(5) // Use a slightly larger pool for tests
        .build(manager)
        .expect("Failed to create test DB pool.");
    Arc::new(pool)
}

// Helper to insert a unique test user (returns Result)
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
    user_uuid: Uuid,
    name: &str,
) -> Result<Character, DieselError> {
    let new_character = NewCharacter {
        user_id: user_uuid,
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        name: name.to_string(),
        ..Default::default() // Use default for other fields
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

impl Drop for TestDataGuard {
    fn drop(&mut self) {
        if self.character_ids.is_empty() && self.user_ids.is_empty() {
            return;
        }
        println!("--- Cleaning up integration test data ---");
        let mut conn = self
            .pool
            .get()
            .expect("Failed to get DB connection for cleanup");

        if !self.character_ids.is_empty() {
            let delete_chars = diesel::delete(
                characters::table.filter(characters::id.eq_any(&self.character_ids)),
            )
            .execute(&mut conn);
            if let Err(e) = delete_chars {
                eprintln!("Error cleaning up characters: {:?}", e);
            } else {
                println!("Cleaned up {} characters.", self.character_ids.len());
            }
        }

        if !self.user_ids.is_empty() {
            let delete_users =
                diesel::delete(users::table.filter(users::id.eq_any(&self.user_ids)))
                    .execute(&mut conn);
            if let Err(e) = delete_users {
                eprintln!("Error cleaning up users: {:?}", e);
            } else {
                println!("Cleaned up {} users.", self.user_ids.len());
            }
        }
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
            ..Default::default() // Use default for other fields
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
    let mut conn = pool.get()?; // Get connection from the pool

    // --- Setup Test Data ---
    // Clean first (optional but safer)
    diesel::delete(characters::table).execute(&mut conn)?;
    diesel::delete(users::table).execute(&mut conn)?;

    // Insert a user
    let user = insert_test_user(&mut conn, "list_user")?;
    guard.add_user(user.id); // Register for cleanup

    // Insert two characters for this user
    let char1 = insert_test_character(&mut conn, user.id, "List Character 1")?;
    let char2 = insert_test_character(&mut conn, user.id, "List Character 2")?;
    guard.add_character(char1.id); // Register for cleanup
    guard.add_character(char2.id); // Register for cleanup

    // --- Call Handler Function ---
    let app_state = AppState { pool: pool.clone() }; // Create AppState with the same pool
    let result = list_characters(State(app_state)).await; // Call handler directly

    // --- Assertions ---
    assert!(result.is_ok(), "list_characters failed: {:?}", result.err());
    let json_response = result.unwrap();
    let characters_list = json_response.0; // Extract Vec<Character> from Json

    // Filter results to only those created in this test
    let inserted_ids: HashSet<Uuid> = vec![char1.id, char2.id].into_iter().collect();
    let relevant_characters_from_api: Vec<&Character> = characters_list
        .iter()
        .filter(|c| inserted_ids.contains(&c.id))
        .collect();

    assert_eq!(
        relevant_characters_from_api.len(),
        2,
        "Expected 2 test characters, found {}",
        relevant_characters_from_api.len()
    );

    // Check if the IDs of the inserted characters are present in the list
    let found_ids: HashSet<Uuid> = relevant_characters_from_api
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert!(
        found_ids.contains(&char1.id),
        "Character 1 not found in list"
    );
    assert!(
        found_ids.contains(&char2.id),
        "Character 2 not found in list"
    );

    println!("Successfully listed characters via handler.");
    Ok(()) // Guard will clean up when test finishes
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

#[tokio::test]
async fn test_chat_message_insert_and_query() -> Result<(), AnyhowError> {
    let pool = create_test_pool();
    let mut guard = TestDataGuard::new(pool.clone());
    let mut conn = pool.get()?;

    let user = insert_test_user(&mut conn, "message_user")?;
    guard.add_user(user.id);

    let character = insert_test_character(&mut conn, user.id, "Message Character")?;
    guard.add_character(character.id);

    let session = {
        let new_session = NewChatSession {
            user_id: user.id,
            character_id: character.id,
            ..Default::default()
        };
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .get_result::<ChatSession>(&mut conn)?
    };

    let test_content = "This is a test message.".to_string();
    let new_message = NewChatMessage {
        session_id: session.id,
        message_type: MessageType::User,
        content: test_content.clone(),
        rag_embedding_id: None,
    };

    let inserted_message: ChatMessage = diesel::insert_into(chat_messages::table)
        .values(&new_message)
        .get_result(&mut conn)?;

    assert_eq!(inserted_message.session_id, session.id);
    assert_eq!(inserted_message.message_type, MessageType::User);
    assert_eq!(inserted_message.content, test_content);
    assert!(inserted_message.rag_embedding_id.is_none());

    let found_message: ChatMessage = chat_messages::table
        .find(inserted_message.id)
        .first(&mut conn)?;

    assert_eq!(found_message.id, inserted_message.id);
    assert_eq!(found_message.session_id, session.id);
    assert_eq!(found_message.content, test_content);

    println!("Successfully inserted and queried chat message (manual cleanup).");
    Ok(())
}

// TODO: Add tests for assets, lorebooks, entries, chat etc.
// TODO: Implement proper transaction management for test isolation. (Consider TestDataGuard sufficient for now)
// TODO: Use a dedicated TEST_DATABASE_URL.
