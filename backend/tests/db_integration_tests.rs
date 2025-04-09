use diesel::prelude::*;
use diesel::pg::PgConnection;
use std::env;
use dotenvy::dotenv;
use uuid::Uuid;
use std::sync::Arc;
use diesel::r2d2::{ConnectionManager, Pool};
use scribe_backend::models::users::{User, NewUser};
use scribe_backend::models::character_card::{Character, NewCharacter};
use scribe_backend::schema;
use axum::extract::State;
use scribe_backend::routes::characters::list_characters;
use scribe_backend::state::AppState;

// --- DbPool Type ---
pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

// Helper function to establish a test database connection
// For now, reads DATABASE_URL. Ideally, use a separate TEST_DATABASE_URL
// and implement transaction rollback for isolation.
fn establish_connection() -> PgConnection {
    dotenv().ok(); // Load .env file if present

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

#[test]
fn test_user_character_insert_and_query() {
    let mut conn = establish_connection();

    // --- Insert User ---
    let test_username = format!("test_user_{}", Uuid::new_v4());
    let test_password_hash = "test_hash"; // Use a real hash in practice

    let new_user = NewUser {
        username: test_username.clone(),
        password_hash: test_password_hash,
    };

    let inserted_user: User = diesel::insert_into(schema::users::table)
        .values(&new_user)
        .get_result(&mut conn)
        .expect("Error inserting test user");

    assert_eq!(inserted_user.username, test_username);

    // --- Insert Character ---
    let test_char_name = format!("Test Character {}", Uuid::new_v4());
    let test_spec = "character_card_v2".to_string();
    let test_spec_version = "2.0".to_string();

    let new_character = NewCharacter {
        user_id: inserted_user.id, // Use the ID from the inserted user
        spec: test_spec.clone(),
        spec_version: test_spec_version.clone(),
        name: test_char_name.clone(),
        description: Some("A test character".to_string()),
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
    };

    let inserted_character: Character = diesel::insert_into(schema::characters::table)
        .values(new_character)
        .get_result(&mut conn)
        .expect("Error inserting test character");

    assert_eq!(inserted_character.name, test_char_name);
    assert_eq!(inserted_character.user_id, inserted_user.id);
    assert_eq!(inserted_character.spec, test_spec);

    // --- Query Character ---
    let found_character: Character = schema::characters::table
        .find(inserted_character.id) // Find by the ID we got back
        .first(&mut conn)
        .expect("Error finding inserted character");

    assert_eq!(found_character.id, inserted_character.id);
    assert_eq!(found_character.name, test_char_name);
    assert_eq!(found_character.user_id, inserted_user.id);

    // --- Cleanup (Manual for now, use transactions later) ---
    // It's better to wrap the test in a transaction and roll it back.
    // Manually deleting for this simple example.
    diesel::delete(schema::characters::table.find(inserted_character.id))
        .execute(&mut conn)
        .expect("Error deleting test character");

    diesel::delete(schema::users::table.find(inserted_user.id))
        .execute(&mut conn)
        .expect("Error deleting test user");

    println!("Successfully inserted and queried user and character.");
}

#[tokio::test] // Use tokio test macro for async fn
async fn test_list_characters_endpoint() {
    let mut conn = establish_connection(); // For test setup
    let pool = create_test_pool(); // Create pool for AppState
    let app_state = AppState { pool };

    // --- Setup Test Data ---
    // Insert a user
    let user = insert_test_user(&mut conn, "list_user");

    // Insert two characters for this user
    let char1 = insert_test_character(&mut conn, user.id, "List Character 1");
    let char2 = insert_test_character(&mut conn, user.id, "List Character 2");

    // --- Call Handler Function ---
    // Simulate calling the list_characters handler
    let result = list_characters(State(app_state)).await; // Pass mock state

    // --- Assertions ---
    assert!(result.is_ok(), "list_characters failed: {:?}", result.err());
    let json_response = result.unwrap();
    let characters_list = json_response.0; // Extract Vec<Character> from Json

    assert_eq!(characters_list.len(), 2, "Expected 2 characters, found {}", characters_list.len());

    // Check if the IDs of the inserted characters are present in the list
    let found_ids: std::collections::HashSet<Uuid> = characters_list.into_iter().map(|c| c.id).collect();
    assert!(found_ids.contains(&char1.id), "Character 1 not found in list");
    assert!(found_ids.contains(&char2.id), "Character 2 not found in list");

    println!("Successfully listed characters.");

    // --- Cleanup ---
    // Manual cleanup, replace with transaction rollback later
    diesel::delete(schema::characters::table.filter(schema::characters::id.eq_any(vec![char1.id, char2.id])))
        .execute(&mut conn)
        .expect("Error deleting test characters");
    diesel::delete(schema::users::table.find(user.id))
        .execute(&mut conn)
        .expect("Error deleting test user");
}

// --- Test Helper Functions ---

// Helper to create a pool for tests
fn create_test_pool() -> DbPool {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for test pool");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .expect("Failed to create test DB pool.");
    Arc::new(pool)
}

// Helper to insert a unique test user
fn insert_test_user(conn: &mut PgConnection, prefix: &str) -> User {
    let test_username = format!("{}_{}", prefix, Uuid::new_v4());
    let new_user = NewUser {
        username: test_username.clone(),
        password_hash: "test_hash",
    };
    diesel::insert_into(schema::users::table)
        .values(&new_user)
        .get_result(conn)
        .expect(&format!("Error inserting test user {}", test_username))
}

// Helper to insert a test character
fn insert_test_character(conn: &mut PgConnection, user_uuid: Uuid, name: &str) -> Character {
    let new_character = NewCharacter {
        user_id: user_uuid,
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        name: name.to_string(),
        description: None, personality: None, scenario: None, first_mes: None,
        mes_example: None, creator_notes: None, system_prompt: None,
        post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None,
        creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None,
    };
    diesel::insert_into(schema::characters::table)
        .values(new_character)
        .get_result(conn)
        .expect(&format!("Error inserting test character {}", name))
}

// TODO: Add tests for assets, lorebooks, entries, chat etc.
// TODO: Implement proper transaction management for test isolation.
// TODO: Use a dedicated TEST_DATABASE_URL. 