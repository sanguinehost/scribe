use axum::Router;
use deadpool_diesel::postgres::{Manager as DeadpoolManager, Pool as DeadpoolPool, Runtime as DeadpoolRuntime, PoolConfig};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use scribe_backend::auth::{session_store::DieselSessionStore, user_store::Backend as AuthBackend};
use scribe_backend::PgPool;
use scribe_backend::state::AppState;
use std::net::TcpListener;
use std::env;
use uuid::Uuid;
use tower_cookies::CookieManagerLayer;
use tower_sessions::{Expiry, SessionManagerLayer};
use axum_login::AuthManagerLayerBuilder;
use time;
use scribe_backend::models::{
    users::{User, NewUser},
    characters::Character,
    character_card::NewCharacter,
    chat::{ChatSession, NewChatSession, ChatMessage, NewChatMessage, MessageType},
};
use scribe_backend::schema;
use diesel::RunQueryDsl;
use bcrypt;
use axum::{
    body::Body,
    http::{header::SET_COOKIE, Method, Request, StatusCode},
};
use tower::ServiceExt;
use scribe_backend::config::Config;
use std::sync::Arc;
use diesel::SelectableHelper;
use diesel::prelude::*;

// Define the embedded migrations macro
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations"); // Use relative path from crate root

/// Structure to hold information about the running test application.
pub struct TestApp {
    pub address: String,
    pub router: Router, // The configured Axum router
    pub db_pool: PgPool,
    // Add other relevant fields, e.g., http client if needed for direct API calls
}

/// Sets up the application state and router for integration testing, WITHOUT spawning a server.
pub async fn spawn_app() -> TestApp {
    // Ensure tracing subscriber is initialized for tests
    // Use std::sync::Once to ensure it's only called once
    static TRACING_INIT: std::sync::Once = std::sync::Once::new();
    TRACING_INIT.call_once(|| {
         // Could use test-specific subscriber settings if needed
        scribe_backend::logging::init_subscriber();
    });
    
    dotenvy::dotenv().ok(); // Load .env for test environment variables

    // --- Database Setup ---
    let db_name = format!("test_db_{}", Uuid::new_v4());
    let base_db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set for testing");
    let (main_db_url, _) = base_db_url.rsplit_once('/').expect("Invalid DATABASE_URL format");
    
    let manager_default = DeadpoolManager::new(format!("{}/postgres", main_db_url), DeadpoolRuntime::Tokio1);
    let pool_default = DeadpoolPool::builder(manager_default).max_size(1).build().expect("Failed to create default DB pool");
    let conn_default = pool_default.get().await.expect("Failed to get default DB connection");
    
    let db_name_clone = db_name.clone(); 
    conn_default.interact(move |conn| {
        diesel::sql_query(format!("DROP DATABASE IF EXISTS \"{}\"", db_name_clone))
            .execute(conn).expect("Failed to drop test DB");
        diesel::sql_query(format!("CREATE DATABASE \"{}\"", db_name_clone))
            .execute(conn).expect("Failed to create test DB");
        Ok::<(), diesel::result::Error>(())
    }).await.expect("DB interaction failed").expect("Failed to create test DB");

    // Use the original db_name here
    let test_db_url_unquoted = format!("{}/{}", main_db_url, db_name);
    let manager = DeadpoolManager::new(test_db_url_unquoted.clone(), DeadpoolRuntime::Tokio1);
    let pool_config = PoolConfig::default();
    let db_pool = DeadpoolPool::builder(manager)
        .config(pool_config)
        .build()
        .expect("Failed to create test DB pool");

    // Run migrations on the test database
    let conn = db_pool.get().await.expect("Failed to get test DB connection for migration");
    conn.interact(|conn| conn.run_pending_migrations(MIGRATIONS).map(|_| ())) // Discard version info
        .await
        .expect("Migration interact task failed")
        .expect("Failed to run migrations on test DB");

    // --- Listener Setup ---
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://127.0.0.1:{}", port);
    // We get the address but don't actually use the listener to serve

    // --- Auth Setup ---
    let session_store = DieselSessionStore::new(db_pool.clone());
    let session_manager_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // Required for tests, SessionManagerLayer handles signing/encryption
        .with_same_site(cookie::SameSite::Lax) // Use cookie::SameSite
        .with_expiry(Expiry::OnInactivity(time::Duration::days(1)));

    let auth_layer = AuthManagerLayerBuilder::new(AuthBackend::new(db_pool.clone()), session_manager_layer).build();

    // --- AppState ---
    let config = Arc::new(Config::load().expect("Failed to load test configuration"));
    let app_state = AppState::new(db_pool.clone(), config);

    // --- Router Setup (mirroring main.rs structure) ---
    use scribe_backend::routes::{
        auth::{register_handler, login_handler, logout_handler, me_handler},
        characters::{get_character_handler, list_characters_handler, upload_character_handler},
        chat::chat_routes,
        health::health_check,
    };
    use axum_login::login_required;

    let protected_api_routes = Router::new()
        .route("/auth/me", axum::routing::get(me_handler))
        .route("/auth/logout", axum::routing::post(logout_handler))
        .nest("/characters", 
            Router::new()
                .route("/upload", axum::routing::post(upload_character_handler))
                .route("/", axum::routing::get(list_characters_handler))
                .route("/{id}", axum::routing::get(get_character_handler))
        )
        .nest("/chats", chat_routes()) 
        .route_layer(login_required!(AuthBackend, login_url = "/api/auth/login"));

    let public_api_routes = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/auth/register", axum::routing::post(register_handler))
        .route("/auth/login", axum::routing::post(login_handler));

    let app_router = Router::new()
        .nest("/api", public_api_routes)
        .nest("/api", protected_api_routes)
        .layer(CookieManagerLayer::new())
        .layer(auth_layer)
        .with_state(app_state);
    
    // --- DO NOT Run Server (in background) ---
    // The router will be called directly using oneshot
    
    TestApp {
        address, // Keep address for building request URIs
        router: app_router, // Return the router for direct calls via oneshot
        db_pool,
    }
}

// --- Database Helper Functions ---

pub async fn create_test_user(
    pool: &PgPool,
    username: &str,
    password: &str,
) -> User {
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .expect("Failed to hash password");

    let new_user = NewUser {
        username: username.to_string(),
        password_hash: hashed_password, // Assign String directly
    };

    let conn = pool.get().await.expect("Failed to get DB conn for create_user");
    conn.interact(move |conn| {
        diesel::insert_into(schema::users::table)
            .values(&new_user)
            .get_result::<User>(conn)
            .expect("Failed to insert test user")
    })
    .await
    .expect("Interact failed for create_user")
}

pub async fn create_test_character(
    pool: &PgPool,
    user_id: Uuid,
    name: &str,
) -> Character {
    let new_character = NewCharacter {
        user_id,
        spec: "chara_card_v2".to_string(),
        spec_version: "2.0".to_string(),
        name: name.to_string(),
        description: Some(format!("Description for {}", name)),
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
        extensions: None,
    };

    let conn = pool.get().await.expect("Failed to get DB conn for create_character");
    conn.interact(move |conn| {
        diesel::insert_into(schema::characters::table)
            .values(&new_character)
            .returning(Character::as_select())
            .get_result::<Character>(conn)
            .expect("Failed to insert test character")
    })
    .await
    .expect("Interact failed for create_character")
}

pub async fn create_test_chat_session(
    pool: &PgPool,
    user_id: Uuid,
    character_id: Uuid,
) -> ChatSession {
    let new_session = NewChatSession {
        user_id,
        character_id,
        title: Some(format!("Test Chat {}", Uuid::new_v4().to_string().split('-').next().unwrap_or(""))),
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
    };

    let conn = pool.get().await.expect("Failed to get DB conn for create_chat_session");
    conn.interact(move |conn| {
        diesel::insert_into(schema::chat_sessions::table)
            .values(&new_session)
            .get_result::<ChatSession>(conn)
            .expect("Failed to insert test chat session")
    })
    .await
    .expect("Interact failed for create_chat_session")
}

// Helper to fetch a chat session directly from DB (used for verification)
pub async fn get_chat_session_from_db(pool: &PgPool, session_id: Uuid) -> Option<ChatSession> {
    let conn = pool.get().await.expect("Failed to get DB conn for get_chat_session");
    conn.interact(move |conn| {
        schema::chat_sessions::table
            .find(session_id)
            .select(ChatSession::as_select())
            .first::<ChatSession>(conn)
            .optional() // Return Option<ChatSession>
    })
    .await
    .expect("Interact failed for get_chat_session")
    .expect("DB query failed for get_chat_session") // Handle potential Diesel error inside interact
}

pub async fn create_test_chat_message(
    pool: &PgPool,
    session_id: Uuid,
    message_type: MessageType,
    content: &str,
) -> ChatMessage {
    let new_message = NewChatMessage {
        session_id,
        message_type,
        content: content.to_string(),
        rag_embedding_id: None, // Not relevant for basic tests yet
    };

    let conn = pool.get().await.expect("Failed to get DB conn for create_chat_message");
    conn.interact(move |conn| {
        diesel::insert_into(schema::chat_messages::table)
            .values(&new_message)
            .get_result::<ChatMessage>(conn)
            .expect("Failed to insert test chat message")
    })
    .await
    .expect("Interact failed for create_chat_message")
}

// --- API Helper Functions ---

/// Creates a user directly in the DB, then performs API login via oneshot to get an auth cookie.
pub async fn create_test_user_and_login(
    app: &TestApp,
    username: &str,
    password: &str,
) -> (String, User) {
    let user = create_test_user(&app.db_pool, username, password).await;

    let login_request = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/api/auth/login", app.address)) // Use full address for URI
        .header(axum::http::header::CONTENT_TYPE, "application/json") // Use axum::http::header explicitly
        .body(Body::from(
            serde_json::json!({
                "username": username,
                "password": password,
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = app.router.clone().oneshot(login_request).await.unwrap();

    // Uncomment this check - it should pass now if setup is correct
    assert_eq!(login_response.status(), StatusCode::OK);

    // --- Extract Cookie using CookieManager ---
    // The CookieManagerLayer adds the CookieManager to the request extensions.
    // For the response, we need to get the jar from the CookieManager that *should* be in the response extensions
    // if the layers were applied correctly. This part is tricky with `oneshot`.
    // A common pattern is to wrap the service in CookieManager again for the test.
    
    // Alternative: Extract Set-Cookie header and parse manually (but carefully)
    let cookie_header = login_response
        .headers()
        .get(SET_COOKIE)
        .expect("Login response missing Set-Cookie header")
        .to_str()
        .expect("Set-Cookie header is not valid ASCII");

    // DEBUG: Print the actual Set-Cookie header value
    // eprintln!("DEBUG: Set-Cookie header value: {}", cookie_header); // Keep commented out unless debugging

    // Manually parse the Set-Cookie header to find the session cookie value (now named 'id')
    let session_cookie_value = cookie_header
        .split(';')
        .find_map(|part| {
            let mut parts = part.trim().splitn(2, '=');
            let name = parts.next()?;
            let value = parts.next()?;
            if name == "id" { Some(value.to_string()) } else { None } // LOOK FOR "id" INSTEAD OF "session"
        })
        .expect("Could not find 'id' cookie in Set-Cookie header"); // Update expect message

    // Return the raw cookie value string (name=value) for use in subsequent request headers
    let full_cookie_string = format!("id={}", session_cookie_value); // Use "id="
    
    // Keep assertion that cookie *value* exists and is not empty
    assert!(!session_cookie_value.is_empty(), "Set-Cookie header 'id' cookie had an empty value"); // Update assertion message

    (full_cookie_string, user)
}