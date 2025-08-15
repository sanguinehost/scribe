#![cfg(test)]
// backend/tests/chronicle_service_tests.rs

use anyhow::{Context, Result as AnyhowResult};
use bcrypt;
use diesel::{PgConnection, RunQueryDsl, prelude::*};
use scribe_backend::{
    crypto,
    models::{
        chronicle::{CreateChronicleRequest, UpdateChronicleRequest},
        chronicle_event::{CreateEventRequest, EventSource, EventFilter},
        users::{User, UserDbQuery, NewUser, UserRole, AccountStatus, SerializableSecretDek},
    },
    schema::users,
    services::ChronicleService,
    test_helpers::{self, TestDataGuard},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use uuid::Uuid;

// Unit Tests for Chronicle Service
mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_create_chronicle_request_validation() {
        // Test valid request
        let valid_request = CreateChronicleRequest {
            name: "Test Chronicle".to_string(),
            description: Some("A test chronicle".to_string()),
        };
        assert_eq!(valid_request.name, "Test Chronicle");

        // Test empty name - this would be caught by validation
        let invalid_request = CreateChronicleRequest {
            name: "".to_string(),
            description: None,
        };
        assert!(invalid_request.name.is_empty());
    }

    #[tokio::test]
    async fn test_event_source_serialization() {
        // Test EventSource enum serialization/deserialization
        assert_eq!(EventSource::UserAdded.to_string(), "USER_ADDED");
        assert_eq!(EventSource::AiExtracted.to_string(), "AI_EXTRACTED");
        assert_eq!(EventSource::GameApi.to_string(), "GAME_API");
        assert_eq!(EventSource::System.to_string(), "SYSTEM");

        // Test parsing
        assert_eq!("USER_ADDED".parse::<EventSource>().unwrap(), EventSource::UserAdded);
        assert_eq!("AI_EXTRACTED".parse::<EventSource>().unwrap(), EventSource::AiExtracted);
        assert_eq!("GAME_API".parse::<EventSource>().unwrap(), EventSource::GameApi);
        assert_eq!("SYSTEM".parse::<EventSource>().unwrap(), EventSource::System);

        // Test invalid source
        assert!("INVALID".parse::<EventSource>().is_err());
    }

    #[tokio::test]
    async fn test_create_event_request_with_keywords() {
        let request = CreateEventRequest {
            event_type: "CHARACTER_INTERACTION".to_string(),
            summary: "Hero meets the mysterious bartender at the tavern".to_string(),
            source: EventSource::AiExtracted,
            keywords: Some(vec!["Hero".to_string(), "Bartender".to_string(), "tavern".to_string()]),
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        assert_eq!(request.event_type, "CHARACTER_INTERACTION");
        assert_eq!(request.source, EventSource::AiExtracted);
        assert!(request.keywords.is_some());
        assert_eq!(request.keywords.as_ref().unwrap().len(), 3);
    }
}

// Integration Tests
mod integration_tests {
    use super::*;

    /// Helper to hash a password for tests
    fn hash_test_password(password: &str) -> String {
        bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash test password with bcrypt")
    }

    /// Helper to insert a unique test user with a known password hash
    fn insert_test_user_with_password(
        conn: &mut PgConnection,
        username: &str,
        password: &str,
    ) -> Result<User, diesel::result::Error> {
        let hashed_password = hash_test_password(password);
        let email = format!("{username}@example.com");

        let kek_salt = crypto::generate_salt().expect("Failed to generate KEK salt for test user");
        let dek = crypto::generate_dek().expect("Failed to generate DEK for test user");

        let secret_password = SecretString::new(password.to_string().into());
        let kek = crypto::derive_kek(&secret_password, &kek_salt)
            .expect("Failed to derive KEK for test user");

        let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(dek.expose_secret(), &kek)
            .expect("Failed to encrypt DEK for test user");

        let new_user = NewUser {
            username: username.to_string(),
            password_hash: hashed_password,
            email,
            kek_salt,
            encrypted_dek,
            encrypted_dek_by_recovery: None,
            role: UserRole::User,
            recovery_kek_salt: None,
            dek_nonce,
            recovery_dek_nonce: None,
            account_status: AccountStatus::Active,
        };

        let user_db: UserDbQuery = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(UserDbQuery::as_returning())
            .get_result(conn)?;

        // Convert UserDbQuery to User
        let user = User {
            id: user_db.id,
            username: user_db.username,
            email: user_db.email,
            password_hash: user_db.password_hash,
            kek_salt: user_db.kek_salt,
            encrypted_dek: user_db.encrypted_dek,
            dek_nonce: user_db.dek_nonce,
            encrypted_dek_by_recovery: user_db.encrypted_dek_by_recovery,
            recovery_kek_salt: user_db.recovery_kek_salt,
            recovery_dek_nonce: user_db.recovery_dek_nonce,
            dek: Some(SerializableSecretDek(dek)),
            recovery_phrase: None,
            role: user_db.role,
            account_status: Some(format!("{:?}", user_db.account_status).to_lowercase()),
            default_persona_id: user_db.default_persona_id,
            created_at: user_db.created_at,
            updated_at: user_db.updated_at,
        };

        Ok(user)
    }

    async fn setup_test_user(test_app: &scribe_backend::test_helpers::TestApp) -> AnyhowResult<User> {
        let username = format!("testuser_{}", Uuid::new_v4().simple());
        let password = "TestPassword123!";

        let conn = test_app.db_pool.get().await.context("Failed to get DB connection")?;
        let user = conn
            .interact(move |conn| {
                insert_test_user_with_password(conn, &username, password)
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create test user interaction: {e}"))?
            .map_err(|e| anyhow::anyhow!("Failed to create test user: {e}"))?;

        Ok(user)
    }

    #[tokio::test]
    async fn test_chronicle_crud_operations() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        // Test: Create Chronicle
        let create_request = CreateChronicleRequest {
            name: "Epic Fantasy Campaign".to_string(),
            description: Some("A long-running D&D campaign".to_string()),
        };

        let created_chronicle = chronicle_service
            .create_chronicle(user.id, create_request.clone())
            .await
            .unwrap();

        assert_eq!(created_chronicle.name, create_request.name);
        assert_eq!(created_chronicle.description, create_request.description);
        assert_eq!(created_chronicle.user_id, user.id);

        // Test: Get Chronicle
        let retrieved_chronicle = chronicle_service
            .get_chronicle(user.id, created_chronicle.id)
            .await
            .unwrap();

        assert_eq!(retrieved_chronicle.id, created_chronicle.id);
        assert_eq!(retrieved_chronicle.name, created_chronicle.name);

        // Test: Update Chronicle
        let update_request = UpdateChronicleRequest {
            name: Some("Updated Campaign Name".to_string()),
            description: Some("Updated description".to_string()),
        };

        let updated_chronicle = chronicle_service
            .update_chronicle(user.id, created_chronicle.id, update_request.clone())
            .await
            .unwrap();

        assert_eq!(updated_chronicle.name, "Updated Campaign Name");
        assert_eq!(updated_chronicle.description, Some("Updated description".to_string()));

        // Test: List User Chronicles
        let user_chronicles = chronicle_service
            .get_user_chronicles(user.id)
            .await
            .unwrap();

        assert_eq!(user_chronicles.len(), 1);
        assert_eq!(user_chronicles[0].id, updated_chronicle.id);

        // Test: Delete Chronicle
        chronicle_service
            .delete_chronicle(user.id, created_chronicle.id)
            .await
            .unwrap();

        // Verify deletion
        let result = chronicle_service
            .get_chronicle(user.id, created_chronicle.id)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_chronicle_event_operations() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user and chronicle
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        let create_chronicle_request = CreateChronicleRequest {
            name: "Test Chronicle".to_string(),
            description: Some("For testing events".to_string()),
        };

        let chronicle = chronicle_service
            .create_chronicle(user.id, create_chronicle_request)
            .await
            .unwrap();

        // Test: Create Event
        let event_data = json!({
            "location": "Starting Village",
            "mood": "mysterious",
            "npcs": ["Village Elder", "Suspicious Merchant"]
        });

        let create_event_request = CreateEventRequest {
            event_type: "SCENE_START".to_string(),
            summary: "The adventure begins in a quiet village with mysterious fog".to_string(),
            source: EventSource::UserAdded,
            keywords: Some(vec!["village".to_string(), "fog".to_string()]),
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let created_event = chronicle_service
            .create_event(user.id, chronicle.id, create_event_request.clone(), None)
            .await
            .unwrap();

        assert_eq!(created_event.event_type, create_event_request.event_type);
        assert_eq!(created_event.summary, create_event_request.summary);
        assert_eq!(created_event.source, EventSource::UserAdded.to_string());
        assert_eq!(created_event.chronicle_id, chronicle.id);
        assert_eq!(created_event.user_id, user.id);

        // Test: Create multiple events for filtering
        let event2_request = CreateEventRequest {
            event_type: "COMBAT_ENCOUNTER".to_string(),
            summary: "Fought off bandits on the road".to_string(),
            source: EventSource::AiExtracted,
            keywords: Some(vec!["combat".to_string(), "bandits".to_string()]),
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let event2 = chronicle_service
            .create_event(user.id, chronicle.id, event2_request, None)
            .await
            .unwrap();

        // Test: Get Events with Default Filter
        let events = chronicle_service
            .get_chronicle_events(user.id, chronicle.id, EventFilter::default())
            .await
            .unwrap();

        assert_eq!(events.len(), 2);
        // Events should be ordered by created_at desc by default
        assert_eq!(events[0].id, event2.id); // Most recent first
        assert_eq!(events[1].id, created_event.id);

        // Test: Filter by Event Type
        let filter = EventFilter {
            event_type: Some("SCENE_START".to_string()),
            ..Default::default()
        };

        let filtered_events = chronicle_service
            .get_chronicle_events(user.id, chronicle.id, filter)
            .await
            .unwrap();

        assert_eq!(filtered_events.len(), 1);
        assert_eq!(filtered_events[0].id, created_event.id);

        // Test: Filter by Source
        let filter = EventFilter {
            source: Some(EventSource::AiExtracted),
            ..Default::default()
        };

        let filtered_events = chronicle_service
            .get_chronicle_events(user.id, chronicle.id, filter)
            .await
            .unwrap();

        assert_eq!(filtered_events.len(), 1);
        assert_eq!(filtered_events[0].id, event2.id);

        // Test: Get Specific Event
        let retrieved_event = chronicle_service
            .get_event(user.id, created_event.id)
            .await
            .unwrap();

        assert_eq!(retrieved_event.id, created_event.id);
        assert_eq!(retrieved_event.event_type, created_event.event_type);

        // Test: Delete Event
        chronicle_service
            .delete_event(user.id, event2.id)
            .await
            .unwrap();

        // Verify event was deleted
        let events_after_delete = chronicle_service
            .get_chronicle_events(user.id, chronicle.id, EventFilter::default())
            .await
            .unwrap();

        assert_eq!(events_after_delete.len(), 1);
        assert_eq!(events_after_delete[0].id, created_event.id);
    }

    #[tokio::test]
    async fn test_chronicle_with_counts() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user and chronicle
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        let create_chronicle_request = CreateChronicleRequest {
            name: "Test Chronicle with Counts".to_string(),
            description: Some("Testing counts".to_string()),
        };

        let chronicle = chronicle_service
            .create_chronicle(user.id, create_chronicle_request)
            .await
            .unwrap();

        // Add some events
        for i in 1..=3 {
            let event_request = CreateEventRequest {
                event_type: "TEST_EVENT".to_string(),
                summary: format!("Test event {}", i),
                source: EventSource::UserAdded,
                keywords: None,
                timestamp_iso8601: None,
                chat_session_id: None,
            };

            chronicle_service
                .create_event(user.id, chronicle.id, event_request, None)
                .await
                .unwrap();
        }

        // Test: Get Chronicles with Counts
        let chronicles_with_counts = chronicle_service
            .get_user_chronicles_with_counts(user.id)
            .await
            .unwrap();

        assert_eq!(chronicles_with_counts.len(), 1);
        
        let chronicle_with_counts = &chronicles_with_counts[0];
        assert_eq!(chronicle_with_counts.chronicle.id, chronicle.id);
        assert_eq!(chronicle_with_counts.event_count, 3);
        assert_eq!(chronicle_with_counts.chat_session_count, 0); // No linked sessions yet
    }

    #[tokio::test]
    async fn test_unauthorized_access() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup two test users
        let user1 = setup_test_user(&test_app).await.unwrap();
        let user2 = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user1.id);
        _guard.add_user(user2.id);

        // User1 creates a chronicle
        let create_request = CreateChronicleRequest {
            name: "User1's Chronicle".to_string(),
            description: Some("Private chronicle".to_string()),
        };

        let chronicle = chronicle_service
            .create_chronicle(user1.id, create_request)
            .await
            .unwrap();

        // Test: User2 tries to access User1's chronicle
        let result = chronicle_service
            .get_chronicle(user2.id, chronicle.id)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));

        // Test: User2 tries to update User1's chronicle
        let update_request = UpdateChronicleRequest {
            name: Some("Hacked Chronicle".to_string()),
            description: None,
        };

        let result = chronicle_service
            .update_chronicle(user2.id, chronicle.id, update_request)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));

        // Test: User2 tries to delete User1's chronicle
        let result = chronicle_service
            .delete_chronicle(user2.id, chronicle.id)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_nonexistent_chronicle_operations() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        let nonexistent_id = Uuid::new_v4();

        // Test: Get nonexistent chronicle
        let result = chronicle_service
            .get_chronicle(user.id, nonexistent_id)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));

        // Test: Create event in nonexistent chronicle
        let event_request = CreateEventRequest {
            event_type: "TEST".to_string(),
            summary: "Test event".to_string(),
            source: EventSource::UserAdded,
            keywords: None,
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let result = chronicle_service
            .create_event(user.id, nonexistent_id, event_request, None)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_cascade_delete() {
        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user and chronicle
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        let create_chronicle_request = CreateChronicleRequest {
            name: "Cascade Test Chronicle".to_string(),
            description: Some("Testing cascade delete".to_string()),
        };

        let chronicle = chronicle_service
            .create_chronicle(user.id, create_chronicle_request)
            .await
            .unwrap();

        // Create events in the chronicle
        let event_request = CreateEventRequest {
            event_type: "TEST_EVENT".to_string(),
            summary: "Event to be cascade deleted".to_string(),
            source: EventSource::UserAdded,
            keywords: None,
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let event = chronicle_service
            .create_event(user.id, chronicle.id, event_request, None)
            .await
            .unwrap();

        // Delete the chronicle
        chronicle_service
            .delete_chronicle(user.id, chronicle.id)
            .await
            .unwrap();

        // Verify that the event was also deleted (cascade)
        let result = chronicle_service
            .get_event(user.id, event.id)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), scribe_backend::errors::AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_chronicle_event_encryption() {
        use scribe_backend::auth::session_dek::SessionDek;

        let test_app = test_helpers::spawn_app(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());

        // Setup test user and chronicle
        let user = setup_test_user(&test_app).await.unwrap();
        _guard.add_user(user.id);

        let create_chronicle_request = CreateChronicleRequest {
            name: "Encryption Test Chronicle".to_string(),
            description: Some("Testing event summary encryption".to_string()),
        };

        let chronicle = chronicle_service
            .create_chronicle(user.id, create_chronicle_request)
            .await
            .unwrap();

        // Create a SessionDek using the user's DEK
        let session_dek = SessionDek::new(user.dek.as_ref().unwrap().0.expose_secret().clone());

        // Test: Create Event with Encryption (SessionDek provided)
        let encrypted_event_request = CreateEventRequest {
            event_type: "ENCRYPTED_EVENT".to_string(),
            summary: "This is a secret summary with sensitive information about the hidden cave".to_string(),
            source: EventSource::UserAdded,
            keywords: Some(vec!["secret".to_string(), "hidden cave".to_string()]),
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let encrypted_event = chronicle_service
            .create_event(user.id, chronicle.id, encrypted_event_request.clone(), Some(&session_dek))
            .await
            .unwrap();

        // Verify the event was created and has encrypted fields
        assert_eq!(encrypted_event.event_type, encrypted_event_request.event_type);
        assert_eq!(encrypted_event.summary, encrypted_event_request.summary); // Legacy field still has plaintext
        assert!(encrypted_event.has_encrypted_summary()); // Should have encrypted data
        assert!(encrypted_event.summary_encrypted.is_some());
        assert!(encrypted_event.summary_nonce.is_some());

        // Test: Decrypt the summary using the SessionDek
        let decrypted_summary = encrypted_event.get_decrypted_summary(&session_dek.0).unwrap();
        assert_eq!(decrypted_summary, encrypted_event_request.summary);

        // Test: Create Event without Encryption (SessionDek not provided)
        let unencrypted_event_request = CreateEventRequest {
            event_type: "UNENCRYPTED_EVENT".to_string(),
            summary: "This is a public summary".to_string(),
            source: EventSource::UserAdded,
            keywords: None,
            timestamp_iso8601: None,
            chat_session_id: None,
        };

        let unencrypted_event = chronicle_service
            .create_event(user.id, chronicle.id, unencrypted_event_request.clone(), None)
            .await
            .unwrap();

        // Verify the event was created without encrypted fields
        assert_eq!(unencrypted_event.event_type, unencrypted_event_request.event_type);
        assert_eq!(unencrypted_event.summary, unencrypted_event_request.summary);
        assert!(!unencrypted_event.has_encrypted_summary()); // Should NOT have encrypted data
        assert!(unencrypted_event.summary_encrypted.is_none());
        assert!(unencrypted_event.summary_nonce.is_none());

        // Test: Fallback to legacy plaintext when no encrypted version exists
        let fallback_summary = unencrypted_event.get_decrypted_summary(&session_dek.0).unwrap();
        assert_eq!(fallback_summary, unencrypted_event_request.summary);
    }
}