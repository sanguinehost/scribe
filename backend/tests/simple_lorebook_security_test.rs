use diesel::prelude::*;
use scribe_backend::{
    models::lorebooks::ChatSessionLorebook,
    test_helpers::{self, spawn_app}, // Added self to import test_helpers module
};
use chrono::Utc;
use qdrant_client::qdrant::{
    Condition, FieldCondition, Filter, Match, r#match::MatchValue, condition::ConditionOneOf,
};
use uuid::Uuid;

#[derive(QueryableByName)]
struct OwnershipCheck {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    user_id: Uuid,
}

#[tokio::test]
async fn test_comprehensive_lorebook_ids_basic_functionality() {
    let test_app = spawn_app(false, false, false).await;
    let conn = test_app.db_pool.get().await.unwrap();
    
    let test_result = conn.interact(|conn| {
        // Create test data using raw SQL to avoid struct compatibility issues
        let user_id = Uuid::new_v4();
        let character_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let lorebook1_id = Uuid::new_v4(); // Character-linked
        let lorebook2_id = Uuid::new_v4(); // Session-linked
        let lorebook3_id = Uuid::new_v4(); // Unlinked
        
        // Insert test user
        diesel::sql_query(
            "INSERT INTO users (id, username, password_hash, email, kek_salt, encrypted_dek, dek_nonce, role, account_status, created_at, updated_at) 
             VALUES ($1, 'testuser', 'hash', 'test@example.com', 'salt', $2, $3, 'User', 'active', $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Binary, _>(vec![0u8; 32])
        .bind::<diesel::sql_types::Binary, _>(vec![0u8; 12])
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test character
        diesel::sql_query(
            "INSERT INTO characters (id, user_id, name, spec, spec_version, description, personality, scenario, first_mes, mes_example, creator_notes, system_prompt, post_history_instructions, alternate_greetings, tags, creator, character_version, extensions, visibility, created_at, updated_at) 
             VALUES ($1, $2, 'Test Character', 'chara_card_v3', '3.0', $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'private', $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Binary>, _>(Some(b"Test character description".to_vec()))
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test chat session
        diesel::sql_query(
            "INSERT INTO chat_sessions (id, user_id, character_id, title, system_prompt, temperature, max_output_tokens, frequency_penalty, presence_penalty, top_k, top_p, seed, stop_sequences, history_management_strategy, history_management_limit, visibility, created_at, updated_at, active_custom_persona_id, model_name, gemini_thinking_budget, gemini_enable_code_execution, active_impersonated_character_id) 
             VALUES ($1, $2, $3, 'Test Session', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'keep_recent', 50, 'private', $4, $5, NULL, 'gemini-2.0-flash-exp', NULL, NULL, NULL)"
        )
        .bind::<diesel::sql_types::Uuid, _>(session_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test lorebooks
        for (id, name) in [
            (lorebook1_id, "Character Lorebook"),
            (lorebook2_id, "Session Lorebook"),
            (lorebook3_id, "Unlinked Lorebook"),
        ] {
            diesel::sql_query(
                "INSERT INTO lorebooks (id, user_id, name, description, source_format, is_public, created_at, updated_at) 
                 VALUES ($1, $2, $3, $4, 'scribe', false, $5, $6)"
            )
            .bind::<diesel::sql_types::Uuid, _>(id)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(format!("Test {name}")))
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // Link lorebook1 to character
        diesel::sql_query(
            "INSERT INTO character_lorebooks (character_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Uuid, _>(lorebook1_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Link lorebook2 to session
        diesel::sql_query(
            "INSERT INTO chat_session_lorebooks (chat_session_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(session_id)
        .bind::<diesel::sql_types::Uuid, _>(lorebook2_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // TEST 1: Should retrieve both character-linked and session-linked lorebooks
        let active_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(active_ids.is_some(), "Should have active lorebooks");
        let ids = active_ids.unwrap();
        assert_eq!(ids.len(), 2, "Should have exactly 2 active lorebooks");
        assert!(ids.contains(&lorebook1_id), "Should include character-linked lorebook");
        assert!(ids.contains(&lorebook2_id), "Should include session-linked lorebook");
        assert!(!ids.contains(&lorebook3_id), "Should NOT include unlinked lorebook");
        
        // TEST 2: Test deduplication - link same lorebook to both character and session
        diesel::sql_query(
            "INSERT INTO character_lorebooks (character_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Uuid, _>(lorebook2_id) // Same as session-linked
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        let dedup_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(dedup_ids.is_some(), "Should still have active lorebooks after duplication");
        let dedup_ids = dedup_ids.unwrap();
        assert_eq!(dedup_ids.len(), 2, "Should still have only 2 unique lorebooks after deduplication");
        assert!(dedup_ids.contains(&lorebook1_id), "Should include character-linked lorebook");
        assert!(dedup_ids.contains(&lorebook2_id), "Should include deduplicated lorebook");
        
        Ok::<(), diesel::result::Error>(())
    }).await;
    
    let _ = test_result.unwrap();
}

#[tokio::test]
async fn test_no_lorebook_links_returns_none() {
    let test_app = spawn_app(false, false, false).await;
    let conn = test_app.db_pool.get().await.unwrap();
    
    let test_result = conn.interact(|conn| {
        // Test that function returns None when no lorebook links exist
        let user_id = Uuid::new_v4();
        let character_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        let result = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(result.is_none(), "Should return None when no lorebook links exist");
        
        Ok::<(), diesel::result::Error>(())
    }).await;
    
    let _ = test_result.unwrap();
}

#[tokio::test]
async fn test_cross_user_lorebook_isolation() {
    let test_app = spawn_app(false, false, false).await;
    let conn = test_app.db_pool.get().await.unwrap();
    
    let test_result = conn.interact(|conn| {
        // Create two separate users
        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();
        let character1_id = Uuid::new_v4();
        let character2_id = Uuid::new_v4();
        let session1_id = Uuid::new_v4();
        let session2_id = Uuid::new_v4();
        let lorebook1_id = Uuid::new_v4(); // User1's lorebook
        let lorebook2_id = Uuid::new_v4(); // User2's lorebook
        
        // Insert users
        for (user_id, username) in [(user1_id, "user1"), (user2_id, "user2")] {
            diesel::sql_query(
                "INSERT INTO users (id, username, password_hash, email, kek_salt, encrypted_dek, dek_nonce, role, account_status, created_at, updated_at) 
                 VALUES ($1, $2, 'hash', $3, 'salt', $4, $5, 'User', 'active', $6, $7)"
            )
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(username)
            .bind::<diesel::sql_types::Text, _>(format!("{username}@example.com"))
            .bind::<diesel::sql_types::Binary, _>(vec![0u8; 32])
            .bind::<diesel::sql_types::Binary, _>(vec![0u8; 12])
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // Insert characters for each user
        for (char_id, user_id, name) in [(character1_id, user1_id, "User1 Character"), (character2_id, user2_id, "User2 Character")] {
            diesel::sql_query(
                "INSERT INTO characters (id, user_id, name, spec, spec_version, description, personality, scenario, first_mes, mes_example, creator_notes, system_prompt, post_history_instructions, alternate_greetings, tags, creator, character_version, extensions, visibility, created_at, updated_at) 
                 VALUES ($1, $2, $3, 'chara_card_v3', '3.0', $4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'private', $5, $6)"
            )
            .bind::<diesel::sql_types::Uuid, _>(char_id)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Binary>, _>(Some(b"Test character description".to_vec()))
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // Insert chat sessions for each user
        for (session_id, user_id, character_id, title) in [(session1_id, user1_id, character1_id, "User1 Session"), (session2_id, user2_id, character2_id, "User2 Session")] {
            diesel::sql_query(
                "INSERT INTO chat_sessions (id, user_id, character_id, title, system_prompt, temperature, max_output_tokens, frequency_penalty, presence_penalty, top_k, top_p, seed, stop_sequences, history_management_strategy, history_management_limit, visibility, created_at, updated_at, active_custom_persona_id, model_name, gemini_thinking_budget, gemini_enable_code_execution, active_impersonated_character_id) 
                 VALUES ($1, $2, $3, $4, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'keep_recent', 50, 'private', $5, $6, NULL, 'gemini-2.0-flash-exp', NULL, NULL, NULL)"
            )
            .bind::<diesel::sql_types::Uuid, _>(session_id)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Uuid, _>(character_id)
            .bind::<diesel::sql_types::Text, _>(title)
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // Insert lorebooks owned by each user
        for (id, user_id, name) in [(lorebook1_id, user1_id, "User1 Lorebook"), (lorebook2_id, user2_id, "User2 Lorebook")] {
            diesel::sql_query(
                "INSERT INTO lorebooks (id, user_id, name, description, source_format, is_public, created_at, updated_at) 
                 VALUES ($1, $2, $3, $4, 'scribe', false, $5, $6)"
            )
            .bind::<diesel::sql_types::Uuid, _>(id)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(format!("Test {name}")))
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // CROSS-USER ATTACK SIMULATION: Try to link User2's lorebook to User1's character
        // This simulates a potential attack or bug where cross-user data gets linked
        diesel::sql_query(
            "INSERT INTO character_lorebooks (character_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character1_id) // User1's character
        .bind::<diesel::sql_types::Uuid, _>(lorebook2_id) // User2's lorebook (ATTACK!)
        .bind::<diesel::sql_types::Uuid, _>(user1_id)    // User1's ID
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // SECURITY TEST: User1 should NOT get access to User2's lorebook
        // even though it's been maliciously linked to User1's character
        let user1_active_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session1_id,
            character1_id,
            user1_id,
        )?;
        
        // Verify that User1 does NOT get the maliciously linked lorebook
        // (This confirms the security vulnerability has been fixed)
        if let Some(ids) = &user1_active_ids {
            assert!(!ids.contains(&lorebook2_id), "SECURITY FIX VERIFIED: User1 cannot access User2's lorebook even when maliciously linked");
            println!("SECURITY CONFIRMED: Cross-user lorebook access has been prevented!");
        }
        
        // Additional verification: User1 should have no active lorebooks since User2's lorebook is filtered out
        assert!(user1_active_ids.is_none() || user1_active_ids.as_ref().unwrap().is_empty(), 
                "User1 should have no active lorebooks when only other users' lorebooks are linked");
        
        // POSITIVE TEST: Verify User1 can still access their own lorebook when properly linked
        diesel::sql_query(
            "INSERT INTO character_lorebooks (character_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character1_id) // User1's character
        .bind::<diesel::sql_types::Uuid, _>(lorebook1_id) // User1's lorebook (correct!)
        .bind::<diesel::sql_types::Uuid, _>(user1_id)    // User1's ID
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        let user1_own_lorebooks = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session1_id,
            character1_id,
            user1_id,
        )?;
        
        // User1 should now have access to their own lorebook
        assert!(user1_own_lorebooks.is_some(), "User1 should have access to their own lorebook");
        let own_ids = user1_own_lorebooks.unwrap();
        assert_eq!(own_ids.len(), 1, "User1 should have exactly 1 lorebook (their own)");
        assert!(own_ids.contains(&lorebook1_id), "User1 should have access to their own lorebook");
        assert!(!own_ids.contains(&lorebook2_id), "User1 should still NOT have access to User2's lorebook");
        
        // PROPER SECURITY: Add verification that User2's lorebook actually belongs to User2
        // This is what should be checked in the application layer
        let lorebook_ownership_query = diesel::sql_query(
            "SELECT user_id FROM lorebooks WHERE id = $1"
        )
        .bind::<diesel::sql_types::Uuid, _>(lorebook2_id);
        
        let ownership_result: Result<Vec<OwnershipCheck>, diesel::result::Error> = lorebook_ownership_query.load(conn);
        if let Ok(owners) = ownership_result {
            if let Some(owner) = owners.first() {
                assert_eq!(owner.user_id, user2_id, "Lorebook should be owned by User2");
                assert_ne!(owner.user_id, user1_id, "Lorebook should NOT be owned by User1");
            }
        }
        
        Ok::<(), diesel::result::Error>(())
    }).await;
    
    let _ = test_result.unwrap();
}

#[tokio::test]
async fn test_lorebook_activation_hierarchy() {
    let test_app = spawn_app(false, false, false).await;
    let conn = test_app.db_pool.get().await.unwrap();
    
    let test_result = conn.interact(|conn| {
        // Setup test data
        let user_id = Uuid::new_v4();
        let character_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let character_lorebook_id = Uuid::new_v4(); // Linked to character
        let session_lorebook_id = Uuid::new_v4();   // Linked to session
        let unlinked_lorebook_id = Uuid::new_v4();  // Not linked to anything
        
        // Insert test user
        diesel::sql_query(
            "INSERT INTO users (id, username, password_hash, email, kek_salt, encrypted_dek, dek_nonce, role, account_status, created_at, updated_at) 
             VALUES ($1, 'testuser', 'hash', 'test@example.com', 'salt', $2, $3, 'User', 'active', $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Binary, _>(vec![0u8; 32])
        .bind::<diesel::sql_types::Binary, _>(vec![0u8; 12])
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test character
        diesel::sql_query(
            "INSERT INTO characters (id, user_id, name, spec, spec_version, description, personality, scenario, first_mes, mes_example, creator_notes, system_prompt, post_history_instructions, alternate_greetings, tags, creator, character_version, extensions, visibility, created_at, updated_at) 
             VALUES ($1, $2, 'Test Character', 'chara_card_v3', '3.0', $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'private', $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::Binary>, _>(Some(b"Test character description".to_vec()))
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test chat session
        diesel::sql_query(
            "INSERT INTO chat_sessions (id, user_id, character_id, title, system_prompt, temperature, max_output_tokens, frequency_penalty, presence_penalty, top_k, top_p, seed, stop_sequences, history_management_strategy, history_management_limit, visibility, created_at, updated_at, active_custom_persona_id, model_name, gemini_thinking_budget, gemini_enable_code_execution, active_impersonated_character_id) 
             VALUES ($1, $2, $3, 'Test Session', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'keep_recent', 50, 'private', $4, $5, NULL, 'gemini-2.0-flash-exp', NULL, NULL, NULL)"
        )
        .bind::<diesel::sql_types::Uuid, _>(session_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        // Insert test lorebooks
        for (id, name) in [
            (character_lorebook_id, "Character Lorebook"),
            (session_lorebook_id, "Session Lorebook"),
            (unlinked_lorebook_id, "Unlinked Lorebook"),
        ] {
            diesel::sql_query(
                "INSERT INTO lorebooks (id, user_id, name, description, source_format, is_public, created_at, updated_at) 
                 VALUES ($1, $2, $3, $4, 'scribe', false, $5, $6)"
            )
            .bind::<diesel::sql_types::Uuid, _>(id)
            .bind::<diesel::sql_types::Uuid, _>(user_id)
            .bind::<diesel::sql_types::Text, _>(name)
            .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(Some(format!("Test {name}")))
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
            .execute(conn)?;
        }
        
        // TEST 1: Only character-linked lorebook
        diesel::sql_query(
            "INSERT INTO character_lorebooks (character_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(character_id)
        .bind::<diesel::sql_types::Uuid, _>(character_lorebook_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        let char_only_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(char_only_ids.is_some(), "Should have character-linked lorebook");
        let char_ids = char_only_ids.unwrap();
        assert_eq!(char_ids.len(), 1, "Should have exactly 1 lorebook");
        assert!(char_ids.contains(&character_lorebook_id), "Should include character lorebook");
        assert!(!char_ids.contains(&session_lorebook_id), "Should NOT include session lorebook yet");
        assert!(!char_ids.contains(&unlinked_lorebook_id), "Should NOT include unlinked lorebook");
        
        // TEST 2: Add session-linked lorebook
        diesel::sql_query(
            "INSERT INTO chat_session_lorebooks (chat_session_id, lorebook_id, user_id, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind::<diesel::sql_types::Uuid, _>(session_id)
        .bind::<diesel::sql_types::Uuid, _>(session_lorebook_id)
        .bind::<diesel::sql_types::Uuid, _>(user_id)
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .bind::<diesel::sql_types::Timestamptz, _>(Utc::now())
        .execute(conn)?;
        
        let both_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(both_ids.is_some(), "Should have both lorebooks");
        let both_ids = both_ids.unwrap();
        assert_eq!(both_ids.len(), 2, "Should have exactly 2 lorebooks");
        assert!(both_ids.contains(&character_lorebook_id), "Should include character lorebook");
        assert!(both_ids.contains(&session_lorebook_id), "Should include session lorebook");
        assert!(!both_ids.contains(&unlinked_lorebook_id), "Should NOT include unlinked lorebook");
        
        // TEST 3: Verify unlinked lorebook is never included
        let final_ids = ChatSessionLorebook::get_comprehensive_active_lorebook_ids(
            conn,
            session_id,
            character_id,
            user_id,
        )?;
        
        assert!(final_ids.is_some(), "Should still have lorebooks");
        let final_ids = final_ids.unwrap();
        assert!(!final_ids.contains(&unlinked_lorebook_id), "Unlinked lorebook should NEVER be included");
        
        Ok::<(), diesel::result::Error>(())
    }).await;
    
    let _ = test_result.unwrap();
}

#[tokio::test]
async fn test_lorebook_deletion_cleans_up_vectors() {
    // This test requires a mock Qdrant service to verify deletion calls
    let test_app = spawn_app(false, false, false).await;
    let mock_qdrant_service = test_app
        .mock_qdrant_service
        .expect("Mock Qdrant service should be present in TestApp");

    // Create a user and get the authenticated client and user ID
    let (user, auth_cookie) = test_helpers::create_user_with_dek_in_session(
        &test_app.router,
        &test_app.db_pool,
        "test_user".to_string(),
        "password123".to_string(),
        None, // No plaintext DEK needed for this test
    )
    .await
    .expect("Failed to create user and get session");

    let client = reqwest::Client::builder()
        .cookie_store(true) // Enable cookie store for this client
        .build()
        .expect("Failed to build reqwest client");

    let user_id = user.id;

    // 1. Create a lorebook
    let create_lorebook_payload = serde_json::json!({
        "name": "Test Lorebook for Deletion",
        "description": "A lorebook to be deleted",
        "source_format": "scribe",
        "is_public": false
    });

    let create_response = client
        .post(format!("{}/api/lorebooks", test_app.address).as_str()) // Use test_app.address
        .header(reqwest::header::COOKIE, &auth_cookie) // Add auth_cookie
        .json(&create_lorebook_payload)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(create_response.status().is_success()); // Changed is_ok() to is_success()
    let lorebook: scribe_backend::models::lorebooks::Lorebook = create_response
        .json()
        .await
        .expect("Failed to parse lorebook response");
    let lorebook_id = lorebook.id;

    // 2. Add an entry to the lorebook (which would create vectors)
    // We don't need to actually create vectors here, just simulate the flow
    // The important part is that delete_lorebook is called with the correct ID
    let create_entry_payload = serde_json::json!({
        "entry_title": "Entry 1",
        "keys_text": "test, entry",
        "content": "Some content for the lorebook entry.",
        "comment": "A test entry comment.",
        "is_enabled": true,
        "is_constant": false,
        "insertion_order": 100,
        "placement_hint": "before_prompt"
    });

    let create_entry_response = client
        .post(format!("{}/api/lorebooks/{}/entries", test_app.address, lorebook_id).as_str()) // Use test_app.address and include lorebook_id
        .header(reqwest::header::COOKIE, &auth_cookie) // Add auth_cookie
        .json(&create_entry_payload)
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(create_entry_response.status().is_success()); // Changed is_ok() to is_success()

    // 3. Delete the lorebook
    let delete_response = client
        .delete(format!("{}/api/lorebooks/{}", test_app.address, lorebook_id).as_str()) // Use test_app.address
        .header(reqwest::header::COOKIE, &auth_cookie) // Add auth_cookie
        .send()
        .await
        .expect("Failed to execute request.");

    assert!(delete_response.status().is_success()); // Changed is_ok() to is_success()

    // 4. Verify that delete_points_by_filter was called on the mock Qdrant service
    let calls = mock_qdrant_service.get_delete_points_by_filter_calls(); // Removed .await
    assert_eq!(calls.len(), 1, "delete_points_by_filter should have been called once");

    let called_filter = &calls[0];

    // Verify the filter conditions
    assert!(called_filter.must.iter().any(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "lorebook_id" && f.r#match.as_ref().map_or(false, |m| m.match_value.as_ref().map_or(false, |mv| mv == &MatchValue::Keyword(lorebook_id.to_string())))
        } else {
            false
        }
    }), "Filter should contain lorebook_id condition");

    assert!(called_filter.must.iter().any(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "user_id" && f.r#match.as_ref().map_or(false, |m| m.match_value.as_ref().map_or(false, |mv| mv == &MatchValue::Keyword(user_id.to_string())))
        } else {
            false
        }
    }), "Filter should contain user_id condition");

    assert!(called_filter.must.iter().any(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "source_type" && f.r#match.as_ref().map_or(false, |m| m.match_value.as_ref().map_or(false, |mv| mv == &MatchValue::Keyword("lorebook_entry".to_string())))
        } else {
            false
        }
    }), "Filter should contain source_type condition");
}

#[tokio::test]
async fn test_vector_cleanup_filter_structure() {
    // This is a unit test for the filter structure, independent of the full API flow
    let lorebook_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let vector_filter = Filter {
        must: vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "lorebook_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(lorebook_id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "user_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(user_id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "source_type".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                    }),
                    ..Default::default()
                })),
            },
        ],
        ..Default::default()
    };

    // Assertions to verify the filter structure
    assert_eq!(vector_filter.must.len(), 3);

    let lorebook_condition = vector_filter.must.iter().find(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "lorebook_id"
        } else {
            false
        }
    }).expect("Lorebook ID condition not found");

    if let Some(ConditionOneOf::Field(f)) = &lorebook_condition.condition_one_of {
        assert_eq!(f.key, "lorebook_id");
        assert_eq!(f.r#match.as_ref().unwrap().match_value.as_ref().unwrap(), &MatchValue::Keyword(lorebook_id.to_string()));
    } else {
        panic!("Expected Field condition for lorebook_id");
    }

    let user_condition = vector_filter.must.iter().find(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "user_id"
        } else {
            false
        }
    }).expect("User ID condition not found");

    if let Some(ConditionOneOf::Field(f)) = &user_condition.condition_one_of {
        assert_eq!(f.key, "user_id");
        assert_eq!(f.r#match.as_ref().unwrap().match_value.as_ref().unwrap(), &MatchValue::Keyword(user_id.to_string()));
    } else {
        panic!("Expected Field condition for user_id");
    }

    let source_type_condition = vector_filter.must.iter().find(|c| {
        if let Some(ConditionOneOf::Field(f)) = &c.condition_one_of {
            f.key == "source_type"
        } else {
            false
        }
    }).expect("Source type condition not found");

    if let Some(ConditionOneOf::Field(f)) = &source_type_condition.condition_one_of {
        assert_eq!(f.key, "source_type");
        assert_eq!(f.r#match.as_ref().unwrap().match_value.as_ref().unwrap(), &MatchValue::Keyword("lorebook_entry".to_string()));
    } else {
        panic!("Expected Field condition for source_type");
    }
}