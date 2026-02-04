#![cfg(test)]

use chrono::Utc;
use diesel::prelude::*;
#[cfg(feature = "sqlite-backend")]
use scribe_backend::db::SqliteInteractExt;
use scribe_backend::services::embeddings::metadata::CognitiveFactMetadata;
use scribe_backend::{
    auth::session_dek::SessionDek,
    db::DbId,
    models::cognitive_memory::{CognitiveFact, NewCognitiveFact},
    schema::cognitive_facts,
    test_helpers::{self, PipelineCall},
};
use secrecy::SecretBox;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_actor_aware_recall_prioritization() -> anyhow::Result<()> {
    // 1. Setup App
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "actor_aware_user".to_string(),
        "password".to_string(),
    )
    .await?;

    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // 2. Create and Insert Mock Facts
    // Fact 1: About Aragorn
    let fact1_id = Uuid::new_v4();
    let (who1_enc, who1_nonce) = scribe_backend::crypto::encrypt_gcm(b"Aragorn", &session_dek.0)?;
    let (what1_enc, what1_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"found the ancient sword", &session_dek.0)?;
    let (where1_enc, where1_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"Rivendell", &session_dek.0)?;
    let (when1_enc, when1_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"Third Age", &session_dek.0)?;
    let (why1_enc, why1_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"to reclaim his heritage", &session_dek.0)?;

    // Fact 2: About Legolas
    let fact2_id = Uuid::new_v4();
    let (who2_enc, who2_nonce) = scribe_backend::crypto::encrypt_gcm(b"Legolas", &session_dek.0)?;
    let (what2_enc, what2_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"shot an arrow", &session_dek.0)?;
    let (where2_enc, where2_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"Mirkwood", &session_dek.0)?;
    let (when2_enc, when2_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"Third Age", &session_dek.0)?;
    let (why2_enc, why2_nonce) =
        scribe_backend::crypto::encrypt_gcm(b"to defend the forest", &session_dek.0)?;

    #[cfg(feature = "postgres-backend")]
    let conn = test_app.db_pool.get().await?;
    #[cfg(feature = "sqlite-backend")]
    let mut conn = test_app.db_pool.get()?;
    conn.interact(move |conn| {
        diesel::insert_into(cognitive_facts::table)
            .values(&vec![
                NewCognitiveFact {
                    id: fact1_id.into(),
                    user_id: user.id,
                    chronicle_id: chronicle_id.into(),
                    who_encrypted: who1_enc,
                    who_nonce: who1_nonce,
                    what_encrypted: what1_enc,
                    what_nonce: what1_nonce,
                    where_encrypted: where1_enc,
                    where_nonce: where1_nonce,
                    when_encrypted: when1_enc,
                    when_nonce: when1_nonce,
                    why_encrypted: why1_enc,
                    why_nonce: why1_nonce,
                    fact_type: "Experience".to_string(),
                    message_variant_id: None,
                    confidence: 1.0,
                    significance: 1.0,
                    created_at: Utc::now().into(),
                },
                NewCognitiveFact {
                    id: fact2_id.into(),
                    user_id: user.id,
                    chronicle_id: chronicle_id.into(),
                    who_encrypted: who2_enc,
                    who_nonce: who2_nonce,
                    what_encrypted: what2_enc,
                    what_nonce: what2_nonce,
                    where_encrypted: where2_enc,
                    where_nonce: where2_nonce,
                    when_encrypted: when2_enc,
                    when_nonce: when2_nonce,
                    why_encrypted: why2_enc,
                    why_nonce: why2_nonce,
                    fact_type: "Experience".to_string(),
                    message_variant_id: None,
                    confidence: 1.0,
                    significance: 1.0,
                    created_at: Utc::now().into(),
                },
            ])
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;

    // 3. Setup Mock Embedding Pipeline Responses
    // Return both facts for any query, but we'll see if prioritization works
    let fact_meta1 = CognitiveFactMetadata {
        user_id: user.id,
        fact_id: fact1_id.into(),
        chronicle_id: chronicle_id.into(),
        source_type: "cognitive_fact".to_string(),
        game_time: None,
        reasoning_content: None,
        reasoning_content_nonce: None,
        message_variant_id: None,
    };
    let fact_meta2 = CognitiveFactMetadata {
        user_id: user.id,
        fact_id: fact2_id.into(),
        chronicle_id: chronicle_id.into(),
        source_type: "cognitive_fact".to_string(),
        game_time: None,
        reasoning_content: None,
        reasoning_content_nonce: None,
        message_variant_id: None,
    };

    // Return Legolas (non-match) first, then Aragorn (match)
    test_app
        .mock_embedding_pipeline_service
        .set_fact_responses_sequence(vec![Ok(vec![
            (0.9, fact_meta2.clone()),
            (0.8, fact_meta1.clone()),
        ])]);
    test_app
        .mock_embedding_pipeline_service
        .set_opinion_responses_sequence(vec![Ok(vec![])]);

    // 4. Call recall_context with "Aragorn" as target actor
    let context_aragorn = test_app
        .recall_pipeline
        .recall_context(
            user.id,
            chronicle_id.into(),
            "What happened?",
            &session_dek,
            test_app.create_app_state().await,
            Some(vec!["Aragorn".to_string()]),
            None,
            None,
        )
        .await?;

    println!("Context for Aragorn:\n{}", context_aragorn);

    // Verify Aragorn fact is present
    assert!(context_aragorn.contains("Aragorn"));
    assert!(context_aragorn.contains("found the ancient sword"));

    // Verify Legolas fact is also present
    assert!(context_aragorn.contains("Legolas"));

    // Verify Aragorn (matching) comes BEFORE Legolas (non-matching)
    let aragorn_pos = context_aragorn.find("Aragorn").unwrap();
    let legolas_pos = context_aragorn.find("Legolas").unwrap();
    assert!(
        aragorn_pos < legolas_pos,
        "Aragorn should be prioritized before Legolas"
    );

    Ok(())
}
