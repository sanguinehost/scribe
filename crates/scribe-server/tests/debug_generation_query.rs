#[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend"), test))]
mod tests {
    use diesel::prelude::*;
    use scribe_backend::db::get_conn;
    use scribe_backend::db::SqliteInteractExt;
    use scribe_backend::db::{DbDecimal, DbId};
    use scribe_backend::models::chats::{ChatMode, NewChat, NewChatBuilder};
    use scribe_backend::models::users::NewUser;
    use scribe_backend::schema::{chat_sessions, users};
    use scribe_backend::test_helpers::spawn_app;

    #[tokio::test]
    async fn debug_session_queries() {
        let test_app = spawn_app(false, false, false).await;

        let user_id = DbId::new();
        let session_id = DbId::new();

        // precise setup as in the failing test
        let mut conn = get_conn(&test_app.db_pool).await.unwrap();

        // Create user
        conn.interact(move |conn| {
            diesel::insert_into(users::table)
                .values(NewUser {
                    id: user_id,
                    username: "test_user".to_string(),
                    ..Default::default()
                })
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

        // Create chat
        let new_chat = NewChat {
            id: session_id,
            user_id: user_id,
            model_name: Some("gemini-1.5-pro".to_string()),
            history_management_strategy: "message_window".to_string(),
            history_management_limit: 20,
            game_master_mode_enabled: false,
            ..Default::default()
        };

        let new_chat_clone = new_chat.clone();

        conn.interact(move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(new_chat_clone)
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

        let mut conn1 = get_conn(&test_app.db_pool).await.unwrap();

        // Debug Query 1
        println!("Running Query 1...");
        let res1 = conn1
            .interact(move |conn| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .select((
                        chat_sessions::history_management_strategy,
                        chat_sessions::history_management_limit,
                        chat_sessions::character_id,
                        chat_sessions::system_prompt_ciphertext,
                        chat_sessions::system_prompt_nonce,
                        chat_sessions::temperature,
                        chat_sessions::max_output_tokens,
                        chat_sessions::frequency_penalty,
                        chat_sessions::presence_penalty,
                        chat_sessions::top_k,
                        chat_sessions::model_name,
                    ))
                    .first::<(
                        String,
                        i32,
                        Option<DbId>,
                        Option<Vec<u8>>,
                        Option<Vec<u8>>,
                        Option<DbDecimal>,
                        Option<i32>,
                        Option<DbDecimal>,
                        Option<DbDecimal>,
                        Option<i32>,
                        String,
                    )>(conn)
            })
            .await
            .unwrap();

        match res1 {
            Ok(_) => println!("Query 1 Passed"),
            Err(e) => println!("Query 1 Failed: {:?}", e),
        }

        let mut conn2 = get_conn(&test_app.db_pool).await.unwrap();

        // Debug Query 2
        println!("Running Query 2...");
        let res2 = conn2
            .interact(move |conn| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .select((
                        chat_sessions::model_provider,
                        chat_sessions::thinking_budget,
                        chat_sessions::thinking_level,
                        chat_sessions::enable_code_execution,
                        chat_sessions::player_chronicle_id,
                        chat_sessions::agent_mode,
                        chat_sessions::game_master_mode_enabled,
                        chat_sessions::game_state,
                        chat_sessions::rag_chronicles_limit,
                        chat_sessions::rag_lorebooks_limit,
                        chat_sessions::rag_older_chat_limit,
                    ))
                    .first::<(
                        Option<String>,
                        Option<i32>,
                        Option<String>,
                        Option<bool>,
                        Option<DbId>,
                        Option<String>,
                        bool,
                        Option<scribe_backend::db::DbJson>,
                        Option<i32>,
                        Option<i32>,
                        Option<i32>,
                    )>(conn)
            })
            .await
            .unwrap();

        match res2 {
            Ok(_) => println!("Query 2 Passed"),
            Err(e) => println!("Query 2 Failed: {:?}", e),
        }
    }
}
