use crate::{
    errors::AppError,
    models::{
        Message,
        lorebook_dtos::{
            ExtractLorebookEntriesFromChatPayload, ExtractLorebookEntriesFromChatResponse,
        },
    },
    schema::chat_messages,
};
use diesel::{QueryDsl, SelectableHelper, prelude::*};
use secrecy::{ExposeSecret, SecretBox};
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

use super::LorebookService;

impl LorebookService {
    /// Extract lorebook entries from chat messages
    #[instrument(skip(self, user_dek, payload))]
    pub async fn extract_entries_from_chat(
        &self,
        user_id: Uuid,
        lorebook_id: Uuid,
        payload: ExtractLorebookEntriesFromChatPayload,
        user_dek: &SecretBox<Vec<u8>>,
    ) -> Result<ExtractLorebookEntriesFromChatResponse, AppError> {
        info!(
            user_id = %user_id,
            lorebook_id = %lorebook_id,
            chat_session_id = %payload.chat_session_id,
            start_index = ?payload.start_message_index,
            end_index = ?payload.end_message_index,
            "Starting lorebook entry extraction from chat messages"
        );

        // 1. Verify user owns the lorebook
        self.verify_lorebook_ownership(user_id, lorebook_id).await?;

        // 2. Verify user owns the chat session
        self.verify_chat_ownership(user_id, payload.chat_session_id)
            .await?;

        // 3. Fetch messages from the chat session
        let messages = self
            .fetch_messages_for_extraction(
                payload.chat_session_id,
                payload.start_message_index,
                payload.end_message_index,
            )
            .await?;

        if messages.is_empty() {
            return Ok(ExtractLorebookEntriesFromChatResponse {
                success: false,
                entries_extracted: 0,
                entries: vec![],
                message: "No messages found in the specified range".to_string(),
            });
        }

        // 4. Decrypt message content
        let decrypted_messages = self.decrypt_messages(&messages, user_dek)?;

        // 5. Format messages for AI analysis
        let _formatted_context = self.format_messages_for_extraction(&decrypted_messages);

        // 6. Use AI to extract lorebook entries
        // TODO: Implement AI extraction logic using agentic system
        // For now, return a placeholder response
        info!(
            user_id = %user_id,
            lorebook_id = %lorebook_id,
            message_count = messages.len(),
            "Message extraction prepared, AI analysis would happen here"
        );

        Ok(ExtractLorebookEntriesFromChatResponse {
            success: true,
            entries_extracted: 0,
            entries: vec![],
            message: format!(
                "Extracted analysis from {} messages (AI implementation pending)",
                messages.len()
            ),
        })
    }

    /// Verify that the user owns the lorebook
    async fn verify_lorebook_ownership(
        &self,
        user_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        use crate::schema::lorebooks;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebook_exists = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id))
                    .filter(lorebooks::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "Interaction error while verifying lorebook ownership: {:?}",
                    e
                );
                AppError::InternalServerErrorGeneric(format!("Database interaction failed: {e}"))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook ownership: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to verify lorebook ownership: {e}"))
            })?;

        if lorebook_exists == 0 {
            return Err(AppError::NotFound(format!(
                "Lorebook with ID {lorebook_id} not found or access denied"
            )));
        }

        Ok(())
    }

    /// Verify that the user owns the chat session
    async fn verify_chat_ownership(
        &self,
        user_id: Uuid,
        chat_session_id: Uuid,
    ) -> Result<(), AppError> {
        use crate::schema::chat_sessions;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let chat_exists = conn
            .interact(move |conn_sync| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(chat_session_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .count()
                    .get_result::<i64>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while verifying chat ownership: {:?}", e);
                AppError::InternalServerErrorGeneric(format!("Database interaction failed: {e}"))
            })?
            .map_err(|e| {
                error!("Failed to query chat ownership: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to verify chat ownership: {e}"))
            })?;

        if chat_exists == 0 {
            return Err(AppError::NotFound(format!(
                "Chat session with ID {chat_session_id} not found or access denied"
            )));
        }

        Ok(())
    }

    /// Fetch messages from the chat session for extraction
    async fn fetch_messages_for_extraction(
        &self,
        chat_session_id: Uuid,
        start_index: Option<usize>,
        end_index: Option<usize>,
    ) -> Result<Vec<Message>, AppError> {
        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // Fetch all messages from the session, ordered by creation time
        let all_messages = conn
            .interact(move |conn_sync| {
                chat_messages::table
                    .filter(chat_messages::session_id.eq(chat_session_id))
                    .order(chat_messages::created_at.asc())
                    .select(Message::as_select())
                    .load::<Message>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching messages: {:?}", e);
                AppError::InternalServerErrorGeneric(format!("Database interaction failed: {e}"))
            })?
            .map_err(|e| {
                error!("Failed to query messages: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to fetch messages: {e}"))
            })?;

        // Apply index-based filtering if specified
        let messages = match (start_index, end_index) {
            (Some(start), Some(end)) => {
                if start > end {
                    return Err(AppError::BadRequest(
                        "start_message_index must be less than or equal to end_message_index"
                            .to_string(),
                    ));
                }
                let end_inclusive = end + 1; // Make end index inclusive
                all_messages
                    .into_iter()
                    .skip(start)
                    .take(end_inclusive.saturating_sub(start))
                    .collect()
            }
            (Some(start), None) => all_messages.into_iter().skip(start).collect(),
            (None, Some(end)) => {
                let end_inclusive = end + 1;
                all_messages.into_iter().take(end_inclusive).collect()
            }
            (None, None) => all_messages,
        };

        debug!("Fetched {} messages for extraction", messages.len());

        Ok(messages)
    }

    /// Decrypt message content for AI analysis
    fn decrypt_messages(
        &self,
        messages: &[Message],
        user_dek: &SecretBox<Vec<u8>>,
    ) -> Result<Vec<(String, String)>, AppError> {
        let user_dek_bytes = user_dek.expose_secret();
        let mut decrypted = Vec::new();

        for msg in messages {
            // Decrypt content
            let content_bytes = if let Some(nonce) = &msg.content_nonce {
                self.encryption_service
                    .decrypt(&msg.content, nonce, user_dek_bytes)?
            } else {
                // Fallback for unencrypted messages (shouldn't happen in production)
                msg.content.clone()
            };

            // Convert bytes to string
            let content = String::from_utf8(content_bytes).map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to decode message content: {e}"
                ))
            })?;

            // Determine role label
            let role = match msg.message_type {
                crate::models::chats::MessageRole::User => "User",
                crate::models::chats::MessageRole::Assistant => "Assistant",
                crate::models::chats::MessageRole::System => "System",
            };

            decrypted.push((role.to_string(), content));
        }

        Ok(decrypted)
    }

    /// Format messages into a text context for AI analysis
    fn format_messages_for_extraction(&self, messages: &[(String, String)]) -> String {
        messages
            .iter()
            .map(|(role, content)| format!("{}: {}", role, content))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}
