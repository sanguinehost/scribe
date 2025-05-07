// backend/src/services/history_manager.rs

use crate::models::chats::ChatMessage as DbChatMessage; // Removed unused MessageRole import
use tracing::{debug, warn};

/// Applies the configured history management strategy to a list of chat messages.
///
/// # Arguments
///
/// * `history` - The full chat history retrieved from the database.
/// * `strategy` - The history management strategy (e.g., "sliding_window_tokens", "none").
/// * `limit` - The limit associated with the strategy (e.g., token count, message count).
///
/// # Returns
///
/// A new `Vec<DbChatMessage>` containing the managed history.
pub fn manage_history(
    history: Vec<DbChatMessage>,
    strategy: &str,
    limit: i32,
) -> Vec<DbChatMessage> {
    if limit <= 0 {
        warn!(%strategy, %limit, "History management limit is non-positive, returning full history.");
        return history;
    }

    debug!(%strategy, %limit, initial_length = history.len(), "Applying history management");

    let managed_history = match strategy {
        "sliding_window_messages" | "message_window" => apply_sliding_window_messages(history, limit as usize),
        "sliding_window_tokens" => apply_sliding_window_tokens(history, limit as usize),
        "truncate_tokens" => apply_truncate_tokens(history, limit as usize),
        "none" | _ => {
            if strategy != "none" {
                warn!(%strategy, "Unknown history management strategy, defaulting to 'none'.");
            }
            history // Return original history if strategy is 'none' or unknown
        }
    };

    debug!(final_length = managed_history.len(), "History management applied");
    managed_history
}

/// Keeps the most recent `limit` messages.
fn apply_sliding_window_messages(
    history: Vec<DbChatMessage>,
    limit: usize,
) -> Vec<DbChatMessage> {
    let history_len = history.len(); // Calculate length before consuming history
    if history_len <= limit {
        return history;
    }
    let skip_amount = history_len - limit;
    history.into_iter().skip(skip_amount).collect()
}

/// Keeps the most recent messages whose total token count (approximated by char count) is within the `limit`.
/// Always keeps at least the most recent message, even if it exceeds the limit.
fn apply_sliding_window_tokens(
    history: Vec<DbChatMessage>,
    limit: usize,
) -> Vec<DbChatMessage> {
    let mut current_tokens = 0;
    let mut result = Vec::new();

    for message in history.into_iter().rev() {
        // TODO: Replace character count with a proper tokenizer (e.g., tiktoken-rs)
        let message_tokens = message.content.chars().count(); // Approximation

        if result.is_empty() || current_tokens + message_tokens <= limit {
            current_tokens += message_tokens;
            result.push(message);
        } else {
            // Stop adding messages once the limit is exceeded (but keep the ones already added)
            break;
        }
    }

    result.reverse(); // Restore original order
    result
}

/// Keeps ALL messages, but truncates the older ones if necessary to stay within the token `limit`.
/// (Approximated by character count).
/// This differs from sliding_window_tokens by keeping all messages rather than dropping any.
fn apply_truncate_tokens(
    history: Vec<DbChatMessage>,
    limit: usize,
) -> Vec<DbChatMessage> {
    debug!("apply_truncate_tokens: got {} messages with limit {}", history.len(), limit);

    // Handle edge cases: empty history or zero limit
    if history.is_empty() || limit == 0 {
        debug!("History empty or limit is 0, returning empty vec.");
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current_tokens = 0;

    // Iterate backwards through messages (newest to oldest)
    for message in history.into_iter().rev() {
        // Use character count as token approximation
        // TODO: Replace character count with a proper tokenizer (e.g., tiktoken-rs)
        let message_tokens = message.content.chars().count();

        if current_tokens + message_tokens <= limit {
            // This message fits entirely within the remaining limit
            current_tokens += message_tokens;
            result.push(message); // Add the original message
            debug!("Added full message ({} tokens, total {}): '{}'", message_tokens, current_tokens, result.last().unwrap().content);
        } else {
            // This message would exceed the limit if added fully.
            // Calculate remaining space and truncate the *beginning* of this message if possible.
            let remaining_limit = limit - current_tokens;
            if remaining_limit > 0 {
                // We have some space left, truncate the message
                let mut truncated_message = message.clone(); // Clone needed as we might modify content
                let content_len = truncated_message.content.chars().count();

                if content_len > remaining_limit {
                    // Truncate the beginning to fit exactly remaining_limit
                    let skip_chars = content_len - remaining_limit;
                    truncated_message.content = truncated_message.content.chars().skip(skip_chars).collect();
                    let truncated_len = truncated_message.content.chars().count(); // Should be == remaining_limit
                    debug!("Truncated message from {} to {} chars (fits remaining {}), total {}: '{}'",
                           content_len, truncated_len, remaining_limit, limit, truncated_message.content);
                    // current_tokens += truncated_len; // This assignment is unused as we break immediately after
                    result.push(truncated_message);
                } else {
                    // This case should not be logically reachable if message_tokens > remaining_limit,
                    // but if it happens (e.g., due to char vs byte issues not handled here),
                    // add the message as is if it fits the remaining limit.
                    // If it doesn't fit, it means remaining_limit was 0, handled below.
                     debug!("Message ({}) already fits remaining limit ({}), adding as is. Total: {}", content_len, remaining_limit, current_tokens + content_len);
                     // current_tokens += content_len; // This assignment is unused as we break immediately after
                     result.push(truncated_message); // Add the original message clone
                }

            } else {
                 // No space left (limit was already reached by newer messages)
                 debug!("No remaining limit ({} tokens used >= limit {}), stopping.", current_tokens, limit);
            }
            // Stop processing older messages once we've had to truncate or couldn't fit the next one
            break;
        }
    }

    // Restore original chronological order (oldest first)
    result.reverse();

    // Log the final state
    let final_token_count: usize = result.iter().map(|m| m.content.chars().count()).sum();
    debug!("Truncation complete. Returning {} messages with total tokens: {} (limit: {})", result.len(), final_token_count, limit);
    for (i, msg) in result.iter().enumerate() {
        debug!("Final message {}: '{}' ({} tokens)",
               i,
               msg.content,
               msg.content.chars().count());
    }

    result
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::chats::MessageRole;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_message(id: Uuid, role: MessageRole, content: &str) -> DbChatMessage {
        DbChatMessage {
            id,
            session_id: Uuid::new_v4(),
            message_type: role,
            content: content.to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn test_manage_history_none() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Hi");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "none", 10);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[1].id, msg2.id);
    }

    #[test]
    fn test_manage_history_unknown_strategy() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello");
        let history = vec![msg1.clone()];
        let managed = manage_history(history.clone(), "unknown_strategy", 10);
        assert_eq!(managed.len(), 1); // Should default to 'none'
        assert_eq!(managed[0].id, msg1.id);
    }

     #[test]
    fn test_manage_history_zero_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello");
        let history = vec![msg1.clone()];
        let managed = manage_history(history.clone(), "sliding_window_messages", 0);
        assert_eq!(managed.len(), 1); // Should return full history
        assert_eq!(managed[0].id, msg1.id);
    }

    // --- Sliding Window Messages ---

    #[test]
    fn test_sliding_window_messages_under_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "1");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "2");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_messages", 3);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[1].id, msg2.id);
    }

    #[test]
    fn test_sliding_window_messages_at_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "1");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "2");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_messages", 2);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[1].id, msg2.id);
    }

    #[test]
    fn test_sliding_window_messages_over_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "1");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "2");
        let msg3 = create_test_message(Uuid::new_v4(), MessageRole::User, "3");
        let history = vec![msg1.clone(), msg2.clone(), msg3.clone()];
        let managed = manage_history(history.clone(), "sliding_window_messages", 2);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg2.id); // msg1 should be dropped
        assert_eq!(managed[1].id, msg3.id);
    }

    #[test]
    fn test_sliding_window_messages_limit_one() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "1");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "2");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_messages", 1);
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].id, msg2.id); // Only the last message
    }

    // --- Sliding Window Tokens (Character Count Approximation) ---

    #[test]
    fn test_sliding_window_tokens_under_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World"); // 5 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_tokens", 15);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[1].id, msg2.id);
    }

    #[test]
    fn test_sliding_window_tokens_at_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World"); // 5 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_tokens", 10);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[1].id, msg2.id);
    }

    #[test]
    fn test_sliding_window_tokens_over_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "This is long"); // 12 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Short"); // 5 chars
        let msg3 = create_test_message(Uuid::new_v4(), MessageRole::User, "Medium"); // 6 chars
        let history = vec![msg1.clone(), msg2.clone(), msg3.clone()]; // Total 23 chars
        let managed = manage_history(history.clone(), "sliding_window_tokens", 15); // Limit 15
        assert_eq!(managed.len(), 2); // msg2 (5) + msg3 (6) = 11 <= 15
        assert_eq!(managed[0].id, msg2.id);
        assert_eq!(managed[1].id, msg3.id);
    }

     #[test]
    fn test_sliding_window_tokens_keeps_last_if_over_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Short"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "This message is very long indeed"); // 30 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_tokens", 10); // Limit 10
        assert_eq!(managed.len(), 1); // Only keeps the last message
        assert_eq!(managed[0].id, msg2.id);
    }

    // --- Truncate Tokens (Character Count Approximation) ---

    #[test]
    fn test_truncate_tokens_under_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World"); // 5 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 15);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].content, "Hello");
        assert_eq!(managed[1].content, "World");
    }

     #[test]
    fn test_truncate_tokens_at_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World"); // 5 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 10);
        assert_eq!(managed.len(), 2);
        assert_eq!(managed[0].content, "Hello");
        assert_eq!(managed[1].content, "World");
    }

    #[test]
    fn test_truncate_tokens_over_limit_truncates_oldest() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "This is message one"); // 19 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "This is message two"); // 19 chars
        let history = vec![msg1.clone(), msg2.clone()]; // Total 38 chars
        let managed = manage_history(history.clone(), "truncate_tokens", 30); // Limit 30
        assert_eq!(managed.len(), 2);
        // msg2 (19 chars) is kept fully. Remaining limit = 30 - 19 = 11
        // msg1 should be truncated to 11 chars from the end: "message one"
        assert_eq!(managed[0].id, msg1.id);
        assert_eq!(managed[0].content, "message one");
        assert_eq!(managed[1].id, msg2.id);
        assert_eq!(managed[1].content, "This is message two");
    }

    #[test]
    fn test_truncate_tokens_over_limit_drops_oldest() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "This is message one"); // 19 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "This is message two"); // 19 chars
        let history = vec![msg1.clone(), msg2.clone()]; // Total 38 chars
        let managed = manage_history(history.clone(), "truncate_tokens", 15); // Limit 15
        assert_eq!(managed.len(), 1); // msg2 (19) exceeds limit, so only msg2 is kept, truncated
        // msg2 should be truncated to keep the last 15 characters
        assert_eq!(managed[0].id, msg2.id);
        assert_eq!(managed[0].content, " is message two");
    }

    #[test]
    fn test_truncate_tokens_keeps_last_if_over_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Short"); // 5 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "This message is very long indeed"); // 30 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 10); // Limit 10
        assert_eq!(managed.len(), 1); // Only keeps the last message, truncated
        assert_eq!(managed[0].id, msg2.id);
        assert_eq!(managed[0].content, "ong indeed"); // Last 10 chars
    }

     #[test]
    fn test_truncate_tokens_multiple_messages() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "One");   // 3
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Two"); // 3
        let msg3 = create_test_message(Uuid::new_v4(), MessageRole::User, "Three"); // 5
        let msg4 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Four"); // 4
        let history = vec![msg1.clone(), msg2.clone(), msg3.clone(), msg4.clone()]; // Total 15
        let managed = manage_history(history.clone(), "truncate_tokens", 10); // Limit 10

        // Expected: msg4 (4), msg3 (5) = 9 chars. Remaining limit = 1.
        // msg2 ("Two") should be truncated to 1 char ("o").
        assert_eq!(managed.len(), 3);
        assert_eq!(managed[0].id, msg2.id);
        assert_eq!(managed[0].content, "o");
        assert_eq!(managed[1].id, msg3.id);
        assert_eq!(managed[1].content, "Three");
        assert_eq!(managed[2].id, msg4.id);
        assert_eq!(managed[2].content, "Four");
    }
}