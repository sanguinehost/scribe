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
        "sliding_window_messages" => apply_sliding_window_messages(history, limit as usize),
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
    
    // If history is empty, return empty result
    if history.is_empty() {
        return Vec::new();
    }

    // Clone the messages since we'll be modifying them
    let mut messages = history;
    let total_messages = messages.len();

    // Log the original message content and tokens
    for (i, msg) in messages.iter().enumerate() {
        debug!("Original message {}: {:?} - {} tokens", 
               i, 
               msg.content, 
               msg.content.chars().count());
    }

    // First calculate total tokens (character count) in all messages
    let total_tokens: usize = messages.iter()
        .map(|m| m.content.chars().count())
        .sum();

    debug!("Total tokens: {}, limit: {}", total_tokens, limit);

    // If total tokens are already within limit, just return the original history
    if total_tokens <= limit {
        debug!("No truncation needed, returning original {} messages", messages.len());
        return messages;
    }

    // We need to truncate, starting with the oldest messages
    let excess_tokens = total_tokens - limit;
    let mut tokens_to_remove = excess_tokens;
    
    debug!("Need to remove {} tokens", tokens_to_remove);
    
    // Start with the oldest messages (lowest indices) and truncate as needed
    for i in 0..total_messages {
        let msg_tokens = messages[i].content.chars().count();
        
        if tokens_to_remove > 0 {
            // Need to truncate this message
            if msg_tokens <= tokens_to_remove {
                // This message would be truncated entirely, but we need to keep at least 1 character
                let truncated_content: String = messages[i].content.chars().take(1).collect();
                debug!("Message {}: Truncated from {} to 1 char: '{}'", 
                       i, msg_tokens, truncated_content);
                messages[i].content = truncated_content;
                tokens_to_remove -= msg_tokens - 1; // Subtract tokens removed (all but 1)
            } else {
                // Can truncate part of this message
                let keep_chars = msg_tokens - tokens_to_remove;
                // Keep the *first* keep_chars characters
                // let skip_chars = msg_tokens - keep_chars; // No longer needed
                let truncated_content: String = messages[i].content.chars().take(keep_chars).collect();
                debug!("Message {}: Truncated from {} to {} chars: '{}'", 
                       i, msg_tokens, keep_chars, truncated_content);
                messages[i].content = truncated_content;
                tokens_to_remove = 0; // All needed truncation done
            }
        }
        
        // Stop once we've removed enough tokens
        if tokens_to_remove == 0 {
            debug!("Removed sufficient tokens, stopping truncation");
            break;
        }
    }

    // Log the final message content and tokens
    debug!("After truncation, returning {} messages:", messages.len());
    for (i, msg) in messages.iter().enumerate() {
        debug!("Final message {}: {:?} - {} tokens", 
               i, 
               msg.content, 
               msg.content.chars().count());
    }

    messages
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