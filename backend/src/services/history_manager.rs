// backend/src/services/history_manager.rs

use crate::models::chats::ChatMessage;
use tracing::{debug, warn};

/// Applies the configured history management strategy to a list of chat messages.
///
/// # Arguments
///
/// * `history` - The full chat history retrieved from the database.
/// * `strategy` - The history management strategy (e.g., "`sliding_window_tokens`", "`none`").
/// * `limit` - The limit associated with the strategy (e.g., token count, message count).
///
/// # Returns
///
/// A new `Vec<ChatMessage>` containing the managed history.
/// Applies the specified strategy to manage history within the given limit
fn apply_strategy(history: Vec<ChatMessage>, strategy: &str, limit: usize) -> Vec<ChatMessage> {
    match strategy {
        "sliding_window_messages" | "message_window" => {
            apply_sliding_window_messages(history, limit)
        }
        "sliding_window_tokens" => apply_sliding_window_tokens(history, limit),
        "truncate_tokens" => apply_truncate_tokens(history, limit),
        "none" => history, // Return original history if strategy is 'none'
        _ => {
            warn!(%strategy, "Unknown history management strategy, defaulting to 'none'.");
            history // Return original history if strategy is unknown
        }
    }
}

pub fn manage_history(history: Vec<ChatMessage>, strategy: &str, limit: i32) -> Vec<ChatMessage> {
    if limit <= 0 {
        warn!(%strategy, %limit, "History management limit is non-positive, returning full history.");
        return history;
    }

    debug!(%strategy, %limit, initial_length = history.len(), "Applying history management");

    let usize_limit = limit.try_into().unwrap_or(0);
    let managed_history = apply_strategy(history, strategy, usize_limit);

    debug!(
        final_length = managed_history.len(),
        "History management applied"
    );
    managed_history
}

/// Keeps the most recent `limit` messages.
fn apply_sliding_window_messages(history: Vec<ChatMessage>, limit: usize) -> Vec<ChatMessage> {
    let history_len = history.len(); // Calculate length before consuming history
    if history_len <= limit {
        return history;
    }
    let skip_amount = history_len - limit;
    history.into_iter().skip(skip_amount).collect()
}

/// Keeps the most recent messages whose total token count (approximated by char count) is within the `limit`.
/// Always keeps at least the most recent message, even if it exceeds the limit.
fn apply_sliding_window_tokens(history: Vec<ChatMessage>, limit: usize) -> Vec<ChatMessage> {
    let mut current_tokens = 0;
    let mut result = Vec::new();

    for message in history.into_iter().rev() {
        // TODO: Replace character count with a proper tokenizer (e.g., tiktoken-rs)
        let message_tokens = estimate_message_tokens(&message);

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
/// This differs from `sliding_window_tokens` by keeping all messages rather than dropping any.
fn apply_truncate_tokens(history: Vec<ChatMessage>, limit: usize) -> Vec<ChatMessage> {
    debug!(
        "apply_truncate_tokens: got {} messages with limit {}",
        history.len(),
        limit
    );

    // Handle edge cases: empty history or zero limit
    if history.is_empty() || limit == 0 {
        debug!("History empty or limit is 0, returning empty vec.");
        return Vec::new();
    }

    let result = process_messages_within_limit(history, limit);
    log_final_truncation_state(&result, limit);
    result
}

/// Process messages from newest to oldest, fitting them within the token limit
fn process_messages_within_limit(history: Vec<ChatMessage>, limit: usize) -> Vec<ChatMessage> {
    let mut result = Vec::new();
    let mut current_tokens = 0;

    // Iterate backwards through messages (newest to oldest)
    for message in history.into_iter().rev() {
        let message_tokens = estimate_message_tokens(&message);

        if current_tokens + message_tokens <= limit {
            current_tokens += message_tokens;
            result.push(message);
            log_message_accepted(message_tokens, current_tokens, &result);
        } else {
            let remaining_limit = limit - current_tokens;
            if remaining_limit > 0 {
                if let Some(truncated_message) = try_truncate_message(message, remaining_limit, limit) {
                    result.push(truncated_message);
                }
            } else {
                debug!(
                    "No remaining limit ({} tokens used >= limit {}), stopping.",
                    current_tokens, limit
                );
            }
            break;
        }
    }

    // Restore original chronological order (oldest first)
    result.reverse();
    result
}

/// Attempt to truncate a message to fit within the remaining token limit
fn try_truncate_message(message: ChatMessage, remaining_limit: usize, total_limit: usize) -> Option<ChatMessage> {
    let mut truncated_message = message;
    let content_str = String::from_utf8_lossy(&truncated_message.content);
    let content_len = content_str.chars().count();

    if content_len > remaining_limit {
        let skip_chars = content_len - remaining_limit;
        let truncated_content_str: String = content_str.chars().skip(skip_chars).collect();
        truncated_message.content = truncated_content_str.into_bytes();

        debug!(
            "Truncating message: skip_chars={}, remaining_limit={}, limit={}, content={}",
            skip_chars,
            remaining_limit,
            total_limit,
            String::from_utf8_lossy(&truncated_message.content)
        );
    } else {
        debug!(
            "Message ({}) already fits remaining limit ({}), adding as is.",
            content_len,
            remaining_limit
        );
    }
    Some(truncated_message)
}

/// Log when a message is accepted within the token limit
fn log_message_accepted(message_tokens: usize, current_tokens: usize, result: &[ChatMessage]) {
    if let Some(last_message) = result.last() {
        debug!(
            "Message accepted: tokens={}, current_tokens={}, content={}",
            message_tokens,
            current_tokens,
            String::from_utf8_lossy(&last_message.content)
        );
    }
}

/// Log the final state after truncation processing
fn log_final_truncation_state(result: &[ChatMessage], limit: usize) {
    let final_token_count: usize = result
        .iter()
        .map(|m| String::from_utf8_lossy(&m.content).chars().count())
        .sum();
    debug!(
        "Truncation complete. Returning {} messages with total tokens: {} (limit: {})",
        result.len(),
        final_token_count,
        limit
    );
    for (i, msg) in result.iter().enumerate() {
        debug!(
            "Message({}): {}, tokens={}",
            i,
            String::from_utf8_lossy(&msg.content),
            estimate_message_tokens(msg)
        );
    }
}

/// Naive token count approximation - counts characters which is roughly proportional to tokens
fn estimate_message_tokens(message: &ChatMessage) -> usize {
    // Convert Vec<u8> to String before calling chars()
    let content_str = String::from_utf8_lossy(&message.content).to_string();
    let message_tokens = content_str.chars().count(); // Approximation
    message_tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::chats::MessageRole;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_message(id: Uuid, role: MessageRole, content: &str) -> ChatMessage {
        ChatMessage {
            id,
            session_id: Uuid::new_v4(),
            message_type: role,
            content: content.as_bytes().to_vec(),
            content_nonce: None, // Added missing field
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
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
        let msg2 = create_test_message(
            Uuid::new_v4(),
            MessageRole::Assistant,
            "This message is very long indeed",
        ); // 30 chars
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "sliding_window_tokens", 10); // Limit 10
        assert_eq!(managed.len(), 1); // Only keeps the last message
        assert_eq!(managed[0].id, msg2.id);
    }

    // --- Truncate Tokens (Character Count Approximation) ---

    #[test]
    fn test_truncate_tokens_under_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 20);
        assert_eq!(managed.len(), 2);
        assert_eq!(String::from_utf8_lossy(&managed[0].content), "Hello");
        assert_eq!(String::from_utf8_lossy(&managed[1].content), "World");
    }

    #[test]
    fn test_truncate_tokens_at_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "Hello");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "World");
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 10);
        assert_eq!(managed.len(), 2);
        assert_eq!(String::from_utf8_lossy(&managed[0].content), "Hello");
        assert_eq!(String::from_utf8_lossy(&managed[1].content), "World");
    }

    #[test]
    fn test_truncate_tokens_over_limit_truncates_oldest() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "This is message one");
        let msg2 = create_test_message(
            Uuid::new_v4(),
            MessageRole::Assistant,
            "This is message two",
        );
        let history = vec![msg1.clone(), msg2.clone()];
        let managed = manage_history(history.clone(), "truncate_tokens", 30);

        assert_eq!(managed.len(), 2, "Should keep two messages, one truncated");
        assert_eq!(
            String::from_utf8_lossy(&managed[0].content),
            "message one",
            "First message should be truncated"
        );
        assert_eq!(
            String::from_utf8_lossy(&managed[1].content),
            "This is message two",
            "Second message should be intact"
        );
    }

    #[test]
    fn test_truncate_tokens_over_limit_drops_oldest() {
        let msg1 = create_test_message(
            Uuid::new_v4(),
            MessageRole::User,
            "This is a very long first message that will be dropped",
        );
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Short second");
        let history = vec![msg1, msg2];
        let managed = manage_history(history, "truncate_tokens", 10);

        assert_eq!(
            managed.len(),
            1,
            "Should keep only the (truncated) second message"
        );
        assert_eq!(
            String::from_utf8_lossy(&managed[0].content),
            "ort second",
            "Second message should be truncated"
        );
    }

    #[test]
    fn test_truncate_tokens_keeps_last_if_over_limit() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "First message"); // 13 chars
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Second message"); // 14 chars
        let history = vec![msg1, msg2]; // Total 27 chars

        // Limit allows only part of the first message, second message fully
        let limit = 20;
        let managed = manage_history(history, "truncate_tokens", limit);

        assert_eq!(
            managed.len(),
            2,
            "Should keep both messages, truncating the first"
        );

        // Second message (newest) should be untouched
        assert_eq!(
            String::from_utf8_lossy(&managed[1].content),
            "Second message"
        );

        // First message (oldest) should be truncated
        // "Second message" is 14 tokens. Remaining limit = 20 - 14 = 6.
        // "First message" (13 tokens) should be truncated to 6 tokens by skipping the first (13-6)=7 chars.
        // "First message".chars().skip(7).collect() == "essage"
        let expected_truncated_msg1 = "essage";
        assert_eq!(
            String::from_utf8_lossy(&managed[0].content),
            expected_truncated_msg1,
            "Oldest message should be truncated from the beginning to fit the remaining token limit"
        );
    }

    #[test]
    fn test_truncate_tokens_multiple_messages() {
        let msg1 = create_test_message(Uuid::new_v4(), MessageRole::User, "One");
        let msg2 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Two");
        let msg3 = create_test_message(Uuid::new_v4(), MessageRole::User, "Three");
        let msg4 = create_test_message(Uuid::new_v4(), MessageRole::Assistant, "Four");
        let history = vec![msg1, msg2, msg3, msg4];
        let managed = manage_history(history, "truncate_tokens", 10);

        assert_eq!(managed.len(), 3);
        assert_eq!(String::from_utf8_lossy(&managed[0].content), "o");
        assert_eq!(String::from_utf8_lossy(&managed[1].content), "Three");
        assert_eq!(String::from_utf8_lossy(&managed[2].content), "Four");
    }
}
