use tokenizers::Tokenizer;
use crate::IntelligenceError;

pub struct TokenCounter {
    tokenizer: Tokenizer,
}

impl TokenCounter {
    pub fn new_default() -> Result<Self, IntelligenceError> {
        // In a real scenario, we'd load a specific tokenizer file.
        // For now, we'll try to load from a common model name or return error.
        Err(IntelligenceError::Internal("Default tokenizer loading not implemented".to_string()))
    }

    pub fn count_tokens(&self, text: &str) -> usize {
        match self.tokenizer.encode(text, true) {
            Ok(encoding) => encoding.get_ids().len(),
            Err(_) => text.split_whitespace().count(), // Fallback
        }
    }
}
