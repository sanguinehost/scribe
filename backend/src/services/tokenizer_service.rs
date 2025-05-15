use std::path::Path;
use std::sync::Arc;

use sentencepiece::SentencePieceProcessor;
use tracing::{debug, error, info};

use crate::errors::{AppError, Result};

/// Model-specific tokenizer for LLM operations
/// 
/// The TokenizerService wraps SentencePiece models and provides methods for
/// encoding text to token IDs and decoding token IDs back to text.
#[derive(Debug, Clone)]
pub struct TokenizerService {
    processor: Arc<SentencePieceProcessor>,
    model_name: String,
}

impl TokenizerService {
    /// Create a new TokenizerService from a SentencePiece model file
    pub fn new(model_path: impl AsRef<Path>) -> Result<Self> {
        let path = model_path.as_ref();
        let model_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        debug!("Loading SentencePiece model from {}", path.display());
        
        let processor = SentencePieceProcessor::open(path)
            .map_err(|e| {
                error!("Failed to load SentencePiece model: {}", e);
                AppError::ConfigError(format!("Failed to load tokenizer model: {}", e))
            })?;
        
        info!("Loaded SentencePiece model: {}", model_name);
        
        Ok(Self {
            processor: Arc::new(processor),
            model_name,
        })
    }

    /// Returns the name of the model
    pub fn model_name(&self) -> &str {
        &self.model_name
    }
    
    /// Returns the vocabulary size of the model
    pub fn vocab_size(&self) -> usize {
        self.processor.len()
    }

    /// Returns the BOS (Beginning of Sequence) token ID if available
    pub fn bos_id(&self) -> Option<u32> {
        self.processor.bos_id()
    }

    /// Returns the EOS (End of Sequence) token ID if available
    pub fn eos_id(&self) -> Option<u32> {
        self.processor.eos_id()
    }

    /// Returns the PAD token ID if available
    pub fn pad_id(&self) -> Option<u32> {
        self.processor.pad_id()
    }

    /// Returns the UNK (Unknown) token ID
    pub fn unk_id(&self) -> u32 {
        self.processor.unk_id()
    }

    /// Encodes a single text string into token IDs
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        let pieces = self.processor.encode(text).map_err(|e| {
            error!("Failed to encode text: {}", e);
            AppError::TextProcessingError(format!("Tokenizer encoding error: {}", e))
        })?;
        
        Ok(pieces.into_iter().map(|p| p.id).collect())
    }

    /// Encodes a batch of text strings into token IDs
    pub fn encode_batch(&self, texts: &[String]) -> Result<Vec<Vec<u32>>> {
        let mut results = Vec::with_capacity(texts.len());
        
        for text in texts {
            let tokens = self.encode(text)?;
            results.push(tokens);
        }
        
        Ok(results)
    }

    /// Decodes token IDs back to text
    pub fn decode(&self, token_ids: &[u32]) -> Result<String> {
        self.processor.decode_piece_ids(token_ids).map_err(|e| {
            error!("Failed to decode token IDs: {}", e);
            AppError::TextProcessingError(format!("Tokenizer decoding error: {}", e))
        })
    }

    /// Gets the piece (token) for a given ID
    pub fn id_to_piece(&self, id: u32) -> Result<Option<String>> {
        // This is a helper method - SentencePiece doesn't provide a direct id_to_piece method,
        // so we need to decode a single token
        if id >= self.processor.len() as u32 {
            return Ok(None);
        }
        
        let text = self.decode(&[id])?;
        Ok(Some(text))
    }

    /// Gets the ID for a given piece (token)
    pub fn piece_to_id(&self, piece: &str) -> Result<Option<u32>> {
        self.processor.piece_to_id(piece)
            .map_err(|e| {
                error!("Failed to get ID for piece '{}': {}", piece, e);
                AppError::TextProcessingError(format!("Error in piece_to_id: {}", e))
            })
    }

    /// Counts the number of tokens in a text string
    pub fn count_tokens(&self, text: &str) -> Result<usize> {
        let tokens = self.encode(text)?;
        Ok(tokens.len())
    }
}

// Update AppError with TextProcessingError
impl From<sentencepiece::SentencePieceError> for AppError {
    fn from(err: sentencepiece::SentencePieceError) -> Self {
        AppError::TextProcessingError(format!("SentencePiece error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn get_test_model_path() -> PathBuf {
        PathBuf::from("/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model")
    }

    #[test]
    fn test_tokenizer_service_creation() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        
        // Basic assertions to make sure the tokenizer is working
        assert!(tokenizer.vocab_size() > 0);
        assert_eq!(tokenizer.model_name(), "gemma.model");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        
        let text = "Hello world, this is a test.";
        let tokens = tokenizer.encode(text).expect("Failed to encode text");
        let decoded = tokenizer.decode(&tokens).expect("Failed to decode tokens");
        
        // The decoded text might not exactly match the original
        // due to tokenization nuances, but should be close
        assert!(decoded.contains("Hello world"));
        assert!(decoded.contains("test"));
    }

    #[test]
    fn test_special_tokens() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        
        // Test if special tokens are available (model-dependent)
        // These assertions may need adjustment based on the actual model used
        assert!(tokenizer.unk_id() > 0);
    }

    #[test]
    fn test_token_counting() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
        
        let text = "Short text.";
        let token_count = tokenizer.count_tokens(text).expect("Failed to count tokens");
        
        // The exact count will depend on the model, but should be reasonable
        assert!(token_count > 0);
        assert!(token_count < 10); // A short text shouldn't have too many tokens
    }
}