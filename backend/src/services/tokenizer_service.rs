use std::path::{Path, PathBuf};
use std::sync::Arc;

use image::GenericImageView;
use sentencepiece::SentencePieceProcessor;
use tracing::{debug, error, info, warn};

use crate::errors::{AppError, Result};

/// Represents a token count estimate with detailed breakdowns
#[derive(Debug, Clone, Default)]
pub struct TokenEstimate {
    /// Total number of tokens (text + images + video + audio)
    pub total: usize,
    /// Number of tokens from text content
    pub text: usize,
    /// Number of tokens from image content
    pub images: usize,
    /// Number of tokens from video content
    pub video: usize,
    /// Number of tokens from audio content
    pub audio: usize,
    /// Indicates whether this is an exact count or an estimate
    pub is_estimate: bool,
}

impl TokenEstimate {
    /// Creates a new token estimate with only text tokens
    #[must_use]
    pub const fn new_text_only(count: usize) -> Self {
        Self {
            total: count,
            text: count,
            images: 0,
            video: 0,
            audio: 0,
            is_estimate: false,
        }
    }

    /// Add counts from another estimate
    pub fn combine(&mut self, other: &Self) {
        self.total += other.total;
        self.text += other.text;
        self.images += other.images;
        self.video += other.video;
        self.audio += other.audio;
        // If either is an estimate, the combined result is an estimate
        self.is_estimate = self.is_estimate || other.is_estimate;
    }
}

/// Supported content types for token counting
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    Text,
    Image,
    Video,
    Audio,
}

/// Model-specific tokenizer for LLM operations
///
/// The `TokenizerService` wraps `SentencePiece` models and provides methods for
/// encoding text to token IDs and decoding token IDs back to text.
#[derive(Debug, Clone)]
pub struct TokenizerService {
    processor: Arc<SentencePieceProcessor>,
    model_name: String,
}

impl TokenizerService {
    /// Create a new `TokenizerService` from a `SentencePiece` model file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The model file cannot be read
    /// - The model file is not a valid `SentencePiece` model
    /// - The processor cannot be initialized
    pub fn new(model_path: impl AsRef<Path>) -> Result<Self> {
        let path = model_path.as_ref();
        let model_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        debug!("Loading SentencePiece model from {}", path.display());

        let processor = SentencePieceProcessor::open(path).map_err(|e| {
            error!("Failed to load SentencePiece model: {}", e);
            AppError::ConfigError(format!("Failed to load tokenizer model: {e}"))
        })?;

        info!("Loaded SentencePiece model: {}", model_name);

        Ok(Self {
            processor: Arc::new(processor),
            model_name,
        })
    }

    /// Returns the name of the model
    #[must_use]
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// Returns the vocabulary size of the model
    #[must_use]
    pub fn vocab_size(&self) -> usize {
        self.processor.len()
    }

    /// Returns the BOS (Beginning of Sequence) token ID if available
    #[must_use]
    pub fn bos_id(&self) -> Option<u32> {
        self.processor.bos_id()
    }

    /// Returns the EOS (End of Sequence) token ID if available
    #[must_use]
    pub fn eos_id(&self) -> Option<u32> {
        self.processor.eos_id()
    }

    /// Returns the PAD token ID if available
    #[must_use]
    pub fn pad_id(&self) -> Option<u32> {
        self.processor.pad_id()
    }

    /// Returns the UNK (Unknown) token ID
    #[must_use]
    pub fn unk_id(&self) -> u32 {
        self.processor.unk_id()
    }

    /// Encodes a single text string into token IDs
    ///
    /// # Errors
    ///
    /// Returns an error if the text cannot be encoded by the `SentencePiece` processor
    pub fn encode(&self, text: &str) -> Result<Vec<u32>> {
        let pieces = self.processor.encode(text).map_err(|e| {
            error!("Failed to encode text: {}", e);
            AppError::TextProcessingError(format!("Tokenizer encoding error: {e}"))
        })?;

        Ok(pieces.into_iter().map(|p| p.id).collect())
    }

    /// Encodes a batch of text strings into token IDs
    ///
    /// # Errors
    ///
    /// Returns an error if any text in the batch cannot be encoded
    pub fn encode_batch(&self, texts: &[String]) -> Result<Vec<Vec<u32>>> {
        let mut results = Vec::with_capacity(texts.len());

        for text in texts {
            let tokens = self.encode(text)?;
            results.push(tokens);
        }

        Ok(results)
    }

    /// Decodes token IDs back to text
    ///
    /// # Errors
    ///
    /// Returns an error if the token IDs cannot be decoded by the `SentencePiece` processor
    pub fn decode(&self, token_ids: &[u32]) -> Result<String> {
        self.processor.decode_piece_ids(token_ids).map_err(|e| {
            error!("Failed to decode token IDs: {}", e);
            AppError::TextProcessingError(format!("Tokenizer decoding error: {e}"))
        })
    }

    /// Gets the piece (token) for a given ID
    ///
    /// # Errors
    ///
    /// Returns an error if the ID cannot be converted to a piece
    pub fn id_to_piece(&self, id: u32) -> Result<Option<String>> {
        // This is a helper method - SentencePiece doesn't provide a direct id_to_piece method,
        // so we need to decode a single token
        if id >= u32::try_from(self.processor.len()).unwrap_or(u32::MAX) {
            return Ok(None);
        }

        let text = self.decode(&[id])?;
        Ok(Some(text))
    }

    /// Gets the ID for a given piece (token)
    ///
    /// # Errors
    ///
    /// Returns an error if the piece cannot be converted to an ID
    pub fn piece_to_id(&self, piece: &str) -> Result<Option<u32>> {
        self.processor.piece_to_id(piece).map_err(|e| {
            error!("Failed to get ID for piece '{}': {}", piece, e);
            AppError::TextProcessingError(format!("Error in piece_to_id: {e}"))
        })
    }

    /// Counts the number of tokens in a text string
    ///
    /// # Errors
    ///
    /// Returns an error if the text cannot be tokenized
    pub fn count_tokens(&self, text: &str) -> Result<usize> {
        let tokens = self.encode(text)?;
        Ok(tokens.len())
    }

    /// Estimates tokens for text, returning a `TokenEstimate` object
    ///
    /// # Errors
    ///
    /// Returns an error if the text cannot be tokenized by the underlying `SentencePiece` model
    pub fn estimate_text_tokens(&self, text: &str) -> Result<TokenEstimate> {
        let token_count = self.count_tokens(text)?;
        Ok(TokenEstimate::new_text_only(token_count))
    }

    /// Estimates tokens for an image based on Gemini's image token counting rules
    ///
    /// Gemini 2.0 counts images as follows:
    /// - Images with both dimensions ≤ 384 pixels: 258 tokens
    /// - Larger images: 258 tokens per 768x768 tile (scaled and cropped as needed)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The image file cannot be read or opened
    /// - The image format is not supported
    /// - Image dimensions cannot be determined
    pub fn estimate_image_tokens(&self, image_path: impl AsRef<Path>) -> Result<TokenEstimate> {
        let path = image_path.as_ref();

        // Open the image to get dimensions
        let img = image::open(path).map_err(|e| {
            error!("Failed to open image at {}: {}", path.display(), e);
            AppError::TextProcessingError(format!(
                "Failed to open image for token estimation: {e}"
            ))
        })?;

        let (width, height) = img.dimensions();

        // Small images (both dimensions ≤ 384 pixels) are counted as 258 tokens
        if width <= 384 && height <= 384 {
            debug!("Small image ({}x{}): 258 tokens", width, height);
            return Ok(TokenEstimate {
                total: 258,
                images: 258,
                is_estimate: true,
                ..Default::default()
            });
        }

        // Larger images are processed into 768x768 tiles
        // Calculate how many tiles would be needed (ceiling division)
        let tiles_x = ((width + 767) / 768) as usize; // Integer ceiling division
        let tiles_y = ((height + 767) / 768) as usize; // Integer ceiling division
        let total_tiles = tiles_x * tiles_y;

        // Each tile is 258 tokens
        let token_count = total_tiles * 258;

        debug!(
            "Large image ({}x{}): {} tiles, {} tokens",
            width, height, total_tiles, token_count
        );

        Ok(TokenEstimate {
            total: token_count,
            images: token_count,
            is_estimate: true,
            ..Default::default()
        })
    }

    /// Estimates tokens for video content based on Gemini's counting rules
    ///
    /// For Gemini, video is counted at a fixed rate of 263 tokens per second
    #[must_use]
    pub fn estimate_video_tokens(&self, duration_seconds: f64) -> TokenEstimate {
        // Calculate token count with safe conversion
        let token_count = if duration_seconds <= 0.0 {
            0
        } else {
            let tokens = duration_seconds * 263.0;
            let tokens_ceiled = tokens.ceil();
            // Use safe conversion with bounds checking
            match tokens_ceiled {
                x if x >= 1_000_000_000.0 => 1_000_000_000,
                x if x <= 0.0 => 0,
                x => {
                    // Safe conversion: we've bounds-checked that x is positive and within usize range
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        x.trunc() as usize
                    }
                }
            }
        };

        TokenEstimate {
            total: token_count,
            video: token_count,
            is_estimate: true,
            ..Default::default()
        }
    }

    /// Estimates tokens for audio content based on Gemini's counting rules
    ///
    /// For Gemini, audio is counted at a fixed rate of 32 tokens per second
    #[must_use]
    pub fn estimate_audio_tokens(&self, duration_seconds: f64) -> TokenEstimate {
        // Calculate token count with safe conversion
        let token_count = if duration_seconds <= 0.0 {
            0
        } else {
            let tokens = duration_seconds * 32.0;
            let tokens_ceiled = tokens.ceil();
            // Use safe conversion with bounds checking
            match tokens_ceiled {
                x if x >= 1_000_000_000.0 => 1_000_000_000,
                x if x <= 0.0 => 0,
                x => {
                    // Safe conversion: we've bounds-checked that x is positive and within usize range
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    {
                        x.trunc() as usize
                    }
                }
            }
        };

        TokenEstimate {
            total: token_count,
            audio: token_count,
            is_estimate: true,
            ..Default::default()
        }
    }

    /// Estimates total tokens for mixed content
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Text cannot be tokenized
    /// - Any image files cannot be read or processed
    /// - Image dimensions cannot be determined
    pub fn estimate_content_tokens(
        &self,
        text: Option<&str>,
        image_paths: Option<&[PathBuf]>,
        video_duration: Option<f64>,
        audio_duration: Option<f64>,
    ) -> Result<TokenEstimate> {
        let mut total_estimate = TokenEstimate::default();

        // Add text tokens if provided
        if let Some(text_content) = text {
            let text_estimate = self.estimate_text_tokens(text_content)?;
            total_estimate.combine(&text_estimate);
        }

        // Add image tokens if provided
        if let Some(images) = image_paths {
            for image_path in images {
                match self.estimate_image_tokens(image_path) {
                    Ok(image_estimate) => {
                        total_estimate.combine(&image_estimate);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to estimate tokens for image {}: {}",
                            image_path.display(),
                            e
                        );
                        // Continue with other images, don't fail the entire estimation
                    }
                }
            }
        }

        // Add video tokens if provided
        if let Some(duration) = video_duration {
            let video_estimate = self.estimate_video_tokens(duration);
            total_estimate.combine(&video_estimate);
        }

        // Add audio tokens if provided
        if let Some(duration) = audio_duration {
            let audio_estimate = self.estimate_audio_tokens(duration);
            total_estimate.combine(&audio_estimate);
        }

        Ok(total_estimate)
    }
}

// Update AppError with TextProcessingError
impl From<sentencepiece::SentencePieceError> for AppError {
    fn from(err: sentencepiece::SentencePieceError) -> Self {
        Self::TextProcessingError(format!("SentencePiece error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn get_test_model_path() -> PathBuf {
        PathBuf::from(
            "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
        )
    }

    fn get_test_image_path() -> PathBuf {
        PathBuf::from("/home/socol/Workspace/sanguine-scribe/test_data/test_card.png")
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
        let token_count = tokenizer
            .count_tokens(text)
            .expect("Failed to count tokens");

        // The exact count will depend on the model, but should be reasonable
        assert!(token_count > 0);
        assert!(token_count < 10); // A short text shouldn't have too many tokens
    }

    #[test]
    fn test_token_estimate_text() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

        let text = "This is a test of the token estimation functionality.";
        let estimate = tokenizer
            .estimate_text_tokens(text)
            .expect("Failed to estimate tokens");

        assert_eq!(estimate.images, 0);
        assert_eq!(estimate.video, 0);
        assert_eq!(estimate.audio, 0);
        assert!(estimate.text > 0);
        assert_eq!(estimate.total, estimate.text);
        assert!(!estimate.is_estimate); // Text counting is exact, not an estimate
    }

    #[test]
    fn test_token_estimate_image() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

        let image_path = get_test_image_path();
        if !image_path.exists() {
            println!(
                "Test image not found at {}, skipping test",
                image_path.display()
            );
            return;
        }

        let estimate = tokenizer
            .estimate_image_tokens(image_path)
            .expect("Failed to estimate image tokens");

        assert_eq!(estimate.text, 0);
        assert_eq!(estimate.video, 0);
        assert_eq!(estimate.audio, 0);
        assert!(estimate.images > 0);
        assert_eq!(estimate.total, estimate.images);
        assert!(estimate.is_estimate); // Image counting is an estimate

        // Basic check - should be either 258 (small image) or multiple of 258 (large image)
        assert_eq!(estimate.images % 258, 0);
    }

    #[test]
    fn test_token_estimate_video() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

        let duration = 10.5; // 10.5 seconds
        let estimate = tokenizer.estimate_video_tokens(duration);

        assert_eq!(estimate.text, 0);
        assert_eq!(estimate.images, 0);
        assert_eq!(estimate.audio, 0);
        assert!(estimate.video > 0);
        assert_eq!(estimate.total, estimate.video);
        assert!(estimate.is_estimate);

        // 10.5 seconds * 263 tokens/second = 2761.5, ceiling = 2762
        assert_eq!(estimate.video, 2762);
    }

    #[test]
    fn test_token_estimate_audio() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

        let duration = 60.0; // 60 seconds (1 minute)
        let estimate = tokenizer.estimate_audio_tokens(duration);

        assert_eq!(estimate.text, 0);
        assert_eq!(estimate.images, 0);
        assert_eq!(estimate.video, 0);
        assert!(estimate.audio > 0);
        assert_eq!(estimate.total, estimate.audio);
        assert!(estimate.is_estimate);

        // 60.0 seconds * 32 tokens/second = 1920
        assert_eq!(estimate.audio, 1920);
    }

    #[test]
    fn test_token_estimate_mixed() {
        let model_path = get_test_model_path();
        let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");

        let text = "This is a test message with an image and some audio.";
        let image_path = get_test_image_path();
        let image_paths = if image_path.exists() {
            Some(vec![image_path])
        } else {
            None
        };
        let video_duration = Some(5.0); // 5 seconds
        let audio_duration = Some(30.0); // 30 seconds

        let estimate = tokenizer
            .estimate_content_tokens(
                Some(text),
                image_paths.as_deref(),
                video_duration,
                audio_duration,
            )
            .expect("Failed to estimate mixed tokens");

        // Text tokens should be greater than 0
        assert!(estimate.text > 0);

        // If we had an image to test with
        if image_paths.is_some() {
            assert!(estimate.images > 0);
            assert_eq!(estimate.images % 258, 0); // Should be multiple of 258
        }

        // Video: 5.0 seconds * 263 tokens/second = 1315
        assert_eq!(estimate.video, 1315);

        // Audio: 30.0 seconds * 32 tokens/second = 960
        assert_eq!(estimate.audio, 960);

        // Total should be sum of all parts
        assert_eq!(
            estimate.total,
            estimate.text + estimate.images + estimate.video + estimate.audio
        );

        // Mixed content should be marked as an estimate
        assert!(estimate.is_estimate);
    }

    #[test]
    fn test_token_estimate_combine() {
        let est1 = TokenEstimate {
            total: 100,
            text: 100,
            images: 0,
            video: 0,
            audio: 0,
            is_estimate: false,
        };

        let est2 = TokenEstimate {
            total: 258,
            text: 0,
            images: 258,
            video: 0,
            audio: 0,
            is_estimate: true,
        };

        let mut combined = est1;
        combined.combine(&est2);

        assert_eq!(combined.total, 358);
        assert_eq!(combined.text, 100);
        assert_eq!(combined.images, 258);
        assert_eq!(combined.video, 0);
        assert_eq!(combined.audio, 0);
        assert!(combined.is_estimate); // Should be true if any component is an estimate
    }
}
