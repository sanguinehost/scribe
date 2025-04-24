// backend/src/text_processing/chunking.rs

use crate::errors::AppError;
use tracing::{debug, warn, instrument}; // Removed unused 'error' import

// Using ICU4X for sentence splitting.

// TODO: Determine a sensible default/configurable max chunk size (e.g., in tokens or characters)
// TODO: Consider using a token counter (e.g., tiktoken-rs) instead of char count.
const DEFAULT_MAX_CHUNK_SIZE_CHARS: usize = 500; // Example: Character limit

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChunk {
    pub content: String,
    // Add metadata later if needed (e.g., original message ID, position)
}

/// Chunks the given text based on paragraphs, falling back to sentences if a paragraph is too long.
///
/// This is a basic implementation and should be improved with:
/// 1. A robust sentence tokenizer library.
/// 2. A more accurate way to measure chunk size (e.g., token count).
/// 3. Configurable max chunk size.
/// 4. Handling of edge cases (e.g., extremely long sentences).
#[instrument(skip(text), fields(text_len = text.len()))]
pub fn chunk_text(text: &str) -> Result<Vec<TextChunk>, AppError> {
    if text.trim().is_empty() {
        return Ok(vec![]);
    }

    // Use the segmenter directly, relying on its compiled_data feature.
    // Remove the explicit provider fetching.
    // let provider = icu_testdata::get_provider(); // REMOVED

    // Create segmenters using the auto constructor which leverages compiled data
    // These constructors return Self directly, not Result, assuming compiled data is available.
    let sentence_segmenter = icu_segmenter::SentenceSegmenter::new();
    let _line_segmenter = icu_segmenter::LineSegmenter::new_auto();

    let mut chunks = Vec::new();
    let max_size = DEFAULT_MAX_CHUNK_SIZE_CHARS; // Use constant for now

    // 1. Split into paragraphs (simple approach: split by double newline)
    // This might need refinement based on actual markdown/text formatting.
    for paragraph in text.split("\n\n") {
        let trimmed_paragraph = paragraph.trim();
        if trimmed_paragraph.is_empty() {
            continue;
        }

        // 2. Check paragraph size
        if trimmed_paragraph.chars().count() <= max_size {
            // Paragraph fits within the limit
            debug!(chunk_len = trimmed_paragraph.len(), "Adding paragraph chunk");
            chunks.push(TextChunk {
                content: trimmed_paragraph.to_string(),
            });
        } else {
            // 3. Paragraph too long, split into sentences using punkt
            warn!(paragraph_len = trimmed_paragraph.len(), max_size, "Paragraph exceeds max chunk size, splitting into sentences using ICU");

            // Iterate over sentence boundaries using ICU
            // The segmenter returns byte indices.
            let mut start = 0;
            for end in sentence_segmenter.segment_str(trimmed_paragraph) {
                 // Extract the sentence slice using byte indices
                let sentence_slice = &trimmed_paragraph[start..end];
                let trimmed_sentence = sentence_slice.trim();

                if trimmed_sentence.is_empty() {
                    start = end; // Move start to the end of the current segment
                    continue;
                }

                if trimmed_sentence.chars().count() > max_size {
                    // TODO: Handle sentences that are themselves too long.
                    // TODO: Handle sentences that are themselves too long more gracefully.
                    // Options: Truncate, split further (harder, maybe by clauses/tokens), skip?
                    warn!(sentence_len = trimmed_sentence.len(), max_size, "Sentence still exceeds max chunk size, truncating");
                    // For now, truncate. A better strategy might involve token-level splitting.
                     chunks.push(TextChunk {
                         content: trimmed_sentence.chars().take(max_size).collect(),
                     });
                } else {
                     debug!(chunk_len = trimmed_sentence.len(), "Adding sentence chunk");
                     chunks.push(TextChunk {
                         content: trimmed_sentence.to_string(),
                     });
                }
                // Update start index for the next iteration AFTER processing the current segment
                start = end;
            }
        }
    }

    if chunks.is_empty() && !text.trim().is_empty() {
        // Handle case where input text is not empty but splitting resulted in no chunks
        // (e.g., text shorter than max size but contains no paragraph/sentence breaks recognized by basic split)
        warn!("Chunking resulted in no chunks for non-empty input, adding entire text as one chunk.");
        chunks.push(TextChunk { content: text.trim().to_string() });
    }

    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    // use icu_locid::locale; // Already removed
    // use icu_provider::DataProvider; // Already removed
    // use icu_segmenter::provider::{SentenceBreakDataV1Marker, LineBreakDataV1Marker}; // Already removed

    /* REMOVED test_provider function
    fn test_provider() -> impl DataProvider<SentenceBreakDataV1Marker> + DataProvider<LineBreakDataV1Marker> + Sized + Clone + Send + Sync + 'static {
        icu_testdata::get_provider()
    }
    */

    #[test]
    fn test_chunk_simple_paragraph() {
        let text = "This is a single paragraph. It should fit in one chunk.";
        let expected = vec![TextChunk { content: text.to_string() }];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_chunk_multiple_paragraphs() {
        let text = "First paragraph.\n\nSecond paragraph, also short.";
        let expected = vec![
            TextChunk { content: "First paragraph.".to_string() },
            TextChunk { content: "Second paragraph, also short.".to_string() },
        ];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_chunk_long_paragraph_fallback_to_sentences() {
        // Create text longer than DEFAULT_MAX_CHUNK_SIZE_CHARS
        let long_sentence = "This is a very long sentence designed to exceed the default character limit all by itself, forcing a split if the paragraph logic works correctly. ".repeat(10); // Approx 1000 chars
        let text = format!("Short first sentence. {} Short third sentence.", long_sentence);

        let result = chunk_text(&text).unwrap();

        // Expecting sentences because the paragraph is too long.
        // ICU should correctly identify the sentences.
        assert!(result.len() >= 3, "Expected at least 3 chunks (sentence, long sentence parts, sentence)");
        assert!(result.iter().all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS), "All chunks should be within size limit");
        assert_eq!(result[0].content, "Short first sentence."); // ICU keeps punctuation
        assert!(result.last().unwrap().content.contains("Short third sentence.")); // ICU keeps punctuation
    }

     #[test]
    fn test_chunk_empty_input() {
        let text = "";
        let expected: Vec<TextChunk> = vec![];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_chunk_whitespace_input() {
        let text = "   \n\n   \t ";
        let expected: Vec<TextChunk> = vec![];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_chunk_text_without_breaks_fits() {
        let text = "Single block of text without paragraph breaks that fits.";
        let expected = vec![TextChunk { content: text.to_string() }];
        let result = chunk_text(text).unwrap();
        // The current basic paragraph split might fail this if it doesn't see \n\n
        // Let's adjust the expectation based on current logic (treats as one paragraph)
        assert_eq!(result, expected);
    }

     #[test]
    fn test_chunk_text_without_breaks_too_long() {
        let text = "A".repeat(DEFAULT_MAX_CHUNK_SIZE_CHARS + 10); // Exceeds limit
        let result = chunk_text(&text).unwrap();
        // ICU should treat this as one long sentence.
        // Since the sentence itself is too long, it gets truncated by the current logic.
        assert_eq!(result.len(), 1, "Expected one chunk as ICU sees one sentence");
        assert_eq!(result[0].content.chars().count(), DEFAULT_MAX_CHUNK_SIZE_CHARS, "Chunk should be truncated");
    }
}