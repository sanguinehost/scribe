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

// Placeholder for ChatMessage structure used in chunk_messages tests
// In a real scenario, this would likely import the actual ChatMessage model
// from `crate::models` or similar.
#[derive(Debug, Clone)]
struct TestChatMessage {
    // Assuming basic fields for testing purposes
    // author: String, // Commented out: unused field
    content: String,
}

/// Chunks the content of multiple chat messages.
///
/// Iterates through a slice of messages, applying `chunk_text` to the content
/// of each message and collecting all resulting chunks.
///
/// TODO: Consider adding metadata to TextChunk later (e.g., original message index/ID, author)
///       if the RAG pipeline needs to associate chunks back to specific messages.
/// TODO: Explore alternative chunking strategies (e.g., combining message pairs before chunking)
///       if simple per-message chunking proves insufficient.
#[instrument(skip(messages), fields(num_messages = messages.len()))]
pub fn chunk_messages<M>(messages: &[M]) -> Result<Vec<TextChunk>, AppError>
where
    // Use a trait bound to accept any type with a `content()` method returning &str
    // This makes the function more flexible without needing the concrete ChatMessage type here.
    M: HasContent,
{
    let mut all_chunks = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        let content = message.content();
        if content.trim().is_empty() {
            debug!(message_index = index, "Skipping message with empty content");
            continue;
        }
        debug!(message_index = index, content_len = content.len(), "Chunking message content");
        match chunk_text(content) {
            Ok(message_chunks) => {
                // TODO: Potentially add message index/ID metadata to chunks here
                all_chunks.extend(message_chunks);
            }
            Err(e) => {
                // Decide on error handling: return error immediately or log and continue?
                // For now, return immediately.
                warn!(message_index = index, error = ?e, "Failed to chunk message content");
                return Err(e);
            }
        }
    }
    debug!(total_chunks = all_chunks.len(), "Finished chunking messages");
    Ok(all_chunks)
}

/// Simple trait to abstract getting message content.
/// Implement this for your actual ChatMessage struct.
pub trait HasContent {
    fn content(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::repeat;

    // Implement the trait for the test struct
    impl HasContent for TestChatMessage {
        fn content(&self) -> &str {
            &self.content
        }
    }

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

    #[test]
    fn test_chunk_long_sentence_exceeding_limit() {
        // Create a sentence longer than the limit, without paragraph breaks
        let long_text = repeat('a').take(DEFAULT_MAX_CHUNK_SIZE_CHARS + 50).collect::<String>() + ".";
        let result = chunk_text(&long_text).unwrap();

        // Expecting one chunk, truncated, because ICU sees one sentence and it's too long
        assert_eq!(result.len(), 1, "Expected one chunk for a single long sentence.");
        assert_eq!(result[0].content.chars().count(), DEFAULT_MAX_CHUNK_SIZE_CHARS, "Chunk should be truncated to max size.");
        assert!(result[0].content.starts_with('a'), "Truncated content should start with 'a'.");
        // Check if the trailing punctuation was lost due to truncation (expected behaviour for now)
        assert!(!result[0].content.ends_with('.'), "Truncated content shouldn't end with the original period.");
    }

    #[test]
    fn test_chunk_mixed_short_long_sentences_in_paragraph() {
        // Paragraph longer than max_size, containing short and very long sentences
        let very_long_sentence = "Sentence ".repeat(DEFAULT_MAX_CHUNK_SIZE_CHARS / 5); // Approx 100 chars if max_size is 500
        let even_longer_sentence = "Longer ".repeat(DEFAULT_MAX_CHUNK_SIZE_CHARS / 3); // Approx 166 chars if max_size is 500
        // Input: "Short sentence 1. {very_long}Sentence 2 is also short. {even_longer}. Sentence 4 is final."
        let text = format!("Short sentence 1. {}Sentence 2 is also short. {}. Sentence 4 is final.", very_long_sentence, even_longer_sentence);
        // println!("--- Test: Mixed Short/Long Sentences ---"); // Keep for debugging if needed
        // println!("Input Text ({} chars): {}", text.chars().count(), text);

        let result = chunk_text(&text);
        assert!(result.is_ok(), "Chunking should succeed");
        let chunks = result.unwrap();

        // --- Debug Print (Keep commented out or remove once assertions are stable) ---
        // println!("Actual number of chunks: {}", chunks.len());
        // for (i, chunk) in chunks.iter().enumerate() {
        //      println!("Chunk {}: ({} chars) \"{}\"", i, chunk.content.chars().count(), chunk.content);
        // }
        // println!("--- End Debug Print ---");

        // Assert based on observed output (4 chunks)
        assert_eq!(chunks.len(), 4, "Expected 4 chunks based on observed behavior");

        // Chunk 0: First sentence
        assert_eq!(chunks[0].content, "Short sentence 1.");

        // Chunk 1: Truncated combination of very_long_sentence and sentence 2
        assert!(chunks[1].content.starts_with("Sentence "), "Chunk 1 should start with 'Sentence '" );
        assert!(chunks[1].content.chars().count() == DEFAULT_MAX_CHUNK_SIZE_CHARS, "Chunk 1 should be truncated to max size");
        assert!(!chunks[1].content.contains("Sentence 2 is also short."), "Chunk 1 should be truncated before 'Sentence 2'");

        // Chunk 2: Truncated even_longer_sentence
        assert!(chunks[2].content.starts_with("Longer "), "Chunk 2 should start with 'Longer '" );
        assert!(chunks[2].content.chars().count() == DEFAULT_MAX_CHUNK_SIZE_CHARS, "Chunk 2 should be truncated to max size");

        // Chunk 3: Final sentence
        assert_eq!(chunks[3].content, "Sentence 4 is final.");

        // General check
        assert!(chunks.iter().all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS), "All chunks must be within size limit");

        // println!("--- Test Complete: Mixed Short/Long Sentences ---");
    }

    #[test]
    fn test_chunk_unusual_whitespace() {
        let text = "  Leading space. \n\n \t Lots of \t tabs and spaces. \n\nTrailing space.  ";
        let expected = vec![
            TextChunk { content: "Leading space.".to_string() },
            TextChunk { content: "Lots of \t tabs and spaces.".to_string() }, // trim() keeps internal whitespace
            TextChunk { content: "Trailing space.".to_string() },
        ];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_chunk_text_with_only_symbols_or_punctuation() {
        let text = "!!! ??? ... ---"; // Should be treated as one paragraph/sentence by current logic
        let expected = vec![TextChunk { content: text.to_string() }];
        let result = chunk_text(text).unwrap();
        assert_eq!(result, expected);

        // Test a longer version that might exceed limit
        let long_symbols = ".".repeat(DEFAULT_MAX_CHUNK_SIZE_CHARS + 1);
        let result_long = chunk_text(&long_symbols).unwrap();
        assert_eq!(result_long.len(), 1); // One sentence chunk
        assert_eq!(result_long[0].content.chars().count(), DEFAULT_MAX_CHUNK_SIZE_CHARS); // Truncated
    }

    #[test]
    fn test_chunk_unicode_sentences() {
        // Example using Japanese text which relies on ICU's segmentation
        let text = "これは最初の文です。これは二番目の文で、少し長いです。\n\nこれは新しい段落です。短い。";
        // Translation: "This is the first sentence. This is the second sentence, it's a bit long.\n\nThis is a new paragraph. Short."

        let result = chunk_text(text).unwrap();

        // Expecting 3 chunks: first two sentences as one paragraph, third sentence as another.
        // Note: The exact splitting depends on ICU's rules for Japanese.
        // Assuming the first paragraph fits.
        assert!(result.len() == 2 || result.len() == 3, "Expected 2 or 3 chunks based on paragraph/sentence splitting");

        if result.len() == 2 { // Assumes first paragraph fits
            assert_eq!(result[0].content, "これは最初の文です。これは二番目の文で、少し長いです。");
            assert_eq!(result[1].content, "これは新しい段落です。短い。");
        } else { // Assumes first paragraph was too long and split
             assert_eq!(result[0].content, "これは最初の文です。");
             assert_eq!(result[1].content, "これは二番目の文で、少し長いです。");
             assert_eq!(result[2].content, "これは新しい段落です。短い。");
        }

         assert!(result.iter().all(|c| !c.content.is_empty()), "Chunks should not be empty");
         assert!(result.iter().all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS), "All chunks must be within limit");
    }

    #[test]
    fn test_chunk_rpg_scenario_eda() {
        // Define the RPG text using a raw string literal
        let rpg_text = r#"Solomon follows Victoria through the silent foyer, the heavy front door closing behind them, sealing the mansion's cold stillness away. The familiar dark sedan waits at the curb, engine idling almost imperceptibly. They slide into the back seats, the scent of leather and Victoria's faint perfume filling the enclosed space.

The car pulls away smoothly, merging into the nascent flow of Melbourne's nightly traffic. Streetlights cast fleeting stripes of cold light across Victoria's impassive face.

"Fortitude," Victoria begins, her voice low and even, cutting through the quiet hum of the engine. "Last night, you experienced its passive resistance. Tonight, you learn its active application – the conscious channeling of Vitae to ignore trauma, to force the unliving flesh beyond mortal limits." She pauses, letting the implication settle. "Pain becomes... irrelevant information, easily discarded."

Her gaze shifts, becoming slightly more intense. "And the Blood Bond. Perhaps the most potent tool of control within Kindred society, second only to Dominate, yet far more enduring. A shared drop of Vitae creates a connection. Three sips, taken on three separate nights, forge an unbreakable chain of loyalty, devotion... obsession." She looks directly at Solomon. "You have drunk once from Lord Remus. You have felt the nascent pull, the respect that transcends mere hierarchy. Understand the process, Solomon. Recognize its signs in others, and guard yourself against unwanted entanglement."

The sedan leaves the main city thoroughfares, heading towards an older, more dilapidated part of Melbourne, characterized by Victorian-era buildings showing signs of neglect – cracked facades, boarded-up windows, overgrown gardens shrouded in darkness. The car turns down a street dominated by a massive, gloomy structure: an old, sprawling psychiatric hospital, clearly long abandoned. High walls topped with rusted spikes surround the grounds, and the main building looms like a gothic horror set piece, its windows dark, empty eyes staring into the night.

The driver navigates through a crumbling gateway, the hinges groaning in protest, and pulls up near a less imposing side building, possibly former administrative offices or staff quarters, also clearly derelict. The air here smells of decay, damp plaster, pigeons, and something vaguely medicinal that lingers even after decades.

"This facility," Victoria states, gesturing towards the dark building, "has been… decommissioned for mortal use. It offers privacy, and suitable materials for testing resilience." She opens her door, stepping out into the cool, still air. The only sounds are the distant city hum and the faint rustling of wind through dead leaves clinging to the overgrown grounds.

She walks towards a boarded-up entrance to the side building. With minimal apparent effort, she pries away several heavy planks, revealing a dark doorway gaping open like a wound. Dust motes dance in the weak light spilling from the car's interior.

"Come," Victoria instructs, stepping through the opening into the palpable darkness within. "Your lesson in endurance begins.""#;

        println!("--- RPG Scenario EDA Test ---");
        println!("Max Chunk Size (Chars): {}", DEFAULT_MAX_CHUNK_SIZE_CHARS);
        println!("Input Text Length (Chars): {}", rpg_text.chars().count());
        println!("Input Text Length (Bytes): {}", rpg_text.len());

        // 1. Analyze original paragraph structure
        let original_paragraphs: Vec<&str> = rpg_text.split("\n\n").map(|p| p.trim()).filter(|p| !p.is_empty()).collect();
        println!("\n--- Original Paragraphs ({} total) ---", original_paragraphs.len());
        for (i, p) in original_paragraphs.iter().enumerate() {
            println!("Paragraph {}: Chars = {}, Bytes = {}", i + 1, p.chars().count(), p.len());
            // Check if any original paragraph exceeds the limit
             if p.chars().count() > DEFAULT_MAX_CHUNK_SIZE_CHARS {
                 println!("  -> Exceeds max chunk size!");
             }
        }

        // 2. Run the chunker
        let result = chunk_text(rpg_text);
        assert!(result.is_ok(), "Chunking should succeed");
        let chunks = result.unwrap();

        // 3. Analyze the resulting chunks
        println!("\n--- Resulting Chunks ({} total) ---", chunks.len());
        let mut total_chunked_chars = 0;
        for (i, chunk) in chunks.iter().enumerate() {
            let char_count = chunk.content.chars().count();
            let byte_count = chunk.content.len();
            total_chunked_chars += char_count;
            println!("Chunk {}: Chars = {}, Bytes = {}", i + 1, char_count, byte_count);
            println!("  Content: \"{}\"", chunk.content); // Print content for inspection

            // Assert that no chunk exceeds the max size
            assert!(char_count <= DEFAULT_MAX_CHUNK_SIZE_CHARS, "Chunk {} exceeds max size!", i + 1);
        }

        println!("\n--- EDA Observations ---");
        println!("Original Paragraph Count: {}", original_paragraphs.len());
        println!("Resulting Chunk Count: {}", chunks.len());
        println!("Total Original Chars (trimmed): {}", original_paragraphs.iter().map(|p| p.chars().count()).sum::<usize>());
        println!("Total Chunked Chars: {}", total_chunked_chars);
        // Note: Total chars might differ slightly due to potential truncation or nuances in trimming/splitting.

        // --- Specific Assertions Based on Manual Inspection ---
        // These assertions depend heavily on DEFAULT_MAX_CHUNK_SIZE_CHARS and the chunker's behavior.
        // Adjust these based on the output and desired behavior.

        // Example: Check if the first paragraph became the first chunk (assuming it fits)
        if original_paragraphs[0].chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS {
             assert_eq!(chunks[0].content, original_paragraphs[0], "First paragraph should be the first chunk if it fits.");
        }

        // Example: Check if a known long paragraph was split.
        // Paragraph 4 (index 3) looks long. Let's find its length.
        let paragraph4_len = original_paragraphs.get(3).map_or(0, |p| p.chars().count());
        if paragraph4_len > DEFAULT_MAX_CHUNK_SIZE_CHARS {
            println!("Observation: Paragraph 4 (length {}) exceeded limit and should have been split.", paragraph4_len);
            // We expect more chunks than original paragraphs if splitting occurred.
             assert!(chunks.len() > original_paragraphs.len(), "Expected more chunks than paragraphs due to splitting.");
             // Find which chunks correspond to paragraph 4. This is harder to assert directly without knowing the exact sentence splits.
             // We could check if chunks roughly starting around where paragraph 4 was seem to be sentence-level.
             // For now, we'll rely on the printout and the length check.
        } else {
            println!("Observation: Paragraph 4 (length {}) fit within the limit.", paragraph4_len);
        }

         // Example: Check the last chunk corresponds to the last paragraph (if it fits)
        if original_paragraphs.last().unwrap().chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS {
            assert_eq!(chunks.last().unwrap().content, *original_paragraphs.last().unwrap(), "Last paragraph should be the last chunk if it fits.");
        }


        println!("\n--- End RPG Scenario EDA Test ---");
        // This test primarily relies on the printed output for analysis.
        // Add more specific assertions as needed based on observed behavior and requirements.
    }

    #[test]
    fn test_chunk_messages_empty_list() {
        let messages: Vec<TestChatMessage> = vec![];
        let result = chunk_messages(&messages).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_chunk_messages_single_short_message() {
        let messages = vec![TestChatMessage {
            // author: "User".to_string(),
            content: "Hello there.".to_string(),
        }];
        let result = chunk_messages(&messages).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].content, "Hello there.");
    }

     #[test]
    fn test_chunk_messages_multiple_short_messages() {
        let messages = vec![
            TestChatMessage {
                // author: "User".to_string(),
                content: "First message.".to_string(),
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: "Second message.".to_string(),
            },
        ];
        let result = chunk_messages(&messages).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].content, "First message.");
        assert_eq!(result[1].content, "Second message.");
    }

    #[test]
    fn test_chunk_messages_with_empty_content() {
        let messages = vec![
            TestChatMessage {
                // author: "User".to_string(),
                content: "Real message.".to_string(),
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: "   ".to_string(), // Empty after trim
            },
            TestChatMessage {
                // author: "User".to_string(),
                content: "".to_string(),   // Empty
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: "Another real one.".to_string(),
            },
        ];
        let result = chunk_messages(&messages).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].content, "Real message.");
        assert_eq!(result[1].content, "Another real one.");
    }

    #[test]
    fn test_chunk_messages_one_message_needs_splitting() {
        let long_content = "This is the first sentence. ".to_string()
            + &"This is a much longer second sentence designed to exceed the limit all on its own, forcing a split. ".repeat(15) // Make it long
            + &"This is the third sentence.";
        let messages = vec![
            TestChatMessage {
                // author: "User".to_string(),
                content: "Short intro.".to_string(),
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: long_content,
            },
            TestChatMessage {
                // author: "User".to_string(),
                content: "Short outro.".to_string(),
            },
        ];

        let result = chunk_messages(&messages).unwrap();

        // Expecting:
        // 1 chunk from "Short intro."
        // Multiple chunks from `long_content` (at least 2: the first sentence, and the truncated long sentence)
        // 1 chunk from "Short outro."
        // The exact number from long_content depends on chunk_text and ICU behavior.
        assert!(result.len() > 3, "Expected more than 3 chunks due to splitting");

        assert_eq!(result[0].content, "Short intro.");
        assert!(result[1].content.starts_with("This is the first sentence.")); // First part of the long message
        // Check that all chunks derived from the long message are within the size limit
        assert!(result.iter().skip(1).take(result.len()-2).all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS));
        assert_eq!(result.last().unwrap().content, "Short outro.");
    }

     #[test]
    fn test_chunk_messages_multiple_messages_need_splitting() {
        // Create two long contents that will both be split by chunk_text
        let long_content1 = "Sentence A1. ".to_string() + &"Long part A that needs splitting. ".repeat(20) + &"Sentence A2.";
        let long_content2 = "Sentence B1. ".to_string() + &"Long part B that also needs splitting. ".repeat(20) + &"Sentence B2.";

        let messages = vec![
            TestChatMessage {
                // author: "User".to_string(),
                content: long_content1,
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: "A short reply in between.".to_string(),
            },
            TestChatMessage {
                // author: "User".to_string(),
                content: long_content2,
            },
        ];

        let result = chunk_messages(&messages).unwrap();

        // Expecting chunks from msg1, 1 chunk from msg2, chunks from msg3
        assert!(result.len() > 3, "Expected significantly more than 3 chunks");

        // Check first chunk is start of msg1
        assert!(result[0].content.starts_with("Sentence A1."));

        // Check intermediate short message chunk exists correctly
        // The exact index depends on how msg1 was split. Find it.
        let intermediate_chunk_index = result.iter().position(|c| c.content == "A short reply in between.");
        assert!(intermediate_chunk_index.is_some(), "Could not find the intermediate short message chunk");

        // Check chunks after the intermediate one belong to msg3
        let intermediate_index = intermediate_chunk_index.unwrap();
        assert!(result[intermediate_index + 1].content.starts_with("Sentence B1."), "Chunk after intermediate should be start of msg3");

        // General check for size limits
        assert!(result.iter().all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS));
    }

    #[test]
    fn test_chunk_messages_unicode_content() {
        let messages = vec![
            TestChatMessage {
                // author: "User".to_string(),
                content: "これは最初の文です。これは二番目の文。\n\n新しい段落。".to_string(),
            },
            TestChatMessage {
                // author: "AI".to_string(),
                content: "了解しました。".to_string(), // "Understood."
            },
        ];
        let result = chunk_messages(&messages).unwrap();

        // Expecting chunks from the first message (potentially split) + 1 chunk from the second.
        // Based on chunk_text test, first message might yield 2 or 3 chunks. +1 for the second.
        assert!(result.len() == 3 || result.len() == 4, "Expected 3 or 4 chunks total");

        // Check the last chunk is the simple response
        assert_eq!(result.last().unwrap().content, "了解しました。");
        assert!(result.iter().all(|c| !c.content.is_empty()));
        assert!(result.iter().all(|c| c.content.chars().count() <= DEFAULT_MAX_CHUNK_SIZE_CHARS));
    }
}