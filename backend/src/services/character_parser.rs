// backend/src/services/character_parser.rs

use crate::models::character_card::{CharacterCardDataV3, CharacterCardV3};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_standard};
use png::Decoder;
use serde_json;
use std::io::{Cursor, Read, Seek}; // Added Read and Seek for zip
use thiserror::Error; // Import the derive macro
use tracing::{info, warn}; // Import logging macros
use zip::ZipArchive;
use zip::result::ZipError; // Added for CHARX parsing // Added for CHARX parsing

// Define potential errors for the parser
#[derive(Debug, Error)] // Use the imported derive macro
pub enum ParserError {
    #[error("I/O Error reading PNG data: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PNG decoding error: {0}")]
    PngError(#[from] png::DecodingError),
    #[error("Character data chunk ('chara' or 'ccv3') not found in PNG.")]
    ChunkNotFound,
    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Unsupported character card format: {0}")]
    UnsupportedFormat(String),
    #[error("Invalid tEXt chunk format for 'chara'.")]
    InvalidTextChunkFormat,
    #[error("Invalid spec field in ccv3 chunk: expected 'chara_card_v3', found '{0}'")]
    InvalidSpecField(String),
    #[error("CHARX (Zip) processing error: {0}")]
    ZipError(#[from] ZipError),
    #[error("Required 'card.json' not found in CHARX archive.")]
    CharxCardJsonNotFound,
}

// Define the structure to represent the parsed result
#[derive(Debug)]
pub enum ParsedCharacterCard {
    V3(CharacterCardV3), // Represents a card parsed from 'ccv3' or a full V3 structure
    V2Fallback(CharacterCardDataV3), // Represents data parsed from 'chara' (V2)
}

// --- Main Parsing Function ---

pub fn parse_character_card_png(png_data: &[u8]) -> Result<ParsedCharacterCard, ParserError> {
    let cursor = Cursor::new(png_data);
    let decoder = Decoder::new(cursor);
    // Note: We only read info here. IDAT chunks are not needed for text data.
    let reader = decoder.read_info()?;
    let info = reader.info();

    let chara_keyword = "chara";
    let ccv3_keyword = "ccv3";

    let mut ccv3_data_base64: Option<String> = None;
    let mut chara_data_base64: Option<String> = None;

    // Iterate over text chunks found in the PNG info
    for text_chunk in &info.uncompressed_latin1_text {
        if text_chunk.keyword == ccv3_keyword {
            ccv3_data_base64 = Some(text_chunk.text.clone());
        } else if text_chunk.keyword == chara_keyword {
            chara_data_base64 = Some(text_chunk.text.clone());
        }
    }

    // Flag to track if V3 parsing was tried and failed
    let mut ccv3_parse_attempted_and_failed = false;

    // --- Prioritize ccv3 ---
    if let Some(base64_str) = ccv3_data_base64 {
        match base64_standard.decode(&base64_str) {
            Ok(decoded_bytes) => {
                match serde_json::from_slice::<CharacterCardV3>(&decoded_bytes) {
                    Ok(card) => {
                        // --- V3 Spec Conformance Checks ---
                        if card.spec != "chara_card_v3" {
                            // Spec says SHOULD NOT consider it V3 if spec is wrong.
                            // We'll log a strong warning but still attempt to use it,
                            // as the data came from the 'ccv3' chunk.
                            // Alternatively, could return Err(ParserError::InvalidSpecField(card.spec.clone()))
                            warn!(
                                "Invalid 'spec' field in 'ccv3' chunk: expected 'chara_card_v3', found '{}'. Proceeding with parsing.",
                                card.spec
                            );
                            // Optionally normalize the spec field if proceeding:
                            // card.spec = "chara_card_v3".to_string();
                        }

                        // Check spec_version
                        if card.spec_version != "3.0" {
                            // Attempt to parse version as float for comparison
                            let current_version: Result<f32, _> = card.spec_version.parse();
                            let target_version: f32 = 3.0;
                            match current_version {
                                Ok(v) if v > target_version => {
                                    warn!(
                                        "Card spec_version ('{}') is newer than supported ('{}'). Some features might not work.",
                                        card.spec_version, target_version
                                    );
                                }
                                Ok(v) if v < target_version => {
                                    warn!(
                                        "Card spec_version ('{}') is older than current spec ('{}'). Attempting to load.",
                                        card.spec_version, target_version
                                    );
                                    // Potentially fill missing fields with defaults here if needed for older versions
                                }
                                Ok(_) => {} // Version matches 3.0
                                Err(_) => {
                                    warn!(
                                        "Could not parse card spec_version ('{}') as a number.",
                                        card.spec_version
                                    );
                                }
                            }
                        }
                        // --- End V3 Spec Conformance Checks ---

                        return Ok(ParsedCharacterCard::V3(card));
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse JSON from 'ccv3' chunk as CharacterCardV3: {}. Falling back to 'chara' if possible.",
                            e
                        );
                        // Don't return error yet, try fallback
                        ccv3_parse_attempted_and_failed = true; // Mark that V3 parsing failed
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to decode base64 from 'ccv3' chunk: {}. Falling back to 'chara' if possible.",
                    e
                );
                // Don't return error yet, try fallback
                ccv3_parse_attempted_and_failed = true; // Mark that V3 parsing failed
            }
        }
    }

    // --- Fallback to chara ---
    if let Some(base64_str) = chara_data_base64 {
        match base64_standard.decode(&base64_str) {
            Ok(decoded_bytes) => {
                match serde_json::from_slice::<CharacterCardDataV3>(&decoded_bytes) {
                    Ok(mut data_v2) => {
                        // Make data_v2 mutable
                        info!(
                            "Loaded character from V2 'chara' chunk. Applying V3 compatibility note."
                        );
                        // Only prepend V2 fallback warning if we actually fell back from a failed V3 attempt
                        if ccv3_parse_attempted_and_failed {
                            const V2_FALLBACK_NOTE: &str = "This character card is Character Card V3, but it is loaded as a Character Card V2. Please use a Character Card V3 compatible application to use this character card properly.\n";
                            if data_v2.creator_notes.is_empty() {
                                data_v2.creator_notes = V2_FALLBACK_NOTE.to_string();
                            } else {
                                data_v2.creator_notes =
                                    format!("{}{}", V2_FALLBACK_NOTE, data_v2.creator_notes);
                            }
                        }
                        // Return the modified V2 data wrapped in the V2Fallback variant
                        return Ok(ParsedCharacterCard::V2Fallback(data_v2));
                    }
                    Err(e) => {
                        // If 'chara' JSON parsing fails, this is a hard error for the fallback
                        return Err(ParserError::JsonError(e));
                    }
                }
            }
            Err(e) => {
                // If 'chara' base64 decoding fails, this is a hard error for the fallback
                return Err(ParserError::Base64Error(e));
            }
        }
    }

    // If neither 'ccv3' nor 'chara' yielded a valid result
    Err(ParserError::ChunkNotFound)
}

// --- JSON Parsing Function ---

pub fn parse_character_card_json(json_data: &[u8]) -> Result<ParsedCharacterCard, ParserError> {
    match serde_json::from_slice::<CharacterCardV3>(json_data) {
        Ok(card) => {
            // --- V3 Spec Conformance Checks (similar to PNG parser) ---
            if card.spec != "chara_card_v3" {
                // Spec says SHOULD NOT consider it V3 if spec is wrong.
                // Log a strong warning but proceed.
                warn!(
                    "Invalid 'spec' field in JSON card: expected 'chara_card_v3', found '{}'. Proceeding with parsing.",
                    card.spec
                );
                // Optionally normalize: card.spec = "chara_card_v3".to_string();
            }

            // Check spec_version
            if card.spec_version != "3.0" {
                let current_version: Result<f32, _> = card.spec_version.parse();
                let target_version: f32 = 3.0;
                match current_version {
                    Ok(v) if v > target_version => {
                        warn!(
                            "JSON Card spec_version ('{}') is newer than supported ('{}'). Some features might not work.",
                            card.spec_version, target_version
                        );
                    }
                    Ok(v) if v < target_version => {
                        warn!(
                            "JSON Card spec_version ('{}') is older than current spec ('{}'). Attempting to load.",
                            card.spec_version, target_version
                        );
                        // Potentially fill missing fields with defaults here if needed
                    }
                    Ok(_) => {} // Version matches 3.0
                    Err(_) => {
                        warn!(
                            "Could not parse JSON card spec_version ('{}') as a number.",
                            card.spec_version
                        );
                    }
                }
            }
            // --- End V3 Spec Conformance Checks ---

            // JSON format directly maps to V3 structure
            Ok(ParsedCharacterCard::V3(card))
        }
        Err(e) => {
            // If it doesn't parse as V3, it's an error for JSON format
            Err(ParserError::JsonError(e))
        }
    }
}

// --- CHARX (Zip) Parsing Function ---

pub fn parse_character_card_charx<R: Read + Seek>(
    charx_data: R,
) -> Result<ParsedCharacterCard, ParserError> {
    let mut archive = ZipArchive::new(charx_data)?;

    // Find and read card.json
    let mut card_file = archive.by_name("card.json").map_err(|e| {
        // Log the specific error for debugging if needed
        warn!("Error finding 'card.json' in CHARX: {}", e);
        // Return the specific error type
        match e {
            ZipError::FileNotFound => ParserError::CharxCardJsonNotFound,
            other_zip_error => ParserError::ZipError(other_zip_error),
        }
    })?;

    // Read the content of card.json into a buffer
    let mut buffer = Vec::new();
    card_file.read_to_end(&mut buffer)?; // Use map_err for better context if needed

    // Parse the JSON content from the buffer
    match serde_json::from_slice::<CharacterCardV3>(&buffer) {
        Ok(card) => {
            // --- V3 Spec Conformance Checks (similar to PNG/JSON parsers) ---
            if card.spec != "chara_card_v3" {
                warn!(
                    "Invalid 'spec' field in CHARX card.json: expected 'chara_card_v3', found '{}'. Proceeding.",
                    card.spec
                );
                // Optionally normalize: card.spec = "chara_card_v3".to_string();
            }
            if card.spec_version != "3.0" {
                let current_version: Result<f32, _> = card.spec_version.parse();
                let target_version: f32 = 3.0;
                match current_version {
                    Ok(v) if v > target_version => warn!(
                        "CHARX Card spec_version ('{}') is newer than supported ('{}').",
                        card.spec_version, target_version
                    ),
                    Ok(v) if v < target_version => warn!(
                        "CHARX Card spec_version ('{}') is older than current spec ('{}').",
                        card.spec_version, target_version
                    ),
                    Ok(_) => {}
                    Err(_) => warn!(
                        "Could not parse CHARX card spec_version ('{}') as number.",
                        card.spec_version
                    ),
                }
            }
            // --- End V3 Spec Conformance Checks ---

            // CHARX format directly maps to V3 structure via card.json
            Ok(ParsedCharacterCard::V3(card))
        }
        Err(e) => {
            // If card.json doesn't parse as V3, it's an error
            Err(ParserError::JsonError(e))
        }
    }
}

// Declare the test module
// #[cfg(test)]
// #[path = "character_parser_tests.rs"]
// mod tests;

// Test module removed from here


// --- Unit Tests moved from tests/character_parser_tests.rs ---

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (character_parser.rs)
    use base64::engine::general_purpose::STANDARD as base64_standard;
    use crc32fast; // Needed for test helpers
    use std::io::{Cursor, Write}; // Added Write for zip helper
    use zip::{ZipWriter, write::FileOptions}; // Added for CHARX test helper

    // --- Test Helpers ---

    // Helper to create a minimal valid PNG with a specific tEXt chunk (Base64 encoded JSON)
    // (Restored original function)
    fn create_test_png_with_text_chunk(keyword: &[u8], json_payload: &str) -> Vec<u8> {
        let base64_payload = base64_standard.encode(json_payload);
        let chunk_data = base64_payload.as_bytes();

        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
        // --- tEXt chunk ---
        let text_chunk_data_internal = [&keyword[..], &[0u8], &chunk_data[..]].concat();
        let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len);
        let chunk_type_text = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text);
        png_bytes.extend_from_slice(&text_chunk_data_internal);
        let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
        png_bytes.extend_from_slice(&crc_text.to_be_bytes());
        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        // IEND
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);
        png_bytes
    }

    // Helper for V2 chara chunk (uses the main helper)
    fn create_test_png_with_chara_chunk(json_payload: &str) -> Vec<u8> {
        create_test_png_with_text_chunk(b"chara", json_payload)
    }

    // Helper to create a minimal valid PNG with a specific tEXt chunk containing *raw* data
    fn create_test_png_with_raw_text_chunk(keyword: &[u8], raw_payload: &[u8]) -> Vec<u8> {
        let chunk_data = raw_payload;

        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
        // --- tEXt chunk ---
        let text_chunk_data_internal = [&keyword[..], &[0u8], &chunk_data[..]].concat();
        let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len);
        let chunk_type_text = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text);
        png_bytes.extend_from_slice(&text_chunk_data_internal);
        let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
        png_bytes.extend_from_slice(&crc_text.to_be_bytes());
        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        // IEND
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);
        png_bytes
    }

    // Helper to create a PNG with multiple tEXt chunks
    fn create_test_png_with_multiple_chunks(chunks: Vec<(&[u8], &str)>) -> Vec<u8> {
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());

        // --- Add specified tEXt chunks ---
        for (keyword, json_payload) in chunks {
            let base64_payload = base64_standard.encode(json_payload);
            let chunk_data = base64_payload.as_bytes();
            let text_chunk_data_internal = [&keyword[..], &[0u8], &chunk_data[..]].concat();
            let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
            png_bytes.extend_from_slice(&text_chunk_len);
            let chunk_type_text = b"tEXt";
            png_bytes.extend_from_slice(chunk_type_text);
            png_bytes.extend_from_slice(&text_chunk_data_internal);
            let crc_text =
                crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
            png_bytes.extend_from_slice(&crc_text.to_be_bytes());
        }

        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        // IEND
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);
        png_bytes
    }

    // Helper to create an in-memory CHARX (zip) archive
    fn create_test_charx(
        card_json_payload: Option<&str>,
        other_files: Option<Vec<(&str, &[u8])>>,
    ) -> Result<Cursor<Vec<u8>>, Box<dyn std::error::Error>> {
        // Create ZipWriter with a Cursor that OWNS the Vec<u8> buffer
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options: FileOptions<()> = FileOptions::default() // Annotate type before chaining
            .compression_method(zip::CompressionMethod::Stored); // Use Stored for simplicity

        // Add card.json if provided
        if let Some(json_str) = card_json_payload {
            zip.start_file("card.json", options)?;
            zip.write_all(json_str.as_bytes())?;
        }

        // Add other files if provided
        if let Some(files) = other_files {
            for (filename, data) in files {
                zip.start_file(filename, options)?;
                zip.write_all(data)?;
            }
        }

        // Finalize the zip archive. finish() consumes the ZipWriter
        // and returns the inner writer (the Cursor<Vec<u8>>).
        let cursor_with_data = zip.finish()?;

        // The cursor now owns the Vec<u8> containing the complete zip data.
        Ok(cursor_with_data)
    }

    #[test]
    fn test_parse_valid_v2_chara_chunk() {
        // Use escaped newline
        // in JSON string
        let v2_json = r#"{
            "name": "Test V2",
            "description": "A V2 character.",
            "personality": "Friendly",
            "first_mes": "Hi there!",
            "mes_example": "<START>User: Hello\\nTest V2: Hi! How are you?<END>",
            "scenario": "A sunny day.",
            "creator_notes": "Created for testing.",
            "system_prompt": "System instructions.",
            "post_history_instructions": "Post history stuff.",
            "tags": ["test", "v2"],
            "creator": "Tester",
            "character_version": "1.0",
            "alternate_greetings": ["Hey!", "Greetings!"],
            "extensions": {}
        }"#;

        let png_data = create_test_png_with_chara_chunk(v2_json);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        // Assert that it's the V2Fallback variant and access its data
        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Test V2".to_string()));
            assert_eq!(data_v2.description, "A V2 character.");
            assert_eq!(data_v2.personality, "Friendly");
            assert_eq!(data_v2.first_mes, "Hi there!");
            // Check the message example with the *escaped* newline sequence
            assert_eq!(
                data_v2.mes_example,
                "<START>User: Hello\\nTest V2: Hi! How are you?<END>"
            );
            assert_eq!(data_v2.scenario, "A sunny day.");
            assert_eq!(data_v2.creator_notes, "Created for testing.");
            assert_eq!(data_v2.system_prompt, "System instructions.");
            assert_eq!(data_v2.post_history_instructions, "Post history stuff.");
            assert_eq!(data_v2.tags, vec!["test".to_string(), "v2".to_string()]);
            assert_eq!(data_v2.creator, "Tester");
            assert_eq!(data_v2.character_version, "1.0");
            assert_eq!(
                data_v2.alternate_greetings,
                vec!["Hey!".to_string(), "Greetings!".to_string()]
            );
            assert!(data_v2.extensions.is_empty());

            // V3 specific fields should be None or default
            assert!(data_v2.character_book.is_none());
            assert!(data_v2.assets.is_none());
            assert!(data_v2.nickname.is_none());
            assert!(data_v2.creator_notes_multilingual.is_none());
            assert!(data_v2.source.is_none());
            assert!(data_v2.group_only_greetings.is_empty());
            assert!(data_v2.creation_date.is_none());
            assert!(data_v2.modification_date.is_none());
        } else {
            panic!("Expected V2Fallback variant, got {:?}", parsed_card);
        }
    }

    #[test]
    fn test_parse_png_no_chara_chunk() {
        // Create PNG data without the 'chara' tEXt chunk (e.g., only IHDR, IDAT, and IEND)
        let mut png_data = Vec::new();
        png_data.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_data.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_data.extend_from_slice(chunk_type_ihdr);
        png_data.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_data.extend_from_slice(&crc_ihdr.to_be_bytes());
        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_data.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_data.extend_from_slice(chunk_type_idat);
        png_data.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_data.extend_from_slice(&crc_idat.to_be_bytes());
        // IEND
        png_data.extend_from_slice(&[0, 0, 0, 0]);
        png_data.extend_from_slice(b"IEND");
        png_data.extend_from_slice(&[174, 66, 96, 130]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::ChunkNotFound => (),
            e => panic!("Expected ChunkNotFound error, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_invalid_base64() {
        let invalid_base64 = "!@#$%^";
        let png_data = create_test_png_with_raw_text_chunk(b"chara", invalid_base64.as_bytes());

        let result = parse_character_card_png(&png_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::Base64Error(_) => (),
            e => panic!("Expected Base64Error, got {:?}", e),
        }

        // Test with invalid base64 in ccv3, falling back to valid chara
        let valid_v2_json = r#"{"name": "Fallback V2"}"#;
        let png_data_fallback = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", "!@#$%^"), // Invalid base64
            (b"chara", valid_v2_json), // Valid JSON
        ]);
        let result_fallback = parse_character_card_png(&png_data_fallback);
        assert!(result_fallback.is_ok());
        if let ParsedCharacterCard::V2Fallback(data) = result_fallback.unwrap() {
            assert_eq!(data.name, Some("Fallback V2".to_string()));
        } else {
            panic!("Expected V2Fallback after ccv3 Base64Error");
        }
    }

    #[test]
    fn test_parse_invalid_json() {
        let invalid_json = "{ name: \"Test V2 } } }"; // Missing quotes, extra braces
        let png_data = create_test_png_with_chara_chunk(invalid_json);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::JsonError(_) => (),
            e => panic!("Expected JsonError, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_not_a_png() {
        let not_png_data = b"This is not a PNG file.";
        let result = parse_character_card_png(not_png_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::PngError(_) => (),
            e => panic!("Expected PngError for invalid PNG data, got {:?}", e),
        }
    }

    // --- V3 Specific Tests (ccv3 chunk) ---
    #[test]
    fn test_parse_valid_v3_ccv3_chunk() {
        let v3_json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.0",
            "data": {
                "name": "Test V3",
                "description": "A V3 character."
            }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", v3_json);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok(), "Parsing V3 failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V3(card_v3) = parsed_card {
            assert_eq!(card_v3.spec, "chara_card_v3");
            assert_eq!(card_v3.spec_version, "3.0");
            assert_eq!(card_v3.data.name, Some("Test V3".to_string()));
            assert_eq!(card_v3.data.description, "A V3 character.");
        } else {
            panic!("Expected V3 variant, got {:?}", parsed_card);
        }
    }

    #[test]
    fn test_prefer_ccv3_over_chara() {
        let v3_json = r#"{"spec": "chara_card_v3", "spec_version": "3.0", "data": {"name": "Test V3"}}"#;
        let v2_json = r#"{"name": "Test V2"}"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"chara", v2_json), // Present but should be ignored
            (b"ccv3", v3_json),
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V3(card_v3) = parsed_card {
            assert_eq!(card_v3.data.name, Some("Test V3".to_string()));
        } else {
            panic!("Expected V3 variant when both chunks present, got {:?}", parsed_card);
        }
    }

    #[test]
    fn test_fallback_to_chara_if_ccv3_invalid_json() {
        let invalid_v3_json = "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
        let valid_v2_json = r#"{"name": "Fallback V2"}"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_v3_json),
            (b"chara", valid_v2_json),
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok(), "Fallback failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Fallback V2".to_string()));
            // Check for the fallback note
            assert!(data_v2.creator_notes.contains("loaded as a Character Card V2"));
        } else {
            panic!("Expected V2Fallback variant after invalid ccv3, got {:?}", parsed_card);
        }
    }

    #[test]
    fn test_parse_ccv3_with_incorrect_spec_field() {
        // Test behavior when ccv3 chunk has correct format but wrong spec value
        let json_wrong_spec = r#"{
            "spec": "chara_card_v2",
            "spec_version": "3.0",
            "data": {
                "name": "Wrong Spec V3"
            }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", json_wrong_spec);
        let result = parse_character_card_png(&png_data);

        // Expecting it to parse as V3 despite wrong spec, based on current implementation (with warning)
        assert!(result.is_ok(), "Parsing V3 failed: {:?}", result.err());
        let parsed_card = result.unwrap();
        if let ParsedCharacterCard::V3(card_v3) = parsed_card {
            assert_eq!(card_v3.spec, "chara_card_v2"); // Should retain original spec
            assert_eq!(card_v3.data.name, Some("Wrong Spec V3".to_string()));
        } else {
            panic!("Expected V3 variant even with wrong spec field, got {:?}", parsed_card);
        }

        // Test fallback if ccv3 has wrong spec AND chara is present
        let valid_v2_json = r#"{"name": "Fallback V2 Correct"}"#;
        let png_data_fallback = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", json_wrong_spec),
            (b"chara", valid_v2_json),
        ]);
        let result_fallback = parse_character_card_png(&png_data_fallback);
        assert!(result_fallback.is_ok());
        // Should still prefer ccv3 even if spec is wrong, as it parsed successfully
        if let ParsedCharacterCard::V3(card_v3) = result_fallback.unwrap() {
             assert_eq!(card_v3.spec, "chara_card_v2");
             assert_eq!(card_v3.data.name, Some("Wrong Spec V3".to_string()));
        } else {
             panic!("Expected V3 variant (with wrong spec) when both present, got fallback");
        }
    }


    #[test]
    fn test_fallback_to_chara_if_ccv3_invalid_base64() {
        let invalid_base64_ccv3 = "!@#$%^"; // Invalid base64 string
        let valid_v2_json = r#"{"name": "Fallback V2 From Bad Base64"}"#;

        // Create raw text chunk for ccv3
        let mut png_bytes = Vec::new();
        png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR (as before)
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());

        // ccv3 chunk with invalid base64
        let ccv3_keyword = b"ccv3";
        let text_chunk_data_ccv3 = [&ccv3_keyword[..], &[0u8], invalid_base64_ccv3.as_bytes()].concat();
        let text_chunk_len_ccv3 = (text_chunk_data_ccv3.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len_ccv3);
        let chunk_type_text_ccv3 = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text_ccv3);
        png_bytes.extend_from_slice(&text_chunk_data_ccv3);
        let crc_text_ccv3 = crc32fast::hash(&[&chunk_type_text_ccv3[..], &text_chunk_data_ccv3[..]].concat());
        png_bytes.extend_from_slice(&crc_text_ccv3.to_be_bytes());

        // chara chunk with valid JSON
        let chara_keyword = b"chara";
        let base64_payload_chara = base64_standard.encode(valid_v2_json);
        let chunk_data_chara = base64_payload_chara.as_bytes();
        let text_chunk_data_chara = [&chara_keyword[..], &[0u8], chunk_data_chara].concat();
        let text_chunk_len_chara = (text_chunk_data_chara.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len_chara);
        let chunk_type_text_chara = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text_chara);
        png_bytes.extend_from_slice(&text_chunk_data_chara);
        let crc_text_chara = crc32fast::hash(&[&chunk_type_text_chara[..], &text_chunk_data_chara[..]].concat());
        png_bytes.extend_from_slice(&crc_text_chara.to_be_bytes());

        // Dummy IDAT and IEND (as before)
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = (idat_data.len() as u32).to_be_bytes();
        png_bytes.extend_from_slice(&idat_len);
        let chunk_type_idat = b"IDAT";
        png_bytes.extend_from_slice(chunk_type_idat);
        png_bytes.extend_from_slice(idat_data);
        let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
        png_bytes.extend_from_slice(&crc_idat.to_be_bytes());
        png_bytes.extend_from_slice(&[0, 0, 0, 0]);
        png_bytes.extend_from_slice(b"IEND");
        png_bytes.extend_from_slice(&[174, 66, 96, 130]);

        let result = parse_character_card_png(&png_bytes);
        assert!(result.is_ok(), "Fallback failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Fallback V2 From Bad Base64".to_string()));
            // Check for the fallback note
            assert!(data_v2.creator_notes.contains("loaded as a Character Card V2"));
        } else {
            panic!("Expected V2Fallback variant after invalid ccv3 base64, got {:?}", parsed_card);
        }
    }

    #[test]
    fn test_error_if_both_invalid() {
        let invalid_json = "{\"invalid json";
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_json),
            (b"chara", invalid_json),
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_err());
        // Expecting JsonError from the chara fallback attempt
        match result.err().unwrap() {
            ParserError::JsonError(_) => (),
            e => panic!("Expected JsonError when both chunks are invalid, got {:?}", e),
        }
    }

    #[test]
    fn test_error_if_chara_invalid_base64_and_no_ccv3() {
         let invalid_base64 = "!@#$%^";
         let png_data = create_test_png_with_raw_text_chunk(b"chara", invalid_base64.as_bytes());

         let result = parse_character_card_png(&png_data);
         assert!(result.is_err());
         match result.err().unwrap() {
             ParserError::Base64Error(_) => (),
             e => panic!("Expected Base64Error, got {:?}", e),
         }
    }


    #[test]
    fn test_parse_ccv3_valid_json_wrong_spec_string() {
        let json = r#"{
            "spec": "wrong_spec",
            "spec_version": "3.0",
            "data": { "name": "V3 Wrong Spec" }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", json);
        let result = parse_character_card_png(&png_data);

        assert!(result.is_ok()); // Should still parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec, "wrong_spec");
            assert_eq!(card.data.name, Some("V3 Wrong Spec".to_string()));
        } else {
            panic!("Expected V3 variant even with wrong spec string");
        }
    }

    #[test]
    fn test_parse_ccv3_newer_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "4.0",
            "data": { "name": "V3 Future Spec" }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", json);
        let result = parse_character_card_png(&png_data);

        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "4.0");
            assert_eq!(card.data.name, Some("V3 Future Spec".to_string()));
        } else {
            panic!("Expected V3 variant for newer spec version");
        }
    }

    #[test]
    fn test_parse_ccv3_older_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "2.5",
            "data": { "name": "V3 Old Spec" }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", json);
        let result = parse_character_card_png(&png_data);

        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "2.5");
            assert_eq!(card.data.name, Some("V3 Old Spec".to_string()));
        } else {
            panic!("Expected V3 variant for older spec version");
        }
    }

    #[test]
    fn test_parse_ccv3_non_numeric_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "beta",
            "data": { "name": "V3 Beta Spec" }
        }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", json);
        let result = parse_character_card_png(&png_data);

        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "beta");
            assert_eq!(card.data.name, Some("V3 Beta Spec".to_string()));
        } else {
            panic!("Expected V3 variant for non-numeric spec version");
        }
    }

    // --- V2 Fallback Notes Tests ---
    #[test]
    fn test_fallback_note_when_v2_notes_empty() {
        let invalid_v3_json = "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
        let v2_json_no_notes = r#"{
            "name": "Fallback V2 No Notes",
            "creator_notes": ""
        }"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_v3_json), // Invalid V3 triggers fallback
            (b"chara", v2_json_no_notes), // V2 with empty notes
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Fallback V2 No Notes".to_string()));
            // Check if creator_notes *only* contains the fallback warning
            assert!(data_v2.creator_notes.contains("loaded as a Character Card V2"), "Missing fallback note");
            assert!(data_v2.creator_notes.starts_with("This character card is Character Card V3"), "Note should start with the warning");
            assert!(data_v2.creator_notes.ends_with("properly.\n"), "Note should end correctly");
            // Verify length if needed to ensure only the note is present
            let expected_note = "This character card is Character Card V3, but it is loaded as a Character Card V2. Please use a Character Card V3 compatible application to use this character card properly.\n";
            assert_eq!(data_v2.creator_notes, expected_note, "Creator notes should be exactly the fallback note");
        } else {
            panic!("Expected V2Fallback variant");
        }
    }

    #[test]
    fn test_fallback_note_when_v2_notes_not_empty() {
        let invalid_v3_json = "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
        let v2_json_with_notes = r#"{
            "name": "Fallback V2 With Notes",
            "creator_notes": "Original V2 notes here."
        }"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_v3_json), // Invalid V3 triggers fallback
            (b"chara", v2_json_with_notes), // V2 with existing notes
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Fallback V2 With Notes".to_string()));
            // Check if creator_notes contains *both* the warning and original notes
            let expected_prefix = "This character card is Character Card V3, but it is loaded as a Character Card V2. Please use a Character Card V3 compatible application to use this character card properly.\n";
            let expected_suffix = "Original V2 notes here.";
            assert!(data_v2.creator_notes.starts_with(expected_prefix), "Notes should start with fallback warning");
            assert!(data_v2.creator_notes.ends_with(expected_suffix), "Notes should end with original notes");
            assert!(data_v2.creator_notes.contains(expected_prefix), "Missing fallback note part");
            assert!(data_v2.creator_notes.contains(expected_suffix), "Missing original notes part");
        } else {
            panic!("Expected V2Fallback variant");
        }
    }

    // --- JSON Parsing Tests ---
    #[test]
    fn test_parse_json_valid_v3() {
        let v3_json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.0",
            "data": { "name": "JSON V3 Test" }
        }"#;
        let result = parse_character_card_json(v3_json.as_bytes());
        assert!(result.is_ok());
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.data.name, Some("JSON V3 Test".to_string()));
        } else {
            panic!("Expected V3 from JSON parse");
        }
    }

    #[test]
    fn test_parse_json_invalid_json() {
        let invalid_json = b"{\"invalid json";
        let result = parse_character_card_json(invalid_json);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::JsonError(_) => (),
            e => panic!("Expected JsonError, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_json_wrong_spec_string() {
         let json = r#"{
            "spec": "wrong_spec",
            "spec_version": "3.0",
            "data": { "name": "JSON Wrong Spec" }
        }"#;
        let result = parse_character_card_json(json.as_bytes());

        assert!(result.is_ok()); // Should still parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec, "wrong_spec");
            assert_eq!(card.data.name, Some("JSON Wrong Spec".to_string()));
        } else {
            panic!("Expected V3 variant even with wrong spec string");
        }
    }


    #[test]
    fn test_parse_json_newer_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.1",
            "data": { "name": "JSON Future Spec" }
        }"#;
        let result = parse_character_card_json(json.as_bytes());

        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "3.1");
            assert_eq!(card.data.name, Some("JSON Future Spec".to_string()));
        } else {
            panic!("Expected V3 variant for newer spec version");
        }
    }

    // --- CHARX Parsing Tests ---
    #[test]
    fn test_parse_charx_valid() {
        let v3_json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.0",
            "data": { "name": "CHARX V3 Test" }
        }"#;
        let charx_data = create_test_charx(Some(v3_json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_ok(), "CHARX parse failed: {:?}", result.err());
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.data.name, Some("CHARX V3 Test".to_string()));
        } else {
            panic!("Expected V3 from CHARX parse");
        }
    }

    #[test]
    fn test_parse_charx_missing_card_json() {
        let charx_data = create_test_charx(None, Some(vec![("other.txt", b"data")]))
            .expect("Failed to create CHARX without card.json");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::CharxCardJsonNotFound => (),
            e => panic!("Expected CharxCardJsonNotFound, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_charx_invalid_card_json() {
        let invalid_json = "{\"invalid json";
        let charx_data =
            create_test_charx(Some(invalid_json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::JsonError(_) => (),
            e => panic!("Expected JsonError from invalid card.json, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_charx_not_a_zip() {
        let not_zip_data = Cursor::new(b"This is definitely not a zip file".to_vec());

        let result = parse_character_card_charx(not_zip_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::ZipError(_) => (),
            e => panic!("Expected ZipError for non-zip data, got {:?}", e),
        }
    }

    #[test]
    fn test_parse_charx_wrong_spec_string() {
        let json = r#"{
            "spec": "wrong_spec",
            "spec_version": "3.0",
            "data": { "name": "CHARX Wrong Spec" }
        }"#;
        let charx_data = create_test_charx(Some(json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec, "wrong_spec");
            assert_eq!(card.data.name, Some("CHARX Wrong Spec".to_string()));
        } else {
            panic!("Expected V3 variant even with wrong spec string");
        }
    }

    #[test]
    fn test_parse_charx_older_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "2.9",
            "data": { "name": "CHARX Old Spec" }
        }"#;
        let charx_data = create_test_charx(Some(json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "2.9");
            assert_eq!(card.data.name, Some("CHARX Old Spec".to_string()));
        } else {
            panic!("Expected V3 variant for older spec version");
        }
    }

    #[test]
    fn test_parse_charx_newer_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "3.1",
            "data": { "name": "CHARX Future Spec" }
        }"#;
        let charx_data = create_test_charx(Some(json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "3.1");
            assert_eq!(card.data.name, Some("CHARX Future Spec".to_string()));
        } else {
            panic!("Expected V3 variant for newer spec version");
        }
    }

    #[test]
    fn test_parse_charx_non_numeric_spec_version() {
        let json = r#"{
            "spec": "chara_card_v3",
            "spec_version": "alpha-1",
            "data": { "name": "CHARX Alpha Spec" }
        }"#;
        let charx_data = create_test_charx(Some(json), None).expect("Failed to create CHARX");

        let result = parse_character_card_charx(charx_data);
        assert!(result.is_ok()); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "alpha-1");
            assert_eq!(card.data.name, Some("CHARX Alpha Spec".to_string()));
        } else {
            panic!("Expected V3 variant for non-numeric spec version");
        }
    }
}
