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

/// Safely convert usize to u32 for PNG chunk lengths
/// PNG chunk lengths are limited to `u32::MAX`, so this is appropriate

// Define potential errors for the parser
#[derive(Debug, Error, Clone)] // Use the imported derive macro, Add Clone
pub enum ParserError {
    #[error("I/O Error reading PNG data: {0}")]
    IoError(String), // Store as String
    #[error("PNG decoding error: {0}")]
    PngError(String), // Store as String
    #[error("Character data chunk ('chara', 'tEXtchara', or 'ccv3') not found in PNG.")]
    ChunkNotFound,
    #[error("Base64 decoding error: {0}")]
    Base64Error(String), // Store as String
    #[error("JSON deserialization error: {0}")]
    JsonError(String), // Store as String
    #[error("Unsupported character card format: {0}")]
    UnsupportedFormat(String),
    #[error("Invalid tEXt chunk format for 'chara'.")]
    InvalidTextChunkFormat,
    #[error("Invalid spec field in ccv3 chunk: expected 'chara_card_v3', found '{0}'")]
    InvalidSpecField(String),
    #[error("CHARX (Zip) processing error: {0}")]
    ZipError(String), // Store as String
    #[error("Required 'card.json' not found in CHARX archive.")]
    CharxCardJsonNotFound,
}

// Manually implement From for non-Clone error types
impl From<std::io::Error> for ParserError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<png::DecodingError> for ParserError {
    fn from(err: png::DecodingError) -> Self {
        Self::PngError(err.to_string())
    }
}

impl From<base64::DecodeError> for ParserError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64Error(err.to_string())
    }
}

impl From<serde_json::Error> for ParserError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err.to_string())
    }
}

impl From<ZipError> for ParserError {
    fn from(err: ZipError) -> Self {
        Self::ZipError(err.to_string())
    }
}

// Define the structure to represent the parsed result
#[derive(Debug)]
pub enum ParsedCharacterCard {
    V3(CharacterCardV3), // Represents a card parsed from 'ccv3' or a full V3 structure
    V2Fallback(CharacterCardDataV3), // Represents data parsed from 'chara' (V2)
}

// --- Helper Functions ---

/// Validates V3 spec fields and logs warnings for version mismatches.
fn validate_v3_spec(card: &CharacterCardV3, source: &str) {
    validate_spec_field(&card.spec, source);
    validate_spec_version(&card.spec_version, source);
}

/// Validates the 'spec' field value.
fn validate_spec_field(spec: &str, source: &str) {
    if spec != "chara_card_v3" {
        warn!(
            "Invalid 'spec' field in {}: expected 'chara_card_v3', found '{}'. Proceeding with parsing.",
            source, spec
        );
    }
}

/// Validates the `spec_version` field value.
fn validate_spec_version(spec_version: &str, source: &str) {
    if spec_version != "3.0" {
        match spec_version.parse::<f32>() {
            Ok(version) => log_version_mismatch(version, spec_version, source),
            Err(_) => log_unparseable_version(spec_version, source),
        }
    }
}

/// Logs appropriate warning for version mismatches.
fn log_version_mismatch(version: f32, spec_version: &str, source: &str) {
    const TARGET_VERSION: f32 = 3.0;

    if version > TARGET_VERSION {
        warn!(
            "{} spec_version ('{}') is newer than supported ('3.0'). Some features might not work.",
            source, spec_version
        );
    } else if version < TARGET_VERSION {
        warn!(
            "{} spec_version ('{}') is older than current spec ('3.0'). Attempting to load.",
            source, spec_version
        );
    }
    // Version matches 3.0 exactly - no warning needed
}

/// Logs warning for unparseable version strings.
fn log_unparseable_version(spec_version: &str, source: &str) {
    warn!(
        "Could not parse {} spec_version ('{}') as a number.",
        source, spec_version
    );
}

/// Extracts text chunks from PNG info.
fn extract_text_chunks(info: &png::Info) -> (Option<String>, Option<String>) {
    let chara_keyword = "chara";
    let ccv3_keyword = "ccv3";
    let text_chara_keyword = "tEXtchara";

    let mut ccv3_data_base64: Option<String> = None;
    let mut chara_data_base64: Option<String> = None;

    for text_chunk in &info.uncompressed_latin1_text {
        if text_chunk.keyword == ccv3_keyword {
            ccv3_data_base64 = Some(text_chunk.text.clone());
            info!("Found 'ccv3' tEXt chunk.");
        } else if text_chunk.keyword == chara_keyword || text_chunk.keyword == text_chara_keyword {
            chara_data_base64 = Some(text_chunk.text.clone());
            info!(keyword = %text_chunk.keyword, "Found V2-style tEXt chunk.");
        }
    }

    (ccv3_data_base64, chara_data_base64)
}

/// Attempts to parse V3 card from base64 data.
fn try_parse_v3_from_base64(
    base64_str: &str,
    source: &str,
) -> Result<CharacterCardV3, ParserError> {
    let decoded_bytes = base64_standard.decode(base64_str).map_err(|e| {
        warn!("Failed to decode base64 from '{}': {}", source, e);
        ParserError::Base64Error(e.to_string())
    })?;

    let mut card = serde_json::from_slice::<CharacterCardV3>(&decoded_bytes).map_err(|e| {
        warn!(
            "Failed to parse JSON from '{}' as CharacterCardV3: {}",
            source, e
        );
        ParserError::JsonError(e.to_string())
    })?;

    // Merge flattened fields (for SillyTavern compatibility)
    card.merge_flattened_fields();
    
    validate_v3_spec(&card, source);
    Ok(card)
}

/// Applies V2 fallback note to character data if needed.
fn apply_v2_fallback_note(data_v2: &mut CharacterCardDataV3, ccv3_parse_failed: bool) {
    if ccv3_parse_failed {
        const V2_FALLBACK_NOTE: &str = "This character card is Character Card V3, but it is loaded as a Character Card V2. Please use a Character Card V3 compatible application to use this character card properly.\n";
        if data_v2.creator_notes.is_empty() {
            data_v2.creator_notes = V2_FALLBACK_NOTE.to_string();
        } else {
            data_v2.creator_notes = format!("{}{}", V2_FALLBACK_NOTE, data_v2.creator_notes);
        }
    }
}

/// Attempts to parse V2 fallback format from chara data.
fn try_parse_chara_fallback(
    chara_data_base64: Option<&String>,
    ccv3_parse_failed: bool,
) -> Result<Option<CharacterCardDataV3>, ParserError> {
    chara_data_base64.map_or(Ok(None), |base64_str| {
        let decoded_bytes = base64_standard.decode(base64_str)?;
        let mut data_v2 = serde_json::from_slice::<CharacterCardDataV3>(&decoded_bytes)?;

        info!("Loaded character from V2 'chara' chunk. Applying V3 compatibility note.");
        apply_v2_fallback_note(&mut data_v2, ccv3_parse_failed);
        Ok(Some(data_v2))
    })
}

// --- Main Parsing Function ---

/// Parses a character card from PNG image data.
///
/// # Errors
///
/// Returns an error if:
/// - PNG format is invalid
/// - Required metadata is missing
/// - JSON parsing fails
pub fn parse_character_card_png(png_data: &[u8]) -> Result<ParsedCharacterCard, ParserError> {
    let cursor = Cursor::new(png_data);
    let decoder = Decoder::new(cursor);
    let mut reader = decoder.read_info()?;
    reader.finish()?;
    let info = reader.info();

    let (ccv3_data_base64, chara_data_base64) = extract_text_chunks(info);

    let mut ccv3_parse_error: Option<ParserError> = None;

    // 1. Try ccv3 first
    if let Some(base64_str) = ccv3_data_base64.as_ref() {
        match try_parse_v3_from_base64(base64_str, "ccv3 chunk") {
            Ok(card) => return Ok(ParsedCharacterCard::V3(card)),
            Err(e) => {
                warn!(
                    "Failed to parse ccv3 chunk: {}. Falling back to 'chara' if possible.",
                    e
                );
                ccv3_parse_error = Some(e);
            }
        }
    }

    // 2. If ccv3 failed or was not present, try chara
    if let Some(base64_str) = chara_data_base64.as_ref() {
        match try_parse_chara_fallback(Some(base64_str), ccv3_parse_error.is_some()) {
            Ok(Some(data_v2)) => return Ok(ParsedCharacterCard::V2Fallback(data_v2)),
            Err(e) => {
                // If chara parsing also failed, we should return this error
                return Err(e);
            }
            Ok(None) => { /* This case should not be reached if base64_str is Some */ }
        }
    }

    // 3. If neither succeeded, return the ccv3 error if it occurred, otherwise ChunkNotFound
    if let Some(err) = ccv3_parse_error {
        return Err(err);
    }

    Err(ParserError::ChunkNotFound)
}

// --- JSON Parsing Function ---

/// Parses a character card from JSON data.
///
/// # Errors
///
/// Returns an error if:
/// - JSON format is invalid
/// - Required fields are missing
pub fn parse_character_card_json(json_data: &[u8]) -> Result<ParsedCharacterCard, ParserError> {
    let mut card = serde_json::from_slice::<CharacterCardV3>(json_data)
        .map_err(|e| ParserError::JsonError(e.to_string()))?;

    // Merge flattened fields (for SillyTavern compatibility)
    card.merge_flattened_fields();
    
    validate_v3_spec(&card, "JSON card");
    Ok(ParsedCharacterCard::V3(card))
}

// --- CHARX (Zip) Parsing Function ---

/// Parses a character card from CHARX (ZIP) format.
///
/// # Errors
///
/// Returns an error if:
/// - ZIP format is invalid
/// - Required files are missing
/// - JSON parsing fails
pub fn parse_character_card_charx<R: Read + Seek>(
    charx_data: R,
) -> Result<ParsedCharacterCard, ParserError> {
    let mut archive = ZipArchive::new(charx_data)?;

    let mut card_file = archive.by_name("card.json").map_err(|e| {
        warn!("Error finding 'card.json' in CHARX: {}", e);
        match e {
            ZipError::FileNotFound => ParserError::CharxCardJsonNotFound,
            other_zip_error => ParserError::ZipError(other_zip_error.to_string()),
        }
    })?;

    let mut buffer = Vec::new();
    card_file.read_to_end(&mut buffer)?;

    let card = serde_json::from_slice::<CharacterCardV3>(&buffer)
        .map_err(|e| ParserError::JsonError(e.to_string()))?;

    validate_v3_spec(&card, "CHARX card.json");
    Ok(ParsedCharacterCard::V3(card))
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

    fn safe_len_to_u32(len: usize) -> u32 {
        u32::try_from(len).unwrap_or_else(|_| panic!("Length {len} is too large to fit in u32"))
    }

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
        let ihdr_len = safe_len_to_u32(ihdr_data.len()).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());

        // tEXt chunk
        let text_chunk_data_internal = [keyword, &[0u8], chunk_data].concat();
        let text_chunk_len = safe_len_to_u32(text_chunk_data_internal.len()).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len);
        let chunk_type_text = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text);
        png_bytes.extend_from_slice(&text_chunk_data_internal);
        let crc_text =
            crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
        png_bytes.extend_from_slice(&crc_text.to_be_bytes());

        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = safe_len_to_u32(idat_data.len()).to_be_bytes();
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
        let ihdr_len = safe_len_to_u32(ihdr_data.len()).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());
        // --- tEXt chunk ---
        let text_chunk_data_internal = [keyword, &[0u8], chunk_data].concat();
        let text_chunk_len = safe_len_to_u32(text_chunk_data_internal.len()).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len);
        let chunk_type_text = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text);
        png_bytes.extend_from_slice(&text_chunk_data_internal);
        let crc_text =
            crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
        png_bytes.extend_from_slice(&crc_text.to_be_bytes());
        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = safe_len_to_u32(idat_data.len()).to_be_bytes();
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
        let ihdr_len = safe_len_to_u32(ihdr_data.len()).to_be_bytes();
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
            let text_chunk_data_internal = [keyword, &[0u8], chunk_data].concat();
            let text_chunk_len = safe_len_to_u32(text_chunk_data_internal.len()).to_be_bytes();
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
        let idat_len = safe_len_to_u32(idat_data.len()).to_be_bytes();
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

        let options: FileOptions<()> =
            FileOptions::default() // Annotate type before chaining
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
            panic!("Expected V2Fallback variant, got {parsed_card:?}");
        }
    }

    #[test]
    fn test_parse_png_no_chara_chunk() {
        // Create PNG data without the 'chara' tEXt chunk (e.g., only IHDR, IDAT, and IEND)
        let mut png_data = Vec::new();
        png_data.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // Signature
        // Dummy IHDR
        let ihdr_data = &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0];
        let ihdr_len = safe_len_to_u32(ihdr_data.len()).to_be_bytes();
        png_data.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_data.extend_from_slice(chunk_type_ihdr);
        png_data.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_data.extend_from_slice(&crc_ihdr.to_be_bytes());
        // Dummy IDAT
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = safe_len_to_u32(idat_data.len()).to_be_bytes();
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
            e => panic!("Expected ChunkNotFound error, got {e:?}"),
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
            e => panic!("Expected Base64Error, got {e:?}"),
        }

        // Test with invalid base64 in ccv3, falling back to valid chara
        let valid_v2_json = r#"{"name": "Fallback V2"}"#;
        let png_data_fallback = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", "!@#$%^"),       // Invalid base64
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
            e => panic!("Expected JsonError, got {e:?}"),
        }
    }

    #[test]
    fn test_parse_not_a_png() {
        let not_png_data = b"This is not a PNG file.";
        let result = parse_character_card_png(not_png_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::PngError(_) => (),
            e => panic!("Expected PngError for invalid PNG data, got {e:?}"),
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
            panic!("Expected V3 variant, got {parsed_card:?}");
        }
    }

    #[test]
    fn test_prefer_ccv3_over_chara() {
        let v3_json =
            r#"{"spec": "chara_card_v3", "spec_version": "3.0", "data": {"name": "Test V3"}}"#;
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
            panic!("Expected V3 variant when both chunks present, got {parsed_card:?}");
        }
    }

    #[test]
    fn test_prefer_ccv3_over_text_chara() {
        let v3_json =
            r#"{"spec": "chara_card_v3", "spec_version": "3.0", "data": {"name": "Test V3"}}"#;
        let v2_json = r#"{"name": "tEXtchara Test"}"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"tEXtchara", v2_json), // Present but should be ignored
            (b"ccv3", v3_json),
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok(), "Parsing failed: {:?}", result.err());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V3(card_v3) = parsed_card {
            assert_eq!(card_v3.data.name, Some("Test V3".to_string()));
        } else {
            panic!("Expected V3 variant when both chunks present, got {parsed_card:?}");
        }
    }

    #[test]
    fn test_fallback_to_chara_if_ccv3_invalid_json() {
        let invalid_v3_json =
            "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
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
            assert!(
                data_v2
                    .creator_notes
                    .contains("loaded as a Character Card V2")
            );
        } else {
            panic!("Expected V2Fallback variant after invalid ccv3, got {parsed_card:?}");
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
            panic!("Expected V3 variant even with wrong spec field, got {parsed_card:?}");
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
        let ihdr_len = safe_len_to_u32(ihdr_data.len()).to_be_bytes();
        png_bytes.extend_from_slice(&ihdr_len);
        let chunk_type_ihdr = b"IHDR";
        png_bytes.extend_from_slice(chunk_type_ihdr);
        png_bytes.extend_from_slice(ihdr_data);
        let crc_ihdr = crc32fast::hash(&[&chunk_type_ihdr[..], &ihdr_data[..]].concat());
        png_bytes.extend_from_slice(&crc_ihdr.to_be_bytes());

        // ccv3 chunk with invalid base64
        let ccv3_keyword = b"ccv3";
        let text_chunk_data_ccv3 =
            [&ccv3_keyword[..], &[0u8], invalid_base64_ccv3.as_bytes()].concat();
        let text_chunk_len_ccv3 = safe_len_to_u32(text_chunk_data_ccv3.len()).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len_ccv3);
        let chunk_type_text_ccv3 = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text_ccv3);
        png_bytes.extend_from_slice(&text_chunk_data_ccv3);
        let crc_text_ccv3 =
            crc32fast::hash(&[&chunk_type_text_ccv3[..], &text_chunk_data_ccv3[..]].concat());
        png_bytes.extend_from_slice(&crc_text_ccv3.to_be_bytes());

        // chara chunk with valid JSON
        let chara_keyword = b"chara";
        let base64_payload_chara = base64_standard.encode(valid_v2_json);
        let chunk_data_chara = base64_payload_chara.as_bytes();
        let text_chunk_data_chara = [&chara_keyword[..], &[0u8], chunk_data_chara].concat();
        let text_chunk_len_chara = safe_len_to_u32(text_chunk_data_chara.len()).to_be_bytes();
        png_bytes.extend_from_slice(&text_chunk_len_chara);
        let chunk_type_text_chara = b"tEXt";
        png_bytes.extend_from_slice(chunk_type_text_chara);
        png_bytes.extend_from_slice(&text_chunk_data_chara);
        let crc_text_chara =
            crc32fast::hash(&[&chunk_type_text_chara[..], &text_chunk_data_chara[..]].concat());
        png_bytes.extend_from_slice(&crc_text_chara.to_be_bytes());

        // Dummy IDAT and IEND (as before)
        let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1];
        let idat_len = safe_len_to_u32(idat_data.len()).to_be_bytes();
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
            assert_eq!(
                data_v2.name,
                Some("Fallback V2 From Bad Base64".to_string())
            );
            // Check for the fallback note
            assert!(
                data_v2
                    .creator_notes
                    .contains("loaded as a Character Card V2")
            );
        } else {
            panic!("Expected V2Fallback variant after invalid ccv3 base64, got {parsed_card:?}");
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
            e => panic!("Expected JsonError when both chunks are invalid, got {e:?}"),
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
            e => panic!("Expected Base64Error, got {e:?}"),
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
        let invalid_v3_json =
            "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
        let v2_json_no_notes = r#"{
            "name": "Fallback V2 No Notes",
            "creator_notes": ""
        }"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_v3_json),   // Invalid V3 triggers fallback
            (b"chara", v2_json_no_notes), // V2 with empty notes
        ]);

        let result = parse_character_card_png(&png_data);
        assert!(result.is_ok());
        let parsed_card = result.unwrap();

        if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
            assert_eq!(data_v2.name, Some("Fallback V2 No Notes".to_string()));
            // Check if creator_notes *only* contains the fallback warning
            assert!(
                data_v2
                    .creator_notes
                    .contains("loaded as a Character Card V2"),
                "Missing fallback note"
            );
            assert!(
                data_v2
                    .creator_notes
                    .starts_with("This character card is Character Card V3"),
                "Note should start with the warning"
            );
            assert!(
                data_v2.creator_notes.ends_with("properly.\n"),
                "Note should end correctly"
            );
            // Verify length if needed to ensure only the note is present
            let expected_note = "This character card is Character Card V3, but it is loaded as a Character Card V2. Please use a Character Card V3 compatible application to use this character card properly.\n";
            assert_eq!(
                data_v2.creator_notes, expected_note,
                "Creator notes should be exactly the fallback note"
            );
        } else {
            panic!("Expected V2Fallback variant");
        }
    }

    #[test]
    fn test_fallback_note_when_v2_notes_not_empty() {
        let invalid_v3_json =
            "{\"spec\": \"chara_card_v3\", \"spec_version\": \"3.0\", \"data\": {invalid}}";
        let v2_json_with_notes = r#"{
            "name": "Fallback V2 With Notes",
            "creator_notes": "Original V2 notes here."
        }"#;
        let png_data = create_test_png_with_multiple_chunks(vec![
            (b"ccv3", invalid_v3_json),     // Invalid V3 triggers fallback
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
            assert!(
                data_v2.creator_notes.starts_with(expected_prefix),
                "Notes should start with fallback warning"
            );
            assert!(
                data_v2.creator_notes.ends_with(expected_suffix),
                "Notes should end with original notes"
            );
            assert!(
                data_v2.creator_notes.contains(expected_prefix),
                "Missing fallback note part"
            );
            assert!(
                data_v2.creator_notes.contains(expected_suffix),
                "Missing original notes part"
            );
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
            e => panic!("Expected JsonError, got {e:?}"),
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
            e => panic!("Expected CharxCardJsonNotFound, got {e:?}"),
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
            e => panic!("Expected JsonError from invalid card.json, got {e:?}"),
        }
    }

    #[test]
    fn test_parse_charx_not_a_zip() {
        let not_zip_data = Cursor::new(b"This is definitely not a zip file".to_vec());

        let result = parse_character_card_charx(not_zip_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            ParserError::ZipError(_) => (),
            e => panic!("Expected ZipError for non-zip data, got {e:?}"),
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

    #[test]
    fn test_parse_text_chara_chunk() {
        let v2_json =
            r#"{"name": "tEXtchara Test", "description": "Testing the tEXtchara chunk."}"#;
        let png_data = create_test_png_with_text_chunk(b"tEXtchara", v2_json);

        let result = parse_character_card_png(&png_data);
        assert!(
            result.is_ok(),
            "Parsing tEXtchara failed: {:?}",
            result.err()
        );

        match result.unwrap() {
            ParsedCharacterCard::V2Fallback(data) => {
                assert_eq!(data.name, Some("tEXtchara Test".to_string()));
                assert_eq!(data.description, "Testing the tEXtchara chunk.");
            }
            other @ ParsedCharacterCard::V3(_) => {
                panic!("Expected V2Fallback for tEXtchara chunk, got {other:?}")
            }
        }
    }
    // Helper to create a minimally valid V3 JSON string
    fn create_minimal_valid_v3_json(spec_version: &str, name: &str) -> String {
        // Based on CharacterCardV3 and CharacterCardDataV3 defaults
        format!(
            r#"{{
        "spec": "chara_card_v3",
        "spec_version": "{spec_version}",
        "data": {{
            "name": "{name}",
            "description": "",
            "personality": "",
            "scenario": "",
            "first_mes": "",
            "mes_example": "",
            "creator_notes": "",
            "system_prompt": "",
            "post_history_instructions": "",
            "alternate_greetings": [],
            "tags": [],
            "creator": "",
            "character_version": "",
            "extensions": {{}},
            "group_only_greetings": []
        }}
    }}"#
        )
    }

    #[test]
    fn test_parse_json_older_spec_version() {
        let json = create_minimal_valid_v3_json("2.9", "JSON Old Spec");
        let result = parse_character_card_json(json.as_bytes());

        assert!(
            result.is_ok(),
            "Parsing failed for older spec version: {:?}",
            result.err()
        ); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "2.9"); // Line 254-255
            assert_eq!(card.data.name, Some("JSON Old Spec".to_string()));
        } else {
            panic!("Expected V3 variant for older spec version");
        }
    }

    #[test]
    fn test_parse_json_non_numeric_spec_version() {
        let json = create_minimal_valid_v3_json("alpha", "JSON Alpha Spec");
        let result = parse_character_card_json(json.as_bytes());

        assert!(
            result.is_ok(),
            "Parsing failed for non-numeric spec version: {:?}",
            result.err()
        ); // Should parse ok, with warning
        if let ParsedCharacterCard::V3(card) = result.unwrap() {
            assert_eq!(card.spec_version, "alpha"); // Line 263
            assert_eq!(card.data.name, Some("JSON Alpha Spec".to_string()));
        } else {
            panic!("Expected V3 variant for non-numeric spec version");
        }
    }

    #[test]
    fn test_parse_charx_other_zip_error() {
        // Create intentionally corrupted zip data (e.g., invalid central directory)
        // This is tricky to do reliably without deep knowledge of the zip format.
        // A simpler approach is to provide data that *looks* like a zip header
        // but is otherwise invalid.
        let corrupted_zip_data = Cursor::new(b"PK\x03\x04DefinitelyNotAZipFile".to_vec());

        let result = parse_character_card_charx(corrupted_zip_data);
        assert!(result.is_err());
        match result.err().unwrap() {
            // Expecting a generic ZipError, not FileNotFound
            ParserError::ZipError(e) => {
                // Line 296 (other_zip_error branch)
                assert!(
                    !e.contains("file not found"),
                    "Expected a generic ZipError, not FileNotFound"
                );
            }
            e => panic!("Expected ZipError for corrupted zip data, got {e:?}"),
        }
    }

    // Helper to create a reader that fails after some bytes
    struct FailingReader {
        data: Cursor<Vec<u8>>,
        fail_after: u64,
        read_count: u64,
    }

    impl Read for FailingReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read_count >= self.fail_after {
                Err(std::io::Error::other("Simulated I/O error"))
            } else {
                // Calculate how many bytes we *can* read before hitting the limit or EOF
                let remaining_in_data = self.data.get_ref().len() as u64 - self.data.position();
                let remaining_before_fail = self.fail_after.saturating_sub(self.read_count);
                let max_readable = std::cmp::min(remaining_in_data, remaining_before_fail);
                let bytes_to_read = usize::try_from(std::cmp::min(buf.len() as u64, max_readable))
                    .unwrap_or_else(|_| panic!("bytes_to_read is too large to fit in usize"));

                if bytes_to_read == 0 && remaining_before_fail > 0 {
                    // If we can still read more before failing, but the underlying reader is EOF, return Ok(0)
                    return Ok(0);
                } else if bytes_to_read == 0 && remaining_before_fail == 0 {
                    // If we are exactly at the fail point and can't read more, return the error
                    return Err(std::io::Error::other("Simulated I/O error"));
                }

                let bytes_read = self.data.read(&mut buf[..bytes_to_read])?;
                self.read_count += bytes_read as u64;
                Ok(bytes_read)
            }
        }
    }

    #[test]
    fn test_png_io_error_conversion() {
        // Create valid PNG data first
        let v3_json =
            r#"{ "spec": "chara_card_v3", "spec_version": "3.0", "data": { "name": "IO Test" } }"#;
        let png_data = create_test_png_with_text_chunk(b"ccv3", v3_json);

        // Wrap it in a reader that will fail partway through
        let failing_reader = FailingReader {
            data: Cursor::new(png_data),
            fail_after: 20, // Fail after reading 20 bytes (e.g., during header/chunk reading)
            read_count: 0,
        };

        // Use the png decoder directly with the failing reader
        let decoder = Decoder::new(failing_reader);
        // Reading info might succeed if fail_after is large enough,
        // the error might occur during the actual pixel data reading (which we skip here)
        // or during finish() if chunks are read lazily. Let's try reading info first.
        let read_result = decoder.read_info();

        // Check if read_info itself failed with IO error
        if let Err(png::DecodingError::IoError(io_err)) = read_result {
            let parser_error: ParserError = png::DecodingError::IoError(io_err).into(); // Line 46-47
            match parser_error {
                ParserError::PngError(s) => {
                    assert!(s.contains("Simulated I/O error"));
                }
                _ => panic!("Expected PngError(IoError variant) from read_info"),
            }
        } else if let Ok(mut reader) = read_result {
            // If read_info succeeded, try reading data or finishing
            let mut buffer = vec![0; 10]; // Small buffer
            let data_read_result = reader.next_frame(&mut buffer);
            if let Err(png::DecodingError::IoError(io_err)) = data_read_result {
                let parser_error: ParserError = png::DecodingError::IoError(io_err).into(); // Line 46-47
                match parser_error {
                    ParserError::PngError(s) => {
                        assert!(s.contains("Simulated I/O error"));
                    }
                    _ => panic!("Expected PngError(IoError variant) from next_frame"),
                }
            } else {
                // If reading data also didn't fail (maybe fail_after was too large),
                // the error should be caught by the From impl anyway if an IO error occurred.
                // We still test the direct conversion below.
                // It's hard to guarantee the exact point of failure within the png library.
            }
        } else {
            panic!(
                "Expected Ok or png::DecodingError::IoError from read_info, got {:?}",
                read_result.err()
            );
        }

        // Also test the direct From<std::io::Error>
        let io_error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied test",
        );
        let parser_error_direct: ParserError = io_error.into(); // Line 40-41
        match parser_error_direct {
            ParserError::IoError(s) => assert!(s.contains("Permission denied test")),
            _ => panic!("Expected IoError from direct conversion"),
        }
    }

    // Test for From<ZipError> (Line 64-65)
    #[test]
    fn test_zip_error_conversion() {
        let zip_error = ZipError::FileNotFound;
        let parser_error: ParserError = zip_error.into(); // Line 64-65
        match parser_error {
            ParserError::ZipError(s) => assert!(s.contains("file not found")),
            _ => panic!("Expected ZipError from conversion"),
        }

        let zip_error_other = ZipError::Io(std::io::Error::other("zip io"));
        let parser_error_other: ParserError = zip_error_other.into(); // Line 64-65
        match parser_error_other {
            // Check for the specific lowercase "i/o error" string representation
            ParserError::ZipError(s) => assert!(
                s.contains("i/o error"),
                "Expected ZipError string to contain 'i/o error', got: {s}"
            ),
            _ => panic!("Expected ZipError from conversion"),
        }
    }
}
