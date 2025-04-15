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
#[cfg(test)]
#[path = "character_parser_tests.rs"]
mod tests;

// Test module removed from here
