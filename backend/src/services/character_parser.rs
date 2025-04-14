// backend/src/services/character_parser.rs

use crate::models::character_card::{CharacterCardDataV3, CharacterCardV3};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use png::Decoder;
use serde_json;
use std::io::Cursor;
use thiserror::Error; // Import the derive macro

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

    // --- Prioritize ccv3 ---
    if let Some(base64_str) = ccv3_data_base64 {
        match base64_standard.decode(&base64_str) {
            Ok(decoded_bytes) => {
                match serde_json::from_slice::<CharacterCardV3>(&decoded_bytes) {
                    Ok(card) => {
                        // Accept if spec is explicitly V3 or if spec is missing/different
                        // but the structure matches CharacterCardV3 based on the 'ccv3' chunk.
                        // We wrap it in ParsedCharacterCard::V3
                        return Ok(ParsedCharacterCard::V3(card));
                    }
                    Err(e) => {
                         println!("Warning: Failed to parse JSON from 'ccv3' chunk as CharacterCardV3: {}. Falling back to 'chara' if possible.", e);
                         // Don't return error yet, try fallback
                    }
                }
            }
            Err(e) => {
                 println!("Warning: Failed to decode base64 from 'ccv3' chunk: {}. Falling back to 'chara' if possible.", e);
                 // Don't return error yet, try fallback
            }
        }
    }

    // --- Fallback to chara ---
    if let Some(base64_str) = chara_data_base64 {
        match base64_standard.decode(&base64_str) {
            Ok(decoded_bytes) => {
                 match serde_json::from_slice::<CharacterCardDataV3>(&decoded_bytes) {
                     Ok(data_v2) => {
                         println!("Info: Loaded character from V2 'chara' chunk.");
                         // Return the V2 data wrapped in the V2Fallback variant
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

// Declare the test module
#[cfg(test)]
#[path = "character_parser_tests.rs"]
mod tests;

// Test module removed from here
