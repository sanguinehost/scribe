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

// --- Main Parsing Function ---

pub fn parse_character_card_png(png_data: &[u8]) -> Result<CharacterCardV3, ParserError> {
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
    // Note: The png crate gives these as Latin-1 strings by default for tEXt.
    // We assume the base64 content itself will be ASCII-compatible.
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
                        if card.spec == "chara_card_v3" {
                            return Ok(card); // Successfully parsed V3
                        } else {
                             println!("Warning: Found 'ccv3' chunk but 'spec' field is not 'chara_card_v3'. Falling back to 'chara' if possible.");
                        }
                    }
                    Err(e) => {
                         println!("Warning: Failed to parse JSON from 'ccv3' chunk: {}. Falling back to 'chara' if possible.", e);
                    }
                }
            }
            Err(e) => {
                 println!("Warning: Failed to decode base64 from 'ccv3' chunk: {}. Falling back to 'chara' if possible.", e);
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
                        return Ok(CharacterCardV3 {
                            spec: "chara_card_v2_fallback".to_string(), // Indicate it's a fallback
                            spec_version: "2.0".to_string(), // Indicate V2 origin
                            data: data_v2,
                        });
                    }
                    Err(e) => {
                         return Err(ParserError::JsonError(e));
                    }
                 }
            }
             Err(e) => {
                 return Err(ParserError::Base64Error(e));
             }
        }
    }

    Err(ParserError::ChunkNotFound)
}

// Declare the test module
#[cfg(test)]
#[path = "character_parser_tests.rs"]
mod tests;

// Test module removed from here 