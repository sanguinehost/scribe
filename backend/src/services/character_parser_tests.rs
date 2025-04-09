// This file will contain tests for character_parser.rs 

// This file contains tests for character_parser.rs
use super::*; // Import items from parent module (character_parser.rs)
use base64::{engine::general_purpose::STANDARD as base64_standard};
use crc32fast; // Needed for test helpers

// --- Tests ---

// Helper remains the same
fn create_test_png_with_chara_chunk(json_payload: &str) -> Vec<u8> {
    let base64_payload = base64_standard.encode(json_payload);
    let chunk_keyword = b"chara";
    let chunk_data = base64_payload.as_bytes();

    // Structure: PNG Signature + Dummy IHDR + tEXt chunk + Dummy IDAT + IEND
    let mut png_bytes = Vec::new();

    // PNG Signature
    png_bytes.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]);

    // --- Dummy IHDR chunk (minimal valid: 1x1 pixel, RGBA, etc.) ---
    let ihdr_data = &[0, 0, 0, 1, // Width: 1
                      0, 0, 0, 1, // Height: 1
                      8,          // Bit depth: 8
                      6,          // Color type: 6 (RGBA)
                      0,          // Compression method: 0
                      0,          // Filter method: 0
                      0];         // Interlace method: 0
    let ihdr_len = (ihdr_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&ihdr_len);
    let chunk_type = b"IHDR";
    png_bytes.extend_from_slice(chunk_type);
    png_bytes.extend_from_slice(ihdr_data);
    let crc = crc32fast::hash(&[&chunk_type[..], &ihdr_data[..]].concat());
    png_bytes.extend_from_slice(&crc.to_be_bytes());

    // --- tEXt chunk ('chara' keyword) ---
    let text_chunk_data_internal = [&chunk_keyword[..], &[0u8], &chunk_data[..]].concat();
    let text_chunk_len = (text_chunk_data_internal.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&text_chunk_len);
    let chunk_type_text = b"tEXt";
    png_bytes.extend_from_slice(chunk_type_text);
    png_bytes.extend_from_slice(&text_chunk_data_internal);
    let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
    png_bytes.extend_from_slice(&crc_text.to_be_bytes());

     // --- Dummy IDAT chunk (minimal, 1 pixel transparent) ---
    let idat_data = &[8, 29, 99, 96, 0, 0, 0, 3, 0, 1]; // zlib compressed data for 1 transparent pixel
    let idat_len = (idat_data.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&idat_len);
    let chunk_type_idat = b"IDAT";
    png_bytes.extend_from_slice(chunk_type_idat);
    png_bytes.extend_from_slice(idat_data);
    let crc_idat = crc32fast::hash(&[&chunk_type_idat[..], &idat_data[..]].concat());
    png_bytes.extend_from_slice(&crc_idat.to_be_bytes());

    // --- IEND chunk (End of PNG) ---
    png_bytes.extend_from_slice(&[0, 0, 0, 0]); // Length 0
    png_bytes.extend_from_slice(b"IEND");
    png_bytes.extend_from_slice(&[174, 66, 96, 130]); // CRC for IEND

    png_bytes
}

// Helper to create a minimal valid PNG with a specific tEXt chunk
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
        let crc_text = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal[..]].concat());
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

#[test]
fn test_parse_valid_v2_chara_chunk() {
    let v2_json = r#"{
        "name": "Test V2",
        "description": "A V2 character.",
        "personality": "Friendly",
        "first_mes": "Hi there!",
        "mes_example": "<START>User: Hello\nTest V2: Hi! How are you?<END>",
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
    let card = result.unwrap();

    // Verify V2 fields are parsed correctly (access via .data)
    assert_eq!(card.spec, "chara_card_v2_fallback");
    assert_eq!(card.spec_version, "2.0");
    assert_eq!(card.data.name, Some("Test V2".to_string()));
    assert_eq!(card.data.description, "A V2 character.");
    assert_eq!(card.data.personality, "Friendly");
    assert_eq!(card.data.first_mes, "Hi there!");
    assert_eq!(card.data.mes_example, "<START>User: Hello\nTest V2: Hi! How are you?<END>");
    assert_eq!(card.data.scenario, "A sunny day.");
    assert_eq!(card.data.creator_notes, "Created for testing.");
    assert_eq!(card.data.system_prompt, "System instructions.");
    assert_eq!(card.data.post_history_instructions, "Post history stuff.");
    assert_eq!(card.data.tags, vec!["test".to_string(), "v2".to_string()]);
    assert_eq!(card.data.creator, "Tester");
    assert_eq!(card.data.character_version, "1.0");
    assert_eq!(card.data.alternate_greetings, vec!["Hey!".to_string(), "Greetings!".to_string()]);
    assert!(card.data.extensions.is_empty());

    // V3 specific fields should be None or default (access via .data)
    assert!(card.data.character_book.is_none());
    assert!(card.data.assets.is_none());
    assert!(card.data.nickname.is_none());
    assert!(card.data.creator_notes_multilingual.is_none());
    assert!(card.data.source.is_none());
    assert!(card.data.group_only_greetings.is_empty());
    assert!(card.data.creation_date.is_none());
    assert!(card.data.modification_date.is_none());
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
    assert!(matches!(result, Err(ParserError::ChunkNotFound)), "Expected ChunkNotFound, got {:?}", result);
}

#[test]
fn test_parse_invalid_base64() {
    // Content doesn't matter here
    let invalid_base64_payload = b"this is not base64==";
    let chunk_keyword = b"chara";

    // --- Create PNG structure --- 
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
    // --- tEXt chunk with INVALID base64 ---
    let text_chunk_data_internal = [&chunk_keyword[..], &[0u8], invalid_base64_payload].concat();
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
    
    let result = parse_character_card_png(&png_bytes);
    assert!(matches!(result, Err(ParserError::Base64Error(_))), "Expected Base64Error, got {:?}", result);
}

#[test]
fn test_parse_invalid_json() {
    let invalid_json = "{ name: \"Missing Quotes\" "; // Malformed JSON
    let png_data = create_test_png_with_chara_chunk(invalid_json);

    let result = parse_character_card_png(&png_data);
    assert!(matches!(result, Err(ParserError::JsonError(_))), "Expected JsonError, got {:?}", result);
}

 #[test]
fn test_parse_not_a_png() {
    let not_png_data = b"this is definitely not a png file";

    let result = parse_character_card_png(not_png_data);
    assert!(matches!(result, Err(ParserError::PngError(_))), "Expected PngError, got {:?}", result);
}

#[test]
fn test_parse_valid_v3_ccv3_chunk() {
    let v3_json = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {
            "name": "Test V3",
            "description": "A V3 character.",
            "nickname": "V3",
            "tags": ["test", "v3"]
        }
    }"#;
    let png_data = create_test_png_with_text_chunk(b"ccv3", v3_json);
    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Parsing V3 failed: {:?}", result.err());
    let card = result.unwrap();
    assert_eq!(card.spec, "chara_card_v3");
    assert_eq!(card.spec_version, "3.0");
    assert_eq!(card.data.name, Some("Test V3".to_string()));
    assert_eq!(card.data.nickname, Some("V3".to_string()));
    assert_eq!(card.data.tags, vec!["test".to_string(), "v3".to_string()]);
    // Check defaults for unspecified fields
    assert_eq!(card.data.description, "A V3 character."); // Explicitly provided
    assert_eq!(card.data.personality, ""); // Default empty
    assert_eq!(card.data.first_mes, ""); // Default empty
}

#[test]
fn test_prefer_ccv3_over_chara() {
     let v3_json = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": {"name": "Actual V3 Name"}
    }"#;
    let v2_json = r#"{"name": "Old V2 Name"}"#;

    let png_data = create_test_png_with_multiple_chunks(vec![
        (b"chara", v2_json),
        (b"ccv3", v3_json),
    ]);

    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Parsing preferred V3 failed: {:?}", result.err());
    let card = result.unwrap();
    assert_eq!(card.spec, "chara_card_v3");
    assert_eq!(card.data.name, Some("Actual V3 Name".to_string()));
}

#[test]
fn test_fallback_to_chara_if_ccv3_invalid_json() {
    let invalid_v3_json = r#"{
        "spec": "chara_card_v3",
        "spec_version": "3.0",
        "data": { name: "Invalid JSON" } // Missing quotes
    }"#;
    let v2_json = r#"{"name": "Fallback V2 Name", "description": "From chara"}"#;

    let png_data = create_test_png_with_multiple_chunks(vec![
        (b"ccv3", invalid_v3_json),
        (b"chara", v2_json),
    ]);

    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Fallback to V2 failed: {:?}", result.err());
    let card = result.unwrap();
    assert_eq!(card.spec, "chara_card_v2_fallback");
    assert_eq!(card.data.name, Some("Fallback V2 Name".to_string()));
    assert_eq!(card.data.description, "From chara");
}

 #[test]
fn test_fallback_to_chara_if_ccv3_invalid_spec_field() {
    let wrong_spec_v3_json = r#"{
        "spec": "chara_card_v2", // Intentionally wrong spec
        "spec_version": "3.0",
        "data": {"name": "Wrong Spec V3"}
    }"#;
    let v2_json = r#"{"name": "Fallback V2 Name Again"}"#;

    let png_data = create_test_png_with_multiple_chunks(vec![
        (b"ccv3", wrong_spec_v3_json),
        (b"chara", v2_json),
    ]);

    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Fallback from wrong spec V3 failed: {:?}", result.err());
    let card = result.unwrap();
    assert_eq!(card.spec, "chara_card_v2_fallback");
    assert_eq!(card.data.name, Some("Fallback V2 Name Again".to_string()));
}

#[test]
fn test_fallback_to_chara_if_ccv3_invalid_base64() {
    let invalid_base64_v3 = "not base64 at all ===";
    let v2_json = r#"{"name": "Base64 Fallback V2 Name"}"#;

     // Create PNG with invalid ccv3 base64 and valid chara
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
    // Add invalid ccv3 chunk
    let keyword_ccv3 = b"ccv3";
    let chunk_data_ccv3 = invalid_base64_v3.as_bytes();
    let text_chunk_data_internal_ccv3 = [&keyword_ccv3[..], &[0u8], &chunk_data_ccv3[..]].concat();
    let text_chunk_len_ccv3 = (text_chunk_data_internal_ccv3.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&text_chunk_len_ccv3);
    let chunk_type_text = b"tEXt";
    png_bytes.extend_from_slice(chunk_type_text);
    png_bytes.extend_from_slice(&text_chunk_data_internal_ccv3);
    let crc_text_ccv3 = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal_ccv3[..]].concat());
    png_bytes.extend_from_slice(&crc_text_ccv3.to_be_bytes());
    // Add valid chara chunk
    let keyword_chara = b"chara";
    let base64_payload_chara = base64_standard.encode(v2_json);
    let chunk_data_chara = base64_payload_chara.as_bytes();
    let text_chunk_data_internal_chara = [&keyword_chara[..], &[0u8], &chunk_data_chara[..]].concat();
    let text_chunk_len_chara = (text_chunk_data_internal_chara.len() as u32).to_be_bytes();
    png_bytes.extend_from_slice(&text_chunk_len_chara);
    png_bytes.extend_from_slice(chunk_type_text); // Re-use chunk type name
    png_bytes.extend_from_slice(&text_chunk_data_internal_chara);
    let crc_text_chara = crc32fast::hash(&[&chunk_type_text[..], &text_chunk_data_internal_chara[..]].concat());
    png_bytes.extend_from_slice(&crc_text_chara.to_be_bytes());
    // Dummy IDAT & IEND
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
    assert!(result.is_ok(), "Fallback from bad base64 V3 failed: {:?}", result.err());
    let card = result.unwrap();
    assert_eq!(card.spec, "chara_card_v2_fallback");
    assert_eq!(card.data.name, Some("Base64 Fallback V2 Name".to_string()));
}

#[test]
fn test_error_if_both_invalid() {
     let invalid_v3_json = "{ data: null ";
     let invalid_v2_json = "{ name: Fail }" ;
     let png_data = create_test_png_with_multiple_chunks(vec![
         (b"ccv3", invalid_v3_json),
         (b"chara", invalid_v2_json),
     ]);
     let result = parse_character_card_png(&png_data);
     // Should fail JSON parsing on the chara chunk after failing on ccv3
     assert!(matches!(result, Err(ParserError::JsonError(_))), "Expected JsonError, got {:?}", result);
}

#[test]
fn test_error_if_chara_invalid_base64() {
    let invalid_base64_chara = "not base64";
    let png_data = create_test_png_with_text_chunk(b"chara", invalid_base64_chara);
    let result = parse_character_card_png(&png_data);
    // Should fail JSON parsing on the decoded (but invalid JSON) bytes
    assert!(matches!(result, Err(ParserError::JsonError(_))), "Expected JsonError, got {:?}", result);
} 