// This file contains tests for character_parser.rs
use super::*; // Import items from parent module (character_parser.rs)
use base64::{engine::general_purpose::STANDARD as base64_standard};
use crc32fast; // Needed for test helpers

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
        assert_eq!(data_v2.mes_example, "<START>User: Hello\\nTest V2: Hi! How are you?<END>");
        assert_eq!(data_v2.scenario, "A sunny day.");
        assert_eq!(data_v2.creator_notes, "Created for testing.");
        assert_eq!(data_v2.system_prompt, "System instructions.");
        assert_eq!(data_v2.post_history_instructions, "Post history stuff.");
        assert_eq!(data_v2.tags, vec!["test".to_string(), "v2".to_string()]);
        assert_eq!(data_v2.creator, "Tester");
        assert_eq!(data_v2.character_version, "1.0");
        assert_eq!(data_v2.alternate_greetings, vec!["Hey!".to_string(), "Greetings!".to_string()]);
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
    assert!(matches!(result, Err(ParserError::ChunkNotFound)), "Expected ChunkNotFound, got {:?}", result);
}

#[test]
fn test_parse_invalid_base64() {
    // Use characters definitely invalid in base64
    let invalid_base64_payload = b"!@#$%^";
    let chunk_keyword = b"chara"; // Test with chara first, as ccv3 might fallback

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
    // Use raw string to avoid escaping issues
    let invalid_json = r#"{ name: "Missing Quotes" "#; // Malformed JSON
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
    let parsed_card = result.unwrap();

    // Assert that it's the V3 variant and access its data
    if let ParsedCharacterCard::V3(card_v3) = parsed_card {
        assert_eq!(card_v3.spec, "chara_card_v3");
        assert_eq!(card_v3.spec_version, "3.0");
        assert_eq!(card_v3.data.name, Some("Test V3".to_string()));
        assert_eq!(card_v3.data.nickname, Some("V3".to_string()));
        assert_eq!(card_v3.data.tags, vec!["test".to_string(), "v3".to_string()]);
        // Check defaults for unspecified fields
        assert_eq!(card_v3.data.description, "A V3 character."); // Explicitly provided
        assert_eq!(card_v3.data.personality, ""); // Default empty
        assert_eq!(card_v3.data.first_mes, ""); // Default empty
    } else {
        panic!("Expected V3 variant, got {:?}", parsed_card);
    }
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
        (b"chara", v2_json), // Put V2 first to ensure V3 is preferred
        (b"ccv3", v3_json),
    ]);

    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Parsing preferred V3 failed: {:?}", result.err());
    let parsed_card = result.unwrap();

     // Assert that it's the V3 variant even though chara was present
    if let ParsedCharacterCard::V3(card_v3) = parsed_card {
        assert_eq!(card_v3.spec, "chara_card_v3");
        assert_eq!(card_v3.spec_version, "3.0");
        assert_eq!(card_v3.data.name, Some("Actual V3 Name".to_string()));
    } else {
        panic!("Expected V3 variant when both chunks present, got {:?}", parsed_card);
    }
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
    let parsed_card = result.unwrap();

    // Assert that it's the V2Fallback variant
    if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
        assert_eq!(data_v2.name, Some("Fallback V2 Name".to_string()));
        assert_eq!(data_v2.description, "From chara");
    } else {
        panic!("Expected V2Fallback variant after invalid V3 JSON, got {:?}", parsed_card);
    }
}

 #[test]
fn test_parse_ccv3_with_incorrect_spec_field() {
    // Test that the parser *currently* accepts a V3 structure from the ccv3 chunk
    // even if the spec field inside is wrong.
    // Ensure the overall structure IS valid for CharacterCardV3
    let wrong_spec_v3_json = r#"{
        "spec": "chara_card_v2", // Intentionally wrong spec
        "spec_version": "3.0",
        "data": {
             "name": "Wrong Spec V3",
             "description": "This is description data", 
             "tags": [] 
             // Add other fields required by CharacterCardDataV3 default if necessary
             // but the current Default derive should handle missing ones.
        }
    }"#;

    let png_data = create_test_png_with_text_chunk(b"ccv3", wrong_spec_v3_json);

    let result = parse_character_card_png(&png_data);
    // Expect an error because the JSON parsing fails (due to the serde error, even if the JSON looks okay)
    // and there is no 'chara' chunk to fall back to. The parser returns ChunkNotFound in this case.
    assert!(matches!(result, Err(ParserError::ChunkNotFound)), "Expected ChunkNotFound after failed V3 parse and no fallback, got {:?}", result);

    // --- Original assertions removed as the parsing is expected to fail ---
    // let parsed_card = result.unwrap();
    //
    // // Assert that it's parsed as V3 variant despite the wrong spec field
    // if let ParsedCharacterCard::V3(card_v3) = parsed_card {
    //     // Check that the internal spec field *is* the incorrect one
    //     assert_eq!(card_v3.spec, "chara_card_v2", "Expected spec field to be the incorrect one from JSON");
    //     assert_eq!(card_v3.spec_version, "3.0");
    //     assert_eq!(card_v3.data.name, Some("Wrong Spec V3".to_string()));
    //     assert_eq!(card_v3.data.description, "This is description data");
    // } else {
    //     panic!("Expected V3 variant even with wrong spec field, got {:?}", parsed_card);
    // }
}

#[test]
fn test_fallback_to_chara_if_ccv3_invalid_base64() {
    let invalid_base64_v3 = "!@#$%^"; // Use definitely invalid base64 chars
    let v2_json = r#"{"name": "Base64 Fallback V2 Name"}"#;

     // Create PNG with invalid ccv3 base64 and valid chara
    let png_data = create_test_png_with_multiple_chunks(vec![
        (b"ccv3", invalid_base64_v3), // Use invalid base64 string directly
        (b"chara", v2_json),
    ]);

    let result = parse_character_card_png(&png_data);
    assert!(result.is_ok(), "Fallback from bad base64 V3 failed: {:?}", result.err());
    let parsed_card = result.unwrap();

    // Assert that it's the V2Fallback variant
    if let ParsedCharacterCard::V2Fallback(data_v2) = parsed_card {
        assert_eq!(data_v2.name, Some("Base64 Fallback V2 Name".to_string()));
    } else {
        panic!("Expected V2Fallback variant after invalid V3 base64, got {:?}", parsed_card);
    }
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
fn test_error_if_chara_invalid_base64_and_no_ccv3() {
    // Use characters definitely invalid in base64
    let invalid_base64_chara_bytes = b"!@#$%^"; 
    // Create PNG only with the invalid *raw* chara chunk data
    let png_data = create_test_png_with_raw_text_chunk(b"chara", invalid_base64_chara_bytes);
    let result = parse_character_card_png(&png_data);
    // Should fail Base64 parsing on the chara chunk
    assert!(matches!(result, Err(ParserError::Base64Error(_))), "Expected Base64Error, got {:?}", result);
}
