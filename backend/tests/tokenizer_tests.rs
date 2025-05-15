use scribe_backend::services::tokenizer_service::TokenizerService;
use std::path::PathBuf;

#[test]
fn test_gemma_tokenizer_integration() {
    // Path to the Gemma model file
    let model_path = PathBuf::from("/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model");
    
    // Create a tokenizer instance
    let tokenizer = TokenizerService::new(model_path).expect("Failed to create tokenizer");
    
    // Test basic tokenizer functionality
    assert!(tokenizer.vocab_size() > 0, "Tokenizer should have a non-zero vocabulary size");
    assert_eq!(tokenizer.model_name(), "gemma.model", "Model name should match");
    
    // Test encoding and decoding
    let test_texts = vec![
        "Hello, world!",
        "This is a test of the tokenizer.",
        "Gemma is a family of lightweight, state-of-the-art open models from Google.",
        "特殊字符和多语言支持测试。", // Test multilingual support
        "1234567890!@#$%^&*()", // Test numbers and special characters
    ];
    
    for text in test_texts {
        println!("Testing text: '{}'", text);
        
        // Encode text to token IDs
        let token_ids = tokenizer.encode(text).expect("Failed to encode text");
        println!("  Token IDs: {:?}", token_ids);
        println!("  Token count: {}", token_ids.len());
        
        // Ensure non-empty token sequence
        assert!(!token_ids.is_empty(), "Token IDs should not be empty");
        
        // Decode token IDs back to text
        let decoded_text = tokenizer.decode(&token_ids).expect("Failed to decode tokens");
        println!("  Decoded text: '{}'", decoded_text);
        
        // The round-trip text might not match exactly due to tokenization nuances,
        // but should contain the core content
        for word in text.split_whitespace() {
            if word.len() > 3 {  // Only check significant words (longer than 3 chars)
                assert!(
                    decoded_text.contains(word) || 
                    // Handle potential partial matches for CJK characters
                    (word.chars().any(|c| c as u32 > 0x4E00) && word.chars().any(|c| decoded_text.contains(c.to_string().as_str()))),
                    "Decoded text '{}' should contain the word '{}'", 
                    decoded_text, 
                    word
                );
            }
        }
        
        // Test token counting
        let count = tokenizer.count_tokens(text).expect("Failed to count tokens");
        assert_eq!(count, token_ids.len(), "Token count should match encoded token length");
    }
    
    // Test handling of special tokens
    println!("Testing special tokens:");
    println!("  BOS token ID: {:?}", tokenizer.bos_id());
    println!("  EOS token ID: {:?}", tokenizer.eos_id());
    println!("  PAD token ID: {:?}", tokenizer.pad_id());
    println!("  UNK token ID: {}", tokenizer.unk_id());
    
    // Test that unknown token ID is available (required for handling OOV words)
    assert!(tokenizer.unk_id() > 0, "UNK token ID should be defined");
}