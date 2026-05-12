use scribe_core::sanitize_personal_info;

#[test]
fn test_pii_stripping_personal_info() {
    let email = "user@example.com";
    let sanitized = sanitize_personal_info(email);
    
    let sanitized_str = sanitized.to_string();
    
    // The sanitized output should NOT contain the raw email
    assert!(!sanitized_str.contains(email));
    
    // It should contain the redaction marker
    assert!(sanitized_str.contains("<personal-info-redacted>"));
}

#[test]
fn test_pii_stripping_multiple_variants() {
    let inputs = vec![
        "admin@scribe.ai",
        "John Doe",
        "123-456-7890",
    ];
    
    for input in inputs {
        let sanitized = sanitize_personal_info(input);
        let sanitized_str = sanitized.to_string();
        
        assert!(!sanitized_str.contains(input), "PII '{}' was not stripped!", input);
        assert!(sanitized_str.contains("<personal-info-redacted>"));
    }
}
