use crate::IntelligenceError;

pub struct SecuritySandbox;

impl SecuritySandbox {
    /// Sandboxes user content by ensuring it doesn't contain common prompt injection patterns.
    /// This is a basic implementation and should be extended with more robust checks.
    pub fn validate_context(content: &str) -> Result<(), IntelligenceError> {
        let lower_content = content.to_lowercase();
        
        // Common injection patterns
        let blacklisted_patterns = [
            "ignore all previous instructions",
            "system prompt:",
            "you are now a",
            "forget everything you were told",
            "new role:",
            "override:",
        ];

        for pattern in blacklisted_patterns {
            if lower_content.contains(pattern) {
                return Err(IntelligenceError::PromptInjectionDetected);
            }
        }

        Ok(())
    }

    /// Wraps user content in a way that clearly demarcates it for the LLM.
    pub fn sanitize_and_wrap(content: &str) -> String {
        format!("<user_context>\n{}\n</user_context>", content)
    }
}
