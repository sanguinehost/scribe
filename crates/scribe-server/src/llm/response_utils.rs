/// This module provides helpers for parsing and cleaning AI-generated responses.
///
/// Strip markdown code fences from AI-generated JSON responses
///
/// AI models often wrap JSON in markdown code blocks like:
/// ```json
/// { "key": "value" }
/// ```
///
/// This function removes the fences to allow direct JSON parsing.
///
/// # Arguments
/// * `content` - The raw AI response content that may contain markdown fences
///
/// # Returns
/// The content with markdown fences stripped, or the original content if no fences found
///
/// # Examples
/// ```
/// use scribe_backend::llm::response_utils::strip_markdown_fences;
///
/// let fenced = "```json\n{\"name\": \"test\"}\n```";
/// assert_eq!(strip_markdown_fences(fenced), "{\"name\": \"test\"}");
///
/// let plain = "{\"name\": \"test\"}";
/// assert_eq!(strip_markdown_fences(plain), "{\"name\": \"test\"}");
/// ```
pub fn strip_markdown_fences(content: &str) -> &str {
    let trimmed = content.trim();

    // Check for and remove ```json or ``` prefix
    let without_prefix = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed)
        .trim();

    // Remove closing ``` suffix
    without_prefix
        .strip_suffix("```")
        .unwrap_or(without_prefix)
        .trim()
}

/// Extracts the first JSON-like block from a string.
///
/// This is useful when an AI model includes preamble or postamble text
/// around a JSON object. It looks for the first '{' and the last '}'.
///
/// # Arguments
/// * `content` - The raw AI response content
///
/// # Returns
/// Some(&str) containing the JSON block, or None if no braces found
pub fn extract_json_block(content: &str) -> Option<&str> {
    let first_brace = content.find('{')?;
    let last_brace = content.rfind('}')?;

    if first_brace < last_brace {
        Some(&content[first_brace..=last_brace])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_json_fences() {
        let input = "```json\n{\"name\": \"test\"}\n```";
        assert_eq!(strip_markdown_fences(input), "{\"name\": \"test\"}");
    }

    #[test]
    fn test_strip_plain_fences() {
        let input = "```\n{\"name\": \"test\"}\n```";
        assert_eq!(strip_markdown_fences(input), "{\"name\": \"test\"}");
    }

    #[test]
    fn test_no_fences() {
        let input = "{\"name\": \"test\"}";
        assert_eq!(strip_markdown_fences(input), "{\"name\": \"test\"}");
    }

    #[test]
    fn test_multiline_json() {
        let input = "```json\n{\n  \"name\": \"test\",\n  \"value\": 42\n}\n```";
        let expected = "{\n  \"name\": \"test\",\n  \"value\": 42\n}";
        assert_eq!(strip_markdown_fences(input), expected);
    }

    #[test]
    fn test_extra_whitespace() {
        let input = "  ```json  \n  {\"name\": \"test\"}  \n  ```  ";
        assert_eq!(strip_markdown_fences(input), "{\"name\": \"test\"}");
    }

    #[test]
    fn test_extract_json_block() {
        let input = "Here is the JSON:\n{\"name\": \"test\"}\nEnjoy!";
        assert_eq!(extract_json_block(input), Some("{\"name\": \"test\"}"));
    }

    #[test]
    fn test_extract_json_block_multiline() {
        let input = "AI: {\n  \"name\": \"test\"\n} -- end";
        assert_eq!(
            extract_json_block(input),
            Some("{\n  \"name\": \"test\"\n}")
        );
    }

    #[test]
    fn test_extract_json_block_none() {
        let input = "No JSON here";
        assert_eq!(extract_json_block(input), None);
    }
}
