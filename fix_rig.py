import sys

with open('backend/src/llm/rig_client.rs', 'r') as f:
    content = f.read()

# Gemini completion
target1 = """                let completion_req = rig::completion::CompletionRequest {
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                };"""

replacement1 = """                let completion_req = rig::completion::CompletionRequest {
                    model: model_name.to_string(),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                    output_schema: None,
                };"""

# MistralRs completion (same target, different replacement)
replacement2 = """                let completion_req = rig::completion::CompletionRequest {
                    model: req.model_name.clone(),
                    preamble: req.preamble,
                    chat_history,
                    documents: vec![],
                    tools: vec![],
                    temperature: req.temperature,
                    max_tokens: req.max_tokens.map(|t| t as u64),
                    additional_params: if additional_params.is_empty() {
                        None
                    } else {
                        Some(serde_json::Value::Object(additional_params))
                    },
                    tool_choice: None,
                    output_schema: None,
                };"""

# We need to find the specific instances because they are non-unique
parts = content.split(target1)
if len(parts) != 4:
    print(f"Error: Found {len(parts)-1} instances of target, expected 3")
    sys.exit(1)

new_content = parts[0] + replacement1 + parts[1] + replacement2 + parts[2] + replacement1 + parts[3]

with open('backend/src/llm/rig_client.rs', 'w') as f:
    f.write(new_content)
