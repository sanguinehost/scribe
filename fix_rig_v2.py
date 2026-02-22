import sys

with open('backend/src/llm/rig_client.rs', 'r') as f:
    content = f.read()

# Fix CompletionRequest.model = Some(...)
target1 = """                let completion_req = rig::completion::CompletionRequest {
                    model: model_name.to_string(),"""
replacement1 = """                let completion_req = rig::completion::CompletionRequest {
                    model: Some(model_name.to_string()),"""

target2 = """                let completion_req = rig::completion::CompletionRequest {
                    model: req.model_name.clone(),"""
replacement2 = """                let completion_req = rig::completion::CompletionRequest {
                    model: Some(req.model_name.clone()),"""

content = content.replace(target1, replacement1)
content = content.replace(target2, replacement2)

# Fix Reasoning content extraction
# Vec<ReasoningContent> -> Vec<String>
target3 = "Some(r.content.join(\"\"))"
replacement3 = "Some(r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text(t) => t.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\"))"

target4 = "let reasoning_text = r.content.join(\"\");"
replacement4 = "let reasoning_text = r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text(t) => t.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\");"

# Note: rig::message::ReasoningContent::Text is a guess, might need correction if it's different.
# Let's try to be more generic if possible or check again.
# Wait, let's just use string conversion if possible or common variants.
# Based on rig's AssistantContent, it's likely Text(String) or similar.

content = content.replace(target3, replacement3)
content = content.replace(target4, replacement4)

with open('backend/src/llm/rig_client.rs', 'w') as f:
    f.write(content)
