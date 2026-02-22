import sys

with open('backend/src/llm/rig_client.rs', 'r') as f:
    content = f.read()

# Fix ReasoningContent extraction for struct variant
target1 = "Some(r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text(t) => t.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\"))"
replacement1 = "Some(r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text { text, .. } => text.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\"))"

target2 = "let reasoning_text = r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text(t) => t.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\");"
replacement2 = "let reasoning_text = r.content.iter().map(|c| match c { rig::message::ReasoningContent::Text { text, .. } => text.clone(), _ => \"\".to_string() }).collect::<Vec<_>>().join(\"\");"

content = content.replace(target1, replacement1)
content = content.replace(target2, replacement2)

with open('backend/src/llm/rig_client.rs', 'w') as f:
    f.write(content)
