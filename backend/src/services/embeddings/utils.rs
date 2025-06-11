use crate::errors::AppError;
use qdrant_client::qdrant::Value as QdrantValue;
use std::collections::HashMap;
use uuid::Uuid;

/// Extracts a string value from Qdrant payload
pub fn extract_string_from_payload(
    payload: &HashMap<String, QdrantValue>,
    field_name: &str,
    context: &str,
) -> Result<String, AppError> {
    payload
        .get(field_name)
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            AppError::SerializationError(format!(
                "Missing or invalid '{field_name}' in {context} payload"
            ))
        })
}

/// Extracts a UUID from Qdrant payload
pub fn extract_uuid_from_payload(
    payload: &HashMap<String, QdrantValue>,
    field_name: &str,
    context: &str,
) -> Result<Uuid, AppError> {
    let uuid_str = extract_string_from_payload(payload, field_name, context)?;
    Uuid::parse_str(&uuid_str).map_err(|e| {
        AppError::SerializationError(format!(
            "Failed to parse '{field_name}' as UUID in {context}: {e}"
        ))
    })
}

/// Extracts an optional string from Qdrant payload
pub fn extract_optional_string_from_payload(
    payload: &HashMap<String, QdrantValue>,
    field_name: &str,
) -> Option<String> {
    payload
        .get(field_name)
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
            _ => None,
        })
}

/// Extracts a string list from Qdrant payload
pub fn extract_string_list_from_payload(
    payload: &HashMap<String, QdrantValue>,
    field_name: &str,
    context: &str,
) -> Result<Option<Vec<String>>, AppError> {
    let result = payload
        .get(field_name)
        .and_then(|v| v.kind.as_ref())
        .map(|k| match k {
            qdrant_client::qdrant::value::Kind::ListValue(list_val) => {
                let mut strings = Vec::new();
                for item_val in &list_val.values {
                    if let Some(qdrant_client::qdrant::value::Kind::StringValue(s)) =
                        item_val.kind.as_ref()
                    {
                        strings.push(s.clone());
                    } else {
                        return Err(AppError::SerializationError(format!(
                            "Non-string value found in '{field_name}' list in {context} payload"
                        )));
                    }
                }
                Ok(strings)
            }
            _ => Ok(Vec::new()),
        });

    match result {
        Some(Ok(list)) if list.is_empty() => Ok(None),
        Some(Ok(list)) => Ok(Some(list)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Extracts a boolean from Qdrant payload
pub fn extract_bool_from_payload(
    payload: &HashMap<String, QdrantValue>,
    field_name: &str,
    context: &str,
) -> Result<bool, AppError> {
    payload
        .get(field_name)
        .and_then(|v| v.kind.as_ref())
        .and_then(|k| match k {
            qdrant_client::qdrant::value::Kind::BoolValue(b) => Some(*b),
            _ => None,
        })
        .ok_or_else(|| {
            AppError::SerializationError(format!(
                "Missing or invalid '{field_name}' in {context} payload"
            ))
        })
}

// Implement conversion from Qdrant payload for ChatMessageChunkMetadata
