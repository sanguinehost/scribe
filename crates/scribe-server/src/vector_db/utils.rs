use qdrant_client::qdrant::Value as QdrantValue;
use serde_json::Value as JsonValue;

/// Converts a Qdrant Value to a Serde JSON Value
pub fn qdrant_value_to_serde_json(value: QdrantValue) -> JsonValue {
    match value.kind {
        Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => JsonValue::String(s),
        Some(qdrant_client::qdrant::value::Kind::DoubleValue(d)) => serde_json::Number::from_f64(d)
            .map(JsonValue::Number)
            .unwrap_or(JsonValue::Null),
        Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) => JsonValue::Number(i.into()),
        Some(qdrant_client::qdrant::value::Kind::BoolValue(b)) => JsonValue::Bool(b),
        Some(qdrant_client::qdrant::value::Kind::StructValue(s)) => {
            let mut map = serde_json::Map::new();
            for (k, v) in s.fields {
                map.insert(k, qdrant_value_to_serde_json(v));
            }
            JsonValue::Object(map)
        }
        Some(qdrant_client::qdrant::value::Kind::ListValue(l)) => JsonValue::Array(
            l.values
                .into_iter()
                .map(qdrant_value_to_serde_json)
                .collect(),
        ),
        Some(qdrant_client::qdrant::value::Kind::NullValue(_)) | None => JsonValue::Null,
    }
}
