// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright The Lance Authors

use std::sync::Arc;
use std::vec;

use lance_arrow::json::{is_arrow_json_field, json_field, JsonArray};

use arrow_array::{Int32Array, RecordBatch, RecordBatchIterator};
use arrow_schema::{DataType, Field as ArrowField, Schema as ArrowSchema};

use crate::Dataset;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn test_scan_limit_offset_preserves_json_extension_metadata() {
    let schema = Arc::new(ArrowSchema::new(vec![
        ArrowField::new("id", DataType::Int32, false),
        json_field("meta", true),
    ]));

    let json_array = JsonArray::try_from_iter((0..50).map(|i| Some(format!(r#"{{"i":{i}}}"#))))
        .unwrap()
        .into_inner();
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from_iter_values(0..50)),
            Arc::new(json_array),
        ],
    )
    .unwrap();

    let reader = RecordBatchIterator::new(vec![Ok(batch)], schema.clone());
    let dataset = Dataset::write(reader, "memory://", None).await.unwrap();

    let mut scanner = dataset.scan();
    scanner.limit(Some(10), None).unwrap();
    let batch_no_offset = scanner.try_into_batch().await.unwrap();
    assert!(is_arrow_json_field(
        batch_no_offset.schema().field_with_name("meta").unwrap()
    ));

    let mut scanner = dataset.scan();
    scanner.limit(Some(10), Some(10)).unwrap();
    let batch_with_offset = scanner.try_into_batch().await.unwrap();
    assert!(is_arrow_json_field(
        batch_with_offset.schema().field_with_name("meta").unwrap()
    ));
    assert_eq!(batch_no_offset.schema(), batch_with_offset.schema());
}
