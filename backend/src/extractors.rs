// backend/src/extractors.rs
//
// Custom extractors that provide better error responses than Axum's defaults.

use axum::{
    async_trait,
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use serde_json::json;

/// Custom JSON extractor that returns JSON error responses even when deserialization fails.
///
/// Axum's default `Json` extractor returns `text/plain` error responses when deserialization fails,
/// which breaks frontend error handling that expects JSON. This wrapper ensures all errors are
/// returned as JSON with proper content-type headers.
///
/// # Usage
/// ```rust,ignore
/// async fn handler(JsonExtractor(payload): JsonExtractor<MyRequest>) -> Result<impl IntoResponse, AppError> {
///     // Use payload normally
/// }
/// ```
pub struct JsonExtractor<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for JsonExtractor<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonExtractorRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonExtractor(value)),
            Err(rejection) => Err(JsonExtractorRejection(rejection)),
        }
    }
}

/// Rejection type that returns JSON error responses
pub struct JsonExtractorRejection(JsonRejection);

impl IntoResponse for JsonExtractorRejection {
    fn into_response(self) -> Response {
        // Extract the error message from the rejection
        let error_message = self.0.to_string();

        // Determine the appropriate status code based on the rejection type
        let status = match &self.0 {
            JsonRejection::JsonDataError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            JsonRejection::JsonSyntaxError(_) => StatusCode::BAD_REQUEST,
            JsonRejection::MissingJsonContentType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        };

        // Return a JSON error response
        let body = Json(json!({
            "error": format!("Request validation failed: {}", error_message),
            "error_code": "INVALID_REQUEST_BODY",
        }));

        (status, body).into_response()
    }
}
