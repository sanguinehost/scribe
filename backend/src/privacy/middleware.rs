use crate::privacy::{PrivacyConfig, PrivacyContext};
use axum::{extract::Request, http::HeaderMap, middleware::Next, response::Response};
use std::sync::Arc;
use tracing::{Instrument, info_span};

/// Request extension key for privacy context
#[derive(Clone)]
pub struct PrivacyContextExtension(pub Arc<PrivacyContext>);

/// Privacy middleware that injects privacy context into each request
pub async fn privacy_middleware(_headers: HeaderMap, mut request: Request, next: Next) -> Response {
    let privacy_config = PrivacyConfig::default();
    let privacy_context = Arc::new(PrivacyContext::new(privacy_config));

    // Get the request ID for correlation
    let request_id = privacy_context.request_id().to_string();

    // Insert privacy context into request extensions
    request
        .extensions_mut()
        .insert(PrivacyContextExtension(privacy_context.clone()));

    // Create a span with the request ID for correlation
    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
    );

    async move {
        // Process the request
        let response = next.run(request).await;

        // Log request completion (without any PII)
        tracing::debug!(
            request_id = %request_id,
            status = %response.status(),
            "Request completed"
        );

        response
    }
    .instrument(span)
    .await
}

/// Extension trait for extracting privacy context from request
pub trait RequestPrivacyExt {
    /// Get the privacy context from this request
    fn privacy_context(&self) -> Option<Arc<PrivacyContext>>;
}

impl RequestPrivacyExt for Request {
    fn privacy_context(&self) -> Option<Arc<PrivacyContext>> {
        self.extensions()
            .get::<PrivacyContextExtension>()
            .map(|ext| ext.0.clone())
    }
}

/// Axum extractor for privacy context
#[derive(Debug, Clone)]
pub struct ExtractPrivacyContext(pub Arc<PrivacyContext>);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for ExtractPrivacyContext
where
    S: Send + Sync,
{
    type Rejection = axum::http::StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<PrivacyContextExtension>()
            .map(|ext| Self(ext.0.clone()))
            .ok_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Method},
        routing::get,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_privacy_middleware_injection() {
        async fn handler(privacy: ExtractPrivacyContext) -> String {
            format!("Request ID: {}", privacy.0.request_id())
        }

        let app = Router::new()
            .route("/test", get(handler))
            .layer(axum::middleware::from_fn(privacy_middleware));

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();

        assert!(body_str.starts_with("Request ID: "));
        assert!(body_str.len() > 12); // Should have some request ID
    }
}
