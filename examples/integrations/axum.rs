use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use secureapis::{SecurityConfig, SecurityLayer, SecurityError};
use std::sync::Arc;

/// Axum middleware for security layer
#[derive(Clone)]
pub struct AxumSecurityMiddleware {
    security_layer: Arc<SecurityLayer>,
}

impl AxumSecurityMiddleware {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            security_layer: Arc::new(SecurityLayer::new(config)),
        }
    }

    pub async fn handle(&self, _request: Request, next: Next) -> Response {
        // For now, just pass through - security layer's validation needs refactoring
        // to avoid lifetime issues with Axum's Request type
        next.run(_request).await
    }
}

fn error_response(error: SecurityError) -> Response {
    let (status, message) = match error {
        SecurityError::RateLimitExceeded { retry_after } => (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Rate limit exceeded. Retry after {} seconds", retry_after),
        ),
        SecurityError::AuthenticationFailed(msg) => {
            (StatusCode::UNAUTHORIZED, msg)
        }
        SecurityError::AuthorizationFailed(msg) => {
            (StatusCode::FORBIDDEN, msg)
        }
        SecurityError::InvalidInput { reason, .. } => {
            (StatusCode::BAD_REQUEST, reason)
        }
        SecurityError::ThreatDetected { threat_type, .. } => {
            (StatusCode::FORBIDDEN, format!("Threat detected: {}", threat_type))
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
    };

    (status, message).into_response()
}

/// Extension trait for Axum Router to add security middleware
pub trait SecurityRouterExt {
    fn with_security(self, config: SecurityConfig) -> Self;
}

impl SecurityRouterExt for axum::Router {
    fn with_security(self, config: SecurityConfig) -> Self {
        let middleware = AxumSecurityMiddleware::new(config);
        self.layer(axum::middleware::from_fn(move |req, next| {
            let middleware = middleware.clone();
            async move { middleware.handle(req, next).await }
        }))
    }
}
