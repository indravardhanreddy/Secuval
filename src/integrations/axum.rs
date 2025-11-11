use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use secureapis::{SecurityConfig, SecurityLayer};
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

    pub async fn handle(&self, request: Request, next: Next) -> Response {
        // Process request through security layer
        match self.security_layer.process_request(&request).await {
            Ok(_context) => {
                // Request is valid, continue to next handler
                next.run(request).await
            }
            Err(error) => {
                // Security check failed, return error response
                let (status, message) = match error {
                    secureapis::SecurityError::RateLimitExceeded { retry_after } => (
                        StatusCode::TOO_MANY_REQUESTS,
                        format!("Rate limit exceeded. Retry after {} seconds", retry_after),
                    ),
                    secureapis::SecurityError::AuthenticationFailed(msg) => {
                        (StatusCode::UNAUTHORIZED, msg)
                    }
                    secureapis::SecurityError::AuthorizationFailed(msg) => {
                        (StatusCode::FORBIDDEN, msg)
                    }
                    secureapis::SecurityError::InvalidInput { reason, .. } => {
                        (StatusCode::BAD_REQUEST, reason)
                    }
                    secureapis::SecurityError::ThreatDetected { threat_type, .. } => {
                        (StatusCode::FORBIDDEN, format!("Threat detected: {}", threat_type))
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
                };

                (status, message).into_response()
            }
        }
    }
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
