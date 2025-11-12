use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use secureapis::{SecurityLayer, SecurityError, ui::state::RequestLog, core::{SecurityContext, ThreatSeverity}, blocked_requests::BlockedRequest};
use std::sync::Arc;
use uuid;

/// Axum middleware for security layer
#[derive(Clone)]
pub struct AxumSecurityMiddleware {
    security_layer: Arc<SecurityLayer>,
}

impl AxumSecurityMiddleware {
    pub fn new_with_layer(security_layer: Arc<SecurityLayer>) -> Self {
        Self { security_layer }
    }

    pub async fn handle(&self, request: Request, next: Next) -> Response {
        // Extract information from the request
        let client_ip = self.extract_client_ip(&request);
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let user_agent = request.headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        let request_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();

        // Update UI state: increment total requests
        if let Some(ui_state) = self.security_layer.ui_state() {
            ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // 1. Rate limiting check
        if self.security_layer.config().rate_limit.enabled {
            if let Err(error) = self.security_layer.rate_limiter().check(&client_ip).await {
                // Rate limited - store blocked request
                let blocked_request = self.create_blocked_request(
                    &request,
                    request_id.clone(),
                    client_ip.clone(),
                    method.clone(),
                    path.clone(),
                    user_agent.clone(),
                    0, // threat_score
                    error.to_string(),
                    ThreatSeverity::Medium,
                    None, // user_id
                    self.extract_request_payload(&request),
                );
                let _ = self.security_layer.blocked_store().add_blocked_request(blocked_request).await;

                if let Some(ui_state) = self.security_layer.ui_state() {
                    ui_state.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: None,
                        status_code: 429,
                        response_time_ms: 0.0,
                        threat_score: 0.0,
                        blocked: true,
                        reason: Some("Rate limit exceeded".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    let _ = ui_state.add_request_log(log).await;
                }
                return error_response(error);
            }
        }

        // 2. Threat detection (check URI and headers)
        let uri = request.uri().to_string();
        let uri_lower = uri.to_lowercase();
        let mut threat_score = 0;

        // Path traversal attempts
        if uri.contains("../") || uri.contains("..\\") {
            if uri.contains("../../../") || uri.contains("..\\..\\..\\") {
                threat_score += 40;
            }
        }

        // URL-encoded path traversal
        if uri.contains("..%2f") || uri.contains("..%5c") {
            threat_score += 50;
        }

        // XSS attempts
        if uri_lower.contains("<script") || uri_lower.contains("javascript:alert") {
            threat_score += 60;
        }

        // SQL Injection
        if uri_lower.contains("union") && uri_lower.contains("select") {
            threat_score += 60;
        }

        if uri_lower.contains("'; drop") || uri_lower.contains("'; delete") {
            threat_score += 60;
        }

        if uri_lower.contains("' or '1'='1") || uri_lower.contains("1'or'1'='1") {
            threat_score += 60;
        }

        // Check headers for suspicious patterns
        for (header_name, header_value) in request.headers() {
            if let Ok(value_str) = header_value.to_str() {
                let value_lower = value_str.to_lowercase();

                // Suspicious scanning tools
                if header_name == "user-agent" {
                    if value_lower.contains("sqlmap") || value_lower.contains("nikto") ||
                       value_lower.contains("nmap") || value_lower.contains("masscan") ||
                       value_lower.contains("burp") {
                        threat_score += 70;
                    }
                }
            }
        }

        // Block if threat score is high enough
        if threat_score >= 40 {
            // Store blocked request
            let blocked_request = self.create_blocked_request(
                &request,
                request_id.clone(),
                client_ip.clone(),
                method.clone(),
                path.clone(),
                user_agent.clone(),
                threat_score,
                "Threat detected".to_string(),
                ThreatSeverity::High,
                None, // user_id
                self.extract_request_payload(&request),
            );
            let _ = self.security_layer.blocked_store().add_blocked_request(blocked_request).await;

            if let Some(ui_state) = self.security_layer.ui_state() {
                ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let log = RequestLog {
                    id: request_id.clone(),
                    timestamp,
                    method: method.clone(),
                    path: path.clone(),
                    client_ip: client_ip.clone(),
                    user_agent: user_agent.clone(),
                    user_id: None,
                    status_code: 403,
                    response_time_ms: 0.0,
                    threat_score: threat_score as f64,
                    blocked: true,
                    reason: Some("Threat detected".to_string()),
                    headers: std::collections::HashMap::new(),
                };
                let _ = ui_state.add_request_log(log).await;
            }
            return error_response(SecurityError::ThreatDetected {
                threat_type: "Suspicious request pattern".to_string(),
                severity: secureapis::core::ThreatSeverity::High,
            });
        }

        // Success: add successful request log
        if let Some(ui_state) = self.security_layer.ui_state() {
            let log = RequestLog {
                id: request_id.clone(),
                timestamp,
                method,
                path,
                client_ip,
                user_agent,
                user_id: None,
                status_code: 200,
                response_time_ms: 0.0,
                threat_score: threat_score as f64,
                blocked: false,
                reason: None,
                headers: std::collections::HashMap::new(),
            };
            let _ = ui_state.add_request_log(log).await;
        }

        next.run(request).await
    }

    fn extract_client_ip(&self, request: &Request) -> String {
        // Try X-Forwarded-For, X-Real-IP, or connection IP
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or("unknown")
            .to_string()
    }

    fn extract_request_payload<B>(&self, request: &Request<B>) -> Option<String>
    where
        B: std::fmt::Debug,
    {
        // Try to extract payload from request body
        // Note: This is a simplified version. In a real implementation,
        // you'd need to handle different body types properly
        let body_str = format!("{:?}", request.body());
        if body_str.len() > 2 && body_str != "()" { // Filter out empty bodies
            Some(body_str)
        } else {
            None
        }
    }

    fn create_blocked_request<B>(
        &self,
        request: &Request<B>,
        id: String,
        client_ip: String,
        method: String,
        path: String,
        user_agent: String,
        threat_score: u32,
        block_reason: String,
        severity: ThreatSeverity,
        user_id: Option<String>,
        payload: Option<String>,
    ) -> BlockedRequest
    where
        B: std::fmt::Debug,
    {
        let headers: std::collections::HashMap<String, String> = request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
            })
            .collect();

        // Calculate request size (headers + body approximation)
        let header_size = headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
        let body_size = payload.as_ref().map(|p| p.len()).unwrap_or(0);
        let request_size = header_size + body_size;

        BlockedRequest {
            id,
            timestamp: chrono::Utc::now(),
            client_ip,
            user_agent,
            method,
            url: request.uri().to_string(),
            headers,
            payload,
            threat_score,
            block_reason,
            severity,
            user_id,
            request_size,
        }
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
    fn with_security_layer(self, security_layer: Arc<SecurityLayer>) -> Self;
}

impl SecurityRouterExt for axum::Router {
    fn with_security_layer(self, security_layer: Arc<SecurityLayer>) -> Self {
        self.layer(axum::middleware::from_fn(move |req, next| {
            let security_layer = security_layer.clone();
            async move {
                AxumSecurityMiddleware::new_with_layer(security_layer).handle(req, next).await
            }
        }))
    }
}
