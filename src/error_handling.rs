use crate::core::SecurityError;
use serde::Serialize;

/// Error response with sanitization to prevent information disclosure
#[derive(Debug, Clone, Serialize)]
pub struct SafeErrorResponse {
    pub error: String,
    pub code: String,
    pub timestamp: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl SafeErrorResponse {
    /// Create a safe error response that doesn't leak information
    pub fn from_security_error(
        error: &SecurityError,
        request_id: String,
        include_details: bool,
    ) -> Self {
        let (error_msg, code, details) = match error {
            SecurityError::RateLimitExceeded { .. } => (
                "Rate limit exceeded".to_string(),
                "RATE_LIMIT_EXCEEDED".to_string(),
                Some("Too many requests. Please try again later.".to_string()),
            ),
            SecurityError::AuthenticationFailed(_) => (
                "Authentication failed".to_string(),
                "AUTH_FAILED".to_string(),
                Some("Invalid or missing authentication credentials.".to_string()),
            ),
            SecurityError::AuthorizationFailed(_) => (
                "Forbidden".to_string(),
                "FORBIDDEN".to_string(),
                Some("You do not have permission to access this resource.".to_string()),
            ),
            SecurityError::InvalidInput { .. } => (
                "Bad request".to_string(),
                "BAD_REQUEST".to_string(),
                Some("The request contains invalid data.".to_string()),
            ),
            SecurityError::ThreatDetected { .. } => (
                "Request blocked".to_string(),
                "THREAT_DETECTED".to_string(),
                Some("Your request was blocked due to suspicious activity.".to_string()),
            ),
            SecurityError::ConfigError(_) => (
                "Internal server error".to_string(),
                "INTERNAL_ERROR".to_string(),
                None,
            ),
            SecurityError::InternalError(_) => (
                "Internal server error".to_string(),
                "INTERNAL_ERROR".to_string(),
                None,
            ),
            SecurityError::CorsViolation(_) => (
                "CORS policy violation".to_string(),
                "CORS_VIOLATION".to_string(),
                Some("This request does not meet the CORS policy requirements.".to_string()),
            ),
            SecurityError::CsrfViolation(_) => (
                "CSRF validation failed".to_string(),
                "CSRF_FAILED".to_string(),
                Some("CSRF token validation failed.".to_string()),
            ),
            SecurityError::HttpsRequired => (
                "HTTPS required".to_string(),
                "HTTPS_REQUIRED".to_string(),
                Some("This endpoint requires a secure HTTPS connection.".to_string()),
            ),
            SecurityError::TransportLayerViolation(_) => (
                "Transport layer violation".to_string(),
                "TRANSPORT_VIOLATION".to_string(),
                Some("The request does not meet security requirements.".to_string()),
            ),
            SecurityError::IpBlocked(_) => (
                "Access denied".to_string(),
                "IP_BLOCKED".to_string(),
                Some("Your IP address does not have access to this resource.".to_string()),
            ),
            SecurityError::VpnDetected(_) => (
                "Access denied".to_string(),
                "VPN_DETECTED".to_string(),
                Some("VPN/Proxy access is not allowed.".to_string()),
            ),
            SecurityError::ProxyDetected(_) => (
                "Access denied".to_string(),
                "PROXY_DETECTED".to_string(),
                Some("Proxy access is not allowed.".to_string()),
            ),
            SecurityError::RequestTimeout(_) => (
                "Request timeout".to_string(),
                "REQUEST_TIMEOUT".to_string(),
                Some("Your request exceeded the maximum allowed time.".to_string()),
            ),
            SecurityError::ConnectionTimeout(_) => (
                "Connection timeout".to_string(),
                "CONNECTION_TIMEOUT".to_string(),
                Some("Your connection exceeded the maximum allowed time.".to_string()),
            ),
            SecurityError::ReplayDetected(_) => (
                "Replay attack detected".to_string(),
                "REPLAY_DETECTED".to_string(),
                Some("Your request appears to be a replay of a previous request.".to_string()),
            ),
        };

        Self {
            error: error_msg,
            code,
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id,
            details: if include_details { details } else { None },
        }
    }
}

/// Error handling security utilities
pub struct ErrorHandler;

impl ErrorHandler {
    /// Check if error should expose details based on context
    pub fn should_expose_details(threat_score: u32, is_authenticated: bool) -> bool {
        // Only expose details to authenticated users with low threat score
        is_authenticated && threat_score < 50
    }

    /// Sanitize error message to prevent information disclosure
    pub fn sanitize_error_message(message: &str) -> String {
        // Remove sensitive paths and file information
        let mut sanitized = message
            .replace(
                std::path::MAIN_SEPARATOR_STR,
                "/",
            )
            .replace('\\', "/");

        // Remove absolute paths like C:/, /home/, /Users/
        let path_patterns = vec![
            regex::Regex::new(r"(?i)[a-z]:/[^/\s]*").unwrap(), // C:/Users
            regex::Regex::new(r"/(?:home|Users|user|usr|var|etc|root|opt)/[^/\s]*").unwrap(), // /home/user
            regex::Regex::new(r"(?i)\b(?:home|Users|user|usr|var|etc|root|opt)\b").unwrap(), // directory names
        ];

        for pattern in path_patterns {
            sanitized = pattern.replace_all(&sanitized, "[REDACTED]").to_string();
        }

        sanitized
    }

    /// Generic error message for production
    pub fn generic_error(request_id: &str, code: u16) -> SafeErrorResponse {
        let (error_msg, code_str) = match code {
            400 => ("Bad Request", "BAD_REQUEST"),
            401 => ("Unauthorized", "UNAUTHORIZED"),
            403 => ("Forbidden", "FORBIDDEN"),
            429 => ("Too Many Requests", "RATE_LIMIT_EXCEEDED"),
            500 => ("Internal Server Error", "INTERNAL_ERROR"),
            _ => ("Error", "UNKNOWN_ERROR"),
        };

        SafeErrorResponse {
            error: error_msg.to_string(),
            code: code_str.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            details: None,
        }
    }

    /// Create error response with rate limit info
    pub fn rate_limit_error(request_id: &str, retry_after: u64) -> (SafeErrorResponse, u64) {
        let response = SafeErrorResponse {
            error: "Rate limit exceeded".to_string(),
            code: "RATE_LIMIT_EXCEEDED".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            details: Some(format!(
                "Please retry after {} seconds",
                retry_after
            )),
        };

        (response, retry_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitized_error_message() {
        let message = "Error at C:\\Users\\admin\\secret.rs";
        let sanitized = ErrorHandler::sanitize_error_message(message);
        assert!(!sanitized.contains("C:\\"));
        assert!(!sanitized.contains("Users"));
    }

    #[test]
    fn test_should_expose_details() {
        assert!(ErrorHandler::should_expose_details(30, true));
        assert!(!ErrorHandler::should_expose_details(60, true));
        assert!(!ErrorHandler::should_expose_details(30, false));
    }

    #[test]
    fn test_generic_error_creation() {
        let error = ErrorHandler::generic_error("req-123", 500);
        assert_eq!(error.code, "INTERNAL_ERROR");
        assert_eq!(error.request_id, "req-123");
    }
}
