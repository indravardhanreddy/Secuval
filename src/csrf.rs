use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;

/// CSRF (Cross-Site Request Forgery) token validation
pub struct CsrfProtection {
    enabled: bool,
    #[allow(dead_code)]
    token_length: usize,
    header_name: String,
    #[allow(dead_code)]
    param_name: String,
}

impl CsrfProtection {
    pub fn new() -> Self {
        Self {
            enabled: true,
            token_length: 32,
            header_name: "X-CSRF-Token".to_string(),
            param_name: "_csrf".to_string(),
        }
    }

    /// Generate a new CSRF token
    pub fn generate_token() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::thread_rng();

        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Validate CSRF token for state-changing requests
    pub async fn validate_csrf<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // CSRF only matters for state-changing methods
        let method = request.method().as_str();
        if !matches!(method, "POST" | "PUT" | "DELETE" | "PATCH") {
            return Ok(());
        }

        // Try to get token from header
        let token_from_header = request
            .headers()
            .get(&self.header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // If no token in header, it might be missing entirely
        if token_from_header.is_none() {
            // Check if it's a form submission with token in body
            // (In real implementation, would parse body)
            context.add_threat_score(30);
            return Err(SecurityError::CsrfViolation(
                "CSRF token missing from request".to_string(),
            ));
        }

        // Validate token format (basic validation)
        if let Some(token) = token_from_header {
            if !Self::is_valid_token_format(&token) {
                context.add_threat_score(40);
                return Err(SecurityError::CsrfViolation(
                    "Invalid CSRF token format".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Validate token format
    fn is_valid_token_format(token: &str) -> bool {
        // Token should be alphanumeric, reasonable length
        if token.len() < 16 || token.len() > 256 {
            return false;
        }

        token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// Check SameSite cookie attribute compliance
    pub fn validate_samesite_cookie(cookie_value: &str) -> bool {
        let lower = cookie_value.to_lowercase();
        lower.contains("samesite=strict")
            || lower.contains("samesite=lax")
            || lower.contains("samesite=none; secure")
    }
}

impl Default for CsrfProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation() {
        let token = CsrfProtection::generate_token();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_token_format_validation() {
        assert!(CsrfProtection::is_valid_token_format(
            "abcd1234abcd1234abcd1234abcd1234"
        ));
        assert!(!CsrfProtection::is_valid_token_format("short")); // Too short
        assert!(!CsrfProtection::is_valid_token_format(
            "token\nwith\ninjection"
        )); // Invalid chars
    }

    #[test]
    fn test_samesite_validation() {
        assert!(CsrfProtection::validate_samesite_cookie(
            "sessionid=abc; Path=/; SameSite=Strict"
        ));
        assert!(CsrfProtection::validate_samesite_cookie(
            "sessionid=abc; Path=/; SameSite=Lax"
        ));
        assert!(!CsrfProtection::validate_samesite_cookie(
            "sessionid=abc; Path=/"
        ));
    }
}
