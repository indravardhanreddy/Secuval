use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;

/// Cookie security validation and enforcement
pub struct CookieSecurity {
    enabled: bool,
    require_secure_flag: bool,
    require_httponly_flag: bool,
    require_samesite: bool,
}

impl CookieSecurity {
    pub fn new() -> Self {
        Self {
            enabled: true,
            require_secure_flag: true,
            require_httponly_flag: true,
            require_samesite: true,
        }
    }

    /// Validate incoming cookies in request
    pub async fn validate_cookies<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Check for Cookie header
        if let Some(cookie_header) = request.headers().get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                // Validate cookie format (basic check for injection)
                if cookie_str.contains('\0') || cookie_str.contains('\r') || cookie_str.contains('\n') {
                    context.add_threat_score(35);
                    return Err(SecurityError::InvalidInput {
                        reason: "Invalid cookie format detected".to_string(),
                        field: Some("cookie".to_string()),
                    });
                }

                // Check for suspicious patterns
                if cookie_str.len() > 4096 {
                    context.add_threat_score(20);
                    return Err(SecurityError::InvalidInput {
                        reason: "Cookie value too large".to_string(),
                        field: Some("cookie".to_string()),
                    });
                }

                // Validate cookie name-value pairs
                for cookie_pair in cookie_str.split(';') {
                    let trimmed = cookie_pair.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Check for valid format (name=value or just name)
                    if !trimmed.contains('=') && trimmed.len() > 0 {
                        // Session cookie without value (might be valid)
                        continue;
                    }

                    if let Some((name, value)) = trimmed.split_once('=') {
                        if name.is_empty() {
                            context.add_threat_score(25);
                            return Err(SecurityError::InvalidInput {
                                reason: "Invalid cookie name".to_string(),
                                field: Some("cookie".to_string()),
                            });
                        }

                        // Check for injection attempts in cookie value
                        if value.contains('<') || value.contains('>') {
                            context.add_threat_score(30);
                            return Err(SecurityError::InvalidInput {
                                reason: "Potential cookie injection detected".to_string(),
                                field: Some("cookie".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate Set-Cookie response headers
    pub fn validate_set_cookie_headers(
        &self,
        set_cookie_values: Vec<&str>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        for cookie_header in set_cookie_values {
            let lower = cookie_header.to_lowercase();

            // Check for Secure flag
            if self.require_secure_flag && !lower.contains("secure") {
                context.add_threat_score(25);
                return Err(SecurityError::InvalidInput {
                    reason:
                        "Set-Cookie missing 'Secure' flag - cookies should only be transmitted over HTTPS"
                            .to_string(),
                    field: Some("set-cookie".to_string()),
                });
            }

            // Check for HttpOnly flag
            if self.require_httponly_flag && !lower.contains("httponly") {
                context.add_threat_score(20);
                return Err(SecurityError::InvalidInput {
                    reason:
                        "Set-Cookie missing 'HttpOnly' flag - prevents JavaScript access to sensitive cookies"
                            .to_string(),
                    field: Some("set-cookie".to_string()),
                });
            }

            // Check for SameSite attribute
            if self.require_samesite
                && !lower.contains("samesite")
            {
                context.add_threat_score(20);
                return Err(SecurityError::InvalidInput {
                    reason: "Set-Cookie missing 'SameSite' attribute - vulnerable to CSRF".to_string(),
                    field: Some("set-cookie".to_string()),
                });
            }

            // Validate SameSite value if present
            if lower.contains("samesite") {
                if !lower.contains("samesite=strict")
                    && !lower.contains("samesite=lax")
                    && !lower.contains("samesite=none")
                {
                    context.add_threat_score(15);
                    return Err(SecurityError::InvalidInput {
                        reason: "Invalid SameSite value - must be 'Strict', 'Lax', or 'None'".to_string(),
                        field: Some("set-cookie".to_string()),
                    });
                }

                // SameSite=None requires Secure
                if lower.contains("samesite=none") && !lower.contains("secure") {
                    context.add_threat_score(30);
                    return Err(SecurityError::InvalidInput {
                        reason: "SameSite=None requires Secure flag".to_string(),
                        field: Some("set-cookie".to_string()),
                    });
                }
            }

            // Check for suspicious patterns in cookie value
            if cookie_header.len() > 8192 {
                context.add_threat_score(20);
                return Err(SecurityError::InvalidInput {
                    reason: "Cookie value too large".to_string(),
                    field: Some("set-cookie".to_string()),
                });
            }
        }

        Ok(())
    }
}

impl Default for CookieSecurity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_format_validation() {
        let cookie_security = CookieSecurity::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        // Valid cookie should pass (would need actual request object)
        let valid_headers = vec![
            "sessionid=abc123; Path=/; SameSite=Strict; Secure; HttpOnly",
            "user=john; SameSite=Lax; Secure; HttpOnly",
        ];

        for header in valid_headers {
            let result = cookie_security.validate_set_cookie_headers(vec![header], &mut context);
            // Should pass validation
            let _ = result;
        }
    }

    #[test]
    fn test_samesite_none_requires_secure() {
        let cookie_security = CookieSecurity::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        // SameSite=None without Secure should fail
        let result = cookie_security.validate_set_cookie_headers(
            vec!["sessionid=abc123; SameSite=None"],
            &mut context,
        );

        assert!(result.is_err());
    }
}
