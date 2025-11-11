use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use std::collections::HashSet;

/// CORS (Cross-Origin Resource Sharing) policy enforcement
pub struct CorsEnforcer {
    enabled: bool,
    allowed_origins: HashSet<String>,
    allow_all_origins: bool,
    allowed_methods: HashSet<String>,
    allowed_headers: HashSet<String>,
    expose_headers: Vec<String>,
    allow_credentials: bool,
    max_age: u32,
}

impl CorsEnforcer {
    pub fn new() -> Self {
        Self {
            enabled: true,
            allowed_origins: HashSet::new(),
            allow_all_origins: false,
            allowed_methods: vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allowed_headers: vec![
                "Content-Type",
                "Authorization",
                "X-API-Key",
                "X-Request-ID",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            expose_headers: vec!["X-Total-Count", "X-Page-Number"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allow_credentials: true,
            max_age: 86400, // 24 hours
        }
    }

    /// Add allowed origin
    pub fn add_allowed_origin(mut self, origin: String) -> Self {
        self.allowed_origins.insert(origin);
        self
    }

    /// Add multiple allowed origins
    pub fn with_allowed_origins(mut self, origins: Vec<String>) -> Self {
        for origin in origins {
            self.allowed_origins.insert(origin);
        }
        self
    }

    /// Allow all origins (NOT RECOMMENDED for production)
    pub fn allow_all_origins(mut self) -> Self {
        self.allow_all_origins = true;
        self
    }

    /// Validate CORS request
    pub async fn check_cors<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Check origin header
        if let Some(origin) = request.headers().get("origin") {
            if let Ok(origin_str) = origin.to_str() {
                if !self.is_origin_allowed(origin_str) {
                    context.add_threat_score(20);
                    return Err(SecurityError::CorsViolation(
                        format!("Origin '{}' is not allowed", origin_str),
                    ));
                }
            }
        }

        // For preflight requests, check Access-Control-Request-Method
        if request.method() == http::Method::OPTIONS {
            if let Some(req_method) = request.headers().get("access-control-request-method") {
                if let Ok(method_str) = req_method.to_str() {
                    if !self.allowed_methods.contains(&method_str.to_uppercase()) {
                        context.add_threat_score(15);
                        return Err(SecurityError::CorsViolation(
                            format!("Method '{}' is not allowed", method_str),
                        ));
                    }
                }
            }

            // Check Access-Control-Request-Headers
            if let Some(req_headers) = request.headers().get("access-control-request-headers") {
                if let Ok(headers_str) = req_headers.to_str() {
                    for header in headers_str.split(',') {
                        let header = header.trim().to_lowercase();
                        if !self.is_header_allowed(&header) {
                            context.add_threat_score(15);
                            return Err(SecurityError::CorsViolation(
                                format!("Header '{}' is not allowed", header),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_origin_allowed(&self, origin: &str) -> bool {
        if self.allow_all_origins {
            return true;
        }

        // Exact match
        if self.allowed_origins.contains(origin) {
            return true;
        }

        // Wildcard subdomain matching (e.g., *.example.com)
        for allowed in &self.allowed_origins {
            if allowed.starts_with("*.") {
                let domain = allowed.trim_start_matches("*.");
                if origin.ends_with(domain) && (origin.ends_with(&allowed[1..]) || origin == &allowed[2..]) {
                    return true;
                }
            }
        }

        false
    }

    fn is_header_allowed(&self, header: &str) -> bool {
        // Common safe headers that are always allowed
        let safe_headers = vec!["content-type", "accept", "accept-language", "accept-encoding"];

        if safe_headers.contains(&header) {
            return true;
        }

        self.allowed_headers.iter().any(|h| h.to_lowercase() == header)
    }

    /// Get CORS response headers
    pub fn get_cors_headers(&self, origin: &str) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();

        // Set allowed origin
        if self.is_origin_allowed(origin) || self.allow_all_origins {
            headers.push(("Access-Control-Allow-Origin", origin.to_string()));
        }

        if self.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials", "true".to_string()));
        }

        headers.push((
            "Access-Control-Allow-Methods",
            self.allowed_methods.iter().cloned().collect::<Vec<_>>().join(", "),
        ));

        headers.push((
            "Access-Control-Allow-Headers",
            self.allowed_headers.iter().cloned().collect::<Vec<_>>().join(", "),
        ));

        headers.push((
            "Access-Control-Expose-Headers",
            self.expose_headers.join(", "),
        ));

        headers.push((
            "Access-Control-Max-Age",
            self.max_age.to_string(),
        ));

        headers
    }
}

impl Default for CorsEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_validation() {
        let enforcer = CorsEnforcer::new()
            .add_allowed_origin("https://example.com".to_string())
            .add_allowed_origin("https://app.example.com".to_string());

        assert!(enforcer.is_origin_allowed("https://example.com"));
        assert!(enforcer.is_origin_allowed("https://app.example.com"));
        assert!(!enforcer.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_wildcard_origin() {
        let enforcer = CorsEnforcer::new()
            .add_allowed_origin("https://*.example.com".to_string());

        assert!(enforcer.is_origin_allowed("https://app.example.com"));
        assert!(enforcer.is_origin_allowed("https://api.example.com"));
    }
}
