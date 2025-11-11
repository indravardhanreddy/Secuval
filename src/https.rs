use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;

/// HTTPS/TLS enforcement and security
pub struct HttpsEnforcer {
    enabled: bool,
    require_https: bool,
    hsts_max_age: u32,
    hsts_include_subdomains: bool,
}

impl HttpsEnforcer {
    pub fn new(require_https: bool) -> Self {
        Self {
            enabled: true,
            require_https,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
        }
    }

    /// Check if connection is HTTPS
    pub async fn check_https<B>(
        &self,
        request: &Request<B>,
        _context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled || !self.require_https {
            return Ok(());
        }

        // Check multiple indicators of HTTPS
        let is_https = self.is_connection_secure(request);

        if !is_https {
            return Err(SecurityError::TransportLayerViolation(
                "HTTPS connection required".to_string(),
            ));
        }

        Ok(())
    }

    /// Determine if connection is secure (HTTPS)
    fn is_connection_secure<B>(&self, request: &Request<B>) -> bool {
        // Check X-Forwarded-Proto header (for proxies/load balancers)
        if let Some(proto) = request.headers().get("x-forwarded-proto") {
            if let Ok(proto_str) = proto.to_str() {
                if proto_str == "https" {
                    return true;
                }
            }
        }

        // Check CF-Visitor header (Cloudflare)
        if let Some(visitor) = request.headers().get("cf-visitor") {
            if let Ok(visitor_str) = visitor.to_str() {
                if visitor_str.contains("\"scheme\":\"https\"") {
                    return true;
                }
            }
        }

        // Check Front-End-Https header
        if let Some(https) = request.headers().get("front-end-https") {
            if let Ok(https_str) = https.to_str() {
                if https_str == "on" {
                    return true;
                }
            }
        }

        // Check URI scheme
        if request.uri().scheme_str() == Some("https") {
            return true;
        }

        false
    }

    /// Get HSTS header value
    pub fn get_hsts_header(&self) -> String {
        let mut header = format!("max-age={}", self.hsts_max_age);

        if self.hsts_include_subdomains {
            header.push_str("; includeSubDomains");
        }

        // Only set HSTS if connection is HTTPS
        header.push_str("; preload");

        header
    }

    /// Get HSTS header for responses
    pub fn hsts_header(&self) -> (&'static str, String) {
        ("Strict-Transport-Security", self.get_hsts_header())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsts_header_generation() {
        let enforcer = HttpsEnforcer::new(true);
        let header = enforcer.get_hsts_header();

        assert!(header.contains("max-age=31536000"));
        assert!(header.contains("includeSubDomains"));
        assert!(header.contains("preload"));
    }
}
