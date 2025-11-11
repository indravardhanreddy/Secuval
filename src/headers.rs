/// Security headers injection and management
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Get all recommended security headers
    pub fn get_all_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            // Clickjacking protection
            ("X-Frame-Options", "DENY"),
            
            // MIME type sniffing protection
            ("X-Content-Type-Options", "nosniff"),
            
            // XSS Protection (legacy, but good for older browsers)
            ("X-XSS-Protection", "1; mode=block"),
            
            // Referrer Policy
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            
            // Feature Policy / Permissions Policy
            ("Permissions-Policy", 
                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"),
            
            // Content Security Policy - restrictive default
            ("Content-Security-Policy", 
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
            
            // Prevent caching of sensitive pages
            ("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private"),
            ("Pragma", "no-cache"),
            ("Expires", "0"),
            
            // Additional security headers
            ("X-Permitted-Cross-Domain-Policies", "none"),
            ("X-UA-Compatible", "IE=edge"),
        ]
    }

    /// Get Content-Security-Policy header with customization
    pub fn get_csp_header(allow_external_scripts: bool) -> String {
        if allow_external_scripts {
            "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()
        } else {
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()
        }
    }

    /// Get HSTS header
    pub fn get_hsts_header(max_age: u32, include_subdomains: bool) -> String {
        let mut header = format!("max-age={}", max_age);
        if include_subdomains {
            header.push_str("; includeSubDomains");
        }
        header.push_str("; preload");
        header
    }

    /// Validate header name (prevent injection)
    pub fn is_valid_header_name(name: &str) -> bool {
        // Header names must follow RFC 7230
        if name.is_empty() || name.len() > 256 {
            return false;
        }

        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        })
    }

    /// Validate header value (prevent injection)
    pub fn is_valid_header_value(value: &str) -> bool {
        // Prevent header injection via CRLF
        !value.contains('\r') && !value.contains('\n') && !value.contains('\0')
    }

    /// Sanitize header value to prevent injection
    pub fn sanitize_header_value(value: &str) -> String {
        value
            .replace('\r', "")
            .replace('\n', "")
            .replace('\0', "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_validation() {
        assert!(SecurityHeaders::is_valid_header_name("X-Custom-Header"));
        assert!(SecurityHeaders::is_valid_header_name("Content-Type"));
        assert!(!SecurityHeaders::is_valid_header_name("Invalid\nHeader"));
        assert!(!SecurityHeaders::is_valid_header_name("Invalid\rHeader"));
    }

    #[test]
    fn test_header_value_validation() {
        assert!(SecurityHeaders::is_valid_header_value("safe-value"));
        assert!(!SecurityHeaders::is_valid_header_value("unsafe\r\nvalue"));
        assert!(!SecurityHeaders::is_valid_header_value("unsafe\nvalue"));
    }

    #[test]
    fn test_header_sanitization() {
        assert_eq!(
            SecurityHeaders::sanitize_header_value("test\r\nvalue"),
            "testvalue"
        );
        assert_eq!(
            SecurityHeaders::sanitize_header_value("test\nvalue"),
            "testvalue"
        );
    }

    #[test]
    fn test_csp_generation() {
        let csp = SecurityHeaders::get_csp_header(false);
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
    }
}
