use crate::config::ValidationConfig;
use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use regex::Regex;


/// Input validator for detecting common injection attacks
pub struct InputValidator {
    config: ValidationConfig,
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    command_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
}

impl InputValidator {
    pub fn new(config: ValidationConfig) -> Self {
        Self {
            sql_patterns: Self::build_sql_patterns(),
            xss_patterns: Self::build_xss_patterns(),
            command_patterns: Self::build_command_patterns(),
            path_traversal_patterns: Self::build_path_traversal_patterns(),
            config,
        }
    }

    /// Validate an incoming request
    pub async fn validate_request<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()>
    {
        if !self.config.enabled {
            return Ok(());
        }

        // Check payload size
        if let Some(content_length) = request.headers().get("content-length") {
            if let Ok(size_str) = content_length.to_str() {
                if let Ok(size) = size_str.parse::<usize>() {
                    if size > self.config.max_payload_size {
                        return Err(SecurityError::InvalidInput {
                            reason: format!(
                                "Payload size {} exceeds maximum {}",
                                size, self.config.max_payload_size
                            ),
                            field: Some("body".to_string()),
                        });
                    }
                }
            }
        }

        // Validate URI
        let uri = request.uri().to_string();
        self.validate_string(&uri, "uri", context)?;

        // Validate headers
        for (name, value) in request.headers() {
            if let Ok(value_str) = value.to_str() {
                if value_str.len() > self.config.max_header_size {
                    return Err(SecurityError::InvalidInput {
                        reason: "Header value too large".to_string(),
                        field: Some(name.as_str().to_string()),
                    });
                }
                self.validate_string(value_str, name.as_str(), context)?;
            }
        }

        // Validate query parameters
        if let Some(query) = request.uri().query() {
            // URL-decode query parameters for validation
            if let Ok(decoded_query) = urlencoding::decode(query) {
                self.validate_string(&decoded_query, "query", context)?;
            }
            // Also check the raw query string in case of mixed encoding attacks
            self.validate_string(query, "query", context)?;
        }

        Ok(())
    }

    /// Validate a string for various injection patterns
    fn validate_string(
        &self,
        input: &str,
        field_name: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        // SQL Injection check
        if self.config.sql_injection_check {
            if self.contains_sql_injection(input) {
                context.add_threat_score(40);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential SQL injection detected".to_string(),
                    field: Some(field_name.to_string()),
                });
            }
        }

        // XSS check
        if self.config.xss_check {
            if self.contains_xss(input) {
                context.add_threat_score(35);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential XSS attack detected".to_string(),
                    field: Some(field_name.to_string()),
                });
            }
        }

        // Command injection check
        if self.config.command_injection_check {
            if self.contains_command_injection(input) {
                context.add_threat_score(45);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential command injection detected".to_string(),
                    field: Some(field_name.to_string()),
                });
            }
        }

        // Path traversal check
        if self.config.path_traversal_check {
            if self.contains_path_traversal(input) {
                context.add_threat_score(30);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential path traversal detected".to_string(),
                    field: Some(field_name.to_string()),
                });
            }
        }

        Ok(())
    }

    fn contains_sql_injection(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.sql_patterns.iter().any(|pattern| pattern.is_match(&lower))
    }

    fn contains_xss(&self, input: &str) -> bool {
        let lower = input.to_lowercase();
        self.xss_patterns.iter().any(|pattern| pattern.is_match(&lower))
    }

    fn contains_command_injection(&self, input: &str) -> bool {
        self.command_patterns.iter().any(|pattern| pattern.is_match(input))
    }

    fn contains_path_traversal(&self, input: &str) -> bool {
        self.path_traversal_patterns
            .iter()
            .any(|pattern| pattern.is_match(input))
    }

    // SQL Injection patterns
    fn build_sql_patterns() -> Vec<Regex> {
        vec![
            // Union-based: union + select together
            Regex::new(r"(?i)\bunion.+select").unwrap(),
            // Drop table: '; DROP
            Regex::new(r"(?i)drop\s+(table|database)").unwrap(),
            // Common SQL injection patterns
            Regex::new(r"(?i)'\s*or\s+'?\d+'?\s*=\s*'?\d+").unwrap(), // ' OR '1'='1
            Regex::new(r"(?i)'\s*or\s+'?\w+'\s*=\s*'?\w+").unwrap(), // ' OR 'a'='a
            Regex::new(r"(?i);?\s*--").unwrap(), // SQL comments
            Regex::new(r"(?i);?\s*#").unwrap(), // MySQL comments
            Regex::new(r"(?i)\/\*\*\/").unwrap(), // /**/ comments
            Regex::new(r"(?i)'\s*;\s*drop").unwrap(), // '; DROP
            Regex::new(r"(?i)'\s*;\s*select").unwrap(), // '; SELECT
            Regex::new(r"(?i)exec\s*\(").unwrap(), // exec(
            Regex::new(r"(?i)execute\s*\(").unwrap(), // execute(
            Regex::new(r"(?i)xp_cmdshell").unwrap(), // xp_cmdshell
            Regex::new(r"(?i)sp_executesql").unwrap(), // sp_executesql
            Regex::new(r"(?i)information_schema").unwrap(), // information_schema
            Regex::new(r"(?i)sysobjects").unwrap(), // sysobjects
            Regex::new(r"(?i)syscolumns").unwrap(), // syscolumns
        ]
    }

    // XSS patterns
    fn build_xss_patterns() -> Vec<Regex> {
        vec![
            // Script tags
            Regex::new(r"(?i)<script").unwrap(),
            // Event handlers
            Regex::new(r"(?i)on(click|error|load|mouseover|mouseout|keydown|keyup|keypress|submit|change|focus|blur)\s*=").unwrap(),
            // JavaScript URLs
            Regex::new(r"(?i)javascript:").unwrap(),
            // VBscript URLs
            Regex::new(r"(?i)vbscript:").unwrap(),
            // Data URLs that might contain scripts
            Regex::new(r"(?i)data:text/html").unwrap(),
            // Iframe tags
            Regex::new(r"(?i)<iframe").unwrap(),
            // Object/embed tags
            Regex::new(r"(?i)<(object|embed)").unwrap(),
            // Meta refresh with javascript
            Regex::new(r"(?i)<meta.*url=javascript").unwrap(),
            // Style with expression (IE)
            Regex::new(r"(?i)expression\s*\(").unwrap(),
            // Style with javascript
            Regex::new(r"(?i)javascript:\s*expression").unwrap(),
            // img onerror and similar
            Regex::new(r"(?i)<img[^>]*\bonerror\s*=").unwrap(),
            // Link with javascript
            Regex::new(r"(?i)<link[^>]*\shref\s*=\s*javascript:").unwrap(),
        ]
    }

    // Command injection patterns
    fn build_command_patterns() -> Vec<Regex> {
        vec![
            // Semicolon + shell command
            Regex::new(r";\s*(/bin|/usr|/sbin)").unwrap(),
            // Semicolon + common commands
            Regex::new(r";\s*(rm|ls|cat|echo|wget|curl|nc|netcat|nmap|ping)").unwrap(),
            // Pipe operators
            Regex::new(r"\|\s*(/bin|/usr|/sbin)").unwrap(),
            Regex::new(r"\|\s*(rm|ls|cat|echo|wget|curl|nc|netcat|nmap|ping)").unwrap(),
            // Logical operators
            Regex::new(r"(&&|\|\|)\s*(/bin|/usr|/sbin)").unwrap(),
            Regex::new(r"(&&|\|\|)\s*(rm|ls|cat|echo|wget|curl|nc|netcat|nmap|ping)").unwrap(),
            // Command substitution
            Regex::new(r"`[^`]*`").unwrap(),
            Regex::new(r"\$\([^)]*\)").unwrap(),
            // Redirection
            Regex::new(r"[<>]\s*(/etc|/proc|/home|/root|/var)").unwrap(),
            // Common injection patterns
            Regex::new(r";\s*rm\s").unwrap(),
            Regex::new(r";\s*cat\s").unwrap(),
            Regex::new(r";\s*wget\s").unwrap(),
            Regex::new(r";\s*curl\s").unwrap(),
            // Null byte injection
            Regex::new(r"%00").unwrap(),
            Regex::new(r"\\x00").unwrap(),
        ]
    }

    // Path traversal patterns
    fn build_path_traversal_patterns() -> Vec<Regex> {
        vec![
            // Multiple ../ in sequence (Unix/Linux)
            Regex::new(r"(\.\./){2,}").unwrap(),
            // Multiple ..\ in sequence (Windows)
            Regex::new(r"(\.\.\\){2,}").unwrap(),
            // Mixed separators
            Regex::new(r"(\.\.[/\\]){2,}").unwrap(),
            // URL encoded
            Regex::new(r"%2e%2e[/\\]").unwrap(),
            Regex::new(r"%2e%2e%2f").unwrap(),
            Regex::new(r"%2e%2e%5c").unwrap(),
            // Double encoded
            Regex::new(r"%252e%252e").unwrap(),
            // Absolute paths that shouldn't be in user input
            Regex::new(r"/etc/").unwrap(),
            Regex::new(r"/proc/").unwrap(),
            Regex::new(r"/home/").unwrap(),
            Regex::new(r"/root/").unwrap(),
            Regex::new(r"/var/").unwrap(),
            Regex::new(r"\\windows\\").unwrap(),
            Regex::new(r"\\system32\\").unwrap(),
            Regex::new(r"c:\\").unwrap(),
            // Encoded absolute paths
            Regex::new(r"%2fetc%2f").unwrap(),
            Regex::new(r"%5cwindows%5c").unwrap(),
        ]
    }

    /// Sanitize input string by removing dangerous characters
    pub fn sanitize(&self, input: &str) -> String {
        if !self.config.sanitize_input {
            return input.to_string();
        }

        let mut sanitized = input.to_string();

        // Remove null bytes
        sanitized = sanitized.replace('\0', "");

        // Escape HTML entities
        sanitized = sanitized
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;");

        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_injection_detection() {
        let config = ValidationConfig::default();
        let validator = InputValidator::new(config);

        assert!(validator.contains_sql_injection("' OR '1'='1"));
        assert!(validator.contains_sql_injection("admin'--"));
        assert!(validator.contains_sql_injection("1 UNION SELECT * FROM users"));
        assert!(validator.contains_sql_injection("; DROP TABLE users;"));
        
        assert!(!validator.contains_sql_injection("normal query string"));
    }

    #[test]
    fn test_xss_detection() {
        let config = ValidationConfig::default();
        let validator = InputValidator::new(config);

        assert!(validator.contains_xss("<script>alert('xss')</script>"));
        assert!(validator.contains_xss("<img src=x onerror=alert(1)>"));
        assert!(validator.contains_xss("javascript:alert(1)"));
        assert!(validator.contains_xss("<iframe src='evil.com'></iframe>"));
        
        assert!(!validator.contains_xss("normal text content"));
    }

    #[test]
    fn test_command_injection_detection() {
        let config = ValidationConfig::default();
        let validator = InputValidator::new(config);

        assert!(validator.contains_command_injection("file.txt; rm -rf /"));
        assert!(validator.contains_command_injection("$(whoami)"));
        assert!(validator.contains_command_injection("`cat /etc/passwd`"));
        assert!(validator.contains_command_injection("file.txt && cat /etc/passwd"));
        
        assert!(!validator.contains_command_injection("normal-filename.txt"));
    }

    #[test]
    fn test_path_traversal_detection() {
        let config = ValidationConfig::default();
        let validator = InputValidator::new(config);

        assert!(validator.contains_path_traversal("../../etc/passwd"));
        assert!(validator.contains_path_traversal("..\\..\\windows\\system32"));
        assert!(validator.contains_path_traversal("/etc/passwd"));
        
        assert!(!validator.contains_path_traversal("normal/path/file.txt"));
    }

    #[test]
    fn test_sanitization() {
        let config = ValidationConfig::default();
        let validator = InputValidator::new(config);

        assert_eq!(
            validator.sanitize("<script>alert('test')</script>"),
            "&lt;script&gt;alert(&#x27;test&#x27;)&lt;/script&gt;"
        );
        assert_eq!(validator.sanitize("normal text"), "normal text");
    }
}
