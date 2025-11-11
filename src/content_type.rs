use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use regex::Regex;

/// Content-Type validation and enforcement
pub struct ContentTypeValidator {
    enabled: bool,
    allowed_types: Vec<String>,
    strict_mode: bool,
    #[allow(dead_code)]
    type_patterns: Vec<(String, Regex)>,
}

impl ContentTypeValidator {
    pub fn new() -> Self {
        Self {
            enabled: true,
            allowed_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
                "application/xml".to_string(),
            ],
            strict_mode: false,
            type_patterns: vec![
                (
                    "json".to_string(),
                    Regex::new(r"(?i)application/json").unwrap(),
                ),
                (
                    "form".to_string(),
                    Regex::new(r"(?i)application/x-www-form-urlencoded").unwrap(),
                ),
                (
                    "multipart".to_string(),
                    Regex::new(r"(?i)multipart/form-data").unwrap(),
                ),
                (
                    "xml".to_string(),
                    Regex::new(r"(?i)(text/|application/)xml").unwrap(),
                ),
            ],
        }
    }

    /// Enable strict mode (only allowed types accepted)
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Add allowed content type
    pub fn allow_type(mut self, mime_type: String) -> Self {
        if !self.allowed_types.contains(&mime_type) {
            self.allowed_types.push(mime_type);
        }
        self
    }

    /// Validate request Content-Type header
    pub async fn validate_content_type<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Content-Type only matters for requests with body
        let method = request.method().as_str();
        if !matches!(method, "POST" | "PUT" | "PATCH") {
            return Ok(());
        }

        // Get Content-Type header
        let content_type = match request.headers().get("content-type") {
            Some(ct) => match ct.to_str() {
                Ok(value) => value,
                Err(_) => {
                    context.add_threat_score(15);
                    return Err(SecurityError::InvalidInput {
                        reason: "Invalid Content-Type header encoding".to_string(),
                        field: Some("content-type".to_string()),
                    });
                }
            },
            None => {
                // Missing Content-Type for request with body
                if self.strict_mode {
                    context.add_threat_score(20);
                    return Err(SecurityError::InvalidInput {
                        reason: "Content-Type header required".to_string(),
                        field: Some("content-type".to_string()),
                    });
                }
                return Ok(());
            }
        };

        // Validate Content-Type format
        if !Self::is_valid_content_type(content_type) {
            context.add_threat_score(20);
            return Err(SecurityError::InvalidInput {
                reason: "Invalid Content-Type format".to_string(),
                field: Some("content-type".to_string()),
            });
        }

        // Check if type is allowed
        if !self.is_allowed_type(content_type) {
            context.add_threat_score(25);
            return Err(SecurityError::InvalidInput {
                reason: format!("Content-Type '{}' not allowed", content_type),
                field: Some("content-type".to_string()),
            });
        }

        // Validate charset
        self.validate_charset(content_type, context)?;

        Ok(())
    }

    /// Check if Content-Type is in allowed list
    fn is_allowed_type(&self, content_type: &str) -> bool {
        let base_type = content_type.split(';').next().unwrap_or("").trim();

        self.allowed_types.iter().any(|allowed| {
            allowed.to_lowercase() == base_type.to_lowercase()
        })
    }

    /// Validate Content-Type header format
    fn is_valid_content_type(content_type: &str) -> bool {
        let parts: Vec<&str> = content_type.split(';').collect();
        if parts.is_empty() {
            return false;
        }

        let base_type = parts[0].trim();

        // Must have format: type/subtype
        if !base_type.contains('/') {
            return false;
        }

        let type_parts: Vec<&str> = base_type.split('/').collect();
        if type_parts.len() != 2 {
            return false;
        }

        // Type and subtype must be non-empty
        type_parts[0].len() > 0 && type_parts[1].len() > 0
    }

    /// Validate charset parameter
    fn validate_charset(
        &self,
        content_type: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !content_type.to_lowercase().contains("charset") {
            return Ok(());
        }

        let allowed_charsets = vec!["utf-8", "utf-16", "iso-8859-1", "us-ascii"];

        // Extract charset value
        if let Some(charset_part) = content_type
            .split(';')
            .find(|p| p.to_lowercase().contains("charset"))
        {
            let charset = charset_part
                .split('=')
                .nth(1)
                .map(|s| s.trim().trim_matches('"'))
                .unwrap_or("");

            if !allowed_charsets.iter().any(|ac| {
                ac.eq_ignore_ascii_case(charset)
            }) {
                context.add_threat_score(15);
                return Err(SecurityError::InvalidInput {
                    reason: format!("Charset '{}' not allowed", charset),
                    field: Some("content-type-charset".to_string()),
                });
            }
        }

        Ok(())
    }

    /// Detect multipart bomb attacks (multiple parts with same content)
    pub fn check_multipart_bomb(
        &self,
        _content_type: &str,
        boundary_count: u32,
        max_parts: u32,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if boundary_count > max_parts {
            context.add_threat_score(50);
            return Err(SecurityError::InvalidInput {
                reason: format!(
                    "Too many multipart boundaries: {} > {}",
                    boundary_count, max_parts
                ),
                field: Some("multipart-count".to_string()),
            });
        }

        Ok(())
    }
}

impl Default for ContentTypeValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_format_validation() {
        assert!(ContentTypeValidator::is_valid_content_type(
            "application/json"
        ));
        assert!(ContentTypeValidator::is_valid_content_type(
            "application/json; charset=utf-8"
        ));
        assert!(!ContentTypeValidator::is_valid_content_type("invalid"));
        assert!(!ContentTypeValidator::is_valid_content_type(""));
    }

    #[test]
    fn test_allowed_types() {
        let validator = ContentTypeValidator::new();
        assert!(validator.is_allowed_type("application/json"));
        assert!(validator.is_allowed_type("application/json; charset=utf-8"));
        assert!(!validator.is_allowed_type("application/octet-stream"));
    }
}
