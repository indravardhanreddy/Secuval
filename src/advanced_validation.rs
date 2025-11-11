use crate::core::{SecurityContext, SecurityError, SecurityResult};
use regex::Regex;

/// Advanced input validation for complex attack patterns
pub struct AdvancedValidator {
    xxe_patterns: Vec<Regex>,
    nosql_patterns: Vec<Regex>,
    ldap_patterns: Vec<Regex>,
    header_injection_patterns: Vec<Regex>,
    template_injection_patterns: Vec<Regex>,
}

impl AdvancedValidator {
    pub fn new() -> Self {
        Self {
            xxe_patterns: Self::build_xxe_patterns(),
            nosql_patterns: Self::build_nosql_patterns(),
            ldap_patterns: Self::build_ldap_patterns(),
            header_injection_patterns: Self::build_header_injection_patterns(),
            template_injection_patterns: Self::build_template_injection_patterns(),
        }
    }

    /// Validate against XXE (XML External Entity) attacks
    pub fn check_xxe(&self, input: &str, context: &mut SecurityContext) -> SecurityResult<()> {
        for pattern in &self.xxe_patterns {
            if pattern.is_match(input) {
                context.add_threat_score(50);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential XXE attack detected".to_string(),
                    field: Some("xml_content".to_string()),
                });
            }
        }
        Ok(())
    }

    /// Validate against NoSQL injection attacks
    pub fn check_nosql_injection(
        &self,
        input: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        for pattern in &self.nosql_patterns {
            if pattern.is_match(input) {
                context.add_threat_score(45);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential NoSQL injection detected".to_string(),
                    field: Some("query_parameter".to_string()),
                });
            }
        }
        Ok(())
    }

    /// Validate against LDAP injection attacks
    pub fn check_ldap_injection(
        &self,
        input: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        for pattern in &self.ldap_patterns {
            if pattern.is_match(input) {
                context.add_threat_score(40);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential LDAP injection detected".to_string(),
                    field: Some("ldap_query".to_string()),
                });
            }
        }
        Ok(())
    }

    /// Validate against header injection attacks
    pub fn check_header_injection(
        &self,
        input: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        for pattern in &self.header_injection_patterns {
            if pattern.is_match(input) {
                context.add_threat_score(50);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential header injection detected".to_string(),
                    field: Some("header_value".to_string()),
                });
            }
        }
        Ok(())
    }

    /// Validate against Template Injection attacks
    pub fn check_template_injection(
        &self,
        input: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        for pattern in &self.template_injection_patterns {
            if pattern.is_match(input) {
                context.add_threat_score(45);
                return Err(SecurityError::InvalidInput {
                    reason: "Potential template injection detected".to_string(),
                    field: Some("template_content".to_string()),
                });
            }
        }
        Ok(())
    }

    // XXE pattern detection
    fn build_xxe_patterns() -> Vec<Regex> {
        vec![
            // DOCTYPE with SYSTEM identifier
            Regex::new(r"(?i)<!DOCTYPE.*SYSTEM").unwrap(),
            // ENTITY declaration with SYSTEM
            Regex::new(r"(?i)<!ENTITY.*SYSTEM").unwrap(),
            // Parameter entity (dangerous in DTD)
            Regex::new(r"(?i)<!ENTITY\s+%").unwrap(),
            // URL-based entity pointing to files
            Regex::new(r#"(?i)SYSTEM\s*["']file://"#).unwrap(),
        ]
    }

    // NoSQL injection patterns
    fn build_nosql_patterns() -> Vec<Regex> {
        vec![
            // MongoDB operators
            Regex::new(r#"[{,]\s*\$[a-z]+\s*:"#).unwrap(),
            // JavaScript injection in NoSQL
            Regex::new(r"(?i)\{\s*\$where").unwrap(),
            // Regex injection
            Regex::new(r"(?i)\{.*\$regex").unwrap(),
            // Array-based injection
            Regex::new(r"(?i)\[\s*\$").unwrap(),
        ]
    }

    // LDAP injection patterns
    fn build_ldap_patterns() -> Vec<Regex> {
        vec![
            // LDAP filter operators
            Regex::new(r"[*()&|].*[*()&|]").unwrap(),
            // Wildcard injection
            Regex::new(r"\*\)").unwrap(),
            // Dangerous LDAP chars in sequence
            Regex::new(r"(\*|[\(\)]){2,}").unwrap(),
        ]
    }

    // Header injection patterns (CRLF)
    fn build_header_injection_patterns() -> Vec<Regex> {
        vec![
            // Carriage return + Line feed
            Regex::new(r"[\r\n]").unwrap(),
            // URL-encoded CRLF
            Regex::new(r"(?i)%0[ad]").unwrap(),
            // Null byte
            Regex::new(r"(?i)%00").unwrap(),
        ]
    }

    // Template injection patterns
    fn build_template_injection_patterns() -> Vec<Regex> {
        vec![
            // Jinja2/Twig syntax
            Regex::new(r"\{\{.*\}\}|\{%.*%\}").unwrap(),
            // ERB syntax
            Regex::new(r"<%.*%>").unwrap(),
            // Expression injection
            Regex::new(r"\$\{.*\}").unwrap(),
            // FreeMarker
            Regex::new(r"\[#.*\]").unwrap(),
        ]
    }
}

impl Default for AdvancedValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xxe_detection() {
        let validator = AdvancedValidator::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        assert!(validator
            .check_xxe("<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>", &mut context)
            .is_err());
    }

    #[test]
    fn test_nosql_injection_detection() {
        let validator = AdvancedValidator::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        assert!(validator
            .check_nosql_injection("{ \"$where\": \"1==1\" }", &mut context)
            .is_err());
        assert!(validator
            .check_nosql_injection("{ \"$regex\": \".*\" }", &mut context)
            .is_err());
    }

    #[test]
    fn test_ldap_injection_detection() {
        let validator = AdvancedValidator::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        assert!(validator
            .check_ldap_injection("*)(uid=*", &mut context)
            .is_err());
    }

    #[test]
    fn test_header_injection_detection() {
        let validator = AdvancedValidator::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        assert!(validator
            .check_header_injection("value\r\nX-Injected: bad", &mut context)
            .is_err());
    }
}
