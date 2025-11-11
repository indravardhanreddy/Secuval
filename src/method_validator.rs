use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use std::collections::HashSet;

/// HTTP method validation and whitelisting
pub struct MethodValidator {
    enabled: bool,
    allowed_methods: HashSet<String>,
}

impl MethodValidator {
    pub fn new() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("GET".to_string());
        allowed.insert("POST".to_string());
        allowed.insert("PUT".to_string());
        allowed.insert("DELETE".to_string());
        allowed.insert("PATCH".to_string());
        allowed.insert("HEAD".to_string());
        allowed.insert("OPTIONS".to_string());

        Self {
            enabled: true,
            allowed_methods: allowed,
        }
    }

    /// Restrict to specific methods only
    pub fn restrict_to(mut self, methods: Vec<&str>) -> Self {
        self.allowed_methods.clear();
        for method in methods {
            self.allowed_methods.insert(method.to_uppercase());
        }
        self
    }

    /// Add allowed method
    pub fn allow_method(mut self, method: &str) -> Self {
        self.allowed_methods.insert(method.to_uppercase());
        self
    }

    /// Validate HTTP method
    pub async fn validate_method<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let method = request.method().to_string().to_uppercase();

        // Check if method is allowed
        if !self.allowed_methods.contains(&method) {
            context.add_threat_score(20);
            return Err(SecurityError::InvalidInput {
                reason: format!("HTTP method '{}' is not allowed", method),
                field: Some("method".to_string()),
            });
        }

        // Check for suspicious method combinations
        if method == "TRACE" || method == "CONNECT" {
            // TRACE and CONNECT are often disabled for security
            context.add_threat_score(35);
            return Err(SecurityError::InvalidInput {
                reason: format!(
                    "HTTP method '{}' is disabled for security reasons",
                    method
                ),
                field: Some("method".to_string()),
            });
        }

        Ok(())
    }

    /// Check if specific method is allowed
    pub fn is_method_allowed(&self, method: &str) -> bool {
        self.allowed_methods.contains(&method.to_uppercase())
    }
}

impl Default for MethodValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_validation() {
        let validator = MethodValidator::new();
        assert!(validator.is_method_allowed("GET"));
        assert!(validator.is_method_allowed("post"));
        assert!(!validator.is_method_allowed("INVALID"));
    }

    #[test]
    fn test_restricted_methods() {
        let validator = MethodValidator::new().restrict_to(vec!["GET", "POST"]);
        assert!(validator.is_method_allowed("GET"));
        assert!(validator.is_method_allowed("POST"));
        assert!(!validator.is_method_allowed("DELETE"));
    }
}
