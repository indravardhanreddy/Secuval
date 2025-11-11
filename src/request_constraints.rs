use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use std::time::Duration;

/// Request constraints validation (timeouts, connection limits, URI length)
pub struct RequestConstraints {
    enabled: bool,
    max_request_time: Duration,
    max_uri_length: usize,
    max_connection_time: Duration,
    #[allow(dead_code)]
    max_connections_per_ip: u32,
}

impl RequestConstraints {
    pub fn new() -> Self {
        Self {
            enabled: true,
            max_request_time: Duration::from_secs(30),    // 30 second timeout
            max_uri_length: 8192,                          // 8KB URI
            max_connection_time: Duration::from_secs(600), // 10 minute connection
            max_connections_per_ip: 1000,                  // Max 1000 concurrent
        }
    }

    /// Set maximum request time
    pub fn with_request_timeout(mut self, duration: Duration) -> Self {
        self.max_request_time = duration;
        self
    }

    /// Set maximum URI length
    pub fn with_max_uri_length(mut self, length: usize) -> Self {
        self.max_uri_length = length;
        self
    }

    /// Validate request constraints
    pub async fn validate_constraints<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Validate URI length
        let uri_length = request.uri().to_string().len();
        if uri_length > self.max_uri_length {
            context.add_threat_score(30);
            return Err(SecurityError::InvalidInput {
                reason: format!(
                    "URI length {} exceeds maximum {}",
                    uri_length, self.max_uri_length
                ),
                field: Some("uri".to_string()),
            });
        }

        // Validate method is present
        if request.method().as_str().is_empty() {
            context.add_threat_score(25);
            return Err(SecurityError::InvalidInput {
                reason: "Invalid or missing HTTP method".to_string(),
                field: Some("method".to_string()),
            });
        }

        // Validate version is HTTP/1.1 or newer (not HTTP/0.9)
        let version = request.version();
        if version == http::Version::HTTP_09 {
            context.add_threat_score(40);
            return Err(SecurityError::InvalidInput {
                reason: "HTTP/0.9 is not supported".to_string(),
                field: Some("version".to_string()),
            });
        }

        Ok(())
    }

    /// Check if request has exceeded time limit
    pub fn check_request_timeout(&self, elapsed_time: Duration) -> SecurityResult<()> {
        if elapsed_time > self.max_request_time {
            return Err(SecurityError::RequestTimeout(
                format!("Request exceeded timeout of {:?}", self.max_request_time),
            ));
        }
        Ok(())
    }

    /// Check connection time
    pub fn check_connection_time(&self, elapsed_time: Duration) -> SecurityResult<()> {
        if elapsed_time > self.max_connection_time {
            return Err(SecurityError::ConnectionTimeout(
                format!("Connection exceeded timeout of {:?}", self.max_connection_time),
            ));
        }
        Ok(())
    }
}

impl Default for RequestConstraints {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_length_validation() {
        let constraints = RequestConstraints::new().with_max_uri_length(1000);
        assert_eq!(constraints.max_uri_length, 1000);
    }

    #[test]
    fn test_timeout_check() {
        let constraints = RequestConstraints::new()
            .with_request_timeout(Duration::from_secs(5));

        assert!(constraints
            .check_request_timeout(Duration::from_secs(3))
            .is_ok());
        assert!(constraints
            .check_request_timeout(Duration::from_secs(10))
            .is_err());
    }
}
