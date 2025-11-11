use crate::core::{SecurityContext, SecurityError, SecurityResult};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Replay attack prevention using nonce and timestamp validation
pub struct ReplayProtection {
    enabled: bool,
    nonce_cache: HashMap<String, u64>,
    timestamp_window: u64,           // seconds
    max_nonces_per_ip: usize,
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            enabled: true,
            nonce_cache: HashMap::new(),
            timestamp_window: 300,      // 5 minute window
            max_nonces_per_ip: 1000,
        }
    }

    /// Set timestamp validation window
    pub fn with_timestamp_window(mut self, seconds: u64) -> Self {
        self.timestamp_window = seconds;
        self
    }

    /// Validate request nonce (prevents replay attacks)
    pub async fn validate_nonce(
        &mut self,
        request_nonce: &str,
        client_id: &str,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        // Validate nonce format (should be hex-encoded, reasonable length)
        if request_nonce.len() < 16 || request_nonce.len() > 256 {
            context.add_threat_score(30);
            return Err(SecurityError::InvalidInput {
                reason: "Invalid nonce format or length".to_string(),
                field: Some("nonce".to_string()),
            });
        }

        // Check if nonce is hex-like (alphanumeric)
        if !request_nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            context.add_threat_score(35);
            return Err(SecurityError::InvalidInput {
                reason: "Nonce contains invalid characters".to_string(),
                field: Some("nonce".to_string()),
            });
        }

        let nonce_key = format!("{}:{}", client_id, request_nonce);

        // Check if nonce was already used
        if self.nonce_cache.contains_key(&nonce_key) {
            context.add_threat_score(80);
            return Err(SecurityError::ReplayDetected(
                "Nonce already used - request replay detected".to_string(),
            ));
        }

        // Store nonce with current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.nonce_cache.insert(nonce_key, now);

        // Cleanup old nonces periodically (simple implementation)
        if self.nonce_cache.len() > self.max_nonces_per_ip * 10 {
            self.cleanup_expired_nonces(now);
        }

        Ok(())
    }

    /// Validate request timestamp (prevents time-based attacks)
    pub fn validate_timestamp(
        &self,
        request_timestamp: u64,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if timestamp is too old
        if now > request_timestamp + self.timestamp_window {
            context.add_threat_score(50);
            return Err(SecurityError::ReplayDetected(
                format!(
                    "Request timestamp is too old (difference: {} seconds, max allowed: {})",
                    now - request_timestamp,
                    self.timestamp_window
                ),
            ));
        }

        // Check if timestamp is in the future (with 60 second leeway for clock skew)
        if request_timestamp > now + 60 {
            context.add_threat_score(35);
            return Err(SecurityError::InvalidInput {
                reason: "Request timestamp is in the future".to_string(),
                field: Some("timestamp".to_string()),
            });
        }

        Ok(())
    }

    /// Generate a new nonce for client
    pub fn generate_nonce() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"0123456789ABCDEFabcdef";
        let mut rng = rand::thread_rng();

        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Get current timestamp for request signing
    pub fn get_current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Cleanup expired nonces
    fn cleanup_expired_nonces(&mut self, now: u64) {
        self.nonce_cache.retain(|_, timestamp| {
            now - *timestamp < self.timestamp_window * 2
        });
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_generation() {
        let nonce = ReplayProtection::generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let mut protection = ReplayProtection::new();
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        let nonce = ReplayProtection::generate_nonce();

        // First use should succeed
        assert!(protection
            .validate_nonce(&nonce, "client1", &mut context)
            .await
            .is_ok());

        // Second use should fail (replay)
        assert!(protection
            .validate_nonce(&nonce, "client1", &mut context)
            .await
            .is_err());
    }

    #[test]
    fn test_timestamp_validation() {
        let protection = ReplayProtection::new().with_timestamp_window(300);
        let mut context = SecurityContext::new("test".to_string(), "127.0.0.1".to_string());

        let now = ReplayProtection::get_current_timestamp();

        // Current timestamp should pass
        assert!(protection.validate_timestamp(now, &mut context).is_ok());

        // 1 minute old should pass
        assert!(protection
            .validate_timestamp(now - 60, &mut context)
            .is_ok());

        // 10 minutes old should fail
        assert!(protection
            .validate_timestamp(now - 600, &mut context)
            .is_err());
    }
}
