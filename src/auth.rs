use crate::config::AuthConfig;
use crate::core::{SecurityError, SecurityResult};
use http::Request;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Authentication manager
pub struct AuthManager {
    config: AuthConfig,
    api_keys_hashed: HashSet<String>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        // Hash API keys for secure storage
        let api_keys_hashed = config
            .api_keys
            .iter()
            .map(|key| Self::hash_api_key(key))
            .collect();

        Self {
            config,
            api_keys_hashed,
        }
    }

    /// Authenticate a request
    pub async fn authenticate<B>(
        &self,
        request: &Request<B>,
    ) -> SecurityResult<Option<UserContext>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Try JWT authentication first
        if let Some(user) = self.authenticate_jwt(request).await? {
            return Ok(Some(user));
        }

        // Try API key authentication
        if let Some(user) = self.authenticate_api_key(request).await? {
            return Ok(Some(user));
        }

        // No authentication found
        if self.config.require_auth {
            Err(SecurityError::AuthenticationFailed(
                "No valid authentication credentials provided".to_string(),
            ))
        } else {
            Ok(None)
        }
    }

    /// Authenticate using JWT token
    async fn authenticate_jwt<B>(&self, request: &Request<B>) -> SecurityResult<Option<UserContext>> {
        let jwt_secret = match &self.config.jwt_secret {
            Some(secret) => secret,
            None => return Ok(None),
        };

        // Extract Bearer token from Authorization header
        let token = match request.headers().get("authorization") {
            Some(header) => match header.to_str() {
                Ok(value) => {
                    if value.starts_with("Bearer ") {
                        &value[7..]
                    } else {
                        return Ok(None);
                    }
                }
                Err(_) => return Ok(None),
            },
            None => return Ok(None),
        };

        // Decode and validate JWT
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| SecurityError::AuthenticationFailed(format!("Invalid JWT: {}", e)))?;

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if token_data.claims.exp < now {
            return Err(SecurityError::AuthenticationFailed(
                "Token expired".to_string(),
            ));
        }

        Ok(Some(UserContext {
            user_id: token_data.claims.sub,
            roles: token_data.claims.roles,
            email: token_data.claims.email,
        }))
    }

    /// Authenticate using API key
    async fn authenticate_api_key<B>(
        &self,
        request: &Request<B>,
    ) -> SecurityResult<Option<UserContext>> {
        if self.api_keys_hashed.is_empty() {
            return Ok(None);
        }

        // Check X-API-Key header
        let api_key = match request.headers().get("x-api-key") {
            Some(header) => match header.to_str() {
                Ok(value) => value,
                Err(_) => return Ok(None),
            },
            None => return Ok(None),
        };

        // Verify API key
        let key_hash = Self::hash_api_key(api_key);
        if self.api_keys_hashed.contains(&key_hash) {
            Ok(Some(UserContext {
                user_id: format!("apikey_{}", &key_hash[..8]),
                roles: vec!["api_user".to_string()],
                email: None,
            }))
        } else {
            Err(SecurityError::AuthenticationFailed(
                "Invalid API key".to_string(),
            ))
        }
    }

    /// Generate a new JWT token
    pub fn generate_token(&self, user_id: String, roles: Vec<String>) -> SecurityResult<String> {
        let jwt_secret = self.config.jwt_secret.as_ref().ok_or_else(|| {
            SecurityError::ConfigError("JWT secret not configured".to_string())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: user_id,
            roles,
            email: None,
            exp: now + self.config.token_expiry.as_secs(),
            iat: now,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .map_err(|e| SecurityError::InternalError(format!("Failed to generate token: {}", e)))
    }

    /// Verify user has required role
    pub fn authorize(&self, user: &UserContext, required_role: &str) -> SecurityResult<()> {
        if user.roles.iter().any(|r| r == required_role) {
            Ok(())
        } else {
            Err(SecurityError::AuthorizationFailed(format!(
                "User does not have required role: {}",
                required_role
            )))
        }
    }

    /// Hash an API key for secure storage
    fn hash_api_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,              // Subject (user ID)
    roles: Vec<String>,       // User roles
    email: Option<String>,    // User email
    exp: u64,                 // Expiration time
    iat: u64,                 // Issued at
}

/// User context after successful authentication
#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_hashing() {
        let key1 = "test-api-key-123";
        let key2 = "test-api-key-456";

        let hash1 = AuthManager::hash_api_key(key1);
        let hash2 = AuthManager::hash_api_key(key2);

        // Same key produces same hash
        assert_eq!(hash1, AuthManager::hash_api_key(key1));
        
        // Different keys produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_token_generation() {
        let config = AuthConfig {
            enabled: true,
            require_auth: false,
            jwt_secret: Some("test-secret-key".to_string()),
            api_keys: vec![],
            token_expiry: std::time::Duration::from_secs(3600),
            refresh_enabled: false,
            mfa_enabled: false,
        };

        let manager = AuthManager::new(config);
        let token = manager
            .generate_token("user123".to_string(), vec!["admin".to_string()])
            .unwrap();

        assert!(!token.is_empty());
    }
}
