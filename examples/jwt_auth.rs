//! # JWT Authentication Example
//! 
//! This example demonstrates JWT token generation and validation.

use secureapis::{AuthConfig, auth::AuthManager};

#[tokio::main]
async fn main() {
    // Configure authentication
    let config = AuthConfig {
        enabled: true,
        require_auth: true,
        jwt_secret: Some("my-secret-key".to_string()),
        api_keys: vec![],
        token_expiry: std::time::Duration::from_secs(3600), // 1 hour
        refresh_enabled: false,
        mfa_enabled: false,
    };

    let auth_manager = AuthManager::new(config);

    // Generate a token for a user
    let token = auth_manager
        .generate_token(
            "user123".to_string(),
            vec!["admin".to_string(), "user".to_string()],
        )
        .unwrap();

    println!("Generated JWT token:");
    println!("{}", token);
    println!("\nUse this token in the Authorization header:");
    println!("Authorization: Bearer {}", token);
}
