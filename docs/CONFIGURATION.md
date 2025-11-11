# Advanced Configuration

## Custom Security Pipeline

```rust
use secureapis::{SecurityConfig, SecurityLayer, middleware::*};

// Create custom configuration
let config = SecurityConfig::new()
    .with_rate_limit(100, 60)
    .with_jwt_validation("secret")
    .with_input_sanitization(true);

let layer = SecurityLayer::new(config);

// Use middleware chain for custom processing
let chain = MiddlewareChain::new()
    .add(CustomAuthMiddleware::new())
    .add(CustomValidationMiddleware::new());
```

## Rate Limiting Strategies

### Per-IP Rate Limiting

```rust
let config = SecurityConfig::new()
    .with_rate_limit(100, 60); // 100 requests per 60 seconds per IP
```

### Adaptive Rate Limiting

```rust
use secureapis::config::RateLimitConfig;

let rate_config = RateLimitConfig {
    enabled: true,
    requests_per_window: 100,
    window_duration: Duration::from_secs(60),
    burst_size: 20,
    per_ip: true,
    per_user: true,
    adaptive: true, // Adjusts limits based on threat level
};
```

## JWT Configuration

### Custom Claims

```rust
use jsonwebtoken::{encode, decode, Header, Validation};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    sub: String,
    company: String,
    permissions: Vec<String>,
    exp: u64,
}

// Generate token with custom claims
let auth_manager = AuthManager::new(auth_config);
let token = auth_manager.generate_token(
    "user123".to_string(),
    vec!["admin".to_string()],
).unwrap();
```

### Token Refresh

```rust
let config = AuthConfig {
    enabled: true,
    require_auth: true,
    jwt_secret: Some("secret".to_string()),
    token_expiry: Duration::from_secs(900), // 15 minutes
    refresh_enabled: true,
    mfa_enabled: false,
    ..Default::default()
};
```

## Input Validation Rules

### Custom Validation Patterns

```rust
use secureapis::validation::InputValidator;

let config = ValidationConfig {
    enabled: true,
    sql_injection_check: true,
    xss_check: true,
    command_injection_check: true,
    path_traversal_check: true,
    sanitize_input: true,
    max_payload_size: 5 * 1024 * 1024, // 5MB
    max_header_size: 4 * 1024,          // 4KB
};
```

## Threat Detection

### Custom Threat Scoring

```rust
use secureapis::core::SecurityContext;

let mut context = SecurityContext::new(
    "request-123".to_string(),
    "192.168.1.1".to_string(),
);

// Add threat scores based on patterns
context.add_threat_score(10); // Suspicious pattern
context.add_threat_score(20); // Known bad IP

if context.is_high_risk() {
    // Block or flag the request
}
```

## Monitoring & Logging

### Custom Log Levels

```rust
use tracing::Level;

let config = MonitoringConfig {
    enabled: true,
    log_requests: true,
    log_responses: true,
    log_security_events: true,
    metrics_enabled: true,
    trace_sampling_rate: 1.0, // Log all requests (100%)
};
```

### Metrics Collection

```rust
use secureapis::monitoring::Monitor;

let monitor = Monitor::new(monitoring_config);
let stats = monitor.stats();

println!("Total requests: {}", stats.total_requests);
println!("Security events: {}", stats.security_events);
```

## Multi-Factor Authentication

```rust
let config = AuthConfig {
    enabled: true,
    require_auth: true,
    jwt_secret: Some("secret".to_string()),
    mfa_enabled: true, // Enable MFA
    ..Default::default()
};
```

## API Key Management

```rust
use secureapis::auth::AuthManager;

let config = AuthConfig {
    enabled: true,
    require_auth: true,
    api_keys: vec![
        "key-1234-5678-9012".to_string(),
        "key-abcd-efgh-ijkl".to_string(),
    ],
    ..Default::default()
};

// Use API key in requests:
// curl -H "X-API-Key: key-1234-5678-9012" http://localhost:3000/api/data
```

## CORS Configuration

```rust
use tower_http::cors::{CorsLayer, Any};

let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(Any);

let app = Router::new()
    .route("/api/data", get(handler))
    .layer(cors)
    .with_security(security_config);
```

## Production Best Practices

1. **Use environment variables for secrets**
   ```rust
   let jwt_secret = std::env::var("JWT_SECRET")
       .expect("JWT_SECRET must be set");
   ```

2. **Enable strict mode in production**
   ```rust
   let config = SecurityConfig::new().strict_mode();
   ```

3. **Set appropriate rate limits**
   ```rust
   let config = SecurityConfig::new()
       .with_rate_limit(1000, 60) // Adjust based on capacity
   ```

4. **Enable comprehensive logging**
   ```rust
   let monitoring = MonitoringConfig {
       log_security_events: true,
       metrics_enabled: true,
       ..Default::default()
   };
   ```

5. **Regularly rotate secrets**
   - JWT secrets
   - API keys
   - Encryption keys
