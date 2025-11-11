# Quick Start Guide

Get started with SecureAPIs in 5 minutes!

## Installation

Add SecureAPIs to your `Cargo.toml`:

```toml
[dependencies]
secureapis = "0.1.0"
axum = "0.7"
tokio = { version = "1", features = ["full"] }
```

## Basic Usage

### 1. Create a Simple Secure API

```rust
use axum::{routing::get, Router};
use secureapis::prelude::*;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Configure security with rate limiting
    let security = SecurityConfig::new()
        .with_rate_limit(100, 60); // 100 requests per minute

    // Build your API
    let app = Router::new()
        .route("/api/hello", get(hello))
        .with_security(security);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on http://{}", addr);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn hello() -> &'static str {
    "Hello from secure API!"
}
```

### 2. Run Your Server

```bash
cargo run
```

### 3. Test It

```bash
# Normal request
curl http://localhost:3000/api/hello

# Try to exceed rate limit (send 110 requests)
for i in {1..110}; do curl http://localhost:3000/api/hello; done
```

## Enable More Security Features

### Add JWT Authentication

```rust
let security = SecurityConfig::new()
    .with_rate_limit(100, 60)
    .with_jwt_validation("your-secret-key");
```

### Enable Full Protection

```rust
let security = SecurityConfig::new()
    .with_rate_limit(100, 60)
    .with_jwt_validation("your-secret-key")
    .with_input_sanitization(true)
    .strict_mode(); // Enable all security features
```

## Generate JWT Tokens

```rust
use secureapis::{AuthConfig, AuthManager};

let config = AuthConfig {
    jwt_secret: Some("your-secret-key".to_string()),
    ..Default::default()
};

let auth = AuthManager::new(config);
let token = auth.generate_token(
    "user123".to_string(),
    vec!["user".to_string()],
).unwrap();

println!("Token: {}", token);
```

## Use the Token

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:3000/api/hello
```

## Next Steps

- See [examples/](../examples/) for complete examples
- Read [CONFIGURATION.md](CONFIGURATION.md) for advanced configuration
- Check [ARCHITECTURE.md](ARCHITECTURE.md) to understand internals
- Run benchmarks with `cargo bench`

## Common Patterns

### Public and Protected Routes

```rust
let app = Router::new()
    // Public route (only rate limited)
    .route("/api/public", get(public_handler))
    // Protected route (requires auth)
    .route("/api/protected", get(protected_handler))
    .with_security(security_config);
```

### Custom Error Handling

```rust
use secureapis::SecurityError;

match security_layer.process_request(&request).await {
    Ok(context) => {
        // Request is valid
    }
    Err(SecurityError::RateLimitExceeded { retry_after }) => {
        // Handle rate limit
    }
    Err(SecurityError::AuthenticationFailed(msg)) => {
        // Handle auth failure
    }
    Err(e) => {
        // Handle other errors
    }
}
```

## Troubleshooting

### Rate Limit Too Strict

Adjust the limits:

```rust
.with_rate_limit(1000, 60) // 1000 requests per minute
```

### JWT Validation Failing

Make sure the secret matches between token generation and validation:

```rust
// Generate
let token = auth.generate_token(user_id, roles).unwrap();

// Validate (use same secret)
let config = SecurityConfig::new()
    .with_jwt_validation("same-secret-here");
```

### High Latency

Check the monitoring logs to see which checks are slow:

```bash
RUST_LOG=debug cargo run
```

## Performance Tips

1. Use release mode: `cargo run --release`
2. Adjust rate limits based on your capacity
3. Enable sampling for logging in high-traffic scenarios
4. Consider caching for repeated validations

## Getting Help

- Check the [examples/](../examples/) directory
- Read the [documentation](.)
- Open an issue on GitHub
- Ask in discussions
