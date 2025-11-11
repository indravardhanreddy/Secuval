# SecureAPIs 🛡️

A high-performance, open-source API security middleware layer written in Rust. Designed to protect against vulnerability assessments, penetration testing attacks, and common API security threats with minimal latency.

Now includes a **comprehensive web-based UI dashboard** for real-time monitoring, request tracking, alert management, and dynamic configuration!

## ✨ What's New: Complete UI Layer

The SecureAPIs project now features a **production-ready UI layer** with:

- 🎯 **Real-Time Dashboard** - Threat levels, metrics, and system health
- 🔍 **Request Tracking** - Track 1000+ requests with detailed analytics
- 🚨 **Smart Alerts** - Automatic alert generation with multiple severity levels
- ⚙️ **Dynamic Settings** - Modify all security settings without restart
- 📊 **Metrics Collection** - Comprehensive performance and security metrics
- 🌐 **Web API** - REST endpoints for frontend integration
- 📱 **Frontend Ready** - Blueprint for React/Vue/Svelte integration

**Learn More:**
- [UI Layer Documentation](docs/UI_LAYER.md) - Complete API reference
- [Frontend Blueprint](docs/FRONTEND_BLUEPRINT.md) - Frontend implementation guide
- [Implementation Summary](docs/UI_IMPLEMENTATION_SUMMARY.md) - Detailed overview

**Try It Out:**
```bash
# Quick start - minimal example
cargo run --example simple_example

# Full-featured with UI dashboard
cargo run --example ui_dashboard

# See all examples and learn more
# → Check out EXAMPLES.md for complete guide
```

## Features

- **🚀 Ultra-Low Latency**: Built in Rust for maximum performance (~microseconds overhead)
- **🔒 Comprehensive Security**: Protection against OWASP Top 10 and API Security Top 10
- **🔄 Framework Agnostic**: Works with Axum, Actix-Web, and custom implementations
- **📊 Real-time Monitoring**: Built-in metrics, logging, and web dashboard
- **🎯 Zero-Copy Where Possible**: Optimized for minimal allocations
- **⚡ Async First**: Built on Tokio for high concurrency
- **🛠️ Fully Dynamic**: Modify all settings on the fly without restart

## Security Features

### 1. Rate Limiting & DDoS Protection
- Token bucket algorithm with configurable limits
- Per-IP, per-user, and global rate limiting
- Adaptive rate limiting based on threat levels

### 2. Input Validation & Sanitization
- SQL injection detection and prevention
- XSS (Cross-Site Scripting) protection
- Command injection prevention
- Path traversal protection
- JSON/XML bomb detection

### 3. Authentication & Authorization
- JWT validation with custom claims
- API key management
- OAuth2 support
- Role-based access control (RBAC)
- Multi-factor authentication (MFA) support

### 4. Request/Response Security
- CORS policy enforcement
- Content Security Policy (CSP)
- Security headers injection
- Request signature validation
- Response tampering detection

### 5. Threat Detection
- Anomaly detection
- Bot detection
- Known vulnerability pattern matching
- Suspicious activity logging

### 6. Web Dashboard & Monitoring ⭐ NEW
- Real-time threat level assessment
- Request tracking and filtering
- Dynamic alert system
- Security metrics and analytics
- Configuration management UI
- User preference settings

## Quick Start

```rust
use secureapis::{SecurityLayer, SecurityConfig};
use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    // Configure security layer
    let security_config = SecurityConfig::default()
        .with_rate_limit(100, 60) // 100 requests per 60 seconds
        .with_jwt_validation("your-secret-key")
        .with_input_sanitization(true);
    
    let security_layer = SecurityLayer::new(security_config);
    
    // Create your API routes
    let app = Router::new()
        .route("/api/data", get(handler))
        .layer(security_layer);
    
    // Run server
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler() -> &'static str {
    "Secure API Response"
}
```

## Deployment

New to SecureAPIs? Follow the guides:

- **[Quick Start Deployment](QUICK_START_DEPLOYMENT.md)** - Get running in 5 minutes
- **[Full Deployment Guide](DEPLOYMENT_GUIDE.md)** - Production-ready setup
- **[Examples Guide](EXAMPLES.md)** - 10 complete working examples

**Key concept:** Use SecureAPIs as a **reverse proxy** in front of your API. All requests go through it first!

## Benchmarks

Typical overhead per request:
- Rate limiting: ~2-5 μs
- Input validation: ~10-50 μs (depending on payload size)
- JWT validation: ~20-30 μs
- Full security stack: ~50-100 μs

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
secureapis = "0.1.0"
```

## Architecture

```
Request → Security Layer → Your API
            ↓
    ┌───────┴────────┐
    │  Rate Limiter  │
    │  Input Filter  │
    │  Auth Check    │
    │  Logger        │
    └────────────────┘
```

## Configuration

See `examples/` directory for detailed configuration options.

## Contributing

Contributions are welcome! Please read our contributing guidelines.

## License

MIT License - see LICENSE file for details.

## Security

Report security vulnerabilities to security@secureapis.org
