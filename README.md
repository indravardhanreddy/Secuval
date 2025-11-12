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

## 🌍 Works with ANY Language!

SecureAPIs provides **language bindings and middleware** that integrate directly into your API - it doesn't matter what language your backend is written in:

```
Client → Your API (ANY Language) → SecureAPIs Middleware (Rust)
         .NET, Java, Node.js, Python, Go, Ruby, PHP...
```

**Native performance with zero code changes needed!**

**Language-Specific Setup:**
- **[Multi-Language Integration Guide](docs/MULTILANGUAGE_INTEGRATION.md)** - Complete explanation
- **[Setup with Common Languages](docs/SETUP_COMMON_LANGUAGES.md)** ⭐ - Copy-paste examples for .NET, Java, Node, Python, Go

## Getting Started

**📖 Documentation Map:** See **[docs/INDEX.md](docs/INDEX.md)** for the complete guide to all documentation.

**❓ Have Questions? Start Here:**
- **[Frequently Asked Questions (FAQ)](docs/FAQ.md)** ⭐ - "How do I use this with my language?" (Start here!)

**� Ready to Set Up?**
- **[Setup with Common Languages](docs/SETUP_COMMON_LANGUAGES.md)** - Copy-paste guides for .NET, Java, Python, Go, Node.js
- **[Quick Start Deployment](QUICK_START_DEPLOYMENT.md)** - Get running in 5 minutes

**📚 Understanding SecureAPIs:**
1. **[FAQ](docs/FAQ.md)** (10 min) - Q&A format
2. **[Multi-Language Integration](docs/MULTILANGUAGE_INTEGRATION.md)** (15 min) - Deep dive
3. **[Architecture Diagrams](docs/ARCHITECTURE_DIAGRAMS.md)** (10 min) - Visual explanations
4. **[The Complete Story](docs/THE_COMPLETE_STORY.md)** (15 min) - Full overview

**🚀 Deployment:**
- **[Quick Start Deployment](QUICK_START_DEPLOYMENT.md)** - 5 minutes
- **[Full Deployment Guide](DEPLOYMENT_GUIDE.md)** - Production setup
- **[Examples Guide](EXAMPLES.md)** - 10 working examples

**Key Concept:** SecureAPIs provides **middleware and language bindings** that protect your API regardless of language:
```
Client → Your API (Any Language) → SecureAPIs Middleware
         .NET, Java, Python, Go...     Security checks
```
Works with ANY language—native performance with minimal integration!

**👉 New to SecureAPIs? Start with [docs/FAQ.md](docs/FAQ.md) - Most common questions answered!**

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
