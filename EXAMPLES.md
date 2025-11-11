# SecureAPIs Examples Guide

Complete examples showing how to use SecureAPIs in your applications.

## Quick Start Examples

### 1. Simple Example ⭐ START HERE
**File:** `examples/simple_example.rs`

The minimal, fastest way to get started with SecureAPIs. Shows basic rate limiting and validation.

```bash
cargo run --example simple_example
```

**Features:**
- Basic rate limiting (50 req/min)
- HTTP server on port 3001
- Single endpoint protection

**Use when:** Learning SecureAPIs for the first time

---

### 2. Complete Example
**File:** `examples/complete_example.rs`

Full-featured example with all major security features enabled.

```bash
cargo run --example complete_example
```

**Features:**
- Rate limiting
- JWT validation
- Input sanitization
- CORS enforcement
- Security headers
- Request logging

**Use when:** Building a real API with comprehensive security

---

## Authentication & Security Features

### 3. JWT Authentication
**File:** `examples/jwt_auth.rs`

Demonstrates JWT token validation and claims verification.

```bash
cargo run --example jwt_auth
```

**Features:**
- JWT token generation
- Token validation
- Custom claims handling
- Expiration checking

**Use when:** Building OAuth2/JWT-based APIs

---

### 4. Security Features Showcase
**File:** `examples/security_features.rs`

In-depth exploration of all available security features.

```bash
cargo run --example security_features
```

**Features:**
- SQL injection prevention
- XSS protection
- CSRF token validation
- Path traversal prevention
- Command injection detection

**Use when:** Understanding specific threat protections

---

## Monitoring & Tracking

### 5. Request Tracking
**File:** `examples/blocked_request_tracking.rs`

Track blocked requests and suspicious activities in real-time.

```bash
cargo run --example blocked_request_tracking
```

**Features:**
- Request tracking
- Block reason logging
- Statistics aggregation
- Alert generation

**Use when:** Investigating security incidents

---

### 6. Live Monitoring Dashboard
**File:** `examples/live_monitor.rs`

Real-time monitoring of security metrics and threat levels.

```bash
cargo run --example live_monitor
```

**Features:**
- Live threat assessment
- Metrics collection
- Dashboard API endpoints
- Performance monitoring

**Use when:** Operating SecureAPIs in production

---

## Web Dashboard

### 7. UI Dashboard Server ⭐ RECOMMENDED FOR PRODUCTION
**File:** `examples/ui_dashboard.rs`

Complete web-based dashboard for monitoring and configuration.

```bash
cargo run --example ui_dashboard
```

**Features:**
- Real-time threat dashboard
- Request tracking (1000+ requests)
- Dynamic settings configuration
- Alert management
- Metrics visualization
- Web-based UI (React/Vue ready)

**Endpoints:**
- Web UI: `http://localhost:3000`
- REST API: `http://localhost:3000/api/v1/*`

**Use when:** You need a comprehensive monitoring and control center

---

### 8. Complete UI Integration
**File:** `examples/complete_ui_integration.rs`

Full integration of security layer with web dashboard.

```bash
cargo run --example complete_ui_integration
```

**Features:**
- Complete security middleware
- Web dashboard
- REST API with authentication
- Dynamic configuration
- Real-time updates

**Use when:** Building a production-grade secure system with UI

---

## Performance & Testing

### 9. Production Setup
**File:** `examples/production_setup.rs`

Real-world production configuration patterns and best practices.

```bash
cargo run --example production_setup
```

**Features:**
- Optimal rate limiting for production
- IP reputation checking
- Content-type validation
- Security headers configuration
- Error handling patterns

**Use when:** Deploying to production

---

### 10. Stress Testing
**File:** `examples/stress_test_example.rs`

Load testing and performance benchmarking.

```bash
cargo run --example stress_test_example
```

**Features:**
- Concurrent request testing
- Performance metrics
- Rate limit verification
- Throughput measurement

**Use when:** Validating performance under load

---

## Framework Integration

### 11. Axum Integration
**File:** `examples/integrations/mod.rs`

Integration patterns with Axum web framework.

```bash
cargo run --example axum_integration
```

**Features:**
- Axum middleware setup
- Route security
- Error handling
- Response modification

**Use when:** Using SecureAPIs with Axum

---

## Learning Path

### For First-Time Users:
1. Start with **Simple Example** (1-2 min)
2. Read **Production Setup** (5 min)
3. Try **UI Dashboard** (5 min)
4. Explore **Security Features** (10 min)

### For Production Deployment:
1. Review **Production Setup**
2. Run **UI Dashboard Server**
3. Configure using **Dynamic Settings API**
4. Monitor with **Live Monitoring Dashboard**
5. Test with **Stress Testing Example**

### For Integration:
1. Review **Complete Example**
2. Check **Framework Integration** for your framework
3. Run locally and test
4. Deploy with **Production Setup** patterns

---

## Common Tasks

### Enable Specific Security Features

Edit `examples/complete_example.rs`:

```rust
let security_config = SecurityConfig::new()
    .with_rate_limit(100, 60)           // Rate limiting
    .with_jwt_validation("secret")      // JWT validation
    .with_input_sanitization(true)      // Input filtering
    .with_cors_enforcement(cors_config) // CORS policy
    .with_security_headers(true);       // Security headers
```

### Monitor in Real-Time

Run the UI Dashboard:

```bash
cargo run --example ui_dashboard
# Open http://localhost:3000 in browser
```

### Test Performance

```bash
cargo run --example stress_test_example
```

### Check Security Settings

Use the Dashboard REST API:

```bash
curl http://localhost:3000/api/v1/settings
```

---

## Documentation

- [Main README](README.md) - Project overview
- [Architecture Guide](docs/ARCHITECTURE.md) - System design
- [Configuration Guide](docs/CONFIGURATION.md) - Detailed settings
- [UI Layer Documentation](docs/UI_LAYER.md) - Dashboard API reference

---

## Getting Help

Each example includes inline documentation. Run any example and observe the output to understand behavior.

For detailed information about specific features, check the relevant source files in `src/`.

---

## Running All Examples

```bash
# Test that all examples compile
cargo build --examples

# Run a specific example
cargo run --example simple_example

# Run with logging
RUST_LOG=debug cargo run --example complete_example
```

---

**Happy Securing! 🛡️**
