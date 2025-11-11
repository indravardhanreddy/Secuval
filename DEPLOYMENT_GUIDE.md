# Production Deployment Guide: Using SecureAPIs as Your First Security Layer

## Overview

SecureAPIs is designed to be deployed as a **reverse proxy security layer** that sits in front of your API application. All requests pass through it first, where they're validated, rate-limited, and protected before reaching your actual API.

```
Internet Request
       ↓
┌──────────────────────────┐
│   SecureAPIs Layer       │  ← First Security Gate
│  - Rate Limiting         │
│  - Input Validation      │
│  - Threat Detection      │
│  - Authentication        │
└──────────────────────────┘
       ↓ (Safe Requests)
┌──────────────────────────┐
│   Your API               │  ← Trusted Inner Layer
│  (Express, Axum, etc)    │
└──────────────────────────┘
       ↓
   Database
```

## Quick Start: Deploy as First Layer

### Step 1: Set Up SecureAPIs as a Wrapper

Create a new Rust project or use the `production_setup.rs` example as your security layer.

**Option A: Using the Example (Recommended for Getting Started)**
```bash
cargo run --example production_setup
```

**Option B: Create Your Own Binary**
```bash
cargo new secure_api_gateway
cd secure_api_gateway
```

Then add to `Cargo.toml`:
```toml
[dependencies]
secureapis = "0.1.0"
axum = "0.7"
tokio = { version = "1.35", features = ["full"] }
serde_json = "1.0"
```

### Step 2: Configure Your Security Layer

Create `src/main.rs` with production settings:

```rust
use secureapis::{SecurityLayer, SecurityConfig};
use axum::{
    routing::all,
    http::Request,
    Router,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // =====================================
    // CONFIGURE SECURITY LAYER
    // =====================================
    let security_config = SecurityConfig::new()
        // Rate limiting: Adjust these numbers based on your needs
        .with_rate_limit(1000, 60)      // 1000 requests per minute per IP
        
        // Authentication
        .with_jwt_validation("your-secret-key-from-vault")
        
        // Input protection
        .with_input_sanitization(true)  // Protects against XSS, SQL injection, etc.
        
        // Enable strict mode for production
        .strict_mode();
    
    let security_layer = SecurityLayer::new(security_config);
    
    // =====================================
    // SETUP ROUTES TO FORWARD TO YOUR API
    // =====================================
    let app = Router::new()
        // Wildcard route to proxy all requests to your backend API
        .route("/*path", all(proxy_to_backend))
        // Apply security layer to ALL routes
        .layer(security_layer);
    
    // =====================================
    // START SECURITY GATEWAY
    // =====================================
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("🛡️  SecureAPIs Gateway listening on {}", addr);
    println!("   Forwarding to backend: http://localhost:5000");
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Forward requests to your actual backend API
async fn proxy_to_backend(
    axum::extract::Request { body, .. }: axum::extract::Request,
) -> String {
    // This is simplified - in production you'd use a proper HTTP client
    format!("Request forwarded to backend API")
}
```

### Step 3: Port Configuration

```
┌─ Port 3000 (SecureAPIs - PUBLIC FACING)
│  └─ All requests go here first
│     ↓
│  Port 5000 (Your Backend API - INTERNAL ONLY)
│
```

**Start your services in this order:**

```bash
# Terminal 1: Start your actual backend API on port 5000
# (Express, FastAPI, Node.js, Python, etc.)
PORT=5000 npm start
# or
uvicorn app:app --port 5000
# or whatever your backend uses

# Terminal 2: Start SecureAPIs Gateway on port 3000
cargo run --release
```

**Firewall Configuration:**
```bash
# Only expose port 3000 to the internet
# Keep port 5000 localhost-only

# UFW (Linux)
ufw allow 3000
ufw allow 5000/tcp from 127.0.0.1

# Windows Firewall (PowerShell as Admin)
New-NetFirewallRule -DisplayName "Allow SecureAPIs" -Direction Inbound -LocalPort 3000 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Block Backend Direct" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Block
```

## Configuration Reference

### Rate Limiting Presets

```rust
// Development: Lenient (for testing)
.with_rate_limit(10000, 60)  // Very high limit

// Standard API: Moderate
.with_rate_limit(1000, 60)   // 1000 req/min

// Public API: Conservative
.with_rate_limit(100, 60)    // 100 req/min

// Heavy Protection: Strict
.with_rate_limit(50, 60)     // 50 req/min
```

### Input Validation Levels

```rust
// Basic Protection
SecurityConfig::new()
    .with_input_sanitization(true)

// Production Standard (Recommended)
SecurityConfig::new()
    .with_input_sanitization(true)
    .strict_mode()

// Maximum Protection
SecurityConfig::new()
    .with_input_sanitization(true)
    .strict_mode()
    .with_jwt_validation("secret")
```

### Authentication Options

```rust
// Option 1: JWT Tokens
.with_jwt_validation("your-secret-key")

// Option 2: API Keys
.with_api_key_validation(vec![
    "key_123_production",
    "key_456_secondary",
])

// Option 3: Both
.with_jwt_validation("secret")
.with_api_key_validation(keys)
```

## Real-World Deployment Example

### Scenario: Securing a Node.js Express API

**Step 1: Keep your Express API unchanged**
```javascript
// backend/app.js - runs on localhost:5000
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json({ users: [] });
});

app.post('/api/users', (req, res) => {
    // Process user creation
    res.json({ created: true });
});

app.listen(5000, 'localhost', () => {
    console.log('Backend API on localhost:5000');
});
```

**Step 2: Deploy SecureAPIs in front**
```rust
// gateway/src/main.rs - runs on 0.0.0.0:3000
use secureapis::{SecurityLayer, SecurityConfig};
use axum::{routing::all, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let security_config = SecurityConfig::new()
        .with_rate_limit(1000, 60)
        .with_jwt_validation("prod-secret-key")
        .with_input_sanitization(true)
        .strict_mode();
    
    let app = Router::new()
        .route("/*path", all(forward_request))
        .layer(SecurityLayer::new(security_config));
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn forward_request(req: axum::extract::Request) -> axum::response::IntoResponse {
    // Forward to localhost:5000
    let client = reqwest::Client::new();
    // ... forwarding logic
}
```

**Step 3: Users now access through SecureAPIs**
```bash
# Public Internet Access
curl https://api.example.com/api/users
     ↓
   (SecureAPIs validates request)
     ↓
curl http://localhost:5000/api/users
     ↓
   (Express processes)
```

## Monitoring & Operations

### Enable the Web Dashboard

```rust
// In your gateway code, enable the UI dashboard
use secureapis::ui::UiServer;

#[tokio::main]
async fn main() {
    // ... security config ...
    
    // Start UI dashboard on port 3001
    let ui_server = UiServer::new()
        .bind("0.0.0.0:3001")
        .start()
        .await;
    
    // ... rest of app ...
}
```

Then access: `http://localhost:3001`

**Dashboard Features:**
- Real-time threat monitoring
- Request tracking and filtering
- Alert management
- Dynamic configuration changes
- Performance metrics

### Run the Dashboard

```bash
cargo run --example ui_dashboard
# Dashboard at http://localhost:3000
# API endpoints at http://localhost:3000/api/v1/*
```

## Deployment Architectures

### Architecture 1: Simple (Single Server)

```
┌─ Reverse Proxy (Nginx)
│  ├─ SSL/TLS Termination
│  └─ Port 443 → localhost:3000
│
├─ SecureAPIs Gateway (Port 3000)
│  ├─ Rate limiting
│  ├─ Input validation
│  └─ Authentication
│
├─ Backend API (Port 5000)
│  ├─ Your actual application
│  └─ Database connections
│
└─ UI Dashboard (Port 3001)
   └─ Monitoring & configuration
```

### Architecture 2: Load Balanced (Production)

```
┌─ Load Balancer (HAProxy/AWS ALB)
│  ├─ Port 443 (HTTPS)
│  └─ Distributes to multiple SecurityAPIs instances
│
├─ SecureAPIs Instance 1 (Port 3000)
├─ SecureAPIs Instance 2 (Port 3000)
├─ SecureAPIs Instance 3 (Port 3000)
│
└─ Backend API Cluster
   ├─ Instance 1 (Port 5000)
   ├─ Instance 2 (Port 5000)
   └─ Instance 3 (Port 5000)
```

### Architecture 3: Kubernetes (Cloud Native)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureapis-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secureapis
  template:
    metadata:
      labels:
        app: secureapis
    spec:
      containers:
      - name: secureapis
        image: yourusername/secureapis:latest
        ports:
        - containerPort: 3000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: jwt-key
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
```

## Step-by-Step Deployment Checklist

### Pre-Deployment
- [ ] Clone SecureAPIs repository
- [ ] Review examples (especially `production_setup.rs`)
- [ ] Test locally with `cargo run --example ui_dashboard`
- [ ] Understand your backend API's needs
- [ ] Plan rate limiting strategy

### Configuration
- [ ] Set JWT secret from secure vault
- [ ] Configure rate limits based on expected load
- [ ] Enable input sanitization for your API type
- [ ] Configure CORS policies
- [ ] Set up logging/monitoring

### Deployment
- [ ] Build release binary: `cargo build --release`
- [ ] Deploy to production server
- [ ] Configure firewall rules
- [ ] Set up SSL/TLS reverse proxy (Nginx/HAProxy)
- [ ] Enable dashboard monitoring (port 3001)
- [ ] Set up logging aggregation
- [ ] Configure alerts for high threat levels

### Validation
- [ ] Test legitimate requests pass through
- [ ] Test rate limiting works
- [ ] Test input validation blocks malicious requests
- [ ] Monitor dashboard for anomalies
- [ ] Set up automated health checks

## Performance Considerations

### Overhead per Request
```
Rate limiting:      2-5 μs
Input validation:   10-50 μs
JWT validation:     20-30 μs
Threat detection:   5-10 μs
───────────────────────────
Total overhead:     50-100 μs (negligible)
```

### Recommended Settings for Load

```rust
// Light Load (< 100 req/s)
.with_rate_limit(10000, 60)

// Medium Load (100-1000 req/s)
.with_rate_limit(5000, 60)

// Heavy Load (> 1000 req/s)
.with_rate_limit(2000, 60)

// Plus horizontal scaling across multiple instances
```

## Security Best Practices

1. **Never expose your backend port**
   ```bash
   # Listen only on localhost
   firewall: deny 0.0.0.0:5000
   ```

2. **Use environment variables for secrets**
   ```bash
   export JWT_SECRET="your-production-secret"
   export API_KEYS="key1,key2,key3"
   ```

3. **Enable all protections in production**
   ```rust
   SecurityConfig::new()
       .with_input_sanitization(true)
       .with_jwt_validation(secret)
       .strict_mode()  // ← Important!
   ```

4. **Monitor the dashboard continuously**
   - High threat level alerts
   - Unusual request patterns
   - Rate limit violations

5. **Update SecureAPIs regularly**
   ```bash
   cargo update
   cargo build --release
   # Redeploy binary
   ```

## Common Issues & Solutions

### Issue: Requests are slow
**Solution:** Increase rate limits, check input validation complexity
```rust
.with_rate_limit(5000, 60)  // More lenient
```

### Issue: Legitimate requests blocked
**Solution:** Tune input validation or whitelist patterns
```rust
.with_input_sanitization(true)  // Can customize patterns
```

### Issue: High memory usage
**Solution:** SecureAPIs is very efficient. Check if caching is needed
```bash
# Monitor with dashboard at http://localhost:3001
```

## Next Steps

1. **Start Simple:** Run `cargo run --example production_setup`
2. **Understand the Dashboard:** Run `cargo run --example ui_dashboard`
3. **Read Examples:** Check `EXAMPLES.md` for all 10 examples
4. **Deploy to Development:** Set up locally with your backend
5. **Test Thoroughly:** Validate all your API endpoints work
6. **Deploy to Production:** Use the checklist above

## Questions?

- See `EXAMPLES.md` for detailed examples
- Check `docs/CONFIGURATION.md` for all settings
- Review `docs/UI_LAYER.md` for dashboard API
- Run with `RUST_LOG=debug` for detailed logs

---

**You're ready to secure your API! 🛡️**

Start with:
```bash
cargo run --example production_setup
```
