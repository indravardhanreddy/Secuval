# Production Deployment Guide: Integrating SecureAPIs Middleware

## Overview

SecureAPIs is designed to be integrated directly into your API applications as middleware. It provides comprehensive security checks at the application layer, protecting against threats before they reach your business logic.

```
Internet Request
       ↓
┌──────────────────────────┐
│   Your API Application   │
│  ├─ SecureAPIs Middleware│  ← Integrated Security
│  │  - Rate Limiting      │
│  │  - Input Validation   │
│  │  - Threat Detection   │
│  │  - Authentication     │
│  └─ Your Business Logic  │
└──────────────────────────┘
       ↓
   Database
```

## Quick Start: Integrate as Middleware

### Step 1: Choose Your Language Integration

SecureAPIs provides native bindings for multiple languages. Choose the one that matches your stack:

**For Rust/Axum (Native):**
```rust
use secureapis::{SecurityLayer, SecurityConfig};
use axum::{Router, routing::get};

let security_config = SecurityConfig::new()
    .with_rate_limit(1000, 60)
    .with_jwt_validation("your-secret")
    .with_input_sanitization(true);

let app = Router::new()
    .route("/api/data", get(handler))
    .layer(SecurityLayer::new(security_config)); // ← Security middleware
```

**For Node.js/Express:**
```javascript
const express = require('express');
const { SecureAPIsMiddleware } = require('secureapis');

const app = express();
const secureAPIs = new SecureAPIsMiddleware({
    rateLimitRequestsPerMinute: 1000,
    enableJwtValidation: true,
    jwtSecret: 'your-secret'
});

app.use(secureAPIs.middleware()); // ← Security middleware
```

**For Python/FastAPI:**
```python
from fastapi import FastAPI
from secureapis import SecureAPIsMiddleware

app = FastAPI()
app.add_middleware(SecureAPIsMiddleware,
    rate_limit_requests_per_minute=1000,
    enable_jwt_validation=True,
    jwt_secret='your-secret'
)  # ← Security middleware
```

### Step 2: Configure Security Settings

Choose appropriate security levels for your application:

```javascript
// Development (lenient)
const config = {
    rateLimitRequestsPerMinute: 10000,
    enableInputSanitization: true,
    enableJwtValidation: false
};

// Production (strict)
const config = {
    rateLimitRequestsPerMinute: 100,
    enableInputSanitization: true,
    enableJwtValidation: true,
    jwtSecret: process.env.JWT_SECRET,
    enableCsrfProtection: true,
    strictMode: true
};
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

**Step 1: Install SecureAPIs**
```bash
npm install secureapis
```

**Step 2: Integrate middleware into your Express app**
```javascript
// app.js - your main Express application
const express = require('express');
const { SecureAPIsMiddleware } = require('secureapis');

const app = express();
app.use(express.json());

// Configure SecureAPIs middleware
const secureAPIs = new SecureAPIsMiddleware({
    rateLimitRequestsPerMinute: 1000,
    enableJwtValidation: true,
    jwtSecret: process.env.JWT_SECRET,
    enableInputSanitization: true,
    enableCsrfProtection: true,
    strictMode: true
});

// Apply security middleware to ALL routes
app.use(secureAPIs.middleware());

// Your API routes (now protected)
app.get('/api/users', (req, res) => {
    res.json({ users: [] });
});

app.post('/api/users', (req, res) => {
    // Input is automatically validated by middleware
    const userData = req.body;
    // Process user creation
    res.json({ created: true, user: userData });
});

app.listen(3000, () => {
    console.log('🛡️ Secure API running on port 3000');
});
```

**Step 3: Users access your API directly**
```bash
# Direct access to your protected API
curl https://api.example.com/api/users
     ↓
   (SecureAPIs middleware validates request)
     ↓
   (Express processes safe request)
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
