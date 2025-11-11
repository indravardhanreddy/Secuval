# Quick Start: Deploy SecureAPIs in 5 Minutes

## The Short Version

SecureAPIs sits **in front of your API** and protects all requests before they reach your code.

```
Internet → SecureAPIs (Port 3000) → Your API (Port 5000)
```

## Installation & Setup

### 1. Add to Your Project (60 seconds)

```toml
# Cargo.toml
[dependencies]
secureapis = "0.1.0"
axum = "0.7"
tokio = { version = "1.35", features = ["full"] }
```

### 2. Minimal Gateway Code (30 seconds)

```rust
use secureapis::{SecurityLayer, SecurityConfig};
use axum::Router;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let config = SecurityConfig::new()
        .with_rate_limit(1000, 60)      // 1000 req/min
        .with_jwt_validation("secret");  // Token validation
    
    let app = Router::new()
        .layer(SecurityLayer::new(config));
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### 3. Run It (30 seconds)

```bash
cargo run --release
# Gateway now listening on port 3000
```

## That's It! 🎉

- Port **3000**: Public (clients connect here)
- Port **5000**: Internal (your backend)

## What's Protected?

✅ Rate limiting (stops floods)
✅ Input validation (blocks XSS/SQL injection)
✅ JWT authentication (validates tokens)
✅ CORS enforcement (controls access)
✅ Security headers (protects clients)

## Monitor It

```bash
cargo run --example ui_dashboard
# Open http://localhost:3000
```

## That's the Entire Setup

All your API requests now pass through SecureAPIs first. Everything is protected automatically.

---

**Next:** Read `DEPLOYMENT_GUIDE.md` for production details
