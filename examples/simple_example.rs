//! # Simple Example: Basic API Security
//! 
//! This example shows a minimal setup with just rate limiting and basic validation.

use axum::{routing::get, Router};
use secureapis::prelude::*;
use std::net::SocketAddr;

mod integrations;
use integrations::axum::SecurityRouterExt;

#[tokio::main]
async fn main() {
    // Simple configuration with just rate limiting
    let security_config = SecurityConfig::new().with_rate_limit(50, 60);

    // Build API
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .route("/api/data", get(api_handler))
        .with_security(security_config);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    println!("🛡️  Simple secure API on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn api_handler() -> &'static str {
    "API data with rate limiting protection"
}
