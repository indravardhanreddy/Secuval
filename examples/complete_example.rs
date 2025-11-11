//! # Complete Example: Secure API with All Features
//! 
//! This example demonstrates a fully secured API using the SecureAPIs middleware
//! with all security features enabled.

use axum::{
    routing::{get, post},
    Json, Router,
};
use secureapis::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

// Include the Axum integration module
mod integrations;
use integrations::axum::SecurityRouterExt;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Configure security layer with strict settings
    let security_config = SecurityConfig::new()
        // Rate limiting: 100 requests per minute
        .with_rate_limit(100, 60)
        // JWT authentication
        .with_jwt_validation("your-super-secret-jwt-key-change-in-production")
        // Enable input sanitization
        .with_input_sanitization(true)
        // Enable strict mode for maximum security
        .strict_mode();

    // Build the API routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/public", get(public_handler))
        .route("/api/data", get(data_handler))
        .route("/api/user", post(create_user_handler))
        .route("/health", get(health_handler))
        // Apply security middleware to all routes
        .with_security(security_config);

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🛡️  SecureAPIs server running on http://{}", addr);
    println!("📊 Security features enabled:");
    println!("   - Rate limiting (100 req/min)");
    println!("   - JWT authentication");
    println!("   - SQL injection protection");
    println!("   - XSS protection");
    println!("   - Command injection protection");
    println!("   - Path traversal protection");
    println!("   - Threat detection");
    println!("   - Request logging");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Root handler
async fn root_handler() -> &'static str {
    "🛡️ SecureAPIs - Protected API Server"
}

// Public endpoint (no auth required, but still rate limited and validated)
async fn public_handler() -> Json<ApiResponse> {
    Json(ApiResponse {
        status: "success".to_string(),
        message: "This is a public endpoint".to_string(),
        data: None,
    })
}

// Protected data endpoint (requires authentication)
async fn data_handler() -> Json<ApiResponse> {
    Json(ApiResponse {
        status: "success".to_string(),
        message: "Secure data retrieved".to_string(),
        data: Some(serde_json::json!({
            "items": ["item1", "item2", "item3"],
            "count": 3
        })),
    })
}

// Create user endpoint (with input validation)
async fn create_user_handler(Json(payload): Json<CreateUserRequest>) -> Json<ApiResponse> {
    // Input is automatically validated by the security middleware
    Json(ApiResponse {
        status: "success".to_string(),
        message: format!("User {} created successfully", payload.username),
        data: Some(serde_json::json!({
            "user_id": "12345",
            "username": payload.username
        })),
    })
}

// Health check endpoint
async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

// Request/Response types
#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse {
    status: String,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}
