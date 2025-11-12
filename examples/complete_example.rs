//! # Complete Example: Secure API with All Features
//! 
//! This example demonstrates a fully secured API using the SecureAPIs middleware
//! with all security features enabled.

//! # Complete Example: Secure API with All Features
//!
//! This example demonstrates a fully secured API using the SecureAPIs middleware
//! with all security features enabled.

use axum::{
    routing::{get, post},
    Json, Router, middleware,
};
use secureapis::prelude::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// Security headers middleware
async fn security_headers_middleware<B>(
    mut response: axum::response::Response<B>,
) -> axum::response::Response<B> {
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}

// Include the Axum integration module
mod integrations;
use integrations::axum::SecurityRouterExt;

/// API Response structure
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
struct ApiResponse {
    /// Response status
    status: String,
    /// Response message
    message: String,
    /// Optional response data
    data: Option<serde_json::Value>,
}

/// User creation request
#[derive(Debug, Deserialize, utoipa::ToSchema)]
struct CreateUserRequest {
    /// Username for the new user
    username: String,
    /// Email address for the new user
    email: String,
}

/// Health check response
#[derive(Debug, Serialize, utoipa::ToSchema)]
struct HealthResponse {
    /// Health status
    status: String,
    /// API version
    version: String,
}

#[derive(OpenApi)]
#[openapi(
    paths(
        root_handler,
        public_handler,
        data_handler,
        create_user_handler,
        test_secure_handler,
        health_handler
    ),
    components(
        schemas(ApiResponse, CreateUserRequest, HealthResponse)
    ),
    info(
        title = "SecureAPIs - Protected API Server",
        version = "0.1.0",
        description = "High-performance API security middleware with comprehensive protection against vulnerabilities"
    ),
    servers(
        (url = "http://localhost:3000", description = "Local development server")
    ),
    security(
        ("jwt_token" = [])
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Configure security layer with strict settings
    let security_config = SecurityConfig::new()
        // Rate limiting: 100 requests per minute
        .with_rate_limit(100000, 60)
        // JWT authentication
        .with_jwt_validation("your-super-secret-jwt-key-change-in-production")
        // Enable input sanitization
        .with_input_sanitization(true)
        // Enable strict mode for maximum security
        .strict_mode();

    // Create blocked requests store
    let blocked_store = Arc::new(secureapis::blocked_requests::BlockedRequestsStore::new(
        "blocked_requests.json".to_string(),
        1000,
    ));

    // Create UI manager for dashboard and monitoring
    let ui_manager = secureapis::ui::UIManager::new(security_config.clone(), blocked_store.clone());

    // Create security layer with UI state for tracking and share the blocked_store
    let security_layer = secureapis::core::SecurityLayer::new(security_config.clone())
        .with_blocked_store(blocked_store.clone())
        .with_ui_state(ui_manager.state.clone());

    // Build the API routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/public", get(public_handler))
        .route("/api/data", get(data_handler))
        .route("/api/user", post(create_user_handler))
        .route("/api/test/secure", get(test_secure_handler))
        .route("/health", get(health_handler))
    .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
    // Add top-level blocked-requests API (used by frontend blocked requests page)
    .merge(secureapis::api::create_api_routes(ui_manager.state.clone()))
    // Add UI dashboard routes
    .merge(secureapis::ui::api::UIRouter::create_router(ui_manager.state.clone()))
        // Apply security middleware to all routes
        .with_security_layer(Arc::new(security_layer))
        // Add security headers to all responses
        .layer(middleware::map_response(security_headers_middleware));

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🛡️  SecureAPIs server running on http://{}", addr);
    println!("� Swagger UI available at: http://{:}/swagger-ui", addr);
    println!("📄 OpenAPI spec at: http://{:}/api-docs/openapi.json", addr);
    println!("�📊 Security features enabled:");
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
#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "API server information", body = String)
    )
)]
async fn root_handler() -> &'static str {
    "🛡️ SecureAPIs - Protected API Server"
}

// Public endpoint (no auth required, but still rate limited and validated)
#[utoipa::path(
    get,
    path = "/api/public",
    responses(
        (status = 200, description = "Public endpoint response", body = ApiResponse),
        (status = 429, description = "Rate limit exceeded")
    ),
    security(())
)]
async fn public_handler() -> Json<ApiResponse> {
    Json(ApiResponse {
        status: "success".to_string(),
        message: "This is a public endpoint".to_string(),
        data: None,
    })
}

// Protected data endpoint (requires authentication)
#[utoipa::path(
    get,
    path = "/api/data",
    responses(
        (status = 200, description = "Secure data retrieved", body = ApiResponse),
        (status = 401, description = "Authentication required"),
        (status = 429, description = "Rate limit exceeded")
    )
)]
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
#[utoipa::path(
    post,
    path = "/api/user",
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created successfully", body = ApiResponse),
        (status = 400, description = "Invalid input data"),
        (status = 422, description = "Input validation failed"),
        (status = 429, description = "Rate limit exceeded")
    ),
    security(())
)]
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

// Test endpoint for load testing (accepts any input for security testing)
#[utoipa::path(
    get,
    path = "/api/test/secure",
    responses(
        (status = 200, description = "Test endpoint response", body = ApiResponse),
        (status = 400, description = "Bad request"),
        (status = 429, description = "Rate limit exceeded")
    )
)]
async fn test_secure_handler(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>
) -> Json<ApiResponse> {
    // This endpoint accepts any input to test security features
    let input = params.get("input").unwrap_or(&"".to_string()).clone();
    let test_type = params.get("type").unwrap_or(&"unknown".to_string()).clone();

    Json(ApiResponse {
        status: "success".to_string(),
        message: format!("Test {} processed", test_type),
        data: Some(serde_json::json!({
            "input_length": input.len(),
            "test_type": test_type,
            "processed": true
        })),
    })
}

// Health check endpoint
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Health check response", body = HealthResponse)
    ),
    security(())
)]
async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
