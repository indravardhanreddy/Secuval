//! API endpoints for serving security data to the frontend

use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::ui::state::UIState;

/// Query parameters for blocked requests endpoint
#[derive(Debug, Deserialize)]
pub struct BlockedRequestsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub reason: Option<String>,
    pub ip: Option<String>,
    pub severity: Option<String>,
}

/// API response for blocked requests
#[derive(Debug, Serialize)]
pub struct BlockedRequestsResponse {
    pub requests: Vec<crate::blocked_requests::BlockedRequest>,
    pub total: usize,
    pub stats: crate::blocked_requests::BlockedRequestsStats,
}

/// Create API routes for security data
pub fn create_api_routes(ui_state: Arc<UIState>) -> Router {
    Router::new()
        .route("/api/blocked-requests", get(get_blocked_requests))
        .route("/api/metrics", get(get_metrics))
        .route("/api/request-logs", get(get_request_logs))
        .with_state(ui_state)
}

/// Get blocked requests with filtering and pagination
async fn get_blocked_requests(
    Query(params): Query<BlockedRequestsQuery>,
    axum::extract::State(ui_state): axum::extract::State<Arc<UIState>>,
) -> Result<Json<BlockedRequestsResponse>, StatusCode> {
    // Get blocked requests from the store
    let requests = ui_state.get_blocked_requests(params.limit, params.offset).await;
    let stats = ui_state.get_blocked_stats().await;

    Ok(Json(BlockedRequestsResponse {
        requests,
        total: stats.total_blocked,
        stats,
    }))
}

/// Get current security metrics
async fn get_metrics(
    axum::extract::State(ui_state): axum::extract::State<Arc<UIState>>,
) -> Json<crate::ui::state::MetricsSnapshot> {
    Json(ui_state.get_metrics_snapshot())
}

/// Get request logs
async fn get_request_logs(
    axum::extract::State(ui_state): axum::extract::State<Arc<UIState>>,
) -> Json<Vec<crate::ui::state::RequestLog>> {
    Json(ui_state.get_request_logs(Some(100)).await)
}