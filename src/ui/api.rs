//! # Web API routes for UI
//! 
//! Provides HTTP endpoints for the UI dashboard and settings management.

use crate::ui::state::UIState;
use crate::ui::settings::{SettingsManager, SettingsUpdate};
use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// UI Router
pub struct UIRouter {
    state: Arc<UIState>,
}

impl UIRouter {
    /// Create a new UI router
    pub fn new(state: Arc<UIState>) -> Self {
        Self { state }
    }

    /// Create the Axum router with real state integration
    pub fn create_router(state: Arc<UIState>) -> Router {
        Router::new()
            // Dashboard endpoints
            .route(
                "/api/ui/dashboard",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let metrics = state.get_metrics_snapshot();
                            let requests = state.get_request_logs(Some(5)).await;
                            
                            // Calculate top blocked IPs
                            let all_requests = state.get_request_logs(Some(1000)).await;
                            let mut ip_blocks: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
                            
                            for req in &all_requests {
                                if req.blocked {
                                    *ip_blocks.entry(req.client_ip.clone()).or_insert(0) += 1;
                                }
                            }
                            
                            let mut top_blocked: Vec<_> = ip_blocks.into_iter().collect();
                            top_blocked.sort_by(|a, b| b.1.cmp(&a.1));
                            
                            let top_blocked_ips: Vec<_> = top_blocked.into_iter().take(10).map(|(ip, count)| {
                                serde_json::json!({
                                    "ip": ip,
                                    "block_count": count,
                                })
                            }).collect();
                            
                            // Calculate total blocked (includes validation failures, rate limiting, and auth failures)
                            let total_blocked = metrics.blocked_requests + metrics.validation_failures + metrics.rate_limited + metrics.auth_failures;
                            let actual_block_rate = if metrics.total_requests == 0 {
                                0.0
                            } else {
                                (total_blocked as f64 / metrics.total_requests as f64) * 100.0
                            };
                            
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "metrics": {
                                        "total_requests": metrics.total_requests,
                                        "blocked_requests": metrics.blocked_requests,
                                        "rate_limited": metrics.rate_limited,
                                        "validation_failures": metrics.validation_failures,
                                        "auth_failures": metrics.auth_failures,
                                        "total_blocked": total_blocked,
                                        "block_rate": actual_block_rate,
                                    },
                                    "threat_level": if actual_block_rate > 50.0 { "critical" } else if actual_block_rate > 20.0 { "high" } else if actual_block_rate > 5.0 { "medium" } else { "low" },
                                    "top_blocked_ips": top_blocked_ips,
                                    "security_status": {
                                        "overall": "secure",
                                        "rate_limit_enabled": true,
                                        "validation_enabled": true,
                                        "auth_enabled": false,
                                    },
                                    "uptime_seconds": 3600,
                                    "recent_requests": requests.iter().map(|r| {
                                        serde_json::json!({
                                            "id": r.id,
                                            "timestamp": r.timestamp.to_rfc3339(),
                                            "method": r.method,
                                            "path": r.path,
                                            "client_ip": r.client_ip,
                                            "status_code": r.status_code,
                                            "blocked": r.blocked,
                                        })
                                    }).collect::<Vec<_>>(),
                                }
                            }))
                        }
                    }
                }),
            )
            // Blocked IPs endpoint
            .route(
                "/api/ui/blocked-ips",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let all_requests = state.get_request_logs(Some(2000)).await;
                            
                            let mut ip_stats: std::collections::HashMap<String, (u32, u32, f64, Option<chrono::DateTime<chrono::Utc>>)> = std::collections::HashMap::new();
                            
                            for req in &all_requests {
                                let entry = ip_stats.entry(req.client_ip.clone()).or_insert((0, 0, 0.0, None));
                                entry.0 += 1; // total requests
                                if req.blocked {
                                    entry.1 += 1; // blocked count
                                    entry.3 = Some(req.timestamp); // last blocked time
                                }
                                entry.2 = (entry.2 + req.threat_score) / 2.0; // avg threat score
                            }
                            
                            let mut blocked_ips: Vec<_> = ip_stats
                                .into_iter()
                                .filter(|(_, (_, blocked, _, _))| *blocked > 0)
                                .map(|(ip, (total, blocked, threat_score, last_blocked))| {
                                    serde_json::json!({
                                        "ip": ip,
                                        "total_requests": total,
                                        "block_count": blocked,
                                        "threat_score": threat_score,
                                        "block_rate": (blocked as f64 / total as f64 * 100.0),
                                        "last_blocked": last_blocked.map(|t| t.to_rfc3339()),
                                    })
                                })
                                .collect();
                            
                            blocked_ips.sort_by(|a, b| {
                                let a_count = a.get("block_count").and_then(|v| v.as_u64()).unwrap_or(0);
                                let b_count = b.get("block_count").and_then(|v| v.as_u64()).unwrap_or(0);
                                b_count.cmp(&a_count)
                            });
                            
                            let total_blocked = blocked_ips.len();
                            let top_blocked: Vec<_> = blocked_ips.into_iter().take(50).collect();
                            
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "blocked_ips": top_blocked,
                                    "total_blocked_ips": total_blocked,
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/health",
                get(|| async {
                    Json(serde_json::json!({
                        "healthy": true,
                        "status": "operational"
                    }))
                }),
            )
            .route(
                "/api/ui/alerts",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let alerts = state.get_alerts().await;
                            let critical = alerts.iter().filter(|a| a.severity == crate::ui::state::AlertSeverity::Critical).count();
                            let warning = alerts.iter().filter(|a| a.severity == crate::ui::state::AlertSeverity::Warning).count();
                            
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "summary": {
                                        "total": alerts.len(),
                                        "critical": critical,
                                        "warning": warning,
                                        "info": alerts.iter().filter(|a| a.severity == crate::ui::state::AlertSeverity::Info).count(),
                                        "requires_attention": critical > 0 || warning > 0,
                                    },
                                    "alerts": alerts.iter().take(10).map(|a| {
                                        serde_json::json!({
                                            "id": a.id.to_string(),
                                            "title": a.title,
                                            "message": a.message,
                                            "severity": format!("{:?}", a.severity),
                                            "timestamp": a.timestamp.to_rfc3339(),
                                        })
                                    }).collect::<Vec<_>>(),
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/alerts/:id/dismiss",
                post({
                    let state = state.clone();
                    move |Path(id): Path<String>| {
                        let state = state.clone();
                        async move {
                            if let Ok(alert_id) = uuid::Uuid::parse_str(&id) {
                                state.dismiss_alert(alert_id).await;
                                (StatusCode::OK, Json(serde_json::json!({ "status": "dismissed" })))
                            } else {
                                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Invalid alert ID" })))
                            }
                        }
                    }
                }),
            )
            // Request tracking
            .route(
                "/api/ui/requests",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let logs = state.get_request_logs(Some(50)).await;
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "requests": logs.iter().map(|r| {
                                        serde_json::json!({
                                            "id": r.id,
                                            "timestamp": r.timestamp.to_rfc3339(),
                                            "method": r.method,
                                            "path": r.path,
                                            "client_ip": r.client_ip,
                                            "status_code": r.status_code,
                                            "response_time_ms": r.response_time_ms,
                                            "threat_score": r.threat_score,
                                            "blocked": r.blocked,
                                            "reason": r.reason,
                                        })
                                    }).collect::<Vec<_>>(),
                                    "total": logs.len(),
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/requests/search",
                post({
                    let state = state.clone();
                    move |Json(query): Json<SearchQuery>| {
                        let state = state.clone();
                        async move {
                            let results = state.search_request_logs(&query.q).await;
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "results": results.iter().map(|r| {
                                        serde_json::json!({
                                            "id": r.id,
                                            "timestamp": r.timestamp.to_rfc3339(),
                                            "method": r.method,
                                            "path": r.path,
                                            "client_ip": r.client_ip,
                                        })
                                    }).collect::<Vec<_>>(),
                                    "count": results.len(),
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/requests/stats",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let metrics = state.get_metrics_snapshot();
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "total_requests": metrics.total_requests,
                                    "blocked_requests": metrics.blocked_requests,
                                    "rate_limited": metrics.rate_limited,
                                    "validation_failures": metrics.validation_failures,
                                    "auth_failures": metrics.auth_failures,
                                    "block_rate": metrics.block_rate,
                                }
                            }))
                        }
                    }
                }),
            )
            // Settings management
            .route(
                "/api/ui/settings",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let config = state.get_config().await;
                            let prefs = state.get_preferences().await;
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "security": {
                                        "rate_limit_enabled": config.rate_limit.enabled,
                                        "rate_limit_requests": config.rate_limit.requests_per_window,
                                        "rate_limit_window_secs": config.rate_limit.window_duration.as_secs(),
                                        "validation_enabled": config.validation.enabled,
                                        "auth_enabled": config.auth.enabled,
                                    },
                                    "ui": {
                                        "theme": prefs.theme,
                                        "refresh_interval_ms": prefs.refresh_interval_ms,
                                        "auto_refresh_enabled": prefs.auto_refresh_enabled,
                                        "alert_sound_enabled": prefs.alert_sound_enabled,
                                    }
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/settings",
                put({
                    let state = state.clone();
                    move |Json(updates): Json<SettingsUpdate>| {
                        let state = state.clone();
                        async move {
                            let manager = SettingsManager::new(state);
                            match manager.batch_update(updates).await {
                                Ok(all_settings) => {
                                    (StatusCode::OK, Json(serde_json::json!({ 
                                        "success": true,
                                        "status": "updated",
                                        "data": all_settings
                                    })))
                                }
                                Err(e) => {
                                    (StatusCode::BAD_REQUEST, Json(serde_json::json!({ 
                                        "success": false,
                                        "error": e 
                                    })))
                                }
                            }
                        }
                    }
                }),
            )
            .route(
                "/api/ui/settings/reset",
                post({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let manager = SettingsManager::new(state);
                            match manager.reset_to_defaults().await {
                                Ok(config) => {
                                    (StatusCode::OK, Json(serde_json::json!({ 
                                        "success": true,
                                        "status": "reset",
                                        "data": {
                                            "security": config,
                                            "ui": manager.get_ui_preferences().await
                                        }
                                    })))
                                }
                                Err(e) => {
                                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ 
                                        "success": false,
                                        "error": e 
                                    })))
                                }
                            }
                        }
                    }
                }),
            )
            // Metrics
            .route(
                "/api/ui/metrics",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let metrics = state.get_metrics_snapshot();
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "timestamp": chrono::Utc::now().to_rfc3339(),
                                    "total_requests": metrics.total_requests,
                                    "blocked_requests": metrics.blocked_requests,
                                    "rate_limited": metrics.rate_limited,
                                    "validation_failures": metrics.validation_failures,
                                    "auth_failures": metrics.auth_failures,
                                    "block_rate": metrics.block_rate,
                                    "avg_response_time_ms": 0.0,
                                    "p95_response_time_ms": 0.0,
                                    "p99_response_time_ms": 0.0,
                                    "requests_per_second": 0.0,
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/metrics/security",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let metrics = state.get_metrics_snapshot();
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "total_threats": metrics.blocked_requests + metrics.validation_failures + metrics.auth_failures,
                                    "blocked_by_rate_limit": metrics.rate_limited,
                                    "validation_failures": metrics.validation_failures,
                                    "auth_failures": metrics.auth_failures,
                                    "avg_threat_level": (metrics.block_rate * 100.0) as u32,
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/metrics/performance",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let metrics = state.get_metrics_snapshot();
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "avg_response_time_ms": 0.0,
                                    "p95_response_time_ms": 0.0,
                                    "p99_response_time_ms": 0.0,
                                    "requests_per_second": 0.0,
                                    "throughput_rps": metrics.total_requests as f64 / 60.0,
                                }
                            }))
                        }
                    }
                }),
            )
            // Activity and events
            .route(
                "/api/ui/events",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let events = state.get_security_events(Some(50)).await;
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "events": events.iter().map(|e| {
                                        serde_json::json!({
                                            "id": e.id,
                                            "timestamp": e.timestamp.to_rfc3339(),
                                            "event_type": e.event_type,
                                            "severity": format!("{:?}", e.severity),
                                            "description": e.description,
                                            "client_ip": e.client_ip,
                                        })
                                    }).collect::<Vec<_>>(),
                                    "total": events.len(),
                                }
                            }))
                        }
                    }
                }),
            )
            .route(
                "/api/ui/activity",
                get({
                    let state = state.clone();
                    move || {
                        let state = state.clone();
                        async move {
                            let activity = state.get_activity_feed(Some(50)).await;
                            Json(serde_json::json!({
                                "success": true,
                                "data": {
                                    "activity": activity.iter().map(|a| {
                                        serde_json::json!({
                                            "id": a.id,
                                            "timestamp": a.timestamp.to_rfc3339(),
                                            "activity_type": a.activity_type,
                                            "description": a.description,
                                            "severity": format!("{:?}", a.severity),
                                        })
                                    }).collect::<Vec<_>>(),
                                    "total": activity.len(),
                                }
                            }))
                        }
                    }
                }),
            )
            }

    /// Serve the UI server
    pub async fn serve(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let router = Self::create_router(self.state.clone());
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;
        Ok(())
    }
}

/// Search query
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

/// Pagination query
#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}
