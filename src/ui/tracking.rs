//! # Request tracking system
//! 
//! Tracks and provides detailed information about API requests and responses.

use crate::ui::state::{UIState, RequestLog};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

/// Request tracker
pub struct RequestTracker {
    state: Arc<UIState>,
}

impl RequestTracker {
    /// Create a new request tracker
    pub fn new(state: Arc<UIState>) -> Self {
        Self { state }
    }

    /// Track a new request
    pub async fn track_request(
        &self,
        method: String,
        path: String,
        client_ip: String,
        user_agent: String,
        user_id: Option<String>,
        threat_score: f64,
    ) -> String {
        let request_id = Uuid::new_v4().to_string();
        
        let log = RequestLog {
            id: request_id.clone(),
            timestamp: Utc::now(),
            method,
            path,
            client_ip,
            user_agent,
            user_id,
            status_code: 200,
            response_time_ms: 0.0,
            threat_score,
            blocked: false,
            reason: None,
            headers: std::collections::HashMap::new(),
        };

        self.state.add_request_log(log).await;
        self.state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        request_id
    }

    /// Update request with response data
    pub async fn update_request(
        &self,
        request_id: &str,
        status_code: u16,
        response_time_ms: f64,
        blocked: bool,
        reason: Option<String>,
    ) {
        let mut logs = self.state.request_logs.write().await;
        
        if let Some(log) = logs.iter_mut().rfind(|l| l.id == request_id) {
            log.status_code = status_code;
            log.response_time_ms = response_time_ms;
            log.blocked = blocked;
            log.reason = reason;

            if blocked {
                self.state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Get request statistics
    pub async fn get_statistics(&self) -> RequestStatistics {
        let logs = self.state.get_request_logs(Some(1000)).await;
        
        let total = logs.len() as u64;
        let blocked = logs.iter().filter(|l| l.blocked).count() as u64;
        
        let response_times: Vec<_> = logs.iter().map(|l| l.response_time_ms).collect();
        let response_times_sorted = {
            let mut times = response_times.clone();
            times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            times
        };

        let avg_response = if !response_times.is_empty() {
            response_times.iter().sum::<f64>() / response_times.len() as f64
        } else {
            0.0
        };

        let p95 = if !response_times_sorted.is_empty() {
            response_times_sorted[(response_times_sorted.len() as f64 * 0.95) as usize]
        } else {
            0.0
        };

        let p99 = if !response_times_sorted.is_empty() {
            response_times_sorted[(response_times_sorted.len() as f64 * 0.99) as usize]
        } else {
            0.0
        };

        let methods: std::collections::HashMap<_, u32> = logs.iter().fold(
            std::collections::HashMap::new(),
            |mut map, log| {
                *map.entry(log.method.clone()).or_insert(0) += 1;
                map
            },
        );

        let methods = methods
            .into_iter()
            .map(|(method, count)| MethodStats { method, count })
            .collect();

        RequestStatistics {
            total_requests: total,
            blocked_requests: blocked,
            block_rate: (blocked as f64 / total as f64 * 100.0).min(100.0),
            avg_response_time_ms: avg_response,
            p95_response_time_ms: p95,
            p99_response_time_ms: p99,
            unique_ips: logs.iter().map(|l| l.client_ip.clone()).collect::<std::collections::HashSet<_>>().len() as u32,
            methods,
        }
    }

    /// Get requests by path
    pub async fn get_requests_by_path(&self) -> Vec<PathStats> {
        let logs = self.state.get_request_logs(Some(1000)).await;
        
        let mut path_stats: std::collections::HashMap<String, PathStats> = std::collections::HashMap::new();

        for log in logs {
            path_stats
                .entry(log.path.clone())
                .or_insert_with(|| PathStats {
                    path: log.path.clone(),
                    count: 0,
                    blocked: 0,
                    avg_response_time: 0.0,
                })
                .count += 1;

            if log.blocked {
                path_stats.get_mut(&log.path).unwrap().blocked += 1;
            }
        }

        let mut stats: Vec<_> = path_stats.into_values().collect();
        stats.sort_by(|a, b| b.count.cmp(&a.count));
        stats.into_iter().take(20).collect()
    }

    /// Get requests by client IP
    pub async fn get_requests_by_ip(&self) -> Vec<IpStats> {
        let logs = self.state.get_request_logs(Some(1000)).await;
        
        let mut ip_stats: std::collections::HashMap<String, IpStats> = std::collections::HashMap::new();

        for log in logs {
            ip_stats
                .entry(log.client_ip.clone())
                .or_insert_with(|| IpStats {
                    ip: log.client_ip.clone(),
                    count: 0,
                    blocked: 0,
                    threat_score: 0.0,
                    user_agent: String::new(),
                })
                .count += 1;

            if log.blocked {
                ip_stats.get_mut(&log.client_ip).unwrap().blocked += 1;
            }
            
            ip_stats.get_mut(&log.client_ip).unwrap().threat_score = log.threat_score;
            ip_stats.get_mut(&log.client_ip).unwrap().user_agent = log.user_agent.clone();
        }

        let mut stats: Vec<_> = ip_stats.into_values().collect();
        stats.sort_by(|a, b| b.count.cmp(&a.count));
        stats.into_iter().take(20).collect()
    }

    /// Search requests
    pub async fn search_requests(&self, query: &str) -> Vec<RequestLog> {
        self.state.search_request_logs(query).await
    }

    /// Get requests with filters
    pub async fn get_filtered_requests(&self, filter: RequestFilter) -> Vec<RequestLog> {
        let logs = self.state.get_request_logs(None).await;
        
        logs.into_iter()
            .filter(|log| {
                if let Some(method) = &filter.method {
                    if !log.method.eq_ignore_ascii_case(method) {
                        return false;
                    }
                }
                
                if let Some(ip) = &filter.client_ip {
                    if log.client_ip != *ip {
                        return false;
                    }
                }
                
                if filter.blocked_only && !log.blocked {
                    return false;
                }
                
                if let Some(min_threat) = filter.min_threat_score {
                    if log.threat_score < min_threat {
                        return false;
                    }
                }
                
                true
            })
            .collect()
    }

    /// Get request trends over time
    pub async fn get_trends(&self, minutes: u32) -> Vec<TrendPoint> {
        let logs = self.state.get_request_logs(None).await;
        let now = Utc::now();
        
        let mut trend_data: std::collections::HashMap<u32, TrendMetrics> = std::collections::HashMap::new();
        
        for log in logs {
            let duration = now.signed_duration_since(log.timestamp);
            if duration.num_minutes() <= minutes as i64 {
                let minute = (duration.num_minutes() as u32) % minutes;
                let metrics = trend_data.entry(minute).or_insert_with(TrendMetrics::default);
                metrics.total_requests += 1;
                if log.blocked {
                    metrics.blocked_requests += 1;
                }
                metrics.avg_response_time += log.response_time_ms;
            }
        }

        let mut points: Vec<_> = trend_data
            .into_iter()
            .map(|(minute, metrics)| TrendPoint {
                minute,
                total_requests: metrics.total_requests,
                blocked_requests: metrics.blocked_requests,
                avg_response_time_ms: if metrics.total_requests > 0 {
                    metrics.avg_response_time / metrics.total_requests as f64
                } else {
                    0.0
                },
            })
            .collect();

        points.sort_by_key(|p| p.minute);
        points
    }
}

/// Request statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStatistics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub block_rate: f64,
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub unique_ips: u32,
    pub methods: Vec<MethodStats>,
}

/// Method statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodStats {
    pub method: String,
    pub count: u32,
}

/// Path statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStats {
    pub path: String,
    pub count: u32,
    pub blocked: u32,
    pub avg_response_time: f64,
}

/// IP statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpStats {
    pub ip: String,
    pub count: u32,
    pub blocked: u32,
    pub threat_score: f64,
    pub user_agent: String,
}

/// Request filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFilter {
    pub method: Option<String>,
    pub client_ip: Option<String>,
    pub blocked_only: bool,
    pub min_threat_score: Option<f64>,
}

/// Trend point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub minute: u32,
    pub total_requests: u32,
    pub blocked_requests: u32,
    pub avg_response_time_ms: f64,
}

/// Trend metrics
#[derive(Debug, Default, Clone)]
struct TrendMetrics {
    total_requests: u32,
    blocked_requests: u32,
    avg_response_time: f64,
}
