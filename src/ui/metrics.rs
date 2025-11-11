//! # Metrics collection and reporting
//! 
//! Collects and reports various metrics about security and performance.

use crate::ui::state::UIState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;
use std::collections::VecDeque;

/// Metrics collector
pub struct MetricsCollector {
    state: Arc<UIState>,
    history: Arc<tokio::sync::RwLock<VecDeque<MetricsSnapshot>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(state: Arc<UIState>) -> Self {
        Self {
            state,
            history: Arc::new(tokio::sync::RwLock::new(VecDeque::with_capacity(1440))), // 24 hours @ 1 min intervals
        }
    }

    /// Collect current metrics
    pub async fn collect(&self) -> MetricsSnapshot {
        let snapshot = self.state.get_metrics_snapshot();
        let requests = self.state.get_request_logs(Some(100)).await;
        
        let response_times: Vec<f64> = requests.iter().map(|r| r.response_time_ms).collect();
        
        let avg_response = if !response_times.is_empty() {
            response_times.iter().sum::<f64>() / response_times.len() as f64
        } else {
            0.0
        };

        let mut sorted_times = response_times.clone();
        sorted_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p95 = if !sorted_times.is_empty() {
            sorted_times[(sorted_times.len() as f64 * 0.95) as usize]
        } else {
            0.0
        };

        let p99 = if !sorted_times.is_empty() {
            sorted_times[(sorted_times.len() as f64 * 0.99) as usize]
        } else {
            0.0
        };

        let metrics_snapshot = MetricsSnapshot {
            timestamp: Utc::now(),
            total_requests: snapshot.total_requests,
            blocked_requests: snapshot.blocked_requests,
            rate_limited: snapshot.rate_limited,
            validation_failures: snapshot.validation_failures,
            auth_failures: snapshot.auth_failures,
            block_rate: snapshot.block_rate,
            avg_response_time_ms: avg_response,
            p95_response_time_ms: p95,
            p99_response_time_ms: p99,
            requests_per_second: (snapshot.total_requests as f64) / (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64 + 1.0),
        };

        // Store in history
        let mut history = self.history.write().await;
        if history.len() >= 1440 {
            history.pop_front();
        }
        history.push_back(metrics_snapshot.clone());

        metrics_snapshot
    }

    /// Get metrics history
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<MetricsSnapshot> {
        let history = self.history.read().await;
        let limit = limit.unwrap_or(100).min(history.len());
        history.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get metrics summary
    pub async fn get_summary(&self) -> MetricsSummary {
        let current = self.collect().await;
        let history = self.history.read().await;

        let previous = history.back().cloned().unwrap_or_else(|| current.clone());
        let current_rate = current.block_rate;
        let previous_rate = previous.block_rate;

        MetricsSummary {
            current: current.clone(),
            previous,
            trend: if current_rate > previous_rate {
                "increasing".to_string()
            } else {
                "decreasing".to_string()
            },
        }
    }

    /// Get security metrics
    pub async fn get_security_metrics(&self) -> SecurityMetrics {
        let snapshot = self.collect().await;
        
        SecurityMetrics {
            total_threats: snapshot.blocked_requests + snapshot.validation_failures + snapshot.auth_failures,
            blocked_by_rate_limit: snapshot.rate_limited,
            validation_failures: snapshot.validation_failures,
            authentication_failures: snapshot.auth_failures,
            blocked_by_threat_detection: snapshot.blocked_requests.saturating_sub(snapshot.rate_limited),
            avg_threat_level: (snapshot.block_rate * 100.0) as u32,
        }
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        let snapshot = self.collect().await;
        
        PerformanceMetrics {
            avg_response_time_ms: snapshot.avg_response_time_ms,
            p95_response_time_ms: snapshot.p95_response_time_ms,
            p99_response_time_ms: snapshot.p99_response_time_ms,
            requests_per_second: snapshot.requests_per_second,
            throughput_rps: snapshot.total_requests as f64 / 60.0, // Approximate per minute
        }
    }

    /// Get top threat sources (IPs)
    pub async fn get_top_threat_sources(&self) -> Vec<ThreatSource> {
        let logs = self.state.get_request_logs(Some(500)).await;
        
        let mut threats: std::collections::HashMap<String, ThreatSource> = std::collections::HashMap::new();

        for log in logs {
            threats
                .entry(log.client_ip.clone())
                .or_insert_with(|| ThreatSource {
                    ip: log.client_ip.clone(),
                    block_count: 0,
                    threat_score: 0.0,
                    last_blocked: Utc::now(),
                })
                .block_count += if log.blocked { 1 } else { 0 };

            if let Some(threat) = threats.get_mut(&log.client_ip) {
                threat.threat_score = (threat.threat_score + log.threat_score) / 2.0;
                threat.last_blocked = log.timestamp;
            }
        }

        let mut sources: Vec<_> = threats.into_values().collect();
        sources.sort_by(|a, b| {
            b.block_count.cmp(&a.block_count)
                .then_with(|| b.threat_score.partial_cmp(&a.threat_score).unwrap_or(std::cmp::Ordering::Equal))
        });

        sources.into_iter().take(10).collect()
    }

    /// Get threat distribution by type
    pub async fn get_threat_distribution(&self) -> Vec<ThreatDistribution> {
        let events = self.state.get_security_events(None).await;
        
        let mut distribution: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for event in events {
            *distribution.entry(event.event_type).or_insert(0) += 1;
        }

        let mut dist: Vec<_> = distribution
            .into_iter()
            .map(|(threat_type, count)| ThreatDistribution {
                threat_type,
                count,
                percentage: 0.0,
            })
            .collect();

        let total: u32 = dist.iter().map(|d| d.count).sum();
        for d in &mut dist {
            d.percentage = (d.count as f64 / total as f64 * 100.0).min(100.0);
        }

        dist.sort_by(|a, b| b.count.cmp(&a.count));
        dist
    }

    /// Get peak traffic times
    pub async fn get_peak_traffic_hours(&self) -> Vec<TrafficPeak> {
        let logs = self.state.get_request_logs(None).await;
        
        let mut hourly: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();

        for log in logs {
            let hour = log.timestamp.format("%H").to_string().parse::<u32>().unwrap_or(0);
            *hourly.entry(hour).or_insert(0) += 1;
        }

        let mut peaks: Vec<_> = hourly
            .into_iter()
            .map(|(hour, requests)| TrafficPeak {
                hour,
                requests,
            })
            .collect();

        peaks.sort_by(|a, b| b.requests.cmp(&a.requests));
        peaks.into_iter().take(10).collect()
    }

    /// Export metrics to JSON
    pub async fn export_metrics(&self) -> Result<String, String> {
        let summary = self.get_summary().await;
        serde_json::to_string_pretty(&summary)
            .map_err(|e| format!("Failed to serialize metrics: {}", e))
    }
}

/// Metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: chrono::DateTime<Utc>,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited: u64,
    pub validation_failures: u64,
    pub auth_failures: u64,
    pub block_rate: f64,
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub requests_per_second: f64,
}

/// Metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub current: MetricsSnapshot,
    pub previous: MetricsSnapshot,
    pub trend: String,
}

/// Security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub total_threats: u64,
    pub blocked_by_rate_limit: u64,
    pub validation_failures: u64,
    pub authentication_failures: u64,
    pub blocked_by_threat_detection: u64,
    pub avg_threat_level: u32,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub requests_per_second: f64,
    pub throughput_rps: f64,
}

/// Threat source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSource {
    pub ip: String,
    pub block_count: u32,
    pub threat_score: f64,
    pub last_blocked: chrono::DateTime<Utc>,
}

/// Threat distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDistribution {
    pub threat_type: String,
    pub count: u32,
    pub percentage: f64,
}

/// Traffic peak
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficPeak {
    pub hour: u32,
    pub requests: u32,
}
