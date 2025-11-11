//! # Dashboard component
//! 
//! Provides a comprehensive view of security metrics and system status.

use crate::ui::state::{UIState, MetricsSnapshot};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;

/// Dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub metrics: MetricsSnapshot,
    pub top_blocked_ips: Vec<IpBlockInfo>,
    pub threat_level: ThreatLevel,
    pub recent_events: Vec<DashboardEvent>,
    pub security_status: SecurityStatus,
    pub uptime_seconds: u64,
    pub active_sessions: u32,
}

/// Dashboard event summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardEvent {
    pub id: String,
    pub event_type: String,
    pub severity: String,
    pub timestamp: String,
    pub description: String,
}

/// Threat level classification
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub rate_limit_enabled: bool,
    pub validation_enabled: bool,
    pub auth_enabled: bool,
    pub threat_detection_enabled: bool,
    pub overall_status: String,
}

/// IP block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlockInfo {
    pub ip: String,
    pub block_count: u32,
    pub last_blocked: String,
    pub reason: String,
}

/// Dashboard component
pub struct Dashboard {
    state: Arc<UIState>,
    start_time: std::time::Instant,
}

impl Dashboard {
    /// Create a new dashboard
    pub fn new(state: Arc<UIState>) -> Self {
        Self {
            state,
            start_time: std::time::Instant::now(),
        }
    }

    /// Get dashboard data
    pub async fn get_data(&self) -> DashboardData {
        let config = self.state.get_config().await;
        let metrics = self.state.get_metrics_snapshot();
        let events = self.state.get_security_events(Some(5)).await;
        
        let threat_level = match metrics.block_rate {
            rate if rate > 10.0 => ThreatLevel::Critical,
            rate if rate > 5.0 => ThreatLevel::High,
            rate if rate > 1.0 => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        };

        let security_status = SecurityStatus {
            rate_limit_enabled: config.rate_limit.enabled,
            validation_enabled: config.validation.enabled,
            auth_enabled: config.auth.enabled,
            threat_detection_enabled: config.threat_detection.enabled,
            overall_status: if threat_level == ThreatLevel::Low {
                "Secure".to_string()
            } else {
                "Monitoring".to_string()
            },
        };

        let recent_events = events.iter().map(|e| DashboardEvent {
            id: e.id.clone(),
            event_type: e.event_type.clone(),
            severity: format!("{:?}", e.severity),
            timestamp: e.timestamp.to_rfc3339(),
            description: e.description.clone(),
        }).collect();

        DashboardData {
            metrics,
            top_blocked_ips: self.get_top_blocked_ips().await,
            threat_level,
            recent_events,
            security_status,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            active_sessions: 1, // Would be tracked separately in production
        }
    }

    /// Get dashboard health check
    pub async fn get_health(&self) -> HealthStatus {
        let config = self.state.get_config().await;
        
        HealthStatus {
            system_healthy: true,
            components: ComponentHealth {
                rate_limiting: config.rate_limit.enabled,
                validation: config.validation.enabled,
                authentication: config.auth.enabled,
                monitoring: config.monitoring.enabled,
                threat_detection: config.threat_detection.enabled,
            },
            last_check: Utc::now(),
        }
    }

    /// Get top blocked IPs
    async fn get_top_blocked_ips(&self) -> Vec<IpBlockInfo> {
        let logs = self.state.get_request_logs(Some(500)).await;
        let mut ip_blocks: std::collections::HashMap<String, (u32, String)> = std::collections::HashMap::new();

        for log in logs {
            if log.blocked {
                let entry = ip_blocks.entry(log.client_ip).or_insert((0, String::new()));
                entry.0 += 1;
                entry.1 = log.reason.unwrap_or_else(|| "Unknown".to_string());
            }
        }

        let mut top_ips: Vec<_> = ip_blocks
            .into_iter()
            .map(|(ip, (count, reason))| IpBlockInfo {
                ip,
                block_count: count,
                last_blocked: Utc::now().to_rfc3339(),
                reason,
            })
            .collect();

        top_ips.sort_by(|a, b| b.block_count.cmp(&a.block_count));
        top_ips.into_iter().take(10).collect()
    }

    /// Get threat timeline for chart
    pub async fn get_threat_timeline(&self, hours: u32) -> Vec<TimelinePoint> {
        let events = self.state.get_security_events(None).await;
        let now = Utc::now();
        
        let mut timeline: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        
        for event in events {
            let duration = now.signed_duration_since(event.timestamp);
            if duration.num_hours() <= hours as i64 {
                let hour = (duration.num_hours() as u32) % hours;
                *timeline.entry(hour).or_insert(0) += 1;
            }
        }

        let mut points: Vec<_> = timeline
            .into_iter()
            .map(|(hour, count)| TimelinePoint {
                timestamp: format!("{}h ago", hour),
                event_count: count,
            })
            .collect();

        points.sort_by_key(|p| p.timestamp.clone());
        points
    }
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub system_healthy: bool,
    pub components: ComponentHealth,
    pub last_check: chrono::DateTime<Utc>,
}

/// Component health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub rate_limiting: bool,
    pub validation: bool,
    pub authentication: bool,
    pub monitoring: bool,
    pub threat_detection: bool,
}

/// Timeline point for charts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub timestamp: String,
    pub event_count: u32,
}
