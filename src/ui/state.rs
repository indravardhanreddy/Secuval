//! # Shared UI state management
//! 
//! Manages the central state for the UI layer, including configuration, metrics, and events.

use crate::config::SecurityConfig;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::VecDeque;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Central UI state
pub struct UIState {
    /// Current security configuration (mutable)
    pub config: Arc<RwLock<SecurityConfig>>,
    
    /// Request metrics
    pub total_requests: Arc<AtomicU64>,
    pub blocked_requests: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    pub validation_failures: Arc<AtomicU64>,
    pub auth_failures: Arc<AtomicU64>,
    pub csrf_failures: Arc<AtomicU64>,
    
    /// Blocked requests store
    pub blocked_store: Arc<crate::blocked_requests::BlockedRequestsStore>,
    
    /// Recent request logs (thread-safe deque)
    pub request_logs: Arc<RwLock<VecDeque<RequestLog>>>,
    
    /// Security events log
    pub security_events: Arc<RwLock<VecDeque<SecurityEvent>>>,
    
    /// Active alerts
    pub alerts: Arc<RwLock<Vec<Alert>>>,
    
    /// Performance metrics
    pub performance_data: Arc<RwLock<PerformanceMetrics>>,
    
    /// User preferences
    pub preferences: Arc<RwLock<UIPreferences>>,
    
    /// Recent activity for dashboard
    pub activity_feed: Arc<RwLock<VecDeque<ActivityEntry>>>,
}

impl UIState {
    /// Create a new UI state with default settings
    pub fn new(config: SecurityConfig, blocked_store: Arc<crate::blocked_requests::BlockedRequestsStore>) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            total_requests: Arc::new(AtomicU64::new(0)),
            blocked_requests: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            validation_failures: Arc::new(AtomicU64::new(0)),
            auth_failures: Arc::new(AtomicU64::new(0)),
            csrf_failures: Arc::new(AtomicU64::new(0)),
            blocked_store,
            request_logs: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            security_events: Arc::new(RwLock::new(VecDeque::with_capacity(500))),
            alerts: Arc::new(RwLock::new(Vec::new())),
            performance_data: Arc::new(RwLock::new(PerformanceMetrics::default())),
            preferences: Arc::new(RwLock::new(UIPreferences::default())),
            activity_feed: Arc::new(RwLock::new(VecDeque::with_capacity(500))),
        }
    }

    /// Get current metrics snapshot
    pub fn get_metrics_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            blocked_requests: self.blocked_requests.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            csrf_failures: self.csrf_failures.load(Ordering::Relaxed),
            block_rate: if self.total_requests.load(Ordering::Relaxed) == 0 {
                0.0
            } else {
                (self.blocked_requests.load(Ordering::Relaxed) as f64
                    / self.total_requests.load(Ordering::Relaxed) as f64)
                    * 100.0
            },
        }
    }

    /// Add a request log entry
    pub async fn add_request_log(&self, log: RequestLog) {
        let mut logs = self.request_logs.write().await;
        if logs.len() >= 1000 {
            logs.pop_front();
        }
        logs.push_back(log);
    }

    /// Add a security event
    pub async fn add_security_event(&self, event: SecurityEvent) {
        let mut events = self.security_events.write().await;
        if events.len() >= 500 {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Add an alert
    pub async fn add_alert(&self, alert: Alert) {
        let mut alerts = self.alerts.write().await;
        alerts.push(alert);
    }

    /// Dismiss an alert by ID
    pub async fn dismiss_alert(&self, alert_id: Uuid) {
        let mut alerts = self.alerts.write().await;
        alerts.retain(|a| a.id != alert_id);
    }

    /// Add activity entry
    pub async fn add_activity(&self, activity: ActivityEntry) {
        let mut feed = self.activity_feed.write().await;
        if feed.len() >= 500 {
            feed.pop_front();
        }
        feed.push_back(activity);
    }

    /// Get request logs with optional filtering
    pub async fn get_request_logs(&self, limit: Option<usize>) -> Vec<RequestLog> {
        let logs = self.request_logs.read().await;
        let limit = limit.unwrap_or(100).min(logs.len());
        logs.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Search request logs
    pub async fn search_request_logs(&self, query: &str) -> Vec<RequestLog> {
        let logs = self.request_logs.read().await;
        logs.iter()
            .filter(|log| {
                log.method.to_uppercase().contains(&query.to_uppercase())
                    || log.path.contains(query)
                    || log.client_ip.contains(query)
                    || log.user_agent.contains(query)
            })
            .cloned()
            .collect()
    }

    /// Get security events with optional filtering
    pub async fn get_security_events(&self, limit: Option<usize>) -> Vec<SecurityEvent> {
        let events = self.security_events.read().await;
        let limit = limit.unwrap_or(50).min(events.len());
        events.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get active alerts
    pub async fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await.clone()
    }

    /// Get activity feed
    pub async fn get_activity_feed(&self, limit: Option<usize>) -> Vec<ActivityEntry> {
        let feed = self.activity_feed.read().await;
        let limit = limit.unwrap_or(50).min(feed.len());
        feed.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Update configuration
    pub async fn update_config(&self, config: SecurityConfig) {
        *self.config.write().await = config;
    }

    /// Get current configuration
    pub async fn get_config(&self) -> SecurityConfig {
        self.config.read().await.clone()
    }

    /// Update preferences
    pub async fn update_preferences(&self, prefs: UIPreferences) {
        *self.preferences.write().await = prefs;
    }

    /// Get current preferences
    pub async fn get_preferences(&self) -> UIPreferences {
        self.preferences.read().await.clone()
    }

    /// Get blocked requests with optional filtering
    pub async fn get_blocked_requests(&self, limit: Option<usize>, offset: Option<usize>) -> Vec<crate::blocked_requests::BlockedRequest> {
        let all_requests = self.blocked_store.get_blocked_requests().await;
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100).min(1000); // Max 1000 for performance
        
        all_requests.into_iter()
            .skip(offset)
            .take(limit)
            .collect()
    }

    /// Get blocked requests statistics
    pub async fn get_blocked_stats(&self) -> crate::blocked_requests::BlockedRequestsStats {
        self.blocked_store.get_stats().await
    }
}

/// Request log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub client_ip: String,
    pub user_agent: String,
    pub user_id: Option<String>,
    pub status_code: u16,
    pub response_time_ms: f64,
    pub threat_score: f64,
    pub blocked: bool,
    pub reason: Option<String>,
    pub headers: std::collections::HashMap<String, String>,
}

/// Security event entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: EventSeverity,
    pub description: String,
    pub client_ip: Option<String>,
    pub user_id: Option<String>,
    pub details: serde_json::Value,
}

/// Security event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Alert for security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub alert_type: AlertType,
    pub dismissed: bool,
    pub related_logs: Vec<String>,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Alert types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertType {
    RateLimitExceeded,
    UnusualActivity,
    AuthenticationFailure,
    ValidationFailure,
    DosDetected,
    ConfigurationChange,
    HighThreatScore,
    AnomalyDetected,
}

/// Activity feed entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub activity_type: String,
    pub description: String,
    pub details: Option<serde_json::Value>,
    pub severity: EventSeverity,
}

/// UI Preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UIPreferences {
    pub theme: String, // "light" or "dark"
    pub refresh_interval_ms: u64,
    pub log_retention_days: u32,
    pub alert_sound_enabled: bool,
    pub auto_refresh_enabled: bool,
    pub items_per_page: u32,
    pub timezone: String,
}

impl Default for UIPreferences {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            refresh_interval_ms: 5000,
            log_retention_days: 30,
            alert_sound_enabled: true,
            auto_refresh_enabled: true,
            items_per_page: 50,
            timezone: "UTC".to_string(),
        }
    }
}

/// Performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub requests_per_second: f64,
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
}

/// Metrics snapshot for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited: u64,
    pub validation_failures: u64,
    pub auth_failures: u64,
    pub csrf_failures: u64,
    pub block_rate: f64,
}
