//! # Alert and warning system
//! 
//! Manages security alerts and warnings for various threat conditions.

use crate::ui::state::{UIState, Alert, AlertSeverity, AlertType};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;
use uuid::Uuid;

/// Alert manager
pub struct AlertManager {
    state: Arc<UIState>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(state: Arc<UIState>) -> Self {
        Self { state }
    }

    /// Create an alert for rate limit exceeded
    pub async fn alert_rate_limit_exceeded(&self, ip: &str, limit: u32) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Rate Limit Exceeded".to_string(),
            message: format!("IP {} has exceeded rate limit of {} requests", ip, limit),
            severity: AlertSeverity::Warning,
            alert_type: AlertType::RateLimitExceeded,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for unusual activity
    pub async fn alert_unusual_activity(&self, description: &str, threat_score: f64) {
        let severity = if threat_score > 80.0 {
            AlertSeverity::Critical
        } else if threat_score > 50.0 {
            AlertSeverity::Warning
        } else {
            AlertSeverity::Info
        };

        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Unusual Activity Detected".to_string(),
            message: format!("{} (Threat Score: {:.1}%)", description, threat_score),
            severity,
            alert_type: AlertType::UnusualActivity,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for authentication failure
    pub async fn alert_auth_failure(&self, user: &str, reason: &str) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Authentication Failure".to_string(),
            message: format!("Failed authentication for user '{}': {}", user, reason),
            severity: AlertSeverity::Warning,
            alert_type: AlertType::AuthenticationFailure,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for validation failure
    pub async fn alert_validation_failure(&self, ip: &str, attack_type: &str) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Input Validation Failed".to_string(),
            message: format!("Potential {} attack detected from {}", attack_type, ip),
            severity: AlertSeverity::Warning,
            alert_type: AlertType::ValidationFailure,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for DDoS detection
    pub async fn alert_dos_detected(&self, ip: &str, request_count: u32) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Potential DDoS Attack".to_string(),
            message: format!("IP {} making {} requests in short time window", ip, request_count),
            severity: AlertSeverity::Critical,
            alert_type: AlertType::DosDetected,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for configuration change
    pub async fn alert_config_changed(&self, changed_fields: Vec<String>) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "Configuration Changed".to_string(),
            message: format!("Security configuration updated: {}", changed_fields.join(", ")),
            severity: AlertSeverity::Info,
            alert_type: AlertType::ConfigurationChange,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for high threat score
    pub async fn alert_high_threat_score(&self, ip: &str, threat_score: f64) {
        let severity = if threat_score > 80.0 {
            AlertSeverity::Critical
        } else {
            AlertSeverity::Warning
        };

        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: "High Threat Score".to_string(),
            message: format!("IP {} has threat score of {:.1}%", ip, threat_score),
            severity,
            alert_type: AlertType::HighThreatScore,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Create an alert for anomaly detection
    pub async fn alert_anomaly_detected(&self, anomaly_type: &str, details: &str) {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            title: format!("Anomaly Detected: {}", anomaly_type),
            message: details.to_string(),
            severity: AlertSeverity::Warning,
            alert_type: AlertType::AnomalyDetected,
            dismissed: false,
            related_logs: vec![],
        };
        
        self.state.add_alert(alert).await;
    }

    /// Get all active alerts
    pub async fn get_alerts(&self) -> Vec<Alert> {
        self.state.get_alerts().await
    }

    /// Get alerts by severity
    pub async fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<Alert> {
        self.state
            .get_alerts()
            .await
            .into_iter()
            .filter(|a| a.severity == severity)
            .collect()
    }

    /// Get critical alerts only
    pub async fn get_critical_alerts(&self) -> Vec<Alert> {
        self.get_alerts_by_severity(AlertSeverity::Critical).await
    }

    /// Dismiss an alert
    pub async fn dismiss_alert(&self, alert_id: Uuid) {
        self.state.dismiss_alert(alert_id).await;
    }

    /// Dismiss all alerts
    pub async fn dismiss_all_alerts(&self) {
        let alerts = self.get_alerts().await;
        for alert in alerts {
            self.state.dismiss_alert(alert.id).await;
        }
    }

    /// Get alert summary
    pub async fn get_summary(&self) -> AlertSummary {
        let alerts = self.get_alerts().await;
        
        let critical = alerts.iter().filter(|a| a.severity == AlertSeverity::Critical).count() as u32;
        let warning = alerts.iter().filter(|a| a.severity == AlertSeverity::Warning).count() as u32;
        let info = alerts.iter().filter(|a| a.severity == AlertSeverity::Info).count() as u32;

        AlertSummary {
            total_alerts: alerts.len() as u32,
            critical,
            warning,
            info,
            requires_attention: critical > 0,
        }
    }

    /// Check for critical conditions and auto-create alerts
    pub async fn check_and_alert(&self) {
        let metrics = self.state.get_metrics_snapshot();
        
        // Alert if block rate is very high
        if metrics.block_rate > 10.0 {
            self.alert_unusual_activity(
                "Block rate is unusually high",
                metrics.block_rate.min(100.0),
            )
            .await;
        }

        // Alert if too many rate limit violations
        if metrics.rate_limited > 100 {
            self.alert_unusual_activity(
                "Many rate limit violations detected",
                75.0,
            )
            .await;
        }

        // Alert if too many auth failures
        if metrics.auth_failures > 50 {
            self.alert_unusual_activity(
                "Suspicious number of authentication failures",
                80.0,
            )
            .await;
        }
    }

    /// Get alert history
    pub async fn get_history(&self, limit: Option<usize>) -> Vec<AlertHistoryEntry> {
        let events = self.state.get_security_events(limit).await;
        
        events.into_iter().map(|e| AlertHistoryEntry {
            id: e.id,
            timestamp: e.timestamp.to_rfc3339(),
            event_type: e.event_type,
            severity: format!("{:?}", e.severity),
            description: e.description,
        }).collect()
    }
}

/// Alert summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total_alerts: u32,
    pub critical: u32,
    pub warning: u32,
    pub info: u32,
    pub requires_attention: bool,
}

/// Alert history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHistoryEntry {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub description: String,
}

/// Alert configuration for notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotificationConfig {
    pub email_on_critical: bool,
    pub slack_on_critical: bool,
    pub pagerduty_on_critical: bool,
    pub webhook_url: Option<String>,
    pub alert_cooldown_minutes: u32,
}

impl Default for AlertNotificationConfig {
    fn default() -> Self {
        Self {
            email_on_critical: true,
            slack_on_critical: false,
            pagerduty_on_critical: false,
            webhook_url: None,
            alert_cooldown_minutes: 5,
        }
    }
}
