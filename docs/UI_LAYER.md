# 🛡️ SecureAPIs - UI Layer Documentation

## Overview

The UI Layer provides a comprehensive, dynamic web-based dashboard and monitoring interface for the SecureAPIs security middleware. It enables real-time tracking of all API requests, threat detection, alert management, and dynamic configuration of security settings.

## 🎯 Core Features

### 1. **Real-Time Dashboard**
- **Threat Level Monitoring**: Visual threat classification (Low, Medium, High, Critical)
- **Security Status**: View status of all security components
- **Top Blocked IPs**: Identify repeat offenders
- **Recent Events**: Last 5 security events with details
- **System Uptime**: Track security layer availability
- **Health Checks**: Component-level health monitoring

### 2. **Comprehensive Request Tracking**
- **Request Logging**: Track up to 1,000 recent requests
- **Detailed Metrics**: 
  - Average, P95, P99 response times
  - Block rates and statistics
  - Method distribution
  - Path analysis
- **Client IP Analysis**: Track requests per IP with threat scores
- **Search & Filter**: 
  - Search by method, path, or IP
  - Filter by status, threat score, or block status
- **Trend Analysis**: Traffic patterns over time

### 3. **Dynamic Alert System**
- **Alert Types**:
  - Rate limit exceeded
  - Unusual activity detected
  - Authentication failures
  - Input validation failures
  - DDoS detection
  - Configuration changes
  - High threat scores
  - Anomaly detection
- **Severity Levels**: Info, Warning, Critical
- **Alert Management**:
  - View active alerts
  - Dismiss individual or all alerts
  - Alert history
  - Auto-alert generation based on thresholds

### 4. **Modifiable Security Settings**
- **Rate Limiting**: Adjust requests/window, burst size, adaptive mode
- **Validation**: Enable/disable specific checks (SQL injection, XSS, etc.)
- **Authentication**: JWT requirements, token expiry, MFA settings
- **Threat Detection**: Bot detection, anomaly detection, signature detection
- **Strict Mode**: One-click activation of maximum security
- **Batch Updates**: Update multiple settings at once
- **Export/Import**: Backup and restore configurations

### 5. **User Preferences**
- **Theme**: Light or dark mode
- **Refresh Interval**: Customize dashboard update frequency
- **Auto-refresh**: Toggle automatic updates
- **Items Per Page**: Configure pagination
- **Timezone**: Set display timezone
- **Log Retention**: Control data retention period
- **Alerts**: Enable/disable sound notifications

### 6. **Metrics & Analytics**
- **Security Metrics**:
  - Total threats blocked
  - Breakdown by threat type
  - Rate limit violations
  - Validation failures
  - Authentication failures
- **Performance Metrics**:
  - Response time statistics
  - Requests per second
  - Throughput tracking
- **Threat Analysis**:
  - Top threat sources (IPs)
  - Threat distribution by type
  - Peak traffic hours
  - Trend history

## 📁 Module Structure

```
ui/
├── mod.rs              # Main UI module and manager
├── state.rs            # Central state management
├── dashboard.rs        # Dashboard component
├── tracking.rs         # Request tracking system
├── alerts.rs          # Alert management system
├── settings.rs        # Dynamic settings manager
├── metrics.rs         # Metrics collection
└── api.rs             # Web API routes
```

## 🚀 Getting Started

### Basic Usage

```rust
use secureapis::prelude::*;

#[tokio::main]
async fn main() {
    // Create configuration
    let config = SecurityConfig::new()
        .with_rate_limit(100, 60)
        .strict_mode();

    // Initialize UI Manager
    let ui = UIManager::new(config);

    // Get dashboard data
    let dashboard = ui.dashboard.get_data().await;
    println!("Threat Level: {:?}", dashboard.threat_level);

    // Track a request
    let request_id = ui.tracker.track_request(
        "GET".to_string(),
        "/api/data".to_string(),
        "192.168.1.1".to_string(),
        "Mozilla/5.0".to_string(),
        None,
        25.5,
    ).await;

    // Update request with response
    ui.tracker.update_request(&request_id, 200, 15.2, false, None).await;

    // Create alerts
    ui.alerts.alert_rate_limit_exceeded("192.168.1.1", 100).await;

    // Modify settings
    ui.settings.update_rate_limit(Some(200), Some(120), None, None).await.ok();
}
```

### Dashboard Access

```rust
// Get full dashboard data
let dashboard_data = ui.dashboard.get_data().await;

// Get health status
let health = ui.dashboard.get_health().await;

// Get threat timeline
let timeline = ui.dashboard.get_threat_timeline(24).await;
```

### Request Tracking

```rust
// Get request statistics
let stats = ui.tracker.get_statistics().await;

// Get requests by path
let paths = ui.tracker.get_requests_by_path().await;

// Get requests by IP
let ips = ui.tracker.get_requests_by_ip().await;

// Search requests
let results = ui.tracker.search_requests("suspicious_pattern").await;

// Get filtered requests
let blocked = ui.tracker.get_filtered_requests(
    RequestFilter {
        method: None,
        client_ip: Some("192.168.1.1".to_string()),
        blocked_only: true,
        min_threat_score: Some(50.0),
    }
).await;

// Get trends
let trends = ui.tracker.get_trends(60).await;
```

### Alert Management

```rust
// Get active alerts
let alerts = ui.alerts.get_alerts().await;

// Get critical alerts only
let critical = ui.alerts.get_critical_alerts().await;

// Create alerts
ui.alerts.alert_unusual_activity("Suspicious activity", 75.0).await;
ui.alerts.alert_dos_detected("192.168.1.5", 500).await;

// Dismiss alerts
ui.alerts.dismiss_alert(alert_id).await;
ui.alerts.dismiss_all_alerts().await;

// Get alert summary
let summary = ui.alerts.get_summary().await;

// Auto-check for alert conditions
ui.alerts.check_and_alert().await;
```

### Dynamic Settings

```rust
// Get current configuration
let config = ui.settings.get_security_config().await;

// Update rate limiting
ui.settings.update_rate_limit(
    Some(200),  // requests per window
    Some(120),  // window duration in seconds
    Some(20),   // burst size
    Some(true), // adaptive mode
).await?;

// Update validation settings
ui.settings.update_validation(
    Some(true),  // SQL injection check
    Some(true),  // XSS check
    Some(true),  // Command injection check
    Some(true),  // Path traversal check
    Some(true),  // Sanitize input
    Some(50*1024*1024), // Max payload size
).await?;

// Enable strict mode
ui.settings.set_strict_mode(true).await?;

// Update UI preferences
ui.settings.update_ui_preferences(
    Some("dark".to_string()),
    Some(5000),
    Some(true),
    Some(50),
    Some("UTC".to_string()),
).await?;

// Export settings
let json = ui.settings.export_settings().await?;

// Import settings
ui.settings.import_settings(&json).await?;

// Reset to defaults
ui.settings.reset_to_defaults().await?;

// Batch update
let update = SettingsUpdate {
    security: Some(SecuritySettingsUpdate {
        rate_limit: Some(RateLimitUpdate {
            requests_per_window: Some(300),
            ..Default::default()
        }),
        ..Default::default()
    }),
    ui: Some(UISettingsUpdate {
        theme: Some("dark".to_string()),
        ..Default::default()
    }),
};
ui.settings.batch_update(update).await?;
```

### Metrics Collection

```rust
// Collect current metrics
let metrics = ui.metrics.collect().await;

// Get metrics summary
let summary = ui.metrics.get_summary().await;

// Get security metrics
let security = ui.metrics.get_security_metrics().await;

// Get performance metrics
let perf = ui.metrics.get_performance_metrics().await;

// Get top threat sources
let threats = ui.metrics.get_top_threat_sources().await;

// Get threat distribution
let dist = ui.metrics.get_threat_distribution().await;

// Get peak traffic times
let peaks = ui.metrics.get_peak_traffic_hours().await;

// Get metrics history
let history = ui.metrics.get_history(Some(100)).await;

// Export metrics
let json = ui.metrics.export_metrics().await?;
```

## 🔗 Web API Endpoints

The UI provides RESTful API endpoints for integration with web frontends:

### Dashboard
- `GET /api/ui/dashboard` - Get full dashboard data
- `GET /api/ui/health` - System health check
- `GET /api/ui/alerts` - Get active alerts
- `POST /api/ui/alerts/:id/dismiss` - Dismiss an alert

### Request Tracking
- `GET /api/ui/requests` - Get recent requests
- `POST /api/ui/requests/search` - Search requests
- `GET /api/ui/requests/stats` - Get statistics

### Settings
- `GET /api/ui/settings` - Get current settings
- `PUT /api/ui/settings` - Update settings
- `POST /api/ui/settings/reset` - Reset to defaults

### Metrics
- `GET /api/ui/metrics` - Get current metrics
- `GET /api/ui/metrics/security` - Security metrics
- `GET /api/ui/metrics/performance` - Performance metrics

### Events & Activity
- `GET /api/ui/events` - Get security events
- `GET /api/ui/activity` - Get activity feed

## 📊 Data Structures

### Dashboard Data
```rust
pub struct DashboardData {
    pub metrics: MetricsSnapshot,
    pub top_blocked_ips: Vec<IpBlockInfo>,
    pub threat_level: ThreatLevel, // Low, Medium, High, Critical
    pub recent_events: Vec<DashboardEvent>,
    pub security_status: SecurityStatus,
    pub uptime_seconds: u64,
    pub active_sessions: u32,
}
```

### Request Log
```rust
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
}
```

### Alert
```rust
pub struct Alert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub message: String,
    pub severity: AlertSeverity, // Info, Warning, Critical
    pub alert_type: AlertType,
    pub dismissed: bool,
}
```

### Metrics Snapshot
```rust
pub struct MetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub rate_limited: u64,
    pub validation_failures: u64,
    pub auth_failures: u64,
    pub block_rate: f64,
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
}
```

## 🎛️ Configuration Example

```rust
// Create with custom security settings
let config = SecurityConfig::new()
    .with_rate_limit(500, 60)
    .with_jwt_validation("your-secret-key")
    .with_input_sanitization(true)
    .strict_mode();

let ui = UIManager::new(config);

// All settings are dynamically modifiable
ui.settings.update_rate_limit(Some(1000), None, None, None).await?;
ui.settings.set_strict_mode(false).await?;
ui.settings.update_ui_preferences(
    Some("dark".to_string()),
    Some(2000),
    Some(true),
    None,
    None,
).await?;
```

## 📈 Performance Characteristics

- **Dashboard Load**: ~5-10ms
- **Request Tracking**: ~1-2µs per request
- **Alert Creation**: ~500-1000ns
- **Settings Update**: ~1-2ms
- **Metrics Collection**: ~5-10ms
- **Memory Usage**: ~2-5MB per 1000 tracked requests

## 🔒 Security Considerations

1. **Authentication**: Implement authentication middleware for API endpoints
2. **Authorization**: Control access to sensitive settings and metrics
3. **Rate Limiting**: Apply rate limits to UI API endpoints
4. **HTTPS**: Always use HTTPS in production
5. **Audit Trail**: All configuration changes are logged
6. **Data Privacy**: PII in request logs can be sanitized

## 🧪 Testing

Run the UI example:
```bash
cargo run --example ui_dashboard
```

This demonstrates all core UI features and capabilities.

## 📝 Advanced Usage

### Real-time Updates
```rust
// Poll for updates
loop {
    let dashboard = ui.dashboard.get_data().await;
    let alerts = ui.alerts.get_alerts().await;
    let metrics = ui.metrics.collect().await;
    
    // Update frontend
    tokio::time::sleep(Duration::from_millis(5000)).await;
}
```

### Custom Alerts
```rust
ui.alerts.alert_unusual_activity(
    "Custom threat pattern detected",
    threat_score,
).await;

// Check and generate automatic alerts
ui.alerts.check_and_alert().await;
```

### Batch Configuration Updates
```rust
let update = SettingsUpdate {
    security: Some(SecuritySettingsUpdate {
        rate_limit: Some(RateLimitUpdate {
            requests_per_window: Some(500),
            window_secs: Some(60),
            burst_size: Some(50),
            adaptive: Some(true),
        }),
        validation: Some(ValidationUpdate {
            sql_injection_check: Some(true),
            xss_check: Some(true),
            sanitize_input: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }),
    ui: Some(UISettingsUpdate {
        theme: Some("dark".to_string()),
        refresh_interval_ms: Some(2000),
        auto_refresh: Some(true),
        ..Default::default()
    }),
};

ui.settings.batch_update(update).await?;
```

## 🐛 Troubleshooting

### No Requests Being Tracked
- Ensure `track_request()` is called before `update_request()`
- Check that request IDs match when updating

### Alerts Not Appearing
- Verify alert conditions are met (threshold-based)
- Check `alert_type` and `severity` settings

### Settings Changes Not Applied
- Call `update_config()` after modifying settings
- Verify configuration is passed to security middleware

## 📚 Examples

See `examples/ui_dashboard.rs` for a comprehensive demonstration of all UI features.

## 🤝 Contributing

UI layer contributions welcome! Follow the main project guidelines.

## 📄 License

MIT License - See LICENSE file for details.
