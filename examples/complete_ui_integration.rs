//! # Complete Integration Example
//! 
//! Demonstrates full integration of the UI layer with the security middleware.
//! Shows how to:
//! - Initialize security middleware
//! - Set up UI dashboard
//! - Track requests through the security layer
//! - Manage alerts and settings
//! - Serve the web API

use secureapis::prelude::*;
use secureapis::ui::state::AlertSeverity;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  SecureAPIs - Complete Integration Example\n");

    // ============ Initialize Security & UI ============
    
    let security_config = SecurityConfig::new()
        .with_rate_limit(100, 60)
        .with_jwt_validation("my-secret-key")
        .with_input_sanitization(true)
        .strict_mode();

    let ui = UIManager::new(security_config.clone());
    println!("✅ Security & UI initialized\n");

    // ============ Simulate Request Processing ============
    
    println!("📝 Simulating request processing...\n");
    
    let test_requests = vec![
        ("GET", "/api/users", "192.168.1.1", 200, 10.5, 5.0),
        ("POST", "/api/users", "192.168.1.1", 201, 25.3, 8.5),
        ("GET", "/api/products", "192.168.1.2", 200, 12.1, 3.0),
        ("DELETE", "/api/users/1", "192.168.1.3", 403, 5.2, 95.0), // High threat
        ("POST", "/admin", "192.168.1.4", 403, 3.0, 85.0), // High threat
        ("GET", "/api/users", "192.168.1.5", 200, 11.2, 2.0),
        ("GET", "/api/data", "192.168.1.1", 200, 15.8, 4.5),
        ("POST", "/api/users", "192.168.1.6", 200, 28.5, 9.2),
        ("GET", "/api/health", "192.168.1.7", 200, 1.5, 0.5),
        ("GET", "/api/status", "192.168.1.1", 200, 8.3, 2.0),
    ];

    for (method, path, ip, status, response_time, threat) in test_requests {
        // Track request
        let request_id = ui.tracker.track_request(
            method.to_string(),
            path.to_string(),
            ip.to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string(),
            None,
            threat,
        ).await;

        // Simulate processing
        tokio::time::sleep(Duration::from_millis(1)).await;

        // Update with response
        let blocked = status == 403;
        let reason = if blocked { Some("Access Denied".to_string()) } else { None };
        
        ui.tracker.update_request(&request_id, status, response_time, blocked, reason).await;

        // Create alerts for high-threat requests
        if threat > 80.0 {
            ui.alerts.alert_high_threat_score(ip, threat).await;
        }
    }

    println!("✅ Processed 10 requests with tracking\n");

    // ============ Display Dashboard Data ============
    
    println!("📊 DASHBOARD OVERVIEW\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let dashboard = ui.dashboard.get_data().await;
    println!("🎯 Metrics:");
    println!("   Total Requests: {}", dashboard.metrics.total_requests);
    println!("   Blocked Requests: {}", dashboard.metrics.blocked_requests);
    println!("   Block Rate: {:.2}%", dashboard.metrics.block_rate);
    println!("   Rate Limited: {}", dashboard.metrics.rate_limited);
    
    println!("\n🔴 Threat Assessment:");
    println!("   Current Level: {:?}", dashboard.threat_level);
    println!("   Status: {}", dashboard.security_status.overall_status);
    println!("   Rate Limiting: {}", if dashboard.security_status.rate_limit_enabled { "✅ ON" } else { "❌ OFF" });
    println!("   Validation: {}", if dashboard.security_status.validation_enabled { "✅ ON" } else { "❌ OFF" });
    println!("   Authentication: {}", if dashboard.security_status.auth_enabled { "✅ ON" } else { "❌ OFF" });
    
    println!("\n🌐 Top Blocked IPs:");
    for (i, ip_info) in dashboard.top_blocked_ips.iter().enumerate().take(3) {
        println!("   {}. {} - {} blocks ({})", i + 1, ip_info.ip, ip_info.block_count, ip_info.reason);
    }
    println!();

    // ============ Display Request Statistics ============
    
    println!("📈 REQUEST STATISTICS\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let stats = ui.tracker.get_statistics().await;
    println!("Total Requests: {}", stats.total_requests);
    println!("Blocked Requests: {}", stats.blocked_requests);
    println!("Block Rate: {:.2}%", stats.block_rate);
    println!("Avg Response Time: {:.2}ms", stats.avg_response_time_ms);
    println!("P95 Response Time: {:.2}ms", stats.p95_response_time_ms);
    println!("P99 Response Time: {:.2}ms", stats.p99_response_time_ms);
    println!("Unique IPs: {}\n", stats.unique_ips);

    println!("HTTP Methods:");
    for method in &stats.methods {
        println!("   - {}: {} requests", method.method, method.count);
    }
    println!();

    println!("Top Paths:");
    let paths = ui.tracker.get_requests_by_path().await;
    for (i, path) in paths.iter().enumerate().take(5) {
        println!("   {}. {} ({} requests, {} blocked)", i + 1, path.path, path.count, path.blocked);
    }
    println!();

    // ============ Display Alerts ============
    
    println!("🚨 ACTIVE ALERTS\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let alerts = ui.alerts.get_alerts().await;
    let summary = ui.alerts.get_summary().await;
    
    println!("Alert Summary:");
    println!("   Total: {}", summary.total_alerts);
    println!("   🔴 Critical: {}", summary.critical);
    println!("   🟠 Warnings: {}", summary.warning);
    println!("   🔵 Info: {}", summary.info);
    println!("   ⚠️  Requires Attention: {}\n", if summary.requires_attention { "YES" } else { "NO" });

    if !alerts.is_empty() {
        println!("Recent Alerts:");
        for (i, alert) in alerts.iter().enumerate().take(5) {
            let severity_icon = match alert.severity {
                AlertSeverity::Critical => "🔴",
                AlertSeverity::Warning => "🟠",
                AlertSeverity::Info => "🔵",
            };
            println!("   {} [{}] {}", severity_icon, format!("{:?}", alert.severity), alert.title);
            println!("      Message: {}", alert.message);
        }
    } else {
        println!("   No active alerts");
    }
    println!();

    // ============ Display Metrics ============
    
    println!("📊 SECURITY METRICS\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let security_metrics = ui.metrics.get_security_metrics().await;
    println!("Total Threats Detected: {}", security_metrics.total_threats);
    println!("Rate Limit Blocks: {}", security_metrics.blocked_by_rate_limit);
    println!("Validation Failures: {}", security_metrics.validation_failures);
    println!("Auth Failures: {}", security_metrics.authentication_failures);
    println!("Blocked by Threat Detection: {}\n", security_metrics.blocked_by_threat_detection);

    println!("Top Threat Sources:");
    let threats = ui.metrics.get_top_threat_sources().await;
    for (i, threat) in threats.iter().enumerate().take(3) {
        println!("   {}. {} - Score: {:.1}%, Blocks: {}", 
            i + 1, threat.ip, threat.threat_score, threat.block_count);
    }
    println!();

    // ============ Display Configuration ============
    
    println!("⚙️  CURRENT CONFIGURATION\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let config = ui.settings.get_security_config().await;
    println!("Rate Limiting:");
    println!("   Enabled: {}", config.rate_limit.enabled);
    println!("   Requests/Window: {}", config.rate_limit.requests_per_window);
    println!("   Window Duration: {:.0}s", config.rate_limit.window_duration.as_secs_f64());
    println!("   Adaptive: {}\n", config.rate_limit.adaptive);

    println!("Validation:");
    println!("   SQL Injection Check: {}", config.validation.sql_injection_check);
    println!("   XSS Check: {}", config.validation.xss_check);
    println!("   Sanitize Input: {}\n", config.validation.sanitize_input);

    println!("Authentication:");
    println!("   Enabled: {}", config.auth.enabled);
    println!("   Require Auth: {}", config.auth.require_auth);
    println!("   MFA Enabled: {}\n", config.auth.mfa_enabled);

    // ============ Demonstrate Dynamic Settings Update ============
    
    println!("🔧 DYNAMIC SETTINGS UPDATE\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    println!("Before: Rate Limit = {} req/60s", config.rate_limit.requests_per_window);
    ui.settings.update_rate_limit(Some(500), Some(120), None, None).await?;
    let updated = ui.settings.get_security_config().await;
    println!("After: Rate Limit = {} req/120s", updated.rate_limit.requests_per_window);
    println!("✅ Settings updated dynamically!\n");

    // ============ Display User Preferences ============
    
    println!("🎨 USER PREFERENCES\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    let prefs = ui.settings.get_ui_preferences().await;
    println!("Theme: {}", prefs.theme);
    println!("Refresh Interval: {}ms", prefs.refresh_interval_ms);
    println!("Auto-Refresh: {}", prefs.auto_refresh_enabled);
    println!("Items Per Page: {}", prefs.items_per_page);
    println!("Timezone: {}\n", prefs.timezone);

    // ============ API Integration Example ============
    
    println!("🌐 API ENDPOINTS AVAILABLE\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Dashboard:");
    println!("   GET  /api/ui/dashboard");
    println!("   GET  /api/ui/health\n");

    println!("Requests:");
    println!("   GET  /api/ui/requests");
    println!("   POST /api/ui/requests/search");
    println!("   GET  /api/ui/requests/stats\n");

    println!("Alerts:");
    println!("   GET  /api/ui/alerts");
    println!("   POST /api/ui/alerts/:id/dismiss\n");

    println!("Settings:");
    println!("   GET  /api/ui/settings");
    println!("   PUT  /api/ui/settings");
    println!("   POST /api/ui/settings/reset\n");

    println!("Metrics:");
    println!("   GET  /api/ui/metrics");
    println!("   GET  /api/ui/metrics/security");
    println!("   GET  /api/ui/metrics/performance\n");

    // ============ Summary ============
    
    println!("✅ INTEGRATION SUMMARY\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("✓ Security middleware configured");
    println!("✓ UI dashboard initialized");
    println!("✓ {} requests tracked", stats.total_requests);
    println!("✓ {} alerts generated", summary.total_alerts);
    println!("✓ {} unique clients monitored", stats.unique_ips);
    println!("✓ Dynamic settings available");
    println!("✓ Web API ready for frontend integration\n");

    println!("🎯 Next Steps:");
    println!("1. Integrate with your API server");
    println!("2. Build web frontend using provided API endpoints");
    println!("3. Configure authentication for UI access");
    println!("4. Set up monitoring and alerting");
    println!("5. Deploy to production\n");

    println!("📚 Documentation:");
    println!("   - UI Layer: docs/UI_LAYER.md");
    println!("   - Frontend Blueprint: docs/FRONTEND_BLUEPRINT.md");
    println!("   - Implementation Summary: docs/UI_IMPLEMENTATION_SUMMARY.md\n");

    Ok(())
}
