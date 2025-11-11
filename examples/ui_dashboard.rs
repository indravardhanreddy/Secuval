//! # UI Dashboard Example
//! 
//! Demonstrates how to use the UI layer to build a comprehensive monitoring dashboard
//! with dynamic settings, request tracking, and alert management.

use secureapis::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  SecureAPIs - UI Dashboard Example\n");

    // Create a security configuration
    let config = SecurityConfig::new()
        .with_rate_limit(100, 60)
        .with_jwt_validation("super-secret-key")
        .with_input_sanitization(true)
        .strict_mode();

    // Create the UI manager
    let ui = UIManager::new(config);
    println!("✅ UI Manager initialized\n");

    // === Dashboard Demo ===
    println!("📊 Dashboard Features:");
    let dashboard_data = ui.dashboard.get_data().await;
    println!("  • Threat Level: {:?}", dashboard_data.threat_level);
    println!("  • Security Status: {}", dashboard_data.security_status.overall_status);
    println!("  • Rate Limiting: {}", dashboard_data.security_status.rate_limit_enabled);
    println!("  • Uptime: {} seconds\n", dashboard_data.uptime_seconds);

    // === Request Tracking Demo ===
    println!("🔍 Request Tracking Features:");
    
    // Simulate tracking some requests
    for i in 1..=5 {
        let request_id = ui.tracker.track_request(
            format!("GET"),
            format!("/api/data/{}", i),
            format!("192.168.1.{}", i),
            "Mozilla/5.0".to_string(),
            Some(format!("user_{}", i)),
            10.0 + (i as f64 * 5.0),
        ).await;
        
        // Simulate response
        tokio::time::sleep(Duration::from_millis(10)).await;
        ui.tracker.update_request(
            &request_id,
            if i % 3 == 0 { 403 } else { 200 },
            15.5,
            i % 3 == 0,
            if i % 3 == 0 { Some("Rate limit exceeded".to_string()) } else { None },
        ).await;
    }

    let stats = ui.tracker.get_statistics().await;
    println!("  • Total Requests: {}", stats.total_requests);
    println!("  • Blocked Requests: {}", stats.blocked_requests);
    println!("  • Block Rate: {:.2}%", stats.block_rate);
    println!("  • Avg Response Time: {:.2}ms", stats.avg_response_time_ms);
    println!("  • Unique IPs: {}\n", stats.unique_ips);

    let top_paths = ui.tracker.get_requests_by_path().await;
    println!("  Top Paths:");
    for path in top_paths.iter().take(3) {
        println!("    - {} ({} requests, {} blocked)", path.path, path.count, path.blocked);
    }
    println!();

    // === Alert Management Demo ===
    println!("🚨 Alert Management Features:");
    
    ui.alerts.alert_rate_limit_exceeded("192.168.1.1", 100).await;
    ui.alerts.alert_unusual_activity("Suspicious pattern detected", 75.0).await;
    ui.alerts.alert_high_threat_score("192.168.1.2", 85.5).await;

    let alert_summary = ui.alerts.get_summary().await;
    println!("  • Total Alerts: {}", alert_summary.total_alerts);
    println!("  • Critical: {}", alert_summary.critical);
    println!("  • Warnings: {}", alert_summary.warning);
    println!("  • Info: {}", alert_summary.info);
    println!("  • Requires Attention: {}\n", alert_summary.requires_attention);

    let alerts = ui.alerts.get_alerts().await;
    println!("  Recent Alerts:");
    for alert in alerts.iter().take(3) {
        println!("    - [{}] {}: {}", format!("{:?}", alert.severity), alert.title, alert.message);
    }
    println!();

    // === Dynamic Settings Demo ===
    println!("⚙️  Dynamic Settings Features:");
    
    let current_config = ui.settings.get_security_config().await;
    println!("  Current Configuration:");
    println!("    • Rate Limit: {} req/{:?}", 
        current_config.rate_limit.requests_per_window,
        current_config.rate_limit.window_duration);
    println!("    • SQL Injection Check: {}", current_config.validation.sql_injection_check);
    println!("    • XSS Check: {}", current_config.validation.xss_check);
    println!("    • Auth Required: {}\n", current_config.auth.require_auth);

    // Update rate limit dynamically
    ui.settings.update_rate_limit(Some(200), Some(120), None, None).await?;
    println!("  ✅ Updated rate limit to 200 req/120s\n");

    // Update validation settings
    ui.settings.update_validation(None, None, None, None, Some(true), None).await?;
    println!("  ✅ Enabled input sanitization\n");

    // Toggle strict mode
    ui.settings.set_strict_mode(true).await?;
    println!("  ✅ Enabled strict security mode\n");

    // Get all settings
    let all_settings = ui.settings.get_all_settings().await;
    println!("  UI Preferences:");
    println!("    • Theme: {}", all_settings.ui.theme);
    println!("    • Refresh Interval: {}ms", all_settings.ui.refresh_interval_ms);
    println!("    • Auto-refresh: {}\n", all_settings.ui.auto_refresh_enabled);

    // === Metrics Collection Demo ===
    println!("📈 Metrics Collection Features:");
    
    let metrics = ui.metrics.collect().await;
    println!("  Current Metrics:");
    println!("    • Total Requests: {}", metrics.total_requests);
    println!("    • Block Rate: {:.2}%", metrics.block_rate);
    println!("    • Avg Response Time: {:.2}ms", metrics.avg_response_time_ms);
    println!("    • P95 Response Time: {:.2}ms", metrics.p95_response_time_ms);
    println!("    • Requests/Second: {:.2}\n", metrics.requests_per_second);

    let security_metrics = ui.metrics.get_security_metrics().await;
    println!("  Security Metrics:");
    println!("    • Total Threats: {}", security_metrics.total_threats);
    println!("    • Rate Limit Blocks: {}", security_metrics.blocked_by_rate_limit);
    println!("    • Validation Failures: {}", security_metrics.validation_failures);
    println!("    • Auth Failures: {}\n", security_metrics.authentication_failures);

    let threat_sources = ui.metrics.get_top_threat_sources().await;
    println!("  Top Threat Sources:");
    for source in threat_sources.iter().take(3) {
        println!("    - IP: {} (Blocks: {}, Threat Score: {:.1}%)", 
            source.ip, source.block_count, source.threat_score);
    }
    println!();

    let threat_dist = ui.metrics.get_threat_distribution().await;
    println!("  Threat Distribution:");
    for dist in threat_dist.iter().take(3) {
        println!("    - {}: {} ({:.1}%)", dist.threat_type, dist.count, dist.percentage);
    }
    println!();

    // === Advanced Features ===
    println!("🔧 Advanced Features:");
    
    // Search requests
    let search_results = ui.tracker.search_requests("192.168").await;
    println!("  • Search Results for '192.168': {} requests found", search_results.len());

    // Get filtered requests
    let blocked_requests = ui.tracker.get_filtered_requests(
        secureapis::ui::tracking::RequestFilter {
            method: None,
            client_ip: None,
            blocked_only: true,
            min_threat_score: None,
        }
    ).await;
    println!("  • Blocked Requests Only: {} found", blocked_requests.len());

    // Get trends
    let trends = ui.tracker.get_trends(60).await;
    println!("  • Traffic Trends (last 60 minutes): {} data points", trends.len());

    // Get request by IP stats
    let ip_stats = ui.tracker.get_requests_by_ip().await;
    println!("  • Top Client IPs:");
    for ip in ip_stats.iter().take(3) {
        println!("    - {} ({} requests, {} blocked, threat: {:.1}%)", 
            ip.ip, ip.count, ip.blocked, ip.threat_score);
    }
    println!();

    // === Configuration Export/Import ===
    println!("📁 Configuration Management:");
    
    let exported = ui.settings.export_settings().await?;
    println!("  • Settings exported ({} bytes)", exported.len());

    // Display sample of exported settings
    println!("  Sample (first 200 chars):\n    {}\n", 
        &exported.chars().take(200).collect::<String>());

    // === Summary ===
    println!("✅ UI Layer Features Demonstrated:");
    println!("   ✓ Real-time dashboard with threat levels");
    println!("   ✓ Comprehensive request tracking with filtering");
    println!("   ✓ Dynamic alert system for security events");
    println!("   ✓ Modifiable security settings and user preferences");
    println!("   ✓ Detailed metrics collection and reporting");
    println!("   ✓ Request analysis and trend tracking");
    println!("   ✓ Configuration export/import for backups");

    println!("\n🎯 Key Capabilities:");
    println!("   • 1000+ concurrent request logs");
    println!("   • 500+ security event tracking");
    println!("   • Real-time alert generation");
    println!("   • Dynamic configuration updates");
    println!("   • Performance metrics (p95, p99)");
    println!("   • Top threat source identification");
    println!("   • Traffic pattern analysis");
    println!("   • Full audit trail");

    Ok(())
}
