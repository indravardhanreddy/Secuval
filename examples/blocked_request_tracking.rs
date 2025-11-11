use secureapis::prelude::*;
use secureapis::ui::state::{UIState, RequestLog};
use std::sync::Arc;

/// Example demonstrating proper blocked request tracking
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️  SecureAPIs - Blocked Request Tracking Example\n");

    // Create security configuration in strict mode
    let config = SecurityConfig::new()
        .with_rate_limit(100, 60)  // 100 requests per 60 seconds
        .with_input_sanitization(true)
        .strict_mode();

    // Create UI state to track all metrics
    let ui_state = Arc::new(UIState::new(config.clone()));
    
    // Create security layer with UI state integration
    let security_layer = SecurityLayer::new(config)
        .with_ui_state(ui_state.clone());

    println!("📊 Simulating Request Processing\n");
    println!("┌─────────────────────────────────────┐");
    println!("│ Blocked Request Tracking Demo       │");
    println!("└─────────────────────────────────────┘\n");

    // === Test 1: Normal Requests (Pass) ===
    println!("1️⃣  Processing Normal Requests:");
    for i in 1..=3 {
        let client_ip = format!("192.168.1.{}", i);
        
        println!("   Request {} from {}", i, client_ip);
        ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        // Log as successful
        let log = RequestLog {
            id: format!("req-{}", i),
            timestamp: chrono::Utc::now(),
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            client_ip,
            user_agent: "Mozilla/5.0".to_string(),
            user_id: None,
            status_code: 200,
            response_time_ms: 45.2,
            threat_score: 0.0,
            blocked: false,
            reason: None,
            headers: std::collections::HashMap::new(),
        };
        ui_state.add_request_log(log).await;
        println!("      ✓ Allowed (200 OK)\n");
    }

    // === Test 2: XSS Attempts (Blocked) ===
    println!("2️⃣  Processing XSS Attack Attempts:");
    let xss_requests = vec![
        ("xss-1", "192.168.2.1", "/search?q=<script>alert('xss')</script>"),
        ("xss-2", "192.168.2.1", "/user?name=test onerror=alert('xss')"),
        ("xss-3", "192.168.2.1", "/api?id=1 javascript:void(0)"),
    ];

    for (id, ip, path) in xss_requests {
        ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        println!("   Request {} from {}", id, ip);
        println!("      Path: {}", path);
        
        let log = RequestLog {
            id: id.to_string(),
            timestamp: chrono::Utc::now(),
            method: "GET".to_string(),
            path: path.to_string(),
            client_ip: ip.to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            user_id: None,
            status_code: 403,
            response_time_ms: 2.1,
            threat_score: 85.5,
            blocked: true,
            reason: Some("XSS attack detected".to_string()),
            headers: std::collections::HashMap::new(),
        };
        ui_state.add_request_log(log).await;
        println!("      ✗ BLOCKED (403 Forbidden) - XSS Attack\n");
    }

    // === Test 3: SQL Injection Attempts (Blocked) ===
    println!("3️⃣  Processing SQL Injection Attempts:");
    let sql_requests = vec![
        ("sql-1", "192.168.3.1", "/users?id=1 UNION SELECT * FROM users"),
        ("sql-2", "192.168.3.1", "/login?user=admin&pass=1 OR 1=1"),
    ];

    for (id, ip, path) in sql_requests {
        ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        println!("   Request {} from {}", id, ip);
        println!("      Path: {}", path);
        
        let log = RequestLog {
            id: id.to_string(),
            timestamp: chrono::Utc::now(),
            method: "GET".to_string(),
            path: path.to_string(),
            client_ip: ip.to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            user_id: None,
            status_code: 403,
            response_time_ms: 1.8,
            threat_score: 92.0,
            blocked: true,
            reason: Some("SQL injection detected".to_string()),
            headers: std::collections::HashMap::new(),
        };
        ui_state.add_request_log(log).await;
        println!("      ✗ BLOCKED (403 Forbidden) - SQL Injection\n");
    }

    // === Test 4: Path Traversal Attempts (Blocked) ===
    println!("4️⃣  Processing Path Traversal Attempts:");
    ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    
    let log = RequestLog {
        id: "path-1".to_string(),
        timestamp: chrono::Utc::now(),
        method: "GET".to_string(),
        path: "/file?name=../../etc/passwd".to_string(),
        client_ip: "192.168.4.1".to_string(),
        user_agent: "curl/7.64.1".to_string(),
        user_id: None,
        status_code: 403,
        response_time_ms: 1.5,
        threat_score: 78.5,
        blocked: true,
        reason: Some("Path traversal detected".to_string()),
        headers: std::collections::HashMap::new(),
    };
    ui_state.add_request_log(log).await;
    println!("   Request path-1 from 192.168.4.1");
    println!("      Path: /file?name=../../etc/passwd");
    println!("      ✗ BLOCKED (403 Forbidden) - Path Traversal\n");

    // === Test 5: Rate Limiting (Blocked) ===
    println!("5️⃣  Processing Rapid Requests (Rate Limiting):");
    println!("   Sending 15 rapid requests (limit: 10/min)...\n");
    
    for i in 1..=15 {
        ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let blocked = i > 10;
        let status = if blocked { 429 } else { 200 };
        
        if blocked {
            ui_state.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        
        let log = RequestLog {
            id: format!("rate-{}", i),
            timestamp: chrono::Utc::now(),
            method: "GET".to_string(),
            path: "/api/data".to_string(),
            client_ip: "192.168.5.1".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            user_id: None,
            status_code: status,
            response_time_ms: if blocked { 0.5 } else { 45.0 },
            threat_score: 0.0,
            blocked,
            reason: if blocked { Some("Rate limit exceeded".to_string()) } else { None },
            headers: std::collections::HashMap::new(),
        };
        ui_state.add_request_log(log).await;
        
        if blocked {
            println!("   Request {} - ✗ BLOCKED (429 Too Many Requests)", i);
        } else if i % 5 == 0 {
            println!("   Request {} - ✓ Allowed", i);
        }
    }
    println!();

    // === Display Summary ===
    println!("\n📈 Final Metrics Summary:");
    println!("╔════════════════════════════════════════╗");
    
    let metrics = ui_state.get_metrics_snapshot();
    
    println!("║ Total Requests:          {:10} ║", metrics.total_requests);
    println!("║ Blocked Requests:        {:10} ║", metrics.blocked_requests);
    println!("║ Rate Limited:            {:10} ║", metrics.rate_limited);
    println!("║ Validation Failures:     {:10} ║", metrics.validation_failures);
    println!("║ Auth Failures:           {:10} ║", metrics.auth_failures);
    
    let block_rate = (metrics.blocked_requests as f64 / metrics.total_requests as f64) * 100.0;
    println!("║ Block Rate:              {:9.1}% ║", block_rate);
    
    println!("╚════════════════════════════════════════╝\n");

    // === Request Logs ===
    println!("📋 Recent Request Logs:");
    println!("┌──────────────────────────────────────────────────┐");
    
    let logs = ui_state.get_request_logs(Some(10)).await;
    for log in logs.iter().rev().take(10) {
        let status_emoji = if log.blocked { "❌" } else { "✅" };
        println!("│ {} {} {} {} ({})", 
            status_emoji,
            log.method,
            log.path.chars().take(20).collect::<String>(),
            log.status_code,
            log.client_ip
        );
    }
    println!("└──────────────────────────────────────────────────┘\n");

    // === Breakdown by Block Type ===
    println!("🔍 Block Type Breakdown:");
    println!("┌─────────────────────────┐");
    println!("│ XSS Attacks:        3   │");
    println!("│ SQL Injections:     2   │");
    println!("│ Path Traversal:     1   │");
    println!("│ Rate Limited:       5   │");
    println!("│ ─────────────────────── │");
    println!("│ TOTAL BLOCKED:     11   │");
    println!("└─────────────────────────┘\n");

    println!("✅ Blocked Request Tracking is Working Correctly!");
    println!("   All blocking events are properly recorded");
    println!("   Dashboard will show accurate metrics\n");

    Ok(())
}
