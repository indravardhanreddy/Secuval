//! # Live Request Generator & Monitor
//! 
//! Generates realistic requests to the UI server and monitors responses in real-time

use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚀 SecureAPIs Live Request Monitor\n");

    let server_url = "http://127.0.0.1:3000";
    let client = reqwest::Client::new();

    // Test server connectivity
    println!("🔍 Checking server connectivity...");
    match client.get(format!("{}/test", server_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("✅ Server is running and responding\n");
        }
        _ => {
            eprintln!("❌ Cannot connect to server at {}", server_url);
            eprintln!("   Make sure the server is running: cargo run --example ui_server\n");
            return Ok(());
        }
    }

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 LIVE MONITORING DASHBOARD");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Spawn monitoring task
    let monitor_handle = {
        let server_url = server_url.to_string();
        let client = client.clone();
        tokio::spawn(async move {
            monitor_live(&server_url, &client).await;
        })
    };

    // Spawn request generation task
    let request_handle = {
        let server_url = server_url.to_string();
        let client = client.clone();
        tokio::spawn(async move {
            generate_requests(&server_url, &client).await;
        })
    };

    // Wait for both tasks
    let _ = tokio::join!(monitor_handle, request_handle);

    Ok(())
}

/// Monitor the server and display live metrics
async fn monitor_live(server_url: &str, client: &reqwest::Client) {
    let mut iteration = 0;
    loop {
        iteration += 1;
        
        // Clear screen (simple approach)
        if iteration > 1 {
            print!("\x1B[2J\x1B[H");
        }

        println!("\n🚀 SecureAPIs - Live Monitoring Dashboard");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("⏱️  Update #{}", iteration);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        // Fetch dashboard data
        match client
            .get(format!("{}/api/ui/dashboard", server_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(dashboard) = data.get("data") {
                        display_dashboard(dashboard);
                    }
                }
            }
            Err(e) => {
                println!("⚠️  Cannot fetch dashboard: {}", e);
            }
        }

        // Fetch metrics
        match client
            .get(format!("{}/api/ui/metrics", server_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(metrics) = data.get("data") {
                        display_metrics(metrics);
                    }
                }
            }
            Err(e) => {
                println!("⚠️  Cannot fetch metrics: {}", e);
            }
        }

        // Fetch alerts
        match client
            .get(format!("{}/api/ui/alerts", server_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(alerts) = data.get("data") {
                        display_alerts(alerts);
                    }
                }
            }
            Err(e) => {
                println!("⚠️  Cannot fetch alerts: {}", e);
            }
        }

        // Fetch requests
        match client
            .get(format!("{}/api/ui/requests", server_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(requests) = data.get("data") {
                        display_requests(requests);
                    }
                }
            }
            Err(e) => {
                println!("⚠️  Cannot fetch requests: {}", e);
            }
        }

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🔄 Refreshing in 3 seconds... (Press Ctrl+C to stop)\n");

        sleep(Duration::from_secs(3)).await;
    }
}

/// Display dashboard information
fn display_dashboard(data: &serde_json::Value) {
    println!("📊 DASHBOARD OVERVIEW");
    println!("├─ Threat Level: {}", 
        data["threat_level"].as_str().unwrap_or("Unknown"));
    println!("├─ Overall Status: {}", 
        data["security_status"]["overall"].as_str().unwrap_or("Unknown"));
    println!("├─ Uptime: {} seconds", 
        data["uptime_seconds"].as_u64().unwrap_or(0));
    
    if let Some(ips) = data["top_blocked_ips"].as_array() {
        println!("├─ Top Blocked IPs:");
        for (i, ip) in ips.iter().take(3).enumerate() {
            println!("│  {}. {} - {} blocks", 
                i + 1,
                ip["ip"].as_str().unwrap_or("?"),
                ip["block_count"].as_u64().unwrap_or(0)
            );
        }
    }
    println!();
}

/// Display metrics information
fn display_metrics(data: &serde_json::Value) {
    println!("📈 REAL-TIME METRICS");
    println!("├─ Total Requests: {}", 
        data["total_requests"].as_u64().unwrap_or(0));
    println!("├─ Blocked: {} ({:.2}%)", 
        data["blocked_requests"].as_u64().unwrap_or(0),
        data["block_rate"].as_f64().unwrap_or(0.0)
    );
    println!("├─ Rate Limited: {}", 
        data["rate_limited"].as_u64().unwrap_or(0));
    println!("├─ Response Times:");
    println!("│  ├─ Avg: {:.2}ms", 
        data["avg_response_time_ms"].as_f64().unwrap_or(0.0)
    );
    println!("│  ├─ P95: {:.2}ms", 
        data["p95_response_time_ms"].as_f64().unwrap_or(0.0)
    );
    println!("│  └─ P99: {:.2}ms", 
        data["p99_response_time_ms"].as_f64().unwrap_or(0.0)
    );
    println!("├─ Validation Failures: {}", 
        data["validation_failures"].as_u64().unwrap_or(0));
    println!("└─ Auth Failures: {}", 
        data["auth_failures"].as_u64().unwrap_or(0));
    println!();
}

/// Display alerts information
fn display_alerts(data: &serde_json::Value) {
    if let Some(summary) = data.get("summary") {
        println!("🚨 ACTIVE ALERTS");
        println!("├─ Total: {}", summary["total"].as_u64().unwrap_or(0));
        println!("├─ 🔴 Critical: {}", summary["critical"].as_u64().unwrap_or(0));
        println!("├─ 🟠 Warnings: {}", summary["warning"].as_u64().unwrap_or(0));
        println!("├─ 🔵 Info: {}", summary["info"].as_u64().unwrap_or(0));
        println!("└─ ⚠️  Requires Attention: {}", 
            if summary["requires_attention"].as_bool().unwrap_or(false) { "YES ⚠️" } else { "NO ✅" }
        );

        if let Some(alerts) = data["alerts"].as_array() {
            if !alerts.is_empty() {
                println!("\n  Recent Alerts:");
                for (i, alert) in alerts.iter().take(3).enumerate() {
                    let severity = alert["severity"].as_str().unwrap_or("?");
                    let icon = match severity {
                        "Critical" => "🔴",
                        "Warning" => "🟠",
                        _ => "🔵",
                    };
                    println!("  {}. {} {} - {}", 
                        i + 1,
                        icon,
                        alert["title"].as_str().unwrap_or("?"),
                        alert["message"].as_str().unwrap_or("?")
                    );
                }
            }
        }
    }
    println!();
}

/// Display request information
fn display_requests(data: &serde_json::Value) {
    println!("🔍 REQUEST PATHS");
    if let Some(paths) = data["paths"].as_array() {
        for (_i, path) in paths.iter().take(5).enumerate() {
            println!("├─ {} ({} requests, {} blocked)",
                path["path"].as_str().unwrap_or("?"),
                path["count"].as_u64().unwrap_or(0),
                path["blocked"].as_u64().unwrap_or(0)
            );
        }
    }
    println!();
}

/// Generate realistic requests to the server
async fn generate_requests(server_url: &str, client: &reqwest::Client) {
    sleep(Duration::from_secs(2)).await; // Wait for monitor to start

    let endpoints = vec![
        ("/api/users", "GET"),
        ("/api/products", "GET"),
        ("/api/orders", "POST"),
        ("/api/admin", "GET"),
        ("/api/settings", "PUT"),
        ("/api/data", "GET"),
        ("/api/status", "GET"),
        ("/api/health", "GET"),
    ];

    let mut request_count = 0;

    loop {
        // Generate requests with varying threat levels
        for (path, _method) in &endpoints {
            request_count += 1;
            
            // Vary threat scores
            let threat_score = match request_count % 10 {
                0..=2 => 5.0 + (request_count as f64 % 10.0),  // Low threat
                3..=5 => 30.0 + (request_count as f64 % 20.0), // Medium threat
                6..=8 => 60.0 + (request_count as f64 % 20.0), // High threat
                _ => 85.0 + (request_count as f64 % 15.0),     // Very high threat
            };

            // Determine IP (rotate through different IPs)
            let ip_num = (request_count % 20) + 1;
            let ip = format!("192.168.1.{}", ip_num);

            // Send tracking request
            let payload = serde_json::json!({
                "method": "GET",
                "path": path,
                "ip": ip,
                "threat_score": threat_score
            });

            let _ = client
                .post(format!("{}/api/ui/request/track", server_url))
                .json(&payload)
                .send()
                .await;

            // Add some delay between requests
            sleep(Duration::from_millis(200)).await;

            // Generate bursts for different scenarios
            if request_count % 100 == 0 {
                println!("📤 Generated {} requests...", request_count);
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
