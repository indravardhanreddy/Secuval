use secureapis::{
    core::SecurityLayer,
    prelude::*,
};
use http::Request;

#[tokio::test]
async fn test_rate_limiting_integration() {
    let config = SecurityConfig::new().with_rate_limit(5, 60);
    let layer = SecurityLayer::new(config);

    let client_ip = "192.168.1.100";

    // First 5 requests should succeed
    for i in 0..5 {
        let request: Request<Vec<u8>> = Request::builder()
            .uri("/api/test")
            .header("x-forwarded-for", client_ip)
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_ok(), "Request {} should succeed", i + 1);
    }

    // 6th request should be rate limited
    let request: Request<Vec<u8>> = Request::builder()
        .uri("/api/test")
        .header("x-forwarded-for", client_ip)
        .body(vec![])
        .unwrap();

    let result = layer.process_request(&request).await;
    assert!(result.is_err(), "Request 6 should be rate limited");
    
    if let Err(SecurityError::RateLimitExceeded { .. }) = result {
        // Expected error
    } else {
        panic!("Expected RateLimitExceeded error");
    }
}

#[tokio::test]
async fn test_sql_injection_detection() {
    let config = SecurityConfig::new().strict_mode();
    let layer = SecurityLayer::new(config);

    let malicious_inputs = vec![
        "' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users;",
        "UNION SELECT * FROM passwords",
    ];

    for input in malicious_inputs {
        let request: Request<Vec<u8>> = Request::builder()
            .uri(format!("/api/user?id={}", urlencoding::encode(input)))
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_err(), "SQL injection should be detected: {}", input);
    }
}

#[tokio::test]
async fn test_xss_detection() {
    let config = SecurityConfig::new().strict_mode();
    let layer = SecurityLayer::new(config);

    let xss_inputs = vec![
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<iframe src='evil.com'></iframe>",
    ];

    for input in xss_inputs {
        let request: Request<Vec<u8>> = Request::builder()
            .uri(format!("/api/comment?text={}", urlencoding::encode(input)))
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_err(), "XSS should be detected: {}", input);
    }
}

#[tokio::test]
async fn test_jwt_authentication() {
    let secret = "test-secret-key";
    let config = SecurityConfig::new()
        .with_jwt_validation(secret);

    let auth_config = AuthConfig {
        jwt_secret: Some(secret.to_string()),
        ..Default::default()
    };

    let auth_manager = secureapis::auth::AuthManager::new(auth_config);
    let token = auth_manager
        .generate_token("user123".to_string(), vec!["user".to_string()])
        .unwrap();

    let layer = SecurityLayer::new(config);

    // Request with valid token
    let request: Request<Vec<u8>> = Request::builder()
        .uri("/api/protected")
        .header("authorization", format!("Bearer {}", token))
        .body(vec![])
        .unwrap();

    let result = layer.process_request(&request).await;
    assert!(result.is_ok(), "Valid JWT should be accepted");

    let context = result.unwrap();
    assert!(context.authenticated, "User should be authenticated");
    assert_eq!(context.user_id, Some("user123".to_string()));
}

#[tokio::test]
async fn test_path_traversal_detection() {
    let config = SecurityConfig::new().strict_mode();
    let layer = SecurityLayer::new(config);

    let malicious_paths = vec![
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "/etc/shadow",
        "....//....//etc/passwd",
    ];

    for path in malicious_paths {
        let request: Request<Vec<u8>> = Request::builder()
            .uri(format!("/api/file?path={}", urlencoding::encode(path)))
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_err(), "Path traversal should be detected: {}", path);
    }
}

#[tokio::test]
async fn test_command_injection_detection() {
    let config = SecurityConfig::new().strict_mode();
    let layer = SecurityLayer::new(config);

    let malicious_commands = vec![
        "file.txt; rm -rf /",
        "$(whoami)",
        "`cat /etc/passwd`",
        "file.txt && cat /etc/passwd",
    ];

    for cmd in malicious_commands {
        let request: Request<Vec<u8>> = Request::builder()
            .uri(format!("/api/process?file={}", urlencoding::encode(cmd)))
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_err(), "Command injection should be detected: {}", cmd);
    }
}

#[tokio::test]
async fn test_valid_requests_pass_through() {
    let config = SecurityConfig::new().strict_mode();
    let layer = SecurityLayer::new(config);

    let valid_requests = vec![
        "/api/users",
        "/api/posts?page=1&limit=10",
        "/api/search?q=hello+world",
        "/health",
    ];

    for uri in valid_requests {
        let request: Request<Vec<u8>> = Request::builder()
            .uri(uri)
            .body(vec![])
            .unwrap();

        let result = layer.process_request(&request).await;
        assert!(result.is_ok(), "Valid request should pass: {}", uri);
    }
}

#[tokio::test]
async fn test_concurrent_requests() {
    use tokio::task;

    let config = SecurityConfig::new().with_rate_limit(100, 60);
    let layer = std::sync::Arc::new(SecurityLayer::new(config));

    let mut handles = vec![];

    // Spawn 50 concurrent requests
    for i in 0..50 {
        let layer = layer.clone();
        let handle = task::spawn(async move {
            let request: Request<Vec<u8>> = Request::builder()
                .uri("/api/test")
                .header("x-forwarded-for", format!("192.168.1.{}", i % 10))
                .body(vec![])
                .unwrap();

            layer.process_request(&request).await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = futures::future::join_all(handles).await;

    // Most should succeed (some might fail due to rate limiting per IP)
    let successful = results.iter().filter(|r| r.as_ref().unwrap().is_ok()).count();
    assert!(successful >= 40, "At least 40 concurrent requests should succeed");
}
