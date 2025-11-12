use crate::config::SecurityConfig;
use crate::ui::state::UIState;
use http::Request;
use std::fmt;
use std::sync::Arc;
use chrono::Utc;

/// Result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Main security error type
#[derive(Debug, Clone)]
pub enum SecurityError {
    /// Rate limit exceeded
    RateLimitExceeded { retry_after: u64 },
    /// Authentication failed
    AuthenticationFailed(String),
    /// Authorization failed
    AuthorizationFailed(String),
    /// Invalid input detected
    InvalidInput { reason: String, field: Option<String> },
    /// Suspicious activity detected
    ThreatDetected { threat_type: String, severity: ThreatSeverity },
    /// Configuration error
    ConfigError(String),
    /// Internal error
    InternalError(String),
    /// CORS policy violation
    CorsViolation(String),
    /// CSRF validation failed
    CsrfViolation(String),
    /// HTTPS required
    HttpsRequired,
    /// Transport layer violation
    TransportLayerViolation(String),
    /// IP blocked
    IpBlocked(String),
    /// VPN detected
    VpnDetected(String),
    /// Proxy detected
    ProxyDetected(String),
    /// Request timeout
    RequestTimeout(String),
    /// Connection timeout
    ConnectionTimeout(String),
    /// Replay attack detected
    ReplayDetected(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimitExceeded { retry_after } => {
                write!(f, "Rate limit exceeded, retry after {} seconds", retry_after)
            }
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::AuthorizationFailed(msg) => write!(f, "Authorization failed: {}", msg),
            Self::InvalidInput { reason, field } => {
                if let Some(field) = field {
                    write!(f, "Invalid input in field '{}': {}", field, reason)
                } else {
                    write!(f, "Invalid input: {}", reason)
                }
            }
            Self::ThreatDetected { threat_type, severity } => {
                write!(f, "Threat detected: {} (severity: {:?})", threat_type, severity)
            }
            Self::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
            Self::CorsViolation(msg) => write!(f, "CORS violation: {}", msg),
            Self::CsrfViolation(msg) => write!(f, "CSRF validation failed: {}", msg),
            Self::HttpsRequired => write!(f, "HTTPS connection required"),
            Self::TransportLayerViolation(msg) => write!(f, "Transport layer violation: {}", msg),
            Self::IpBlocked(msg) => write!(f, "IP blocked: {}", msg),
            Self::VpnDetected(msg) => write!(f, "VPN detected: {}", msg),
            Self::ProxyDetected(msg) => write!(f, "Proxy detected: {}", msg),
            Self::RequestTimeout(msg) => write!(f, "Request timeout: {}", msg),
            Self::ConnectionTimeout(msg) => write!(f, "Connection timeout: {}", msg),
            Self::ReplayDetected(msg) => write!(f, "Replay attack detected: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security context passed through the middleware chain
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub request_id: String,
    pub client_ip: String,
    pub user_id: Option<String>,
    pub authenticated: bool,
    pub roles: Vec<String>,
    pub threat_score: u32,
    pub metadata: std::collections::HashMap<String, String>,
}

impl SecurityContext {
    pub fn new(request_id: String, client_ip: String) -> Self {
        Self {
            request_id,
            client_ip,
            user_id: None,
            authenticated: false,
            roles: Vec::new(),
            threat_score: 0,
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_user(mut self, user_id: String, roles: Vec<String>) -> Self {
        self.user_id = Some(user_id);
        self.authenticated = true;
        self.roles = roles;
        self
    }

    pub fn add_threat_score(&mut self, score: u32) {
        self.threat_score = self.threat_score.saturating_add(score);
    }

    pub fn is_high_risk(&self) -> bool {
        // Threshold increased to 100 to avoid false positives
        // Only block obvious threats
        self.threat_score > 100
    }
}

/// Main security layer
pub struct SecurityLayer {
    config: Arc<SecurityConfig>,
    rate_limiter: Arc<crate::rate_limit::RateLimiter>,
    validator: Arc<crate::validation::InputValidator>,
    auth_manager: Arc<crate::auth::AuthManager>,
    csrf_protection: Arc<crate::csrf::CsrfProtection>,
    monitor: Arc<crate::monitoring::Monitor>,
    blocked_store: Arc<crate::blocked_requests::BlockedRequestsStore>,
    ui_state: Option<Arc<UIState>>,
}

impl SecurityLayer {
    /// Create a new security layer with the given configuration
    pub fn new(config: SecurityConfig) -> Self {
        let config = Arc::new(config);

        Self {
            rate_limiter: Arc::new(crate::rate_limit::RateLimiter::new(
                config.rate_limit.clone(),
            )),
            validator: Arc::new(crate::validation::InputValidator::new(
                config.validation.clone(),
            )),
            auth_manager: Arc::new(crate::auth::AuthManager::new(config.auth.clone())),
            csrf_protection: Arc::new(crate::csrf::CsrfProtection::new()),
            monitor: Arc::new(crate::monitoring::Monitor::new(config.monitoring.clone())),
            blocked_store: Arc::new(crate::blocked_requests::BlockedRequestsStore::new(
                "blocked_requests.json".to_string(),
                1000, // Keep last 1000 blocked requests
            )),
            config,
            ui_state: None,
        }
    }

    /// Replace the internal blocked requests store with an externally provided one.
    /// This is useful to share the same store between the SecurityLayer and the UI.
    pub fn with_blocked_store(mut self, blocked_store: Arc<crate::blocked_requests::BlockedRequestsStore>) -> Self {
        self.blocked_store = blocked_store;
        self
    }

    /// Get the UI state
    pub fn ui_state(&self) -> &Option<Arc<UIState>> {
        &self.ui_state
    }

    /// Get the blocked requests store
    pub fn blocked_store(&self) -> &Arc<crate::blocked_requests::BlockedRequestsStore> {
        &self.blocked_store
    }

    /// Get the rate limiter
    pub fn rate_limiter(&self) -> &Arc<crate::rate_limit::RateLimiter> {
        &self.rate_limiter
    }

    /// Get the config
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }

    /// Set the UI state for metrics collection
    pub fn with_ui_state(mut self, ui_state: Arc<UIState>) -> Self {
        self.ui_state = Some(ui_state);
        self
    }

    /// Process an incoming request through the security pipeline
    pub async fn process_request<B>(
        &self,
        request: &Request<B>,
    ) -> SecurityResult<SecurityContext>
    where
        B: std::fmt::Debug,
    {
        // Extract client IP
        let client_ip = self.extract_client_ip(request);
        let request_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let user_agent = request.headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        // Extract request payload for logging
        let payload = self.extract_request_payload(request);

        let mut context = SecurityContext::new(request_id.clone(), client_ip.clone());

        // Update UI state: increment total requests
        if let Some(ui_state) = &self.ui_state {
            ui_state.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // 1. Rate limiting check (fastest check first)
        if self.config.rate_limit.enabled {
            if let Err(error) = self.rate_limiter.check(&client_ip).await {
                // Rate limited - store blocked request
                let _ = self.blocked_store.store_blocked_request(
                    request,
                    &context,
                    &error,
                    payload.clone(),
                ).await;

                if let Some(ui_state) = &self.ui_state {
                    ui_state.rate_limited.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = crate::ui::state::RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: None,
                        status_code: 429,
                        response_time_ms: 0.0,
                        threat_score: 0.0,
                        blocked: true,
                        reason: Some("Rate limit exceeded".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    ui_state.add_request_log(log).await;
                }
                return Err(error);
            }
        }

        // 2. Authentication check
        if self.config.auth.enabled {
            if let Some(user_context) = self.auth_manager.authenticate(request).await? {
                context = context.with_user(user_context.user_id, user_context.roles);
            } else if self.config.auth.require_auth {
                // Auth failed - store blocked request
                let error = SecurityError::AuthenticationFailed("Authentication required".to_string());
                let _ = self.blocked_store.store_blocked_request(
                    request,
                    &context,
                    &error,
                    payload.clone(),
                ).await;

                if let Some(ui_state) = &self.ui_state {
                    ui_state.auth_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = crate::ui::state::RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: None,
                        status_code: 401,
                        response_time_ms: 0.0,
                        threat_score: 0.0,
                        blocked: true,
                        reason: Some("Authentication failed".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    ui_state.add_request_log(log).await;
                }
                return Err(error);
            }
        }

        // 3. CSRF protection
        if self.config.csrf.enabled && method != "GET" && method != "HEAD" {
            if let Err(error) = self.csrf_protection.validate_csrf(request, &mut context).await {
                // CSRF failed - store blocked request
                let _ = self.blocked_store.store_blocked_request(
                    request,
                    &context,
                    &error,
                    payload.clone(),
                ).await;

                if let Some(ui_state) = &self.ui_state {
                    ui_state.csrf_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = crate::ui::state::RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: None,
                        status_code: 403,
                        response_time_ms: 0.0,
                        threat_score: 0.0,
                        blocked: true,
                        reason: Some("CSRF protection failed".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    ui_state.add_request_log(log).await;
                }
                return Err(error);
            }
        }

        // 4. Input validation
        if self.config.validation.enabled {
            if let Err(e) = self.validator.validate_request(request, &mut context).await {
                // Validation failed
                if let Some(ui_state) = &self.ui_state {
                    ui_state.validation_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = crate::ui::state::RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: context.user_id.clone(),
                        status_code: 400,
                        response_time_ms: 0.0,
                        threat_score: context.threat_score as f64,
                        blocked: true,
                        reason: Some("Validation failed".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    ui_state.add_request_log(log).await;
                }
                return Err(e); // Propagate the original validation error
            }
        }

        // 4. Threat detection
        if self.config.threat_detection.enabled {
            if let Err(_) = self.detect_threats(request, &mut context).await {
                // Threat detected - always log as blocked threat
                if let Some(ui_state) = &self.ui_state {
                    ui_state.blocked_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let log = crate::ui::state::RequestLog {
                        id: request_id.clone(),
                        timestamp,
                        method: method.clone(),
                        path: path.clone(),
                        client_ip: client_ip.clone(),
                        user_agent: user_agent.clone(),
                        user_id: context.user_id.clone(),
                        status_code: 403,
                        response_time_ms: 0.0,
                        threat_score: context.threat_score as f64,
                        blocked: true,
                        reason: Some("Threat detected".to_string()),
                        headers: std::collections::HashMap::new(),
                    };
                    ui_state.add_request_log(log).await;
                }
                return Err(SecurityError::ThreatDetected {
                    threat_type: "Suspicious request pattern".to_string(),
                    severity: ThreatSeverity::High,
                });
            }
        }

        // 5. Monitoring
        if self.config.monitoring.enabled {
            self.monitor.log_request(request, &context).await;
        }

        // Success: add successful request log
        if let Some(ui_state) = &self.ui_state {
            let log = crate::ui::state::RequestLog {
                id: request_id.clone(),
                timestamp,
                method,
                path,
                client_ip,
                user_agent,
                user_id: context.user_id.clone(),
                status_code: 200, // Will be updated later with actual status
                response_time_ms: 0.0, // Will be updated later
                threat_score: context.threat_score as f64,
                blocked: false,
                reason: None,
                headers: std::collections::HashMap::new(),
            };
            ui_state.add_request_log(log).await;
        }

        Ok(context)
    }

    /// Synchronous version of process_request for FFI bindings
    pub fn process_request_sync<B: std::fmt::Debug>(
        &self,
        request: &Request<B>,
    ) -> SecurityResult<SecurityContext> {
        // Create a runtime for executing async code synchronously
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(self.process_request(request))
    }

    fn extract_client_ip<B>(&self, request: &Request<B>) -> String {
        // Try X-Forwarded-For, X-Real-IP, or connection IP
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or("unknown")
            .to_string()
    }

    fn extract_request_payload<B>(&self, request: &Request<B>) -> Option<String>
    where
        B: std::fmt::Debug,
    {
        // Try to extract payload from request body
        // Note: This is a simplified version. In a real implementation,
        // you'd need to handle different body types properly
        let body_str = format!("{:?}", request.body());
        if body_str.len() > 2 && body_str != "()" { // Filter out empty bodies
            Some(body_str)
        } else {
            None
        }
    }

    async fn detect_threats<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        // Smart threat detection based on request patterns
        let uri = request.uri().to_string();
        let uri_lower = uri.to_lowercase();
        
        // Track different attack indicators
        let mut has_sql_combo = false;
        let mut has_xss = false;
        let mut has_path_traversal = false;
        
        // IMPORTANT: Only flag clear, unambiguous attack patterns
        // Threshold is 100 to avoid false positives on legitimate URLs
        
        // Path traversal attempts - only if obvious
        if uri.contains("../") || uri.contains("..\\") {
            // Check if it looks like a real attack (multiple traversals)
            if uri.contains("../../../") || uri.contains("..\\..\\..\\") {
                context.add_threat_score(40);
                has_path_traversal = true;
            }
        }
        
        // URL-encoded path traversal
        if uri.contains("..%2f") || uri.contains("..%5c") {
            context.add_threat_score(50);
            has_path_traversal = true;
        }
        
        // XSS attempts - very specific patterns
        if uri_lower.contains("<script") || uri_lower.contains("javascript:alert") {
            context.add_threat_score(60);
            has_xss = true;
        }
        
        // Obvious XSS event handlers
        if (uri_lower.contains("onerror=") && !uri_lower.contains("onerror_")) ||
           (uri_lower.contains("onload=") && !uri_lower.contains("onload_")) {
            context.add_threat_score(50);
            has_xss = true;
        }
        
        // SQL Injection - check for dangerous combos
        // These keywords together strongly indicate SQL injection
        if uri_lower.contains("union") && uri_lower.contains("select") {
            context.add_threat_score(60);
            has_sql_combo = true;
        }
        
        if uri_lower.contains("'; drop") || uri_lower.contains("'; delete") {
            context.add_threat_score(60);
            has_sql_combo = true;
        }
        
        if uri_lower.contains("' or '1'='1") || uri_lower.contains("1'or'1'='1") {
            context.add_threat_score(60);
            has_sql_combo = true;
        }
        
        // Command injection - shell metacharacters
        if (uri.contains("`;") || uri.contains("`|")) && uri.contains("/api/") {
            context.add_threat_score(50);
        }
        
        // Check headers for suspicious patterns
        for (header_name, header_value) in request.headers() {
            if let Ok(value_str) = header_value.to_str() {
                let value_lower = value_str.to_lowercase();
                
                // Very large headers (potential buffer overflow)
                if value_str.len() > 8192 {
                    context.add_threat_score(30);
                }
                
                // Suspicious scanning tools
                if header_name == "user-agent" {
                    if value_lower.contains("sqlmap") || value_lower.contains("nikto") || 
                       value_lower.contains("nmap") || value_lower.contains("masscan") ||
                       value_lower.contains("burp") {
                        context.add_threat_score(70);
                    }
                }
            }
        }
        
        // Block decision logic:
        if self.config.threat_detection.block_suspicious {
            // Case 1: Obvious attack combo (even if score is low)
            if has_sql_combo || has_xss || has_path_traversal {
                if context.threat_score >= 40 {
                    return Err(SecurityError::ThreatDetected {
                        threat_type: "Suspicious request pattern".to_string(),
                        severity: ThreatSeverity::High,
                    });
                }
            }
            
            // Case 2: Very high score (multiple indicators)
            if context.threat_score >= 100 {
                return Err(SecurityError::ThreatDetected {
                    threat_type: "Suspicious request pattern".to_string(),
                    severity: ThreatSeverity::High,
                });
            }
        }

        Ok(())
    }
}

impl Clone for SecurityLayer {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            rate_limiter: Arc::clone(&self.rate_limiter),
            validator: Arc::clone(&self.validator),
            auth_manager: Arc::clone(&self.auth_manager),
            csrf_protection: Arc::clone(&self.csrf_protection),
            monitor: Arc::clone(&self.monitor),
            blocked_store: Arc::clone(&self.blocked_store),
            ui_state: self.ui_state.clone(),
        }
    }
}
