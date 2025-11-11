use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Main security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub rate_limit: RateLimitConfig,
    pub validation: ValidationConfig,
    pub auth: AuthConfig,
    pub monitoring: MonitoringConfig,
    pub threat_detection: ThreatDetectionConfig,
    pub https: HttpsConfig,
    pub cors: CorsConfig,
    pub csrf: CsrfConfig,
    pub content_type: ContentTypeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig::default(),
            validation: ValidationConfig::default(),
            auth: AuthConfig::default(),
            monitoring: MonitoringConfig::default(),
            threat_detection: ThreatDetectionConfig::default(),
            https: HttpsConfig::default(),
            cors: CorsConfig::default(),
            csrf: CsrfConfig::default(),
            content_type: ContentTypeConfig::default(),
        }
    }
}

impl SecurityConfig {
    /// Create a new security config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure rate limiting
    pub fn with_rate_limit(mut self, requests: u32, window_secs: u64) -> Self {
        self.rate_limit.requests_per_window = requests;
        self.rate_limit.window_duration = Duration::from_secs(window_secs);
        self.rate_limit.burst_size = requests; // Set burst size to match requests per window
        self.rate_limit.enabled = true;
        self
    }

    /// Enable JWT validation with secret
    pub fn with_jwt_validation(mut self, secret: impl Into<String>) -> Self {
        self.auth.jwt_secret = Some(secret.into());
        self.auth.require_auth = true;
        self
    }

    /// Enable input sanitization
    pub fn with_input_sanitization(mut self, enabled: bool) -> Self {
        self.validation.sanitize_input = enabled;
        self
    }

    /// Set strict mode (maximum security)
    pub fn strict_mode(mut self) -> Self {
        self.validation.sql_injection_check = true;
        self.validation.xss_check = true;
        self.validation.command_injection_check = true;
        self.validation.path_traversal_check = true;
        self.validation.sanitize_input = true;
        self.threat_detection.anomaly_detection = true;
        self.threat_detection.bot_detection = true;
        self
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_window: u32,
    pub window_duration: Duration,
    pub burst_size: u32,
    pub per_ip: bool,
    pub per_user: bool,
    pub adaptive: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_window: 100_000, // 1 lakh (100k) requests per window
            window_duration: Duration::from_secs(60),
            burst_size: 10_000, // 10k burst size
            per_ip: true,
            per_user: true,
            adaptive: true,
        }
    }
}

/// Input validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub enabled: bool,
    pub sql_injection_check: bool,
    pub xss_check: bool,
    pub command_injection_check: bool,
    pub path_traversal_check: bool,
    pub sanitize_input: bool,
    pub max_payload_size: usize,
    pub max_header_size: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sql_injection_check: true,
            xss_check: true,
            command_injection_check: true,
            path_traversal_check: true,
            sanitize_input: true,
            max_payload_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 8 * 1024,           // 8KB
        }
    }
}

/// Authentication and authorization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub require_auth: bool,
    pub jwt_secret: Option<String>,
    pub api_keys: Vec<String>,
    pub token_expiry: Duration,
    pub refresh_enabled: bool,
    pub mfa_enabled: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_auth: false,
            jwt_secret: None,
            api_keys: Vec::new(),
            token_expiry: Duration::from_secs(3600), // 1 hour
            refresh_enabled: false,
            mfa_enabled: false,
        }
    }
}

/// Monitoring and logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub log_requests: bool,
    pub log_responses: bool,
    pub log_security_events: bool,
    pub metrics_enabled: bool,
    pub trace_sampling_rate: f64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_requests: true,
            log_responses: false,
            log_security_events: true,
            metrics_enabled: true,
            trace_sampling_rate: 0.1, // 10% sampling
        }
    }
}

/// Threat detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionConfig {
    pub enabled: bool,
    pub anomaly_detection: bool,
    pub bot_detection: bool,
    pub known_patterns: bool,
    pub block_suspicious: bool,
}

impl Default for ThreatDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            anomaly_detection: true,
            bot_detection: true,
            known_patterns: true,
            block_suspicious: true, // Enable blocking of suspicious requests
        }
    }
}

/// HTTPS/TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpsConfig {
    pub enabled: bool,
    pub require_https: bool,
    pub hsts_max_age: u32,
    pub hsts_include_subdomains: bool,
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_https: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allow_origins: Vec<String>,
    pub allow_all_origins: bool,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: u32,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_origins: vec!["https://localhost:3000".to_string()],
            allow_all_origins: false,
            allow_methods: vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allow_headers: vec!["Content-Type", "Authorization", "X-API-Key"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allow_credentials: true,
            max_age: 86400, // 24 hours
        }
    }
}

/// CSRF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    pub enabled: bool,
    pub token_length: usize,
    pub header_name: String,
    pub param_name: String,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            token_length: 32,
            header_name: "X-CSRF-Token".to_string(),
            param_name: "_csrf".to_string(),
        }
    }
}

/// Content-Type validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentTypeConfig {
    pub enabled: bool,
    pub allowed_types: Vec<String>,
    pub strict_mode: bool,
}

impl Default for ContentTypeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
                "application/xml".to_string(),
            ],
            strict_mode: false,
        }
    }
}
