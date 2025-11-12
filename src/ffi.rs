//! # SecureAPIs FFI (Foreign Function Interface)
//!
//! This module exposes SecureAPIs functionality to other languages via C ABI.
//! Used for creating language bindings (C#, Java, Node.js, etc.)

use crate::config::{
    SecurityConfig, RateLimitConfig, ValidationConfig, AuthConfig, MonitoringConfig,
    ThreatDetectionConfig, HttpsConfig, CorsConfig, CsrfConfig, ContentTypeConfig
};
use crate::core::SecurityLayer;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use serde_json;

/// Simple config structure matching C# SecureAPIsConfig
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SimpleConfig {
    rate_limit_requests: i32,
    rate_limit_window_seconds: i32,
    jwt_secret: Option<String>,
    enable_input_validation: bool,
    enable_cors: bool,
    enable_security_headers: bool,
}

/// Result of a security check
#[repr(C)]
pub struct SecurityCheckResult {
    /// 1 if request is allowed, 0 if blocked
    pub allowed: i32,
    /// HTTP status code (200, 403, 429, etc.)
    pub status_code: i32,
    /// Error message if blocked (null if allowed)
    pub error_message: *const c_char,
    /// Additional headers to add (JSON string, null if none)
    pub headers_json: *const c_char,
}

/// Free a string allocated by Rust
#[no_mangle]
pub extern "C" fn secureapis_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Create a new security configuration from JSON
#[no_mangle]
pub extern "C" fn secureapis_create_config(config_json: *const c_char) -> *mut SecurityLayer {
    if config_json.is_null() {
        return ptr::null_mut();
    }

    // Convert C string to Rust string
    let config_str = unsafe { CStr::from_ptr(config_json) }.to_str();
    let config_str = match config_str {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    // Try to parse as full SecurityConfig first
    let config = if let Ok(full_config) = serde_json::from_str::<SecurityConfig>(config_str) {
        full_config
    } else {
        // Fall back to simple C# config format
        if let Ok(simple_config) = serde_json::from_str::<SimpleConfig>(config_str) {
            SecurityConfig {
                rate_limit: RateLimitConfig {
                    enabled: true,
                    requests_per_window: simple_config.rate_limit_requests as u32,
                    window_duration: std::time::Duration::from_secs(simple_config.rate_limit_window_seconds as u64),
                    burst_size: simple_config.rate_limit_requests as u32,
                    per_ip: true,
                    per_user: false,
                    adaptive: false,
                },
                validation: ValidationConfig {
                    enabled: simple_config.enable_input_validation,
                    sql_injection_check: simple_config.enable_input_validation,
                    xss_check: simple_config.enable_input_validation,
                    command_injection_check: simple_config.enable_input_validation,
                    path_traversal_check: simple_config.enable_input_validation,
                    sanitize_input: simple_config.enable_input_validation,
                    max_payload_size: 10 * 1024 * 1024,
                    max_header_size: 8 * 1024,
                },
                auth: AuthConfig {
                    enabled: simple_config.jwt_secret.is_some(),
                    require_auth: simple_config.jwt_secret.is_some(),
                    jwt_secret: simple_config.jwt_secret,
                    api_keys: Vec::new(),
                    token_expiry: std::time::Duration::from_secs(3600),
                    refresh_enabled: false,
                    mfa_enabled: false,
                },
                monitoring: MonitoringConfig::default(),
                threat_detection: ThreatDetectionConfig::default(),
                https: HttpsConfig::default(),
                cors: CorsConfig {
                    enabled: simple_config.enable_cors,
                    allow_origins: vec!["*".to_string()],
                    allow_all_origins: simple_config.enable_cors,
                    allow_methods: vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                    allow_headers: vec!["*".to_string()],
                    allow_credentials: false,
                    max_age: 86400,
                },
                csrf: CsrfConfig::default(),
                content_type: ContentTypeConfig::default(),
            }
        } else {
            return ptr::null_mut();
        }
    };

    let security_layer = SecurityLayer::new(config);
    Box::into_raw(Box::new(security_layer))
}

/// Free a security layer
#[no_mangle]
pub extern "C" fn secureapis_free_security_layer(layer: *mut SecurityLayer) {
    if !layer.is_null() {
        unsafe {
            let _ = Box::from_raw(layer);
        }
    }
}

/// Check a request for security violations
/// Returns a SecurityCheckResult that must be freed with secureapis_free_result
#[no_mangle]
pub extern "C" fn secureapis_check_request(
    security_layer: *const SecurityLayer,
    method: *const c_char,
    url: *const c_char,
    headers_json: *const c_char,
    body: *const c_char,
    ip: *const c_char,
) -> *mut SecurityCheckResult {
    if security_layer.is_null() {
        return ptr::null_mut();
    }

    // Parse inputs
    let method_str = unsafe { CStr::from_ptr(method) }.to_str().unwrap_or("");
    let url_str = unsafe { CStr::from_ptr(url) }.to_str().unwrap_or("");
    let headers_str = unsafe { CStr::from_ptr(headers_json) }.to_str().unwrap_or("{}");
    let body_str = unsafe { CStr::from_ptr(body) }.to_str().unwrap_or("");
    let ip_str = unsafe { CStr::from_ptr(ip) }.to_str().unwrap_or("");

    // Create a mock HTTP request for the security layer
    let request = create_mock_request(method_str, url_str, headers_str, body_str, ip_str);

    // Get security layer
    let layer = unsafe { &*security_layer };

    // Run security check synchronously
    let result = match layer.process_request_sync(&request) {
        Ok(_) => {
            // Request allowed
            SecurityCheckResult {
                allowed: 1,
                status_code: 200,
                error_message: ptr::null(),
                headers_json: ptr::null(),
            }
        }
        Err(error) => {
            // Request blocked
            let (status_code, error_msg) = match error {
                crate::SecurityError::RateLimitExceeded { retry_after } => {
                    (429, format!("Rate limit exceeded. Retry after {} seconds", retry_after))
                }
                crate::SecurityError::AuthenticationFailed(msg) => (401, msg),
                crate::SecurityError::AuthorizationFailed(msg) => (403, msg),
                crate::SecurityError::InvalidInput { reason, .. } => (400, reason),
                crate::SecurityError::ThreatDetected { threat_type, .. } => {
                    (403, format!("Threat detected: {}", threat_type))
                }
                crate::SecurityError::CorsViolation(msg) => (403, msg),
                crate::SecurityError::CsrfViolation(msg) => (403, msg),
                crate::SecurityError::HttpsRequired => (403, "HTTPS required".to_string()),
                _ => (500, "Internal security error".to_string()),
            };

            let error_cstr = match CString::new(error_msg) {
                Ok(cstr) => cstr,
                Err(_) => return ptr::null_mut(),
            };

            SecurityCheckResult {
                allowed: 0,
                status_code,
                error_message: error_cstr.into_raw(),
                headers_json: ptr::null(), // TODO: Add security headers
            }
        }
    };

    Box::into_raw(Box::new(result))
}

/// Free a security check result
#[no_mangle]
pub extern "C" fn secureapis_free_result(result: *mut SecurityCheckResult) {
    if !result.is_null() {
        unsafe {
            let result = Box::from_raw(result);
            if !result.error_message.is_null() {
                let _ = CString::from_raw(result.error_message as *mut c_char);
            }
            if !result.headers_json.is_null() {
                let _ = CString::from_raw(result.headers_json as *mut c_char);
            }
        }
    }
}

/// Helper function to create a mock HTTP request
fn create_mock_request(
    method: &str,
    url: &str,
    headers_json: &str,
    body: &str,
    ip: &str,
) -> http::Request<String> {
    use http::{Method, Uri, Version};

    // Parse method
    let method = match method.to_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        "HEAD" => Method::HEAD,
        "OPTIONS" => Method::OPTIONS,
        _ => Method::GET,
    };

    // Create URI
    let uri = url.parse::<Uri>().unwrap_or_else(|_| "/".parse().unwrap());

    // Create request
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_11)
        .body(body.to_string())
        .unwrap();

    // Add headers
    if let Ok(headers) = serde_json::from_str::<std::collections::HashMap<String, String>>(headers_json) {
        for (key, value) in headers {
            request.headers_mut().insert(
                http::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(&value).unwrap(),
            );
        }
    }

    // Add IP as a custom header for security checks
    request.headers_mut().insert(
        http::header::HeaderName::from_static("x-forwarded-for"),
        http::header::HeaderValue::from_str(ip).unwrap(),
    );

    request
}