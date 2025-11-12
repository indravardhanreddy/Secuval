//! # SecureAPIs - High-Performance API Security Middleware
//! 
//! A zero-overhead security layer for protecting APIs against common vulnerabilities
//! and penetration testing attacks.

pub mod config;
pub mod core;
pub mod middleware;
pub mod rate_limit;
pub mod validation;
pub mod auth;
pub mod monitoring;
pub mod threats;
pub mod ui;
pub mod https;
pub mod cors;
pub mod headers;
pub mod csrf;
pub mod advanced_validation;
pub mod ip_reputation;
pub mod content_type;
pub mod error_handling;
pub mod request_constraints;
pub mod method_validator;
pub mod cookie_security;
pub mod replay_protection;
pub mod blocked_requests;
pub mod api;

// Re-exports for convenience
pub use config::{SecurityConfig, RateLimitConfig, ValidationConfig, AuthConfig};
pub use core::{SecurityLayer, SecurityContext, SecurityError, SecurityResult};
pub use middleware::{SecurityMiddleware, MiddlewareChain};
pub use ui::{UIManager, Dashboard, RequestTracker, AlertManager, SettingsManager, MetricsCollector};
pub use https::HttpsEnforcer;
pub use cors::CorsEnforcer;
pub use headers::SecurityHeaders;
pub use csrf::CsrfProtection;
pub use advanced_validation::AdvancedValidator;
pub use ip_reputation::IpReputation;
pub use content_type::ContentTypeValidator;
pub use error_handling::{ErrorHandler, SafeErrorResponse};
pub use request_constraints::RequestConstraints;
pub use method_validator::MethodValidator;
pub use cookie_security::CookieSecurity;
pub use replay_protection::ReplayProtection;

/// Prelude module for common imports
pub mod prelude {
    pub use crate::config::*;
    pub use crate::core::{SecurityLayer, SecurityContext, SecurityError, SecurityResult};
    pub use crate::middleware::SecurityMiddleware;
    pub use crate::ui::*;
}
