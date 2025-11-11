use crate::config::MonitoringConfig;
use crate::core::SecurityContext;
use http::Request;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Monitoring and logging system
pub struct Monitor {
    config: MonitoringConfig,
    request_counter: Arc<AtomicU64>,
    security_event_counter: Arc<AtomicU64>,
}

impl Monitor {
    pub fn new(config: MonitoringConfig) -> Self {
        // Initialize tracing subscriber if not already initialized
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init();

        Self {
            config,
            request_counter: Arc::new(AtomicU64::new(0)),
            security_event_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Log an incoming request
    pub async fn log_request<B>(&self, request: &Request<B>, context: &SecurityContext) {
        if !self.config.enabled || !self.config.log_requests {
            return;
        }

        let count = self.request_counter.fetch_add(1, Ordering::Relaxed);

        if self.should_sample() {
            info!(
                request_id = %context.request_id,
                client_ip = %context.client_ip,
                method = %request.method(),
                uri = %request.uri(),
                user_id = ?context.user_id,
                threat_score = context.threat_score,
                request_count = count,
                "Incoming request"
            );
        } else {
            debug!(
                request_id = %context.request_id,
                "Request (sampled out)"
            );
        }
    }

    /// Log a security event
    pub async fn log_security_event(&self, event: SecurityEvent, context: &SecurityContext) {
        if !self.config.enabled || !self.config.log_security_events {
            return;
        }

        self.security_event_counter.fetch_add(1, Ordering::Relaxed);

        match event.severity {
            EventSeverity::Low => debug!(
                request_id = %context.request_id,
                event_type = ?event.event_type,
                description = %event.description,
                "Security event (low)"
            ),
            EventSeverity::Medium => info!(
                request_id = %context.request_id,
                client_ip = %context.client_ip,
                event_type = ?event.event_type,
                description = %event.description,
                "Security event (medium)"
            ),
            EventSeverity::High | EventSeverity::Critical => warn!(
                request_id = %context.request_id,
                client_ip = %context.client_ip,
                user_id = ?context.user_id,
                event_type = ?event.event_type,
                description = %event.description,
                threat_score = context.threat_score,
                "Security event (high/critical)"
            ),
        }
    }

    /// Get monitoring statistics
    pub fn stats(&self) -> MonitoringStats {
        MonitoringStats {
            total_requests: self.request_counter.load(Ordering::Relaxed),
            security_events: self.security_event_counter.load(Ordering::Relaxed),
        }
    }

    /// Determine if this request should be sampled for detailed logging
    fn should_sample(&self) -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < self.config.trace_sampling_rate
    }
}

/// Security event for logging
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub description: String,
    pub severity: EventSeverity,
}

impl SecurityEvent {
    pub fn new(event_type: SecurityEventType, description: String, severity: EventSeverity) -> Self {
        Self {
            event_type,
            description,
            severity,
        }
    }

    pub fn rate_limit_exceeded(identifier: &str) -> Self {
        Self::new(
            SecurityEventType::RateLimitExceeded,
            format!("Rate limit exceeded for: {}", identifier),
            EventSeverity::Medium,
        )
    }

    pub fn auth_failed(reason: &str) -> Self {
        Self::new(
            SecurityEventType::AuthenticationFailed,
            reason.to_string(),
            EventSeverity::Medium,
        )
    }

    pub fn injection_detected(injection_type: &str, field: &str) -> Self {
        Self::new(
            SecurityEventType::InjectionAttempt,
            format!("{} injection detected in field: {}", injection_type, field),
            EventSeverity::High,
        )
    }

    pub fn threat_detected(threat_type: &str) -> Self {
        Self::new(
            SecurityEventType::ThreatDetected,
            format!("Threat detected: {}", threat_type),
            EventSeverity::High,
        )
    }
}

/// Types of security events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventType {
    RateLimitExceeded,
    AuthenticationFailed,
    AuthorizationFailed,
    InjectionAttempt,
    ThreatDetected,
    InvalidInput,
    SuspiciousActivity,
}

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Monitoring statistics
#[derive(Debug, Clone)]
pub struct MonitoringStats {
    pub total_requests: u64,
    pub security_events: u64,
}

/// Metrics recorder for performance monitoring
pub struct MetricsRecorder {
    enabled: bool,
}

impl MetricsRecorder {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Record request duration
    pub fn record_request_duration(&self, duration_micros: u64) {
        if !self.enabled {
            return;
        }
        debug!(duration_micros = duration_micros, "Request duration");
    }

    /// Record security check duration
    pub fn record_security_check_duration(&self, check_name: &str, duration_micros: u64) {
        if !self.enabled {
            return;
        }
        debug!(
            check_name = check_name,
            duration_micros = duration_micros,
            "Security check duration"
        );
    }
}
