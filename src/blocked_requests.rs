use crate::core::{SecurityContext, SecurityError, ThreatSeverity};
use http::Request;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Blocked request storage and management
pub struct BlockedRequestsStore {
    storage_file: String,
    max_entries: usize,
    requests: Arc<RwLock<Vec<BlockedRequest>>>,
}

impl BlockedRequestsStore {
    pub fn new(storage_file: String, max_entries: usize) -> Self {
        let store = Self {
            storage_file,
            max_entries,
            requests: Arc::new(RwLock::new(Vec::new())),
        };
        // Load existing data on startup
        let _ = store.load_from_file();
        store
    }

    /// Store a blocked request
    pub async fn store_blocked_request<B>(
        &self,
        request: &Request<B>,
        context: &SecurityContext,
        error: &SecurityError,
        payload: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let blocked_request = BlockedRequest::from_request(request, context, error, payload);

        let mut requests = self.requests.write().await;

        // Add new request
        requests.push(blocked_request);

        // Keep only the most recent entries
        if requests.len() > self.max_entries {
            requests.remove(0);
        }

        // Save to file
        self.save_to_file(&requests).await?;

        Ok(())
    }

    /// Add a pre-created blocked request
    pub async fn add_blocked_request(
        &self,
        blocked_request: BlockedRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = self.requests.write().await;

        // Add new request
        requests.push(blocked_request);

        // Keep only the most recent entries
        if requests.len() > self.max_entries {
            requests.remove(0);
        }

        // Save to file
        self.save_to_file(&requests).await?;

        Ok(())
    }

    /// Get all blocked requests
    pub async fn get_blocked_requests(&self) -> Vec<BlockedRequest> {
        self.requests.read().await.clone()
    }

    /// Get blocked requests with pagination
    pub async fn get_blocked_requests_paginated(
        &self,
        page: usize,
        per_page: usize,
    ) -> (Vec<BlockedRequest>, usize) {
        let requests = self.requests.read().await;
        let total = requests.len();
        let start = page * per_page;
        let end = (start + per_page).min(total);

        if start >= total {
            (Vec::new(), total)
        } else {
            (requests[start..end].to_vec(), total)
        }
    }

    /// Clear all blocked requests
    pub async fn clear_blocked_requests(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = self.requests.write().await;
        requests.clear();
        self.save_to_file(&requests).await?;
        Ok(())
    }

    /// Load blocked requests from file
    fn load_from_file(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !std::path::Path::new(&self.storage_file).exists() {
            return Ok(());
        }

        let data = fs::read_to_string(&self.storage_file)?;
        let requests: Vec<BlockedRequest> = serde_json::from_str(&data)?;

        // Update in-memory storage
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let mut store_requests = self.requests.write().await;
            *store_requests = requests;
        });

        Ok(())
    }

    /// Save blocked requests to file
    async fn save_to_file(&self, requests: &[BlockedRequest]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string_pretty(requests)?;

        // Create directory if it doesn't exist
        if let Some(parent) = std::path::Path::new(&self.storage_file).parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.storage_file)?;

        file.write_all(json.as_bytes())?;
        file.flush()?;

        Ok(())
    }
}

/// Represents a blocked request with full details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedRequest {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub user_agent: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub payload: Option<String>,
    pub threat_score: u32,
    pub block_reason: String,
    pub severity: ThreatSeverity,
    pub user_id: Option<String>,
    pub request_size: usize,
}

impl BlockedRequest {
    pub fn from_request<B>(
        request: &Request<B>,
        context: &SecurityContext,
        error: &SecurityError,
        payload: Option<String>,
    ) -> Self {
        let headers: std::collections::HashMap<String, String> = request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
            })
            .collect();

        // Calculate request size (headers + body approximation)
        let header_size = headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
        let body_size = payload.as_ref().map(|p| p.len()).unwrap_or(0);
        let request_size = header_size + body_size;

        Self {
            id: context.request_id.clone(),
            timestamp: Utc::now(),
            client_ip: context.client_ip.clone(),
            user_agent: request
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("unknown")
                .to_string(),
            method: request.method().to_string(),
            url: request.uri().to_string(),
            headers,
            payload,
            threat_score: context.threat_score,
            block_reason: error.to_string(),
            severity: match error {
                SecurityError::ThreatDetected { severity, .. } => *severity,
                SecurityError::RateLimitExceeded { .. } => ThreatSeverity::Medium,
                SecurityError::AuthenticationFailed(_) => ThreatSeverity::Medium,
                SecurityError::InvalidInput { .. } => ThreatSeverity::High,
                _ => ThreatSeverity::Medium,
            },
            user_id: context.user_id.clone(),
            request_size,
        }
    }
}

/// Statistics for blocked requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedRequestsStats {
    pub total_blocked: usize,
    pub by_reason: HashMap<String, usize>,
    pub by_ip: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub recent_activity: Vec<DateTime<Utc>>,
}

impl BlockedRequestsStore {
    pub async fn get_stats(&self) -> BlockedRequestsStats {
        let requests = self.requests.read().await;

        let mut by_reason = HashMap::new();
        let mut by_ip = HashMap::new();
        let mut by_severity = HashMap::new();
        let mut recent_activity = Vec::new();

        for request in requests.iter() {
            // Count by reason
            *by_reason.entry(request.block_reason.clone()).or_insert(0) += 1;

            // Count by IP
            *by_ip.entry(request.client_ip.clone()).or_insert(0) += 1;

            // Count by severity
            let severity_str = format!("{:?}", request.severity);
            *by_severity.entry(severity_str).or_insert(0) += 1;

            // Track recent activity (last 24 hours)
            if request.timestamp > Utc::now() - chrono::Duration::hours(24) {
                recent_activity.push(request.timestamp);
            }
        }

        // Sort recent activity
        recent_activity.sort_by(|a, b| b.cmp(a));

        BlockedRequestsStats {
            total_blocked: requests.len(),
            by_reason,
            by_ip,
            by_severity,
            recent_activity,
        }
    }
}