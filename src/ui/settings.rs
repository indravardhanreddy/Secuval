//! # Dynamic settings management
//! 
//! Allows users to dynamically modify security configurations and UI preferences.

use crate::ui::state::{UIState, UIPreferences};
use crate::ui::persistence::PersistenceManager;
use crate::config::SecurityConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;

/// Settings manager
pub struct SettingsManager {
    state: Arc<UIState>,
    persistence: Arc<PersistenceManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsChange {
    pub timestamp: chrono::DateTime<Utc>,
    pub changed_by: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

impl SettingsManager {
    /// Create a new settings manager with default persistence
    pub fn new(state: Arc<UIState>) -> Self {
        Self {
            state,
            persistence: Arc::new(PersistenceManager::default()),
        }
    }

    /// Create a new settings manager with custom persistence path
    pub fn with_persistence<S: Into<String>>(state: Arc<UIState>, path: S) -> Self {
        Self {
            state,
            persistence: Arc::new(PersistenceManager::with_path(path.into())),
        }
    }
    /// Get current security configuration
    pub async fn get_security_config(&self) -> SecurityConfig {
        self.state.get_config().await
    }

    /// Update rate limit configuration
    pub async fn update_rate_limit(
        &self,
        requests_per_window: Option<u32>,
        window_secs: Option<u64>,
        burst_size: Option<u32>,
        adaptive: Option<bool>,
    ) -> Result<SecurityConfig, String> {
        let mut config = self.state.get_config().await;
        
        if let Some(req) = requests_per_window {
            config.rate_limit.requests_per_window = req;
        }
        if let Some(secs) = window_secs {
            config.rate_limit.window_duration = std::time::Duration::from_secs(secs);
        }
        if let Some(burst) = burst_size {
            config.rate_limit.burst_size = burst;
        }
        if let Some(adapt) = adaptive {
            config.rate_limit.adaptive = adapt;
        }

        self.state.update_config(config.clone()).await;
        Ok(config)
    }

    /// Update validation configuration
    pub async fn update_validation(
        &self,
        sql_injection_check: Option<bool>,
        xss_check: Option<bool>,
        command_injection_check: Option<bool>,
        path_traversal_check: Option<bool>,
        sanitize_input: Option<bool>,
        max_payload_size: Option<usize>,
    ) -> Result<SecurityConfig, String> {
        let mut config = self.state.get_config().await;
        
        if let Some(sql) = sql_injection_check {
            config.validation.sql_injection_check = sql;
        }
        if let Some(xss) = xss_check {
            config.validation.xss_check = xss;
        }
        if let Some(cmd) = command_injection_check {
            config.validation.command_injection_check = cmd;
        }
        if let Some(path) = path_traversal_check {
            config.validation.path_traversal_check = path;
        }
        if let Some(sanitize) = sanitize_input {
            config.validation.sanitize_input = sanitize;
        }
        if let Some(size) = max_payload_size {
            config.validation.max_payload_size = size;
        }

        self.state.update_config(config.clone()).await;
        Ok(config)
    }

    /// Update authentication configuration
    pub async fn update_auth(
        &self,
        require_auth: Option<bool>,
        jwt_secret: Option<String>,
        token_expiry_secs: Option<u64>,
        mfa_enabled: Option<bool>,
    ) -> Result<SecurityConfig, String> {
        let mut config = self.state.get_config().await;
        
        if let Some(req) = require_auth {
            config.auth.require_auth = req;
        }
        if let Some(secret) = jwt_secret {
            config.auth.jwt_secret = Some(secret);
        }
        if let Some(expiry) = token_expiry_secs {
            config.auth.token_expiry = std::time::Duration::from_secs(expiry);
        }
        if let Some(mfa) = mfa_enabled {
            config.auth.mfa_enabled = mfa;
        }

        self.state.update_config(config.clone()).await;
        Ok(config)
    }

    /// Update threat detection configuration
    pub async fn update_threat_detection(
        &self,
        bot_detection: Option<bool>,
        anomaly_detection: Option<bool>,
        known_patterns: Option<bool>,
    ) -> Result<SecurityConfig, String> {
        let mut config = self.state.get_config().await;
        
        if let Some(bot) = bot_detection {
            config.threat_detection.bot_detection = bot;
        }
        if let Some(anomaly) = anomaly_detection {
            config.threat_detection.anomaly_detection = anomaly;
        }
        if let Some(patterns) = known_patterns {
            config.threat_detection.known_patterns = patterns;
        }

        self.state.update_config(config.clone()).await;
        Ok(config)
    }

    /// Toggle all security features to strict mode
    pub async fn set_strict_mode(&self, enabled: bool) -> Result<SecurityConfig, String> {
        let mut config = self.state.get_config().await;
        
        config.rate_limit.enabled = enabled;
        config.validation.enabled = enabled;
        config.validation.sql_injection_check = enabled;
        config.validation.xss_check = enabled;
        config.validation.command_injection_check = enabled;
        config.validation.path_traversal_check = enabled;
        config.validation.sanitize_input = enabled;
        config.auth.enabled = enabled;
        config.threat_detection.enabled = enabled;
        config.threat_detection.bot_detection = enabled;
        config.threat_detection.anomaly_detection = enabled;
        config.monitoring.enabled = enabled;

        self.state.update_config(config.clone()).await;
        Ok(config)
    }

    /// Get current UI preferences
    pub async fn get_ui_preferences(&self) -> UIPreferences {
        self.state.get_preferences().await
    }

    /// Update UI preferences
    pub async fn update_ui_preferences(
        &self,
        theme: Option<String>,
        refresh_interval_ms: Option<u64>,
        auto_refresh: Option<bool>,
        items_per_page: Option<u32>,
        timezone: Option<String>,
    ) -> Result<UIPreferences, String> {
        let mut prefs = self.state.get_preferences().await;
        
        if let Some(t) = theme {
            if t == "light" || t == "dark" {
                prefs.theme = t;
            } else {
                return Err("Invalid theme. Must be 'light' or 'dark'".to_string());
            }
        }
        if let Some(interval) = refresh_interval_ms {
            prefs.refresh_interval_ms = interval;
        }
        if let Some(auto) = auto_refresh {
            prefs.auto_refresh_enabled = auto;
        }
        if let Some(items) = items_per_page {
            prefs.items_per_page = items;
        }
        if let Some(tz) = timezone {
            prefs.timezone = tz;
        }

        self.state.update_preferences(prefs.clone()).await;
        Ok(prefs)
    }

    /// Get all settings as a single JSON object
    pub async fn get_all_settings(&self) -> AllSettings {
        AllSettings {
            security: self.state.get_config().await,
            ui: self.state.get_preferences().await,
        }
    }

    /// Batch update settings
    pub async fn batch_update(&self, updates: SettingsUpdate) -> Result<AllSettings, String> {
        // Update security settings
        if let Some(sec) = updates.security {
            if let Some(rl) = sec.rate_limit {
                self.update_rate_limit(
                    rl.requests_per_window,
                    rl.window_secs,
                    rl.burst_size,
                    rl.adaptive,
                ).await?;
            }
            if let Some(val) = sec.validation {
                self.update_validation(
                    val.sql_injection_check,
                    val.xss_check,
                    val.command_injection_check,
                    val.path_traversal_check,
                    val.sanitize_input,
                    val.max_payload_size,
                ).await?;
            }
            if let Some(auth) = sec.auth {
                self.update_auth(
                    auth.require_auth,
                    auth.jwt_secret,
                    auth.token_expiry_secs,
                    auth.mfa_enabled,
                ).await?;
            }
        }

        // Update UI settings
        if let Some(ui) = updates.ui {
            self.update_ui_preferences(
                ui.theme,
                ui.refresh_interval_ms,
                ui.auto_refresh,
                ui.items_per_page,
                ui.timezone,
            ).await?;
        }

        let all_settings = self.get_all_settings().await;
        // Save to disk after successful update
        self.persistence.save_settings(&all_settings).await?;
        Ok(all_settings)
    }

    /// Reset to default configuration
    pub async fn reset_to_defaults(&self) -> Result<SecurityConfig, String> {
        let config = SecurityConfig::default();
        self.state.update_config(config.clone()).await;
        
        // Save defaults to disk
        let all_settings = self.get_all_settings().await;
        self.persistence.save_settings(&all_settings).await?;
        
        Ok(config)
    }

    /// Export settings as JSON
    pub async fn export_settings(&self) -> Result<String, String> {
        let settings = self.get_all_settings().await;
        serde_json::to_string_pretty(&settings)
            .map_err(|e| format!("Failed to serialize settings: {}", e))
    }

    /// Import settings from JSON
    pub async fn import_settings(&self, json: &str) -> Result<AllSettings, String> {
        let settings: AllSettings = serde_json::from_str(json)
            .map_err(|e| format!("Failed to parse settings: {}", e))?;
        
        let settings_clone = settings.clone();
        self.state.update_config(settings.security).await;
        self.state.update_preferences(settings.ui).await;
        
        // Save imported settings to disk
        self.persistence.save_settings(&settings_clone).await?;
        
        Ok(settings_clone)
    }
}

/// All settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllSettings {
    pub security: SecurityConfig,
    pub ui: UIPreferences,
}

/// Settings update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsUpdate {
    pub security: Option<SecuritySettingsUpdate>,
    pub ui: Option<UISettingsUpdate>,
}

/// Security settings update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettingsUpdate {
    pub rate_limit: Option<RateLimitUpdate>,
    pub validation: Option<ValidationUpdate>,
    pub auth: Option<AuthUpdate>,
    pub threat_detection: Option<ThreatDetectionUpdate>,
}

/// Rate limit update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitUpdate {
    pub requests_per_window: Option<u32>,
    pub window_secs: Option<u64>,
    pub burst_size: Option<u32>,
    pub adaptive: Option<bool>,
}

/// Validation update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationUpdate {
    pub sql_injection_check: Option<bool>,
    pub xss_check: Option<bool>,
    pub command_injection_check: Option<bool>,
    pub path_traversal_check: Option<bool>,
    pub sanitize_input: Option<bool>,
    pub max_payload_size: Option<usize>,
}

/// Auth update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUpdate {
    pub require_auth: Option<bool>,
    pub jwt_secret: Option<String>,
    pub token_expiry_secs: Option<u64>,
    pub mfa_enabled: Option<bool>,
}

/// Threat detection update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionUpdate {
    pub bot_detection: Option<bool>,
    pub anomaly_detection: Option<bool>,
    pub signature_detection: Option<bool>,
}

/// UI settings update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UISettingsUpdate {
    pub theme: Option<String>,
    pub refresh_interval_ms: Option<u64>,
    pub auto_refresh: Option<bool>,
    pub items_per_page: Option<u32>,
    pub timezone: Option<String>,
}
