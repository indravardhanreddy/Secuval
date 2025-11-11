//! # Settings persistence
//! 
//! Provides file-based persistence for security configuration and UI preferences.
//! Settings are automatically saved to and loaded from a JSON file.

use crate::ui::settings::AllSettings;
use crate::config::SecurityConfig;
use crate::ui::state::UIPreferences;
use std::path::{Path, PathBuf};
use tokio::fs;

const DEFAULT_SETTINGS_FILE: &str = "settings.json";

/// Settings persistence manager
pub struct PersistenceManager {
    settings_path: PathBuf,
}

impl PersistenceManager {
    /// Create a new persistence manager with default settings file location
    pub fn new() -> Self {
        Self {
            settings_path: PathBuf::from(DEFAULT_SETTINGS_FILE),
        }
    }

    /// Create a new persistence manager with custom settings file path
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            settings_path: path.as_ref().to_path_buf(),
        }
    }

    /// Load settings from disk, or return defaults if file doesn't exist
    pub async fn load_settings(&self) -> Result<AllSettings, String> {
        match fs::read_to_string(&self.settings_path).await {
            Ok(content) => {
                serde_json::from_str(&content)
                    .map_err(|e| format!("Failed to parse settings file: {}", e))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Return defaults if file doesn't exist
                Ok(AllSettings {
                    security: SecurityConfig::default(),
                    ui: UIPreferences::default(),
                })
            }
            Err(e) => Err(format!("Failed to read settings file: {}", e)),
        }
    }

    /// Save settings to disk
    pub async fn save_settings(&self, settings: &AllSettings) -> Result<(), String> {
        let json = serde_json::to_string_pretty(settings)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;

        fs::write(&self.settings_path, json)
            .await
            .map_err(|e| format!("Failed to write settings file: {}", e))
    }

    /// Check if settings file exists
    pub async fn exists(&self) -> bool {
        fs::try_exists(&self.settings_path).await.unwrap_or(false)
    }

    /// Delete the settings file
    pub async fn delete_settings(&self) -> Result<(), String> {
        fs::remove_file(&self.settings_path)
            .await
            .map_err(|e| format!("Failed to delete settings file: {}", e))
    }

    /// Get the path to the settings file
    pub fn get_path(&self) -> &PathBuf {
        &self.settings_path
    }
}

impl Default for PersistenceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_load_defaults_when_missing() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("settings.json");
        let pm = PersistenceManager::with_path(&path);

        let settings = pm.load_settings().await.unwrap();
        assert!(settings.security.rate_limit.enabled);
        assert!(!pm.exists().await);
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("settings.json");
        let pm = PersistenceManager::with_path(&path);

        let settings = AllSettings {
            security: SecurityConfig::default(),
            ui: UIPreferences::default(),
        };

        pm.save_settings(&settings).await.unwrap();
        assert!(pm.exists().await);

        let loaded = pm.load_settings().await.unwrap();
        assert_eq!(loaded.security.rate_limit.enabled, settings.security.rate_limit.enabled);
    }
}
