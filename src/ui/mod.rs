//! # UI Layer for SecureAPIs
//! 
//! Provides a comprehensive web-based dashboard and monitoring interface for the security layer.
//! Includes real-time request tracking, threat monitoring, alert management, and dynamic settings.

pub mod dashboard;
pub mod tracking;
pub mod alerts;
pub mod settings;
pub mod metrics;
pub mod api;
pub mod state;
pub mod persistence;

pub use dashboard::Dashboard;
pub use tracking::RequestTracker;
pub use alerts::AlertManager;
pub use settings::SettingsManager;
pub use metrics::MetricsCollector;
pub use api::UIRouter;
pub use state::UIState;
pub use persistence::PersistenceManager;

use crate::config::SecurityConfig;
use std::sync::Arc;

/// Main UI state manager
pub struct UIManager {
    pub state: Arc<UIState>,
    pub dashboard: Dashboard,
    pub tracker: RequestTracker,
    pub alerts: AlertManager,
    pub settings: SettingsManager,
    pub metrics: MetricsCollector,
}

impl UIManager {
    /// Create a new UI manager with the given security config
    pub fn new(config: SecurityConfig) -> Self {
        let state = Arc::new(UIState::new(config.clone()));
        
        Self {
            state: state.clone(),
            dashboard: Dashboard::new(state.clone()),
            tracker: RequestTracker::new(state.clone()),
            alerts: AlertManager::new(state.clone()),
            settings: SettingsManager::new(state.clone()),
            metrics: MetricsCollector::new(state.clone()),
        }
    }

    /// Get the router for web API endpoints
    pub fn router(&self) -> UIRouter {
        UIRouter::new(self.state.clone())
    }

    /// Start the UI HTTP server
    pub async fn start_server(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let router = self.router();
        router.serve(addr).await
    }
}

/// UI prelude for convenient imports
pub mod prelude {
    pub use crate::ui::*;
}
