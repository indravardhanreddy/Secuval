

/// Core trait for security middleware components
/// 
/// This trait defines a simple interface for creating custom security middleware.
/// Middleware can inspect and modify the security context during request processing.
pub trait SecurityMiddleware: Send + Sync {
    /// Get middleware name for logging
    fn name(&self) -> &str;

    /// Get middleware priority (lower = earlier execution)
    fn priority(&self) -> u32 {
        100
    }
}

/// Middleware chain is currently simplified.
/// For custom middleware, extend the SecurityLayer directly.
pub struct MiddlewareChain {
    _private: (),
}

impl MiddlewareChain {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}
