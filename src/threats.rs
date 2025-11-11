use crate::core::SecurityContext;

/// Threat detection module
pub struct ThreatDetector {
    enabled: bool,
}

impl ThreatDetector {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Analyze request for threats
    pub async fn analyze(&self, context: &mut SecurityContext) -> ThreatAnalysis {
        if !self.enabled {
            return ThreatAnalysis::safe();
        }

        let mut analysis = ThreatAnalysis::new();

        // Bot detection based on user agent
        if let Some(user_agent) = context.metadata.get("user-agent") {
            if self.is_bot_user_agent(user_agent) {
                analysis.add_indicator(ThreatIndicator::BotLike, 10);
            }
        }

        // Anomaly detection based on threat score
        if context.threat_score > 0 {
            let severity = match context.threat_score {
                0..=20 => ThreatSeverity::Low,
                21..=40 => ThreatSeverity::Medium,
                41..=60 => ThreatSeverity::High,
                _ => ThreatSeverity::Critical,
            };
            analysis.add_indicator(ThreatIndicator::HighThreatScore, context.threat_score);
            analysis.severity = severity;
        }

        analysis
    }

    fn is_bot_user_agent(&self, user_agent: &str) -> bool {
        let bot_patterns = [
            "bot", "crawler", "spider", "scraper", "curl", "wget",
            "python", "java", "go-http-client", "axios", "node-fetch",
        ];

        let lower = user_agent.to_lowercase();
        bot_patterns.iter().any(|pattern| lower.contains(pattern))
    }
}

/// Threat analysis result
#[derive(Debug, Clone)]
pub struct ThreatAnalysis {
    pub is_threat: bool,
    pub severity: ThreatSeverity,
    pub indicators: Vec<(ThreatIndicator, u32)>,
    pub total_score: u32,
}

impl ThreatAnalysis {
    fn new() -> Self {
        Self {
            is_threat: false,
            severity: ThreatSeverity::Low,
            indicators: Vec::new(),
            total_score: 0,
        }
    }

    fn safe() -> Self {
        Self::new()
    }

    fn add_indicator(&mut self, indicator: ThreatIndicator, score: u32) {
        self.indicators.push((indicator, score));
        self.total_score += score;
        if self.total_score > 30 {
            self.is_threat = true;
        }
    }
}

/// Threat indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatIndicator {
    BotLike,
    HighThreatScore,
    SuspiciousPattern,
    KnownAttackPattern,
}

/// Threat severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}
