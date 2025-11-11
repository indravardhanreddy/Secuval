use crate::core::{SecurityContext, SecurityError, SecurityResult};
use http::Request;
use std::collections::HashSet;

/// IP reputation, geo-blocking, and VPN/Proxy detection
pub struct IpReputation {
    enabled: bool,
    blacklisted_ips: HashSet<String>,
    whitelisted_ips: HashSet<String>,
    allow_vpn: bool,
    allow_proxy: bool,
    allowed_countries: HashSet<String>,
    blocked_countries: HashSet<String>,
}

impl IpReputation {
    pub fn new() -> Self {
        Self {
            enabled: true,
            blacklisted_ips: HashSet::new(),
            whitelisted_ips: HashSet::new(),
            allow_vpn: false,
            allow_proxy: false,
            allowed_countries: HashSet::new(),
            blocked_countries: HashSet::new(),
        }
    }

    /// Add IP to blacklist
    pub fn blacklist_ip(mut self, ip: String) -> Self {
        self.blacklisted_ips.insert(ip);
        self
    }

    /// Add IP to whitelist
    pub fn whitelist_ip(mut self, ip: String) -> Self {
        self.whitelisted_ips.insert(ip);
        self
    }

    /// Block countries
    pub fn block_countries(mut self, countries: Vec<String>) -> Self {
        for country in countries {
            self.blocked_countries.insert(country.to_uppercase());
        }
        self
    }

    /// Allow specific countries only
    pub fn allow_countries_only(mut self, countries: Vec<String>) -> Self {
        for country in countries {
            self.allowed_countries.insert(country.to_uppercase());
        }
        self
    }

    /// Check IP reputation
    pub async fn check_ip_reputation<B>(
        &self,
        request: &Request<B>,
        context: &mut SecurityContext,
    ) -> SecurityResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let client_ip = &context.client_ip;

        // Check whitelist first (fast-pass)
        if self.whitelisted_ips.contains(client_ip) {
            return Ok(());
        }

        // Check blacklist
        if self.blacklisted_ips.contains(client_ip) {
            context.add_threat_score(80);
            return Err(SecurityError::IpBlocked(
                "IP address is blacklisted".to_string(),
            ));
        }

        // Check for VPN/Proxy indicators
        if !self.allow_vpn && self.is_vpn_detected(request) {
            context.add_threat_score(25);
            return Err(SecurityError::VpnDetected(
                "VPN/Proxy detected, not allowed".to_string(),
            ));
        }

        if !self.allow_proxy && self.is_proxy_detected(request) {
            context.add_threat_score(20);
            return Err(SecurityError::ProxyDetected(
                "Proxy detected, not allowed".to_string(),
            ));
        }

        Ok(())
    }

    /// Detect VPN indicators
    fn is_vpn_detected<B>(&self, request: &Request<B>) -> bool {
        // Check common VPN/proxy headers
        let vpn_headers = vec![
            "cf-connecting-ip",      // Cloudflare
            "x-forwarded-for",       // May indicate proxy
            "x-real-ip",            // Nginx/other proxies
            "x-client-ip",
            "x-customer-ip",
            "x-forwarded-host",
        ];

        // Multiple X-Forwarded-For indicates likely proxy
        let mut forwarded_count = 0;
        for (name, _) in request.headers() {
            if name.as_str() == "x-forwarded-for" {
                forwarded_count += 1;
            }
        }

        if forwarded_count > 1 {
            return true;
        }

        // Check for suspicious header patterns
        for header_name in &vpn_headers {
            if request.headers().contains_key(*header_name) {
                if *header_name == "x-forwarded-for" {
                    if let Some(header) = request.headers().get("x-forwarded-for") {
                        if let Ok(value) = header.to_str() {
                            // Multiple IPs in forwarded-for suggests proxy chain
                            if value.matches(',').count() > 1 {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Detect Proxy indicators
    fn is_proxy_detected<B>(&self, request: &Request<B>) -> bool {
        // Check for proxy-specific headers
        let proxy_indicators = vec![
            "via",
            "x-proxy-authorization",
            "proxy-authorization",
            "x-anonymizer-version",
        ];

        proxy_indicators.iter().any(|header| {
            request.headers().contains_key(*header)
        })
    }

    /// Validate IP address format
    pub fn is_valid_ipv4(ip: &str) -> bool {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        parts.iter().all(|part| {
            part.parse::<u8>().is_ok()
        })
    }

    /// Validate IPv6 format (basic)
    pub fn is_valid_ipv6(ip: &str) -> bool {
        // Basic check for IPv6 format
        ip.contains(':') && ip.chars().all(|c| {
            c.is_ascii_hexdigit() || c == ':' || c == '.'
        })
    }
}

impl Default for IpReputation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_validation() {
        assert!(IpReputation::is_valid_ipv4("192.168.1.1"));
        assert!(IpReputation::is_valid_ipv4("8.8.8.8"));
        assert!(!IpReputation::is_valid_ipv4("256.1.1.1"));
        assert!(!IpReputation::is_valid_ipv4("192.168.1"));
    }

    #[test]
    fn test_ipv6_validation() {
        assert!(IpReputation::is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(IpReputation::is_valid_ipv6("::1"));
        assert!(!IpReputation::is_valid_ipv6("not-an-ip"));
    }

    #[test]
    fn test_blacklist_whitelist() {
        let reputation = IpReputation::new()
            .blacklist_ip("192.168.1.100".to_string())
            .whitelist_ip("10.0.0.1".to_string());

        assert!(reputation.blacklisted_ips.contains("192.168.1.100"));
        assert!(reputation.whitelisted_ips.contains("10.0.0.1"));
    }
}
