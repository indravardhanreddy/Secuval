#!/usr/bin/env python3
"""
Debug script for SecureAPIs Python bindings
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(__file__))

from secureapis import SecureAPIs, SecureAPIsConfig

def debug_xss_detection():
    """Debug XSS detection"""
    print("=== Debugging XSS Detection ===")

    config = SecureAPIsConfig()
    config.enable_xss_protection = True
    config.enable_input_validation = True

    print(f"Config XSS protection: {config.enable_xss_protection}")
    print(f"Config input validation: {config.enable_input_validation}")

    # Print the config dict
    config_dict = config.to_dict()
    print("Configuration JSON:")
    print(json.dumps(config_dict, indent=2))

    secureapis = SecureAPIs(config)

    # Test normal request
    result = secureapis.check_request(
        method="POST",
        path="/api/test",
        headers={"Content-Type": "application/json"},
        body='{"name": "normal"}',
        ip_address="127.0.0.1"
    )
    print(f"Normal request - Allowed: {result.allowed}, Reason: {result.reason}")

    # Test XSS
    result = secureapis.check_request(
        method="POST",
        path="/api/test",
        headers={"Content-Type": "application/json"},
        body='{"name": "<script>alert(\'xss\')</script>"}',
        ip_address="127.0.0.1"
    )
    print(f"XSS request - Allowed: {result.allowed}, Reason: {result.reason}")

    # Test very obvious XSS
    result = secureapis.check_request(
        method="POST",
        path="/api/test",
        headers={"Content-Type": "application/json"},
        body='<script>alert("xss")</script>',
        ip_address="127.0.0.1"
    )
    print(f"Obvious XSS request - Allowed: {result.allowed}, Reason: {result.reason}")

    # Test XSS in URL
    result = secureapis.check_request(
        method="GET",
        path="/api/test?param=<script>alert('xss')</script>",
        headers={},
        body="",
        ip_address="127.0.0.1"
    )
    print(f"XSS in URL - Allowed: {result.allowed}, Reason: {result.reason}")

    # Test rate limiting
    print("\n=== Testing Rate Limiting ===")
    config = SecureAPIsConfig()
    config.rate_limit_requests_per_minute = 2  # Very low limit

    secureapis = SecureAPIs(config)

    # Make requests up to the limit
    for i in range(3):
        result = secureapis.check_request(
            method="GET",
            path="/api/test",
            headers={},
            body="",
            ip_address="192.168.1.100"
        )
        print(f"Request {i+1} - Allowed: {result.allowed}, Reason: {result.reason}")
        if not result.allowed:
            break

if __name__ == "__main__":
    debug_xss_detection()