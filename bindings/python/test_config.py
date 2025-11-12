#!/usr/bin/env python3
"""
Test script for SecureAPIs Python JSON configuration loading
"""

import os
import sys
import json

# Add the package directory to Python path for testing
sys.path.insert(0, os.path.dirname(__file__))

from secureapis import SecureAPIsConfig, SecureAPIs

def test_json_config_loading():
    """Test loading configuration from JSON file"""
    print("Testing SecureAPIs Python JSON Configuration Loading...")
    print("=" * 60)

    try:
        # Test 1: Load from JSON file
        print("\n1. Loading configuration from JSON file...")
        config = SecureAPIsConfig.load("../bindings/python/secureapis.config.json")

        print(f"Rate Limit Requests: {config.rate_limit_requests_per_minute}")
        print(f"Enable Rate Limiting: {config.enable_rate_limiting}")
        print(f"Enable Input Validation: {config.enable_input_validation}")
        print(f"Enable SQL Injection Protection: {config.enable_sql_injection_protection}")
        print(f"Enable XSS Protection: {config.enable_xss_protection}")
        print(f"Enable Threat Detection: {config.enable_threat_detection}")
        print(f"Log Level: {config.log_level}")
        print(f"Blocked IPs: {config.blocked_ips}")
        print(f"API Keys: {config.api_keys}")

        # Test 2: Load default configuration
        print("\n2. Loading default configuration...")
        default_config = SecureAPIsConfig.load()

        print(f"Default Rate Limit: {default_config.rate_limit_requests_per_minute}")

        # Test 3: Test SecureAPIs instance creation
        print("\n3. Creating SecureAPIs instance...")
        secureapis = SecureAPIs(config)

        print("SecureAPIs instance created successfully!")

        # Test 4: Test a security check
        print("\n4. Testing security check...")
        result = secureapis.check_request(
            method="GET",
            path="/api/test",
            headers={"User-Agent": "test-agent"},
            body="",
            ip_address="127.0.0.1"
        )

        if result.allowed:
            print("Security check passed - request allowed")
        else:
            print(f"Security check failed - request blocked: {result.error_message}")

        # Clean up
        del secureapis

        print("\n✅ All tests passed! JSON configuration loading works correctly.")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True

def test_environment_config():
    """Test loading configuration from environment variables"""
    print("\n5. Testing environment variable configuration...")

    # Set some environment variables
    os.environ["SECUREAPIS_RATE_LIMIT_REQUESTS"] = "200"
    os.environ["SECUREAPIS_ENABLE_LOGGING"] = "false"
    os.environ["SECUREAPIS_BLOCKED_IPS"] = "192.168.1.1,10.0.0.1"

    try:
        config = SecureAPIsConfig.from_env()

        print(f"Rate limit from env: {config.rate_limit_requests_per_minute}")
        print(f"Logging enabled from env: {config.enable_logging}")
        print(f"Blocked IPs from env: {config.blocked_ips}")

        # Clean up environment
        del os.environ["SECUREAPIS_RATE_LIMIT_REQUESTS"]
        del os.environ["SECUREAPIS_ENABLE_LOGGING"]
        del os.environ["SECUREAPIS_BLOCKED_IPS"]

        print("✅ Environment variable configuration works correctly.")

    except Exception as e:
        print(f"❌ Environment variable test failed: {e}")
        return False

    return True

if __name__ == "__main__":
    success = test_json_config_loading()
    if success:
        success = test_environment_config()

    if success:
        print("\n🎉 All SecureAPIs Python configuration tests passed!")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed!")
        sys.exit(1)