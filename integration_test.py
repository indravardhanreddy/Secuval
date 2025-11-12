#!/usr/bin/env python3
"""
Integration test script for SecureAPIs C# bindings
Tests various security scenarios against the running ASP.NET Core application
"""

import requests
import json
import time
import sys
from typing import Dict, List, Tuple

# Configuration
BASE_URL = "http://localhost:5000"  # HTTP endpoint
HTTPS_URL = "https://localhost:5001"  # HTTPS endpoint (may not work without cert)

def test_request(method: str, path: str, headers: Dict = None, data: str = None, json_data: Dict = None) -> Tuple[bool, int, str]:
    """Send a test request and return (success, status_code, response_text)"""
    try:
        url = f"{BASE_URL}{path}"
        headers = headers or {}

        if json_data:
            headers['Content-Type'] = 'application/json'
            response = requests.request(method, url, headers=headers, json=json_data, timeout=5, verify=False)
        elif data:
            headers['Content-Type'] = 'application/json'
            response = requests.request(method, url, headers=headers, data=data, timeout=5, verify=False)
        else:
            response = requests.request(method, url, headers=headers, timeout=5, verify=False)

        return True, response.status_code, response.text
    except requests.exceptions.RequestException as e:
        return False, 0, f"Request failed: {e}"

def print_test_result(test_name: str, success: bool, status_code: int, response_text: str, expected_blocked: bool = False):
    """Print formatted test result"""
    status = "✓ PASS" if success else "✗ FAIL"
    blocked_status = "BLOCKED" if status_code in [400, 401, 403, 429] else "ALLOWED"

    print(f"{status} {test_name}")
    print(f"    Status: {status_code} ({blocked_status})")
    if response_text and len(response_text) < 200:
        print(f"    Response: {response_text}")
    print()

def run_security_tests():
    """Run comprehensive security tests"""
    print("🔒 SecureAPIs C# Integration Test Suite")
    print("=" * 50)
    print(f"Testing against: {BASE_URL}")
    print()

    tests_passed = 0
    total_tests = 0

    # Test 1: Normal GET request
    print("🟢 LEGITIMATE REQUESTS")
    total_tests += 1
    success, status, response = test_request("GET", "/api/test")
    expected_allowed = status == 200
    if expected_allowed:
        tests_passed += 1
    print_test_result("Normal GET request", expected_allowed, status, response)

    # Test 2: Normal POST request
    total_tests += 1
    success, status, response = test_request("POST", "/api/users", json_data={"name": "John Doe", "email": "john@example.com"})
    expected_allowed = status == 200
    if expected_allowed:
        tests_passed += 1
    print_test_result("Normal POST request", expected_allowed, status, response)

    # Test 3: Normal PUT request
    total_tests += 1
    success, status, response = test_request("PUT", "/api/users/123", json_data={"name": "Jane Doe"})
    expected_allowed = status == 200
    if expected_allowed:
        tests_passed += 1
    print_test_result("Normal PUT request", expected_allowed, status, response)

    print("🔴 MALICIOUS REQUESTS")
    print("-" * 30)

    # Test 4: XSS Attack
    total_tests += 1
    xss_payload = {"comment": "<script>alert('XSS Attack')</script>"}
    success, status, response = test_request("POST", "/api/comments", json_data=xss_payload)
    expected_blocked = status in [400, 403]
    if expected_blocked:
        tests_passed += 1
    print_test_result("XSS Attack", expected_blocked, status, response, True)

    # Test 5: SQL Injection
    total_tests += 1
    sql_payload = {"query": "'; DROP TABLE users; --"}
    success, status, response = test_request("POST", "/api/search", json_data=sql_payload)
    expected_blocked = status in [400, 403]
    if expected_blocked:
        tests_passed += 1
    print_test_result("SQL Injection", expected_blocked, status, response, True)

    # Test 6: Command Injection
    total_tests += 1
    cmd_payload = {"command": "ls; rm -rf /"}
    success, status, response = test_request("POST", "/api/execute", json_data=cmd_payload)
    expected_blocked = status in [400, 403]
    if expected_blocked:
        tests_passed += 1
    print_test_result("Command Injection", expected_blocked, status, response, True)

    # Test 7: Path Traversal
    total_tests += 1
    success, status, response = test_request("GET", "/../../../etc/passwd")
    expected_blocked = status in [400, 403]
    if expected_blocked:
        tests_passed += 1
    print_test_result("Path Traversal", expected_blocked, status, response, True)

    # Test 8: Malformed JSON
    total_tests += 1
    malformed_data = '{"name": "test", "invalid": json}'
    success, status, response = test_request("POST", "/api/test", data=malformed_data)
    expected_blocked = status in [400, 403]
    if expected_blocked:
        tests_passed += 1
    print_test_result("Malformed JSON", expected_blocked, status, response, True)

    print("🟡 RATE LIMITING TESTS")
    print("-" * 30)

    # Test 9: Rate Limiting
    print("Testing rate limiting (sending 15 requests quickly)...")
    blocked_count = 0
    for i in range(15):
        success, status, response = test_request("GET", "/api/ratelimit")
        if status == 429:
            blocked_count += 1
        time.sleep(0.1)  # Small delay between requests

    total_tests += 1
    rate_limiting_works = blocked_count > 0
    if rate_limiting_works:
        tests_passed += 1
    print_test_result(f"Rate Limiting ({blocked_count}/15 blocked)", rate_limiting_works, 429 if blocked_count > 0 else 200, f"{blocked_count} requests blocked")

    print("🔵 EDGE CASES")
    print("-" * 30)

    # Test 10: Very Large Payload
    total_tests += 1
    large_payload = {"data": "x" * 100000}  # 100KB payload
    success, status, response = test_request("POST", "/api/large", json_data=large_payload)
    expected_blocked = status in [400, 413]
    if expected_blocked:
        tests_passed += 1
    print_test_result("Large Payload", expected_blocked, status, response, True)

    # Test 11: Invalid HTTP Method
    total_tests += 1
    success, status, response = test_request("INVALID", "/api/test")
    expected_blocked = status in [400, 405]
    if expected_blocked:
        tests_passed += 1
    print_test_result("Invalid HTTP Method", expected_blocked, status, response, True)

    # Test 12: Empty Request Body
    total_tests += 1
    success, status, response = test_request("POST", "/api/test", data="")
    expected_allowed = status == 200
    if expected_allowed:
        tests_passed += 1
    print_test_result("Empty Request Body", expected_allowed, status, response)

    print("=" * 50)
    print(f"🧪 TEST RESULTS: {tests_passed}/{total_tests} tests passed")

    if tests_passed == total_tests:
        print("🎉 ALL TESTS PASSED! Integration is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the ASP.NET Core application logs.")
        return False

def wait_for_server(max_attempts: int = 30) -> bool:
    """Wait for the server to be ready"""
    print(f"⏳ Waiting for server at {BASE_URL}...")

    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2, verify=False)
            if response.status_code in [200, 404]:  # 404 is fine, means server is responding
                print("✅ Server is ready!")
                return True
        except:
            pass

        print(f"   Attempt {attempt + 1}/{max_attempts} - server not ready yet...")
        time.sleep(2)

    print("❌ Server failed to start within timeout period")
    return False

if __name__ == "__main__":
    print("SecureAPIs C# Integration Test")
    print("Make sure to run 'dotnet run' in the test_integration directory first!")
    print()

    # Wait for server to be ready
    if not wait_for_server():
        print("Cannot proceed with tests - server is not responding")
        sys.exit(1)

    # Run the tests
    success = run_security_tests()
    sys.exit(0 if success else 1)