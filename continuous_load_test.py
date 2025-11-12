#!/usr/bin/env python3
"""
Continuous load testing for SecureAPIs C# bindings
Tests security features under rapid-fire requests
"""

import requests
import json
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
BASE_URL = "http://localhost:5000"
NUM_THREADS = 5
REQUESTS_PER_THREAD = 50

def send_request(method: str, path: str, headers: dict = None, json_data: dict = None, description: str = ""):
    """Send a single request and return result"""
    try:
        url = f"{BASE_URL}{path}"
        headers = headers or {}

        if json_data:
            headers['Content-Type'] = 'application/json'
            response = requests.request(method, url, headers=headers, json=json_data, timeout=5, verify=False)
        else:
            response = requests.request(method, url, headers=headers, timeout=5, verify=False)

        return {
            'success': True,
            'status': response.status_code,
            'description': description,
            'blocked': response.status_code in [400, 401, 403, 429]
        }
    except Exception as e:
        return {
            'success': False,
            'status': 0,
            'description': description,
            'error': str(e)
        }

def test_legitimate_requests():
    """Test legitimate requests under load"""
    print("🟢 TESTING LEGITIMATE REQUESTS UNDER LOAD")

    results = []
    start_time = time.time()

    def worker(thread_id):
        thread_results = []
        for i in range(REQUESTS_PER_THREAD):
            # Mix of different legitimate requests
            if i % 4 == 0:
                result = send_request("GET", "/api/test", description="GET /api/test")
            elif i % 4 == 1:
                result = send_request("POST", "/api/users",
                    json_data={"name": f"User{i}", "email": f"user{i}@example.com"},
                    description="POST /api/users")
            elif i % 4 == 2:
                result = send_request("PUT", f"/api/users/{i}",
                    json_data={"name": f"UpdatedUser{i}"},
                    description="PUT /api/users")
            else:
                result = send_request("GET", "/health", description="GET /health")

            thread_results.append(result)
        return thread_results

    # Run with multiple threads
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(worker, i) for i in range(NUM_THREADS)]
        for future in as_completed(futures):
            results.extend(future.result())

    end_time = time.time()
    total_time = end_time - start_time

    # Analyze results
    successful = sum(1 for r in results if r['success'])
    blocked = sum(1 for r in results if r.get('blocked', False))
    total_requests = len(results)

    print(f"  Total Requests: {total_requests}")
    print(f"  Successful: {successful}")
    print(f"  Blocked: {blocked}")
    print(".2f")
    print(".2f")

    return successful > total_requests * 0.95  # 95% success rate

def test_malicious_requests():
    """Test malicious requests under load"""
    print("\n🔴 TESTING MALICIOUS REQUESTS UNDER LOAD")

    malicious_payloads = [
        # XSS attacks
        ("POST", "/api/comments", {"comment": "<script>alert('xss')</script>"}, "XSS in comment"),
        ("POST", "/api/posts", {"content": "<img src=x onerror=alert('xss')>"}, "XSS in content"),

        # SQL injection
        ("POST", "/api/search", {"query": "'; DROP TABLE users; --"}, "SQL injection"),
        ("POST", "/api/login", {"username": "' OR '1'='1", "password": "anything"}, "SQL login bypass"),

        # Command injection
        ("POST", "/api/execute", {"command": "ls; rm -rf /"}, "Command injection"),
        ("GET", "/api/download?file=../../../etc/passwd", {}, "Path traversal"),

        # Other attacks
        ("GET", "/admin.php", {}, "Admin access attempt"),
        ("POST", "/api/upload", {"file": "x" * 1000000}, "Large payload"),
    ]

    results = []
    start_time = time.time()

    def worker(thread_id):
        thread_results = []
        for i in range(REQUESTS_PER_THREAD):
            payload = malicious_payloads[i % len(malicious_payloads)]
            method, path, data, desc = payload

            if data:
                result = send_request(method, path, json_data=data, description=desc)
            else:
                result = send_request(method, path, description=desc)

            thread_results.append(result)
        return thread_results

    # Run with multiple threads
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(worker, i) for i in range(NUM_THREADS)]
        for future in as_completed(futures):
            results.extend(future.result())

    end_time = time.time()
    total_time = end_time - start_time

    # Analyze results
    successful = sum(1 for r in results if r['success'])
    blocked = sum(1 for r in results if r.get('blocked', False))
    total_requests = len(results)

    print(f"  Total Requests: {total_requests}")
    print(f"  Successful: {successful}")
    print(f"  Blocked: {blocked}")
    print(".2f")
    print(".2f")

    # For malicious requests, we want high blocking rate
    blocking_rate = blocked / total_requests if total_requests > 0 else 0
    print(".1%")

    return blocking_rate > 0.5  # At least 50% of attacks should be blocked

def test_rate_limiting():
    """Test rate limiting under extreme load"""
    print("\n🟡 TESTING RATE LIMITING UNDER EXTREME LOAD")

    results = []
    start_time = time.time()

    def worker(thread_id):
        thread_results = []
        # Send many requests rapidly from each thread
        for i in range(100):  # 100 requests per thread = 500 total
            result = send_request("GET", "/api/ratelimit", description="Rate limit test")
            thread_results.append(result)
            time.sleep(0.01)  # Small delay but still rapid
        return thread_results

    # Run with multiple threads
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(worker, i) for i in range(NUM_THREADS)]
        for future in as_completed(futures):
            results.extend(future.result())

    end_time = time.time()
    total_time = end_time - start_time

    # Analyze results
    successful = sum(1 for r in results if r['success'])
    blocked = sum(1 for r in results if r.get('blocked', False))
    rate_limited = sum(1 for r in results if r['status'] == 429)
    total_requests = len(results)

    print(f"  Total Requests: {total_requests}")
    print(f"  Successful: {successful}")
    print(f"  Rate Limited (429): {rate_limited}")
    print(f"  Other Blocks: {blocked - rate_limited}")
    print(".2f")
    print(".2f")

    return rate_limited > 10  # Should have some rate limiting

def wait_for_server():
    """Wait for server to be ready"""
    print("⏳ Waiting for server at http://localhost:5000...")

    for attempt in range(30):
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2, verify=False)
            if response.status_code in [200, 404]:
                print("✅ Server is ready!")
                return True
        except:
            pass

        print(f"   Attempt {attempt + 1}/30 - server not ready yet...")
        time.sleep(2)

    print("❌ Server failed to start within timeout period")
    return False

def main():
    """Run continuous load testing"""
    print("🔥 SecureAPIs C# Continuous Load Test")
    print("=" * 50)
    print(f"Target: {BASE_URL}")
    print(f"Threads: {NUM_THREADS}")
    print(f"Requests per thread: {REQUESTS_PER_THREAD}")
    print()

    # Wait for server
    if not wait_for_server():
        print("Cannot proceed with tests - server is not responding")
        sys.exit(1)

    # Run tests
    tests = [
        ("Legitimate Requests", test_legitimate_requests),
        ("Malicious Requests", test_malicious_requests),
        ("Rate Limiting", test_rate_limiting),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"💥 {test_name}: ERROR - {e}")
        print()

    print("=" * 50)
    print(f"🎯 LOAD TEST RESULTS: {passed}/{total} tests passed")

    if passed == total:
        print("🚀 ALL LOAD TESTS PASSED! Security features working under load.")
    else:
        print("⚠️  Some load tests failed. Security features may need tuning.")

    print("\n💡 Note: This tests the C# middleware + Rust core integration under load")
    print("   High blocking rates indicate security features are working correctly")

if __name__ == "__main__":
    main()