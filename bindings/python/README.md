# SecureAPIs Python Bindings

Python bindings for SecureAPIs - a high-performance Rust security library that provides comprehensive web security middleware for Python applications.

## Features

- **High Performance**: Rust-based security checks with minimal overhead
- **Comprehensive Security**: Rate limiting, CSRF protection, XSS prevention, SQL injection detection, and more
- **Framework Integration**: Native support for Django, Flask, and FastAPI
- **Easy Configuration**: Simple configuration with sensible defaults
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/secureapis.git
cd secureapis

# Build the bindings
python bindings/python/setup.py build_ext --inplace
```

### Using pip (when published)

```bash
pip install secureapis
```

## Quick Start

### Basic Usage

```python
from secureapis import SecureAPIs, SecureAPIsConfig

# Create configuration
config = SecureAPIsConfig()
config.rate_limit_requests_per_minute = 100
config.enable_csrf_protection = True
config.enable_xss_protection = True

# Create SecureAPIs instance
secureapis = SecureAPIs(config)

# Check a request
result = secureapis.check_request(
    method="POST",
    path="/api/users",
    headers={"Content-Type": "application/json", "X-CSRF-Token": "valid-token"},
    body='{"name": "John Doe"}',
    ip_address="192.168.1.100"
)

if result.blocked:
    print(f"Request blocked: {result.reason}")
else:
    print("Request allowed")
```

### Django Integration

Add to your Django `settings.py`:

```python
MIDDLEWARE = [
    # ... other middleware
    'secureapis.django_middleware.SecureAPIsMiddleware',
]

# SecureAPIs Configuration
SECUREAPIS_CONFIG = {
    'rate_limit_requests_per_minute': 100,
    'enable_csrf_protection': True,
    'enable_xss_protection': True,
    'enable_sql_injection_protection': True,
    'max_request_size_kb': 1024,
}
```

### Flask Integration

```python
from flask import Flask
from secureapis.flask_middleware import SecureAPIsFlask

app = Flask(__name__)

# Configure SecureAPIs
config = SecureAPIsConfig()
config.rate_limit_requests_per_minute = 100
config.enable_csrf_protection = True

# Initialize middleware
secureapis = SecureAPIsFlask(app, config)

@app.route('/api/users')
def get_users():
    # Request is automatically checked by middleware
    return {'users': []}
```

### FastAPI Integration

```python
from fastapi import FastAPI, Request, HTTPException
from secureapis import SecureAPIs, SecureAPIsConfig

app = FastAPI()
secureapis = SecureAPIs(SecureAPIsConfig())

@app.middleware("http")
async def secureapis_middleware(request: Request, call_next):
    # Convert FastAPI request to SecureAPIs format
    method = request.method
    path = str(request.url.path)
    headers = dict(request.headers)
    body = await request.body()
    ip = request.client.host if request.client else "unknown"

    result = secureapis.check_request(method, path, headers, body.decode(), ip)

    if result.blocked:
        raise HTTPException(status_code=403, detail=result.reason)

    response = await call_next(request)
    return response
```

## Dynamic Configuration (NEW)

SecureAPIs Python bindings now support multiple configuration sources for maximum flexibility:

### Configuration Sources (in order of precedence)

1. **Environment Variables** (highest precedence)
2. **JSON Configuration File**
3. **Code-based Configuration** (lowest precedence)

### JSON Configuration File

Create a `secureapis.config.json` file in your application directory:

```json
{
  "rateLimitRequests": 100,
  "rateLimitWindowSeconds": 60,
  "enableRateLimiting": true,
  "jwtSecret": "your-jwt-secret-here",
  "jwtIssuer": "your-app",
  "jwtAudience": "your-users",
  "enableJwtValidation": false,
  "apiKeys": [
    "api-key-1",
    "api-key-2"
  ],
  "enableInputValidation": true,
  "enableSqlInjectionDetection": true,
  "enableXssDetection": true,
  "enableCommandInjectionDetection": true,
  "enablePathTraversalDetection": true,
  "maxRequestBodySize": 1048576,
  "maxUrlLength": 2048,
  "enableCors": false,
  "allowedOrigins": [
    "https://yourdomain.com",
    "https://app.yourdomain.com"
  ],
  "allowedMethods": [
    "GET",
    "POST",
    "PUT",
    "DELETE"
  ],
  "allowedHeaders": [
    "Content-Type",
    "Authorization",
    "X-API-Key"
  ],
  "enableSecurityHeaders": true,
  "enableHsts": true,
  "enableCsp": false,
  "cspPolicy": "default-src 'self'; script-src 'self' 'unsafe-inline';",
  "enableThreatDetection": true,
  "blockedIPs": [
    "192.168.1.100",
    "10.0.0.1"
  ],
  "blockedUserAgents": [
    "bad-bot",
    "malicious-scanner"
  ],
  "maxRequestsPerMinute": 60,
  "enableLogging": true,
  "logLevel": "Info",
  "enableMetrics": true,
  "strictMode": false,
  "requestTimeoutSeconds": 30,
  "enableIpReputation": false
}
```

#### Usage

```python
from secureapis import SecureAPIs, SecureAPIsConfig

# Option 1: Load from JSON file
config = SecureAPIsConfig.load("secureapis.config.json")
secureapis = SecureAPIs(config)

# Option 2: Load from default location (secureapis.config.json in current directory)
config = SecureAPIsConfig.load()
secureapis = SecureAPIs(config)
```

### Environment Variables

Set environment variables with the `SECUREAPIS_` prefix:

```bash
# Rate limiting
export SECUREAPIS_RATE_LIMIT_REQUESTS=50
export SECUREAPIS_RATE_LIMIT_WINDOW_SECONDS=30
export SECUREAPIS_ENABLE_RATE_LIMITING=true

# Authentication
export SECUREAPIS_JWT_SECRET="your-secret"
export SECUREAPIS_ENABLE_JWT_VALIDATION=true
export SECUREAPIS_API_KEYS="key1,key2,key3"

# Threat detection
export SECUREAPIS_BLOCKED_IPS="192.168.1.100,10.0.0.1"
export SECUREAPIS_ENABLE_THREAT_DETECTION=true
```

### Configuration Priority

When multiple configuration sources are used, they are merged in this order:

1. **Environment Variables** override everything
2. **JSON File** settings are used where environment variables don't specify
3. **Code-based** configuration provides defaults

### Complete Configuration Example

```python
from secureapis import SecureAPIs, SecureAPIsConfig

# Load configuration with automatic fallback
config = SecureAPIsConfig.load("secureapis.config.json")

# Override specific settings programmatically if needed
config.max_request_size_kb = 2048

# Create SecureAPIs instance
secureapis = SecureAPIs(config)

# Use in your application
result = secureapis.check_request("POST", "/api/users", {"Content-Type": "application/json"}, '{"name": "John"}')
if result.allowed:
    print("Request approved")
else:
    print(f"Request blocked: {result.error_message}")
```

## Configuration Options

### Rate Limiting
- `rateLimitRequests`: Maximum requests per window (default: 60)
- `rateLimitWindowSeconds`: Time window in seconds (default: 60)
- `enableRateLimiting`: Enable/disable rate limiting (default: true)

### Authentication
- `jwtSecret`: JWT signing secret
- `jwtIssuer`: JWT issuer claim
- `jwtAudience`: JWT audience claim
- `enableJwtValidation`: Enable JWT validation (default: false)
- `apiKeys`: List of valid API keys

### Input Validation
- `enableInputValidation`: Enable input validation (default: true)
- `enableSqlInjectionDetection`: Detect SQL injection (default: true)
- `enableXssDetection`: Detect XSS attacks (default: true)
- `enableCommandInjectionDetection`: Detect command injection (default: true)
- `enablePathTraversalDetection`: Detect path traversal (default: true)
- `maxRequestBodySize`: Maximum request body size in bytes (default: 1MB)
- `maxUrlLength`: Maximum URL length (default: 2048)

### CORS
- `enableCors`: Enable CORS validation (default: false)
- `allowedOrigins`: List of allowed origins
- `allowedMethods`: List of allowed HTTP methods
- `allowedHeaders`: List of allowed headers

### Security Headers
- `enableSecurityHeaders`: Add security headers (default: true)
- `enableHsts`: Enable HSTS header (default: true)
- `enableCsp`: Enable Content Security Policy (default: false)
- `cspPolicy`: Custom CSP policy string

### Threat Detection
- `enableThreatDetection`: Enable threat detection (default: true)
- `blockedIPs`: List of blocked IP addresses
- `blockedUserAgents`: List of blocked user agents
- `maxRequestsPerMinute`: Maximum requests per minute (default: 60)

### Logging & Monitoring
- `enableLogging`: Enable logging (default: true)
- `logLevel`: Log level (Info, Debug, Warn, Error)
- `enableMetrics`: Enable metrics collection (default: true)

### Advanced
- `strictMode`: Enable strict security mode (default: false)
- `requestTimeoutSeconds`: Request timeout in seconds (default: 30)
- `enableIpReputation`: Enable IP reputation checking (default: false)## Security Features

### Rate Limiting
- Configurable requests per minute per IP
- Automatic blocking of abusive clients
- Sliding window algorithm for fairness

### CSRF Protection
- Automatic token generation and validation
- Support for custom token headers
- Session-based token management

### XSS Prevention
- Input sanitization
- HTML entity encoding
- JavaScript injection detection

### SQL Injection Detection
- Pattern-based detection
- Parameterized query validation
- Database-specific escaping

### IP Reputation
- Integration with threat intelligence feeds
- Configurable blocklists
- Geographic filtering options

## Performance

SecureAPIs is built with performance in mind:
- **Zero-copy operations** where possible
- **Minimal memory allocations**
- **SIMD-accelerated pattern matching**
- **Concurrent request processing**

Typical overhead: < 1ms per request on modern hardware.

## Error Handling

```python
from secureapis import SecureAPIsException

try:
    result = secureapis.check_request(...)
except SecureAPIsException as e:
    print(f"Security check failed: {e}")
```

## Logging

SecureAPIs integrates with Python's logging system:

```python
import logging
logging.basicConfig(level=logging.INFO)

# SecureAPIs will log security events
```

## Development

### Building from Source

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the Rust library
cargo build --release

# Build Python bindings
cd bindings/python
python setup.py build_ext --inplace
```

### Running Tests

```bash
cd bindings/python
python test_secureapis.py
```

### Cross-Platform Building

The bindings support Windows, Linux, and macOS. The build system automatically detects the platform and builds the appropriate native library.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## Support

- **Issues**: GitHub Issues
- **Documentation**: Full docs at docs.secureapis.com
- **Community**: Discord server