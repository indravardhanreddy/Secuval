# SecureAPIs Postman Security Testing Collection

This Postman collection provides comprehensive security testing for your Rust API server.

## How to Use:

### 1. Import the Collection
1. Open Postman
2. Click "Import" button
3. Select "File"
4. Choose `postman_collection.json`
5. Import the collection

### 2. Configure Environment
1. Create a new environment in Postman
2. Add variable: `base_url` = `http://127.0.0.1:3000`
3. Select this environment

### 3. Start Your Rust Server
```bash
cd c:\projects\secureapis
cargo run --example complete_example
```

### 4. Run the Tests

#### Option A: Run Individual Tests
- Expand the collection
- Click on each request
- Click "Send" to test manually

#### Option B: Run Collection Automatically
1. Click "Runner" button in Postman
2. Select "SecureAPIs Security Testing" collection
3. Set iterations (e.g., 5 for rate limiting test)
4. Click "Run"
5. View results in the "Run Results" tab

### 5. Analyze Results

The collection includes automated tests that check for:

✅ **Server Response**: No 5xx errors
✅ **Response Time**: Under 2000ms
✅ **Security Headers**: X-Content-Type-Options, X-Frame-Options
✅ **CORS Headers**: Access-Control-Allow-Origin
✅ **Rate Limiting**: 429 responses when triggered
✅ **Authentication**: 401 responses for protected endpoints
✅ **Input Validation**: Malicious input blocked

## Test Categories:

### 1. Basic Connectivity
- Root endpoint (`/`)
- Health check (`/health`)
- Public API (`/api/public`)

### 2. Authentication
- Protected endpoint without auth (should fail)
- Protected endpoint with invalid token (should fail)

### 3. Input Validation
- Normal user creation
- XSS attack attempts
- SQL injection attempts
- Command injection attempts

### 4. Rate Limiting
- Multiple rapid requests to trigger rate limiting

### 5. Security Headers
- Check for standard security headers

## Expected Results:

Your secure API should show:
- ✅ All basic endpoints respond successfully
- ✅ Protected endpoints return 401 Unauthorized
- ✅ Malicious input is blocked (400/422 responses)
- ✅ Rate limiting triggers after ~100 requests
- ✅ Security headers are present
- ✅ No server errors (5xx)

## Troubleshooting:

- **Connection refused**: Make sure your Rust server is running on port 3000
- **Rate limiting not working**: Try running the rate limit test multiple times quickly
- **Authentication not working**: Check if JWT validation is properly configured

## Advanced Usage:

### Newman (Command Line)
Install Newman and run tests from command line:
```bash
npm install -g newman
newman run postman_collection.json -e environment.json --reporters cli,json
```

### CI/CD Integration
Add this collection to your CI pipeline for automated security regression testing.