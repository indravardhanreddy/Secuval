# Testing SecureAPIs

## Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_rate_limiter

# Run benchmarks
cargo bench
```

## Testing Rate Limiting

```bash
# Use curl to test rate limiting
for i in {1..110}; do
  curl http://localhost:3000/api/data
  echo "Request $i"
done
```

## Testing JWT Authentication

```bash
# Generate a token
cargo run --example jwt_auth

# Use the token in requests
TOKEN="your-generated-token"
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/data
```

## Testing Input Validation

```bash
# Test SQL injection protection
curl -X POST http://localhost:3000/api/user \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "email": "test@test.com"}'

# Test XSS protection
curl -X POST http://localhost:3000/api/user \
  -H "Content-Type: application/json" \
  -d '{"username": "<script>alert('\''xss'\'')</script>", "email": "test@test.com"}'

# Test path traversal
curl "http://localhost:3000/api/file?path=../../etc/passwd"
```

## Load Testing

Using `wrk`:

```bash
# Install wrk (Linux/Mac)
# brew install wrk  # Mac
# sudo apt install wrk  # Ubuntu

# Basic load test
wrk -t4 -c100 -d30s http://localhost:3000/api/data

# With rate limiting
wrk -t4 -c200 -d30s http://localhost:3000/api/data
```

## Expected Results

- **Rate Limiting**: Should block requests after limit is reached
- **SQL Injection**: Should return 400 Bad Request with "SQL injection detected"
- **XSS**: Should return 400 Bad Request with "XSS attack detected"
- **Path Traversal**: Should return 400 Bad Request with "path traversal detected"
- **JWT Auth**: Should return 401 Unauthorized without valid token
