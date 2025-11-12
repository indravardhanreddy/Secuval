@echo off
echo ========================================
echo SecureAPIs Security Testing Script
echo ========================================
echo.

set BASE_URL=http://127.0.0.1:3000

echo Testing basic connectivity...
echo.

echo 1. Testing root endpoint:
curl -s -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/
echo.

echo 2. Testing health endpoint:
curl -s -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/health
echo.

echo 3. Testing public API endpoint:
curl -s -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/public
echo.

echo ========================================
echo Testing Authentication
echo ========================================
echo.

echo 4. Testing protected endpoint (should fail):
curl -s -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/data
echo.

echo 5. Testing protected endpoint with invalid token (should fail):
curl -s -H "Authorization: Bearer invalid.jwt.token" -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/data
echo.

echo ========================================
echo Testing Input Validation
echo ========================================
echo.

echo 6. Testing normal user creation:
curl -s -X POST -H "Content-Type: application/json" -d "{\"username\":\"testuser\",\"email\":\"test@example.com\"}" -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/user
echo.

echo 7. Testing XSS attempt:
curl -s -X POST -H "Content-Type: application/json" -d "{\"username\":\"<script>alert('xss')</script>\",\"email\":\"test@example.com\"}" -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/user
echo.

echo 8. Testing SQL injection attempt:
curl -s -X POST -H "Content-Type: application/json" -d "{\"username\":\"admin' OR '1'='1\",\"email\":\"test@example.com\"}" -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/user
echo.

echo ========================================
echo Testing Rate Limiting
echo ========================================
echo.

echo 9. Testing rate limiting (sending multiple requests quickly):
echo Sending 10 rapid requests to public endpoint...
for /L %%i in (1,1,10) do (
    curl -s %BASE_URL%/api/public >nul
    echo Request %%i sent
    timeout /t 1 /nobreak >nul
)

echo.
echo 10. Final rate limit test (should get 429):
curl -s -w "Status: %%{http_code}, Time: %%{time_total}s\n" %BASE_URL%/api/public
echo.

echo ========================================
echo Security Test Summary
echo ========================================
echo.
echo Check the status codes above:
echo - 200: Success (good for public endpoints)
echo - 401: Unauthorized (good for protected endpoints)
echo - 400/422: Bad Request (good for malicious input)
echo - 429: Too Many Requests (good for rate limiting)
echo - 5xx: Server Error (bad - indicates problems)
echo.
echo If you see mostly 200s for public endpoints, 401s for protected ones,
echo and 400s for malicious input, your security is working well!
echo.
pause