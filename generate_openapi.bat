@echo off
echo ========================================
echo Generate OpenAPI Spec for SecureAPIs
echo ========================================
echo.

cd /d c:\projects\secureapis

echo Building the project with OpenAPI generation...
cargo build --example complete_example

echo.
echo Starting server to generate OpenAPI spec...
start /B cargo run --example complete_example

echo Waiting for server to start...
timeout /t 3 /nobreak >nul

echo.
echo Downloading OpenAPI specification...
curl -s http://127.0.0.1:3000/api-docs/openapi.json -o openapi_spec.json

echo.
if exist openapi_spec.json (
    echo ✅ OpenAPI specification saved as: openapi_spec.json
    echo.
    echo 📄 File contents preview:
    type openapi_spec.json | findstr /i "title\|version\|paths" | head -10
    echo.
    echo 🔍 You can now use this file with automated security scanners like:
    echo    - 42Crunch API Security Audit
    echo    - APIClarity
    echo    - StackHawk
    echo    - Any OpenAPI-compatible security scanner
    echo.
    echo 🌐 Or view the interactive Swagger UI at:
    echo    http://127.0.0.1:3000/swagger-ui
) else (
    echo ❌ Failed to generate OpenAPI spec
    echo Make sure the server is running on port 3000
)

echo.
echo Press any key to stop the server and exit...
pause >nul

echo Stopping server...
taskkill /f /im cargo.exe >nul 2>&1

echo Done!