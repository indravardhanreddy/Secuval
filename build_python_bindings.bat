@echo off
REM Build script for SecureAPIs Python bindings

echo Building SecureAPIs Python bindings...
echo ======================================

REM Build the Rust library first
echo.
echo Building Rust library...
cargo build --release
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Rust library
    exit /b 1
)

REM Build the Python bindings
echo.
echo Building Python bindings...
cd bindings\python
python setup.py build_ext --inplace
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Python bindings
    exit /b 1
)

REM Run tests
echo.
echo Running tests...
python test_secureapis.py
if %errorlevel% neq 0 (
    echo WARNING: Tests failed, but build completed
)

echo.
echo ======================================
echo Python bindings built successfully!
echo ======================================

REM Instructions
echo.
echo To use the bindings:
echo   from secureapis import SecureAPIs, SecureAPIsConfig
echo   config = SecureAPIsConfig()
echo   secureapis = SecureAPIs(config)
echo   result = secureapis.check_request("GET", "/api/users", {}, "", "127.0.0.1")
echo.
echo For Flask integration:
echo   from secureapis.flask_middleware import SecureAPIsFlask
echo   secureapis = SecureAPIsFlask(app, config)
echo.
echo For Django integration:
echo   Add 'secureapis.django_middleware.SecureAPIsMiddleware' to MIDDLEWARE
echo ======================================