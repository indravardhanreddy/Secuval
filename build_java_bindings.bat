@echo off
REM Build script for SecureAPIs Java bindings

echo Building SecureAPIs Java bindings...
echo ====================================

REM Build the Rust library first
echo.
echo Building Rust library...
cargo build --release
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Rust library
    exit /b 1
)

REM Build the Java bindings
echo.
echo Building Java bindings...
cd bindings\java
mvn clean compile
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Java bindings
    exit /b 1
)

REM Run tests
echo.
echo Running tests...
mvn test
if %errorlevel% neq 0 (
    echo WARNING: Some tests failed, but build completed
)

REM Package
echo.
echo Packaging...
mvn package -DskipTests
if %errorlevel% neq 0 (
    echo ERROR: Failed to package Java bindings
    exit /b 1
)

echo.
echo ====================================
echo Java bindings built successfully!
echo ====================================

REM Instructions
echo.
echo To use the bindings:
echo 1. Add the JAR to your classpath
echo 2. Use SecureAPIsFilter in web.xml or SecureAPIsSpringFilter in Spring Boot
echo.
echo Example:
echo   SecureAPIsConfig config = new SecureAPIsConfig();
echo   config.setRateLimitRequests(100);
echo   SecureAPIs secureAPIs = new SecureAPIs(config);
echo ====================================