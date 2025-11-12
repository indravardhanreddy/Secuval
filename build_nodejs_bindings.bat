@echo off
REM Build script for SecureAPIs Node.js bindings

echo Building SecureAPIs Node.js bindings...
echo =======================================

REM Build the Rust library first
echo.
echo Building Rust library...
cargo build --release
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Rust library
    exit /b 1
)

REM Copy the library to Node.js binding directory
echo.
echo Copying Rust library...
if exist "target\release\secureapis.dll" (
    copy "target\release\secureapis.dll" "bindings\nodejs\build\Release\" >nul 2>&1
) else if exist "target\release\libsecureapis.so" (
    copy "target\release\libsecureapis.so" "bindings\nodejs\build\Release\" >nul 2>&1
) else if exist "target\release\libsecureapis.dylib" (
    copy "target\release\libsecureapis.dylib" "bindings\nodejs\build\Release\" >nul 2>&1
)

REM Build the Node.js bindings
echo.
echo Building Node.js bindings...
cd bindings\nodejs
if not exist "build\Release" mkdir "build\Release"
npm run build
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Node.js bindings
    exit /b 1
)

echo.
echo =======================================
echo Node.js bindings built successfully!
echo =======================================

REM Test the bindings
echo.
echo Testing bindings...
npm test
if %errorlevel% neq 0 (
    echo WARNING: Tests failed, but build completed
)

echo.
echo To use the bindings:
echo   const { SecureAPIs } = require('./bindings/nodejs');
echo =======================================