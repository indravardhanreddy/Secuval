@echo off
REM Master build script for all SecureAPIs language bindings

echo ========================================
echo SecureAPIs Language Bindings Build System
echo ========================================
echo.

REM Build the Rust library first (required for all bindings)
echo Building Rust core library...
echo ===============================
cargo build --release
if %errorlevel% neq 0 (
    echo ERROR: Failed to build Rust library
    exit /b 1
)
echo ✓ Rust library built successfully
echo.

REM Build C# bindings
echo Building C# bindings...
echo =======================
if exist bindings\csharp (
    cd bindings\csharp
    call ..\..\build_csharp_bindings.bat
    if %errorlevel% neq 0 (
        echo WARNING: C# bindings build failed
    ) else (
        echo ✓ C# bindings built successfully
    )
    cd ..\..
) else (
    echo ⚠ C# bindings directory not found, skipping
)
echo.

REM Build Java bindings
echo Building Java bindings...
echo ========================
if exist bindings\java (
    call build_java_bindings.bat
    if %errorlevel% neq 0 (
        echo WARNING: Java bindings build failed
    ) else (
        echo ✓ Java bindings built successfully
    )
) else (
    echo ⚠ Java bindings directory not found, skipping
)
echo.

REM Build Node.js bindings
echo Building Node.js bindings...
echo ===========================
if exist bindings\nodejs (
    cd bindings\nodejs
    call ..\..\build_nodejs_bindings.bat
    if %errorlevel% neq 0 (
        echo WARNING: Node.js bindings build failed
    ) else (
        echo ✓ Node.js bindings built successfully
    )
    cd ..\..
) else (
    echo ⚠ Node.js bindings directory not found, skipping
)
echo.

REM Build Python bindings
echo Building Python bindings...
echo ==========================
if exist bindings\python (
    call build_python_bindings.bat
    if %errorlevel% neq 0 (
        echo WARNING: Python bindings build failed
    ) else (
        echo ✓ Python bindings built successfully
    )
) else (
    echo ⚠ Python bindings directory not found, skipping
)
echo.

echo ========================================
echo Build Summary
echo ========================================
echo.

REM Check which bindings were built successfully
set SUCCESS_COUNT=0

if exist csharp\bin\Release\net6.0\SecureAPIs.dll (
    echo ✓ C# bindings: Built
    set /a SUCCESS_COUNT+=1
) else (
    echo ✗ C# bindings: Failed or not found
)

if exist java\target\secureapis-1.0.0.jar (
    echo ✓ Java bindings: Built
    set /a SUCCESS_COUNT+=1
) else (
    echo ✗ Java bindings: Failed or not found
)

if exist nodejs\build\Release\secureapis.node (
    echo ✓ Node.js bindings: Built
    set /a SUCCESS_COUNT+=1
) else (
    echo ✗ Node.js bindings: Failed or not found
)

if exist python\build\lib\secureapis\__init__.py (
    echo ✓ Python bindings: Built
    set /a SUCCESS_COUNT+=1
) else (
    echo ✗ Python bindings: Failed or not found
)

echo.
echo ========================================
echo %SUCCESS_COUNT% out of 4 language bindings built successfully
echo ========================================

if %SUCCESS_COUNT% equ 4 (
    echo 🎉 All bindings built successfully!
    echo.
    echo Next steps:
    echo - Run tests: .\run_all_tests.bat
    echo - Package for distribution
    echo - Deploy to package managers
) else (
    echo ⚠️ Some bindings failed to build. Check the output above.
    echo You can still use the successfully built bindings.
)

echo.
echo Build completed.
echo ========================================