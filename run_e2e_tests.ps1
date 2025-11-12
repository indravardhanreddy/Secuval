#!/usr/bin/env pwsh
<#
.SYNOPSIS
    End-to-End testing pipeline for SecureAPIs
    Builds and tests all language bindings from scratch

.DESCRIPTION
    This script performs a complete end-to-end test of SecureAPIs:
    1. Builds the Rust core library
    2. Builds all language bindings (C#, Java, Node.js, Python)
    3. Runs unit tests for each binding
    4. Runs integration tests against a live server
    5. Provides a comprehensive test report

.PARAMETER SkipIntegration
    Skip the integration tests (server startup and API testing)

.PARAMETER Clean
    Clean all build artifacts before starting

.EXAMPLE
    .\run_e2e_tests.ps1

.EXAMPLE
    .\run_e2e_tests.ps1 -SkipIntegration

.EXAMPLE
    .\run_e2e_tests.ps1 -Clean
#>

param(
    [switch]$SkipIntegration,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = $ScriptDir

# Test results tracking
$TestResults = @{
    Rust = @{ Status = "Not Started"; Details = "" }
    CSharp = @{ Status = "Not Started"; Details = "" }
    Java = @{ Status = "Not Started"; Details = "" }
    NodeJS = @{ Status = "Not Started"; Details = "" }
    Python = @{ Status = "Not Started"; Details = "" }
    Integration = @{ Status = "Not Started"; Details = "" }
}

function Write-Step {
    param([string]$Message)
    Write-Host ">>> $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Update-TestResult {
    param(
        [string]$Component,
        [string]$Status,
        [string]$Details = ""
    )
    $TestResults[$Component].Status = $Status
    $TestResults[$Component].Details = $Details
}

function Clean-BuildArtifacts {
    Write-Step "Cleaning build artifacts..."

    # Clean Rust
    if (Test-Path "$ProjectRoot\target") {
        Remove-Item "$ProjectRoot\target" -Recurse -Force
    }

    # Clean C#
    $csharpDirs = @(
        "$ProjectRoot\bindings\csharp\bin",
        "$ProjectRoot\bindings\csharp\obj",
        "$ProjectRoot\test_integration\bin",
        "$ProjectRoot\test_integration\obj",
        "$ProjectRoot\test_dll\bin",
        "$ProjectRoot\test_dll\obj",
        "$ProjectRoot\TestDll\bin",
        "$ProjectRoot\TestDll\obj",
        "$ProjectRoot\VulnerabilityTester\bin",
        "$ProjectRoot\VulnerabilityTester\obj"
    )
    foreach ($dir in $csharpDirs) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force
        }
    }

    # Clean Java
    if (Test-Path "$ProjectRoot\bindings\java\target") {
        Remove-Item "$ProjectRoot\bindings\java\target" -Recurse -Force
    }

    # Clean Node.js
    $nodeDirs = @(
        "$ProjectRoot\bindings\nodejs\build",
        "$ProjectRoot\bindings\nodejs\node_modules"
    )
    foreach ($dir in $nodeDirs) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force
        }
    }

    # Clean Python
    if (Test-Path "$ProjectRoot\bindings\python\build") {
        Remove-Item "$ProjectRoot\bindings\python\build" -Recurse -Force
    }

    Write-Success "Build artifacts cleaned"
}

function Build-Rust {
    Write-Step "Building Rust core library..."

    try {
        Push-Location $ProjectRoot

        # Build release version
        & cargo build --release
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo build failed"
        }

        # Run tests
        & cargo test --release
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo tests failed"
        }

        Update-TestResult "Rust" "Passed"
        Write-Success "Rust library built and tested successfully"
    }
    catch {
        Update-TestResult "Rust" "Failed" $_.Exception.Message
        Write-Error "Rust build failed: $($_.Exception.Message)"
        throw
    }
    finally {
        Pop-Location
    }
}

function Build-CSharp {
    Write-Step "Building C# bindings..."

    try {
        Push-Location $ProjectRoot

        # Run the build script
        & .\build_csharp_bindings.bat
        if ($LASTEXITCODE -ne 0) {
            throw "C# build script failed"
        }

        # Run tests
        Push-Location "bindings\csharp"
        & dotnet test --verbosity minimal
        if ($LASTEXITCODE -ne 0) {
            throw "C# tests failed"
        }
        Pop-Location

        Update-TestResult "CSharp" "Passed"
        Write-Success "C# bindings built and tested successfully"
    }
    catch {
        Update-TestResult "CSharp" "Failed" $_.Exception.Message
        Write-Error "C# build failed: $($_.Exception.Message)"
        throw
    }
    finally {
        Pop-Location
    }
}

function Build-Java {
    Write-Step "Building Java bindings..."

    try {
        Push-Location $ProjectRoot

        # Check if Java build script exists
        if (!(Test-Path "build_java_bindings.bat")) {
            Update-TestResult "Java" "Skipped" "Build script not found"
            Write-Warning "Java bindings build script not found, skipping"
            return
        }

        # Run the build script
        & .\build_java_bindings.bat
        if ($LASTEXITCODE -ne 0) {
            throw "Java build script failed"
        }

        # Run tests
        Push-Location "bindings\java"
        & mvn test -q
        if ($LASTEXITCODE -ne 0) {
            throw "Java tests failed"
        }
        Pop-Location

        Update-TestResult "Java" "Passed"
        Write-Success "Java bindings built and tested successfully"
    }
    catch {
        Update-TestResult "Java" "Failed" $_.Exception.Message
        Write-Error "Java build failed: $($_.Exception.Message)"
        throw
    }
    finally {
        Pop-Location
    }
}

function Build-NodeJS {
    Write-Step "Building Node.js bindings..."

    try {
        Push-Location $ProjectRoot

        # Check if Node.js build script exists
        if (!(Test-Path "build_nodejs_bindings.bat")) {
            Update-TestResult "NodeJS" "Skipped" "Build script not found"
            Write-Warning "Node.js bindings build script not found, skipping"
            return
        }

        # Run the build script
        & .\build_nodejs_bindings.bat
        if ($LASTEXITCODE -ne 0) {
            throw "Node.js build script failed"
        }

        # Run tests
        Push-Location "bindings\nodejs"
        & npm test
        if ($LASTEXITCODE -ne 0) {
            throw "Node.js tests failed"
        }
        Pop-Location

        Update-TestResult "NodeJS" "Passed"
        Write-Success "Node.js bindings built and tested successfully"
    }
    catch {
        Update-TestResult "NodeJS" "Failed" $_.Exception.Message
        Write-Error "Node.js build failed: $($_.Exception.Message)"
        throw
    }
    finally {
        Pop-Location
    }
}

function Build-Python {
    Write-Step "Building Python bindings..."

    try {
        Push-Location $ProjectRoot

        # Run the build script
        & .\build_python_bindings.bat
        if ($LASTEXITCODE -ne 0) {
            throw "Python build script failed"
        }

        # Run tests
        Push-Location "bindings\python"
        & python test_secureapis.py
        if ($LASTEXITCODE -ne 0) {
            throw "Python tests failed"
        }
        Pop-Location

        Update-TestResult "Python" "Passed"
        Write-Success "Python bindings built and tested successfully"
    }
    catch {
        Update-TestResult "Python" "Failed" $_.Exception.Message
        Write-Error "Python build failed: $($_.Exception.Message)"
        throw
    }
    finally {
        Pop-Location
    }
}

function Run-IntegrationTests {
    if ($SkipIntegration) {
        Update-TestResult "Integration" "Skipped" "Integration tests skipped by user"
        Write-Warning "Integration tests skipped"
        return
    }

    Write-Step "Running integration tests..."

    try {
        Push-Location $ProjectRoot

        # Start the test server in background
        Write-Step "Starting test server..."
        $serverProcess = Start-Process -FilePath "dotnet" -ArgumentList "run --project test_integration\TestIntegration.csproj" -NoNewWindow -PassThru
        Start-Sleep -Seconds 2

        # Wait for server to be ready
        Write-Step "Waiting for server to be ready..."
        $maxAttempts = 30
        $ready = $false
        for ($i = 1; $i -le $maxAttempts; $i++) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:5000/health" -TimeoutSec 2 -ErrorAction Stop
                if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 404) {
                    $ready = $true
                    break
                }
            }
            catch {
                # Server not ready yet
            }
            Write-Host "   Attempt $i/$maxAttempts - server not ready yet..."
            Start-Sleep -Seconds 2
        }

        if (!$ready) {
            throw "Server failed to start within timeout period"
        }

        Write-Success "Server is ready!"

        # Run integration tests
        Write-Step "Running integration test suite..."
        & python integration_test.py
        if ($LASTEXITCODE -ne 0) {
            throw "Integration tests failed"
        }

        Update-TestResult "Integration" "Passed"
        Write-Success "Integration tests passed"
    }
    catch {
        Update-TestResult "Integration" "Failed" $_.Exception.Message
        Write-Error "Integration tests failed: $($_.Exception.Message)"
        throw
    }
    finally {
        # Clean up server process
        if ($serverProcess) {
            try {
                Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
            }
            catch {
                # Process might already be stopped
            }
        }
        Pop-Location
    }
}

function Show-TestSummary {
    Write-Host
    Write-Host ("=" * 60)
    Write-Host "END-TO-END TEST SUMMARY"
    Write-Host ("=" * 60)

    $totalTests = 0
    $passedTests = 0
    $failedTests = 0
    $skippedTests = 0

    foreach ($component in $TestResults.Keys) {
        $result = $TestResults[$component]
        $totalTests++

        switch ($result.Status) {
            "Passed" {
                $passedTests++
                Write-Success "$component`: $($result.Status)"
            }
            "Failed" {
                $failedTests++
                Write-Error "$component`: $($result.Status)"
                if ($result.Details) {
                    Write-Host "   Details: $($result.Details)" -ForegroundColor Red
                }
            }
            "Skipped" {
                $skippedTests++
                Write-Warning "$component`: $($result.Status)"
                if ($result.Details) {
                    Write-Host "   Reason: $($result.Details)" -ForegroundColor Yellow
                }
            }
            default {
                Write-Host "$component`: $($result.Status)" -ForegroundColor Gray
            }
        }
    }

    Write-Host
    Write-Host ("=" * 60)
    Write-Host "RESULTS: $passedTests/$totalTests tests passed, $failedTests failed, $skippedTests skipped"
    Write-Host ("=" * 60)

    if ($failedTests -eq 0) {
        Write-Success "ALL TESTS PASSED! End-to-end pipeline successful."
        return $true
    }
    else {
        Write-Error "SOME TESTS FAILED. Check the output above for details."
        return $false
    }
}

# Main execution
try {
    Write-Host "SecureAPIs End-to-End Testing Pipeline"
    Write-Host ("=" * 50)
    Write-Host "Project Root: $ProjectRoot"
    Write-Host "Skip Integration: $SkipIntegration"
    Write-Host "Clean Build: $Clean"
    Write-Host

    if ($Clean) {
        Clean-BuildArtifacts
    }

    # Run all build and test steps
    Build-Rust
    Build-CSharp
    Build-Java
    Build-NodeJS
    Build-Python
    Run-IntegrationTests

    # Show final summary
    $success = Show-TestSummary

    # Exit with appropriate code
    if ($success) {
        exit 0
    }
    else {
        exit 1
    }
}
catch {
    Write-Error "Pipeline failed: $($_.Exception.Message)"
    Show-TestSummary | Out-Null
    exit 1
}