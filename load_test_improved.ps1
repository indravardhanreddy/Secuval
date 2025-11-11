<#
.SYNOPSIS
  Improved load/test script for SecureAPIs with balanced attack/normal traffic
  
.DESCRIPTION
  This script properly simulates realistic traffic:
  - 30% normal, legitimate API requests
  - 70% malicious payloads (SQL injection, XSS, etc.)
  
  With the improved threat detection, normal requests should NOT be blocked.
#>

param(
    [int]$TotalRequests = 10000,
    [int]$ParallelJobs = 10,
    [string]$TargetUrl = "http://localhost:3000",
    [switch]$Verbose
)

if ($TotalRequests -le 0) { throw "TotalRequests must be > 0" }
if ($ParallelJobs -le 0) { throw "ParallelJobs must be > 0" }
if ($ParallelJobs -gt $TotalRequests) { $ParallelJobs = [math]::Min($ParallelJobs, $TotalRequests) }

if ($TargetUrl.EndsWith('/')) { $TargetUrl = $TargetUrl.TrimEnd('/') }

Write-Host 'WARNING: Run this only against systems you own or are authorized to test.' -ForegroundColor Yellow

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$stats = @{
    Total = 0
    Success = 0
    Blocked = 0
    RateLimited = 0
    Failed = 0
    StartTime = Get-Date
}

# Malicious payloads that SHOULD be blocked
$maliciousPayloads = @{
    SqlInjection = @(
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users; --",
        "' OR 'x'='x"
    )
    XSS = @(
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg/onload=alert(1)>',
        '<body onload=alert(1)>'
    )
    PathTraversal = @(
        '../../../etc/passwd',
        '..\..\windows\system32\drivers\etc\hosts',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd'
    )
    CommandInjection = @(
        '; rm -rf /',
        '`cat /etc/passwd`',
        '$(whoami)',
        '| ls -la',
        '& dir'
    )
}

# Normal, legitimate API paths that should PASS
$normalPaths = @(
    '/api/ui/dashboard',
    '/api/ui/metrics',
    '/api/ui/alerts',
    '/api/ui/requests',
    '/api/ui/health',
    '/api/ui/blocked-ips',
    '/api/health',
    '/health',
    '/api/test',
    '/api/data',
    '/api/users',
    '/api/profile',
    '/api/settings'
)

function Write-Progress-Bar {
    param($Current, $Total)
    if ($Total -le 0) { return }
    $percent = [math]::Round(($Current / $Total) * 100, 1)
    $barLength = 50
    $filled = [math]::Round($barLength * $percent / 100)
    $bar = '[' + ('=' * $filled) + (' ' * ($barLength - $filled)) + ']'
    Write-Host "`r$bar $percent% ($Current/$Total)" -NoNewline -ForegroundColor Cyan
}

$batchSize = [math]::Ceiling($TotalRequests / [double]$ParallelJobs)

$jobs = @()
for ($jobId = 0; $jobId -lt $ParallelJobs; $jobId++) {
    $start = $jobId * $batchSize
    $end = [math]::Min(($jobId + 1) * $batchSize, $TotalRequests)
    if ($start -ge $end) { continue }

    $jobs += Start-Job -ScriptBlock {
        param($Start, $End, $TargetUrl, $NormalPaths, $MaliciousPayloads, $Verbose)

        [System.Random]$rnd = New-Object System.Random([int]((Get-Date).Ticks % 2147483647))

        function Get-RandomAttack {
            $allPayloads = @()
            $allPayloads += $MaliciousPayloads.SqlInjection | ForEach-Object { @{Type='SQLi'; Payload=$_} }
            $allPayloads += $MaliciousPayloads.XSS | ForEach-Object { @{Type='XSS'; Payload=$_} }
            $allPayloads += $MaliciousPayloads.PathTraversal | ForEach-Object { @{Type='PathTraversal'; Payload=$_} }
            $allPayloads += $MaliciousPayloads.CommandInjection | ForEach-Object { @{Type='CmdInjection'; Payload=$_} }
            
            return $allPayloads[$rnd.Next(0, $allPayloads.Count)]
        }

        $results = @{Success=0; Blocked=0; RateLimited=0; Failed=0; Total=0}

        for ($i = $Start; $i -lt $End; $i++) {
            $isAttack = ($rnd.Next(0, 100) -lt 70)  # 70% attacks, 30% normal

            if ($isAttack) {
                # Generate attack payload
                $attack = Get-RandomAttack
                $encoded = [uri]::EscapeDataString($attack.Payload)
                $path = "/api/test/secure?input=$encoded&type=$($attack.Type)&id=$i"
                $uri = "$TargetUrl$path"
            } else {
                # Use legitimate normal path
                $path = $NormalPaths[$rnd.Next(0, $NormalPaths.Count)]
                $uri = $TargetUrl + $path
            }

            try {
                $response = Invoke-WebRequest -Uri $uri -TimeoutSec 3 -ErrorAction Stop
                $status = 0
                if ($response -and $response.StatusCode) { $status = [int]$response.StatusCode }

                if ($status -ge 200 -and $status -lt 400) {
                    $results.Success++
                } elseif ($status -eq 429) {
                    $results.RateLimited++
                } elseif ($status -ge 400 -and $status -lt 500) {
                    $results.Blocked++
                } else {
                    $results.Failed++
                }
            }
            catch {
                $statusCode = 0
                try {
                    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                    }
                } catch { $statusCode = 0 }

                if ($statusCode -eq 429) { $results.RateLimited++ }
                elseif ($statusCode -ge 400 -and $statusCode -lt 500) { $results.Blocked++ }
                else { $results.Failed++ }

                if ($Verbose) {
                    Write-Host ("Request {0} - Status {1}" -f $i, $statusCode)
                }
            }
            $results.Total++
            Start-Sleep -Milliseconds 2
        }

        return $results
    } -ArgumentList $start, $end, $TargetUrl, $normalPaths, $maliciousPayloads, $Verbose
}

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '=                 IMPROVED LOAD TEST RUNNING                  =' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host "Total Requests: $TotalRequests" -ForegroundColor Yellow
Write-Host "Parallel Jobs: $ParallelJobs" -ForegroundColor Yellow
Write-Host "Traffic Ratio: 70% malicious attacks, 30% normal requests`n" -ForegroundColor Yellow
Write-Host "✅ Normal requests should PASS (200 OK)" -ForegroundColor Green
Write-Host "❌ Attack payloads should be BLOCKED (403 Forbidden)`n" -ForegroundColor Red

$completedRequests = 0
while ($true) {
    $running = $jobs | Where-Object { $_.State -eq 'Running' }
    $completedJobs = $jobs | Where-Object { $_.State -eq 'Completed' }

    $completedRequests = 0
    foreach ($j in $completedJobs) {
        $jobId = $jobs.IndexOf($j)
        $startApprox = $jobId * $batchSize
        $endApprox = [math]::Min(($jobId + 1) * $batchSize, $TotalRequests)
        $completedRequests += ($endApprox - $startApprox)
    }

    Write-Progress-Bar -Current $completedRequests -Total $TotalRequests

    if (-not $running) { break }
    Start-Sleep -Milliseconds 500
}

Write-Host "`n`nCollecting results..." -ForegroundColor Green

foreach ($job in $jobs) {
    try {
        $result = Receive-Job -Job $job -Wait -AutoRemoveJob
        if ($result) {
            $stats.Success += ($result.Success -as [int])
            $stats.Blocked += ($result.Blocked -as [int])
            $stats.RateLimited += ($result.RateLimited -as [int])
            $stats.Failed += ($result.Failed -as [int])
            $stats.Total += ($result.Total -as [int])
        }
    } catch {
        Write-Warning "Failed to receive job output: $($_.Exception.Message)"
    }
}

if ($stats.Total -eq 0) { $stats.Total = $stats.Success + $stats.Blocked + $stats.RateLimited + $stats.Failed }

$duration = (Get-Date) - $stats.StartTime

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '=                    LOAD TEST RESULTS                       =' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "Total Requests:       $($stats.Total)" -ForegroundColor Cyan
Write-Host "Successful (OK):      $($stats.Success)" -ForegroundColor Green
Write-Host "Blocked (403):        $($stats.Blocked)" -ForegroundColor Red
Write-Host "Rate Limited (429):   $($stats.RateLimited)" -ForegroundColor Magenta
Write-Host "Failed (Other):       $($stats.Failed)" -ForegroundColor DarkRed

if ($stats.Total -gt 0) {
    $blockRate = [math]::Round(($stats.Blocked / $stats.Total) * 100, 2)
    $successRate = [math]::Round(($stats.Success / $stats.Total) * 100, 2)
    
    Write-Host ""
    Write-Host "Success Rate:         $successRate%" -ForegroundColor Green
    Write-Host "Block Rate:           $blockRate%" -ForegroundColor Red
    
    # Interpretation
    Write-Host ""
    if ($successRate -gt 25 -and $successRate -lt 35) {
        Write-Host "✅ CORRECT: ~30% of requests passed (normal traffic)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Unexpected success rate (expected ~30%)" -ForegroundColor Yellow
    }
    
    if ($blockRate -gt 65 -and $blockRate -lt 75) {
        Write-Host "✅ CORRECT: ~70% of requests blocked (attack payloads)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Unexpected block rate (expected ~70%)" -ForegroundColor Yellow
    }
}

if ($duration.TotalSeconds -gt 0) {
    $rps = [math]::Round($stats.Total / $duration.TotalSeconds, 2)
    Write-Host "Requests/Second:      $rps req/s" -ForegroundColor Cyan
}

Write-Host "Duration:             $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor Cyan

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "=  Dashboard: http://localhost:3000/api/ui/dashboard        =" -ForegroundColor Cyan
Write-Host "=  Metrics:   http://localhost:3000/api/ui/metrics          =" -ForegroundColor Cyan
Write-Host "=  Blocked IPs: http://localhost:3000/api/ui/blocked-ips    =" -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ''

Write-Host "EXPECTED METRICS:" -ForegroundColor Yellow
$allowed = [math]::Round($stats.Total * 0.30)
$blocked = [math]::Round($stats.Total * 0.70)
Write-Host "Total Requests: $($stats.Total)" -ForegroundColor Cyan
Write-Host "Allowed Requests: $allowed (30 percent)" -ForegroundColor Green
Write-Host "Blocked Requests: $blocked (70 percent)" -ForegroundColor Red
Write-Host "Block Rate: 70 percent" -ForegroundColor Red
Write-Host ''
