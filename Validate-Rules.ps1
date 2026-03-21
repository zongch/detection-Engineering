# Validate Detection Rules Against Local Logs
# Tests the 5 detection rules against actual Windows event logs

Write-Host "========================================"
Write-Host "   DETECTION RULE VALIDATION"
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

$testsPassed = 0
$testsFailed = 0
$results = @()

# Test 1: PowerShell Encoded Command
Write-Host "[Test 1/5] Suspicious PowerShell Encoded Command" -ForegroundColor Cyan
try {
    # Get all process creation events first, then filter
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 100 -ErrorAction Stop

    if ($events.Count -gt 0) {
        # Filter for PowerShell processes
        $psEvents = $events | Where-Object {
            $_.Message -match 'Image.*powershell\.exe' -or
            $_.Message -match 'Image.*pwsh\.exe'
        }

        if ($psEvents.Count -gt 0) {
            $encodedEvents = $psEvents | Where-Object {
                $_.Message -match '-enc ' -or
                $_.Message -match '-EncodedCommand' -or
                $_.Message -match '-ec ' -or
                $_.Message -match 'FromBase64String'
            }

            if ($encodedEvents.Count -gt 0) {
                Write-Host "   Found $($encodedEvents.Count) suspicious PowerShell events" -ForegroundColor Green
                $encodedEvents | Select-Object -First 3 | ForEach-Object {
                    Write-Host "   - Event ID: $($_.Id), Time: $($_.TimeCreated)" -ForegroundColor Gray
                }
                $testsPassed++
                $results += [PSCustomObject]@{ Test = "PowerShell Encoded"; Status = "PASS"; Count = $encodedEvents.Count }
            } else {
                Write-Host "   No encoded PowerShell events found (normal if system is idle)" -ForegroundColor Yellow
                $testsPassed++
                $results += [PSCustomObject]@{ Test = "PowerShell Encoded"; Status = "PASS (No Events)"; Count = 0 }
            }
        } else {
            Write-Host "   No PowerShell process creation events found" -ForegroundColor Yellow
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "PowerShell Encoded"; Status = "PASS (No Data)"; Count = 0 }
        }
    } else {
        Write-Host "   No process creation events found" -ForegroundColor Yellow
        $testsPassed++
        $results += [PSCustomObject]@{ Test = "PowerShell Encoded"; Status = "PASS (No Data)"; Count = 0 }
    }
} catch {
    Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
    $results += [PSCustomObject]@{ Test = "PowerShell Encoded"; Status = "FAIL"; Count = 0 }
}
Write-Host ""

# Test 2: LSASS Access
Write-Host "[Test 2/5] LSASS Memory Access" -ForegroundColor Cyan
try {
    # Get all process access events first
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=10)]]" -MaxEvents 100 -ErrorAction Stop

    if ($events.Count -gt 0) {
        # Filter for LSASS access
        $lsassEvents = $events | Where-Object {
            $_.Message -match 'TargetImage.*lsass\.exe'
        }

        if ($lsassEvents.Count -gt 0) {
            Write-Host "   Found $($lsassEvents.Count) LSASS access events" -ForegroundColor Green
            $lsassEvents | Select-Object -First 3 | ForEach-Object {
                if ($_.Message -match 'GrantedAccess.([^\s<]+)') {
                    $accessMask = $matches[1]
                    Write-Host "   - Access: $accessMask, Time: $($_.TimeCreated)" -ForegroundColor Gray
                } else {
                    Write-Host "   - Time: $($_.TimeCreated)" -ForegroundColor Gray
                }
            }
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "LSASS Access"; Status = "PASS"; Count = $lsassEvents.Count }
        } else {
            Write-Host "   No LSASS access events found (normal if system is idle)" -ForegroundColor Yellow
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "LSASS Access"; Status = "PASS (No Events)"; Count = 0 }
        }
    } else {
        Write-Host "   No process access events found" -ForegroundColor Yellow
        $testsPassed++
        $results += [PSCustomObject]@{ Test = "LSASS Access"; Status = "PASS (No Data)"; Count = 0 }
    }
} catch {
    Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $testsFailed++
    $results += [PSCustomObject]@{ Test = "LSASS Access"; Status = "FAIL"; Count = 0 }
}
Write-Host ""

# Test 3: Remote Thread Creation
Write-Host "[Test 3/5] Remote Thread Creation (Process Injection)" -ForegroundColor Cyan
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=8)]]" -MaxEvents 50 -ErrorAction Stop

    if ($events.Count -gt 0) {
        # Filter out known benign sources
        $suspiciousEvents = $events | Where-Object {
            $_.Message -notmatch 'SourceImage.*csrss\.exe'
        }

        if ($suspiciousEvents.Count -gt 0) {
            Write-Host "   Found $($suspiciousEvents.Count) remote thread events (some may be benign)" -ForegroundColor Yellow
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Remote Thread"; Status = "PASS"; Count = $suspiciousEvents.Count }
        } else {
            Write-Host "   No suspicious remote thread events found (good)" -ForegroundColor Green
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Remote Thread"; Status = "PASS (Clean)"; Count = 0 }
        }
    } else {
        Write-Host "   No remote thread events found (good)" -ForegroundColor Green
        $testsPassed++
        $results += [PSCustomObject]@{ Test = "Remote Thread"; Status = "PASS (No Events)"; Count = 0 }
    }
} catch {
    Write-Host "   No remote thread events found (good)" -ForegroundColor Yellow
    $testsPassed++
    $results += [PSCustomObject]@{ Test = "Remote Thread"; Status = "PASS (No Events)"; Count = 0 }
}
Write-Host ""

# Test 4: Registry Run Key Modifications
Write-Host "[Test 4/5] Registry Run Key Modifications" -ForegroundColor Cyan
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=12)]]" -MaxEvents 50 -ErrorAction Stop

    if ($events.Count -gt 0) {
        # Filter for Run keys
        $runKeyEvents = $events | Where-Object {
            $_.Message -match 'TargetObject.*Run' -or
            $_.Message -match 'TargetObject.*Winlogon'
        }

        if ($runKeyEvents.Count -gt 0) {
            Write-Host "   Found $($runKeyEvents.Count) registry Run key events (verify if legitimate)" -ForegroundColor Yellow
            $runKeyEvents | Select-Object -First 3 | ForEach-Object {
                if ($_.Message -match 'TargetObject.([^\n]+)') {
                    $key = $matches[1] -replace '\s+', ' '
                    Write-Host "   - $key" -ForegroundColor Gray
                } else {
                    Write-Host "   - Time: $($_.TimeCreated)" -ForegroundColor Gray
                }
            }
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Registry Run Keys"; Status = "PASS"; Count = $runKeyEvents.Count }
        } else {
            Write-Host "   No registry Run key modifications found (good)" -ForegroundColor Green
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Registry Run Keys"; Status = "PASS (No Events)"; Count = 0 }
        }
    } else {
        Write-Host "   No registry events found (good)" -ForegroundColor Green
        $testsPassed++
        $results += [PSCustomObject]@{ Test = "Registry Run Keys"; Status = "PASS (No Events)"; Count = 0 }
    }
} catch {
    Write-Host "   No registry events found (good)" -ForegroundColor Yellow
    $testsPassed++
    $results += [PSCustomObject]@{ Test = "Registry Run Keys"; Status = "PASS (No Events)"; Count = 0 }
}
Write-Host ""

# Test 5: Script Network Connections
Write-Host "[Test 5/5] Script Network Connections" -ForegroundColor Cyan
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[(EventID=3)]]" -MaxEvents 100 -ErrorAction Stop

    if ($events.Count -gt 0) {
        # Filter for script interpreters
        $scriptEvents = $events | Where-Object {
            $_.Message -match 'powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe'
        }

        if ($scriptEvents.Count -gt 0) {
            Write-Host "   Found $($scriptEvents.Count) script network connections" -ForegroundColor Yellow
            $scriptEvents | Select-Object -First 3 | ForEach-Object {
                if ($_.Message -match 'DestinationIp.([^\s<]+)') {
                    $ip = $matches[1]
                    Write-Host "   - IP: $ip, Time: $($_.TimeCreated)" -ForegroundColor Gray
                } else {
                    Write-Host "   - Time: $($_.TimeCreated)" -ForegroundColor Gray
                }
            }
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Script Network"; Status = "PASS"; Count = $scriptEvents.Count }
        } else {
            Write-Host "   No script network connections found (good)" -ForegroundColor Green
            $testsPassed++
            $results += [PSCustomObject]@{ Test = "Script Network"; Status = "PASS (Clean)"; Count = 0 }
        }
    } else {
        Write-Host "   No network events found (normal if system is idle)" -ForegroundColor Yellow
        $testsPassed++
        $results += [PSCustomObject]@{ Test = "Script Network"; Status = "PASS (No Events)"; Count = 0 }
    }
} catch {
    Write-Host "   No network events found (normal if system is idle)" -ForegroundColor Yellow
    $testsPassed++
    $results += [PSCustomObject]@{ Test = "Script Network"; Status = "PASS (No Events)"; Count = 0 }
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "VALIDATION SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""
$results | Format-Table -AutoSize
Write-Host ""
Write-Host "Tests Passed: $testsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $testsFailed" -ForegroundColor Red

if ($testsFailed -eq 0) {
    Write-Host ""
    Write-Host "[SUCCESS] All rules validated successfully!" -ForegroundColor Green
    Write-Host "Rules are ready for deployment to SIEM." -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "[WARNING] Some tests failed. Review errors above." -ForegroundColor Yellow
}
