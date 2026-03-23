<#
.SYNOPSIS
    Test harness for Detect-ZscalerRegion.ps1.
    Validates CIDR matching, Layer 1/2/3 detection, and end-to-end pipeline.

.DESCRIPTION
    Runs without admin rights or ZCC installed. Tests:
      1. CIDR matching arithmetic (known IPs -> expected results)
      2. Layer 1: Zscaler Public PSE detection (6 CIDRs)
      3. Layer 2: China IP list detection (Private PSE / China Premium)
      4. Layer 3: Custom config detection
      5. Non-China IPs (should NOT match)
      6. Edge cases (boundary IPs, malformed input)
      7. End-to-end dry run (full pipeline with -TestIP)

.EXAMPLE
    .\Test-RegionDetection.ps1

.EXAMPLE
    .\Test-RegionDetection.ps1 -Verbose

.NOTES
    Version: 2.0.0
    No admin rights required. No registry writes. No ZCC required.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$detectScript = Join-Path $scriptDir "Detect-ZscalerRegion.ps1"

$passed = 0
$failed = 0
$total = 0

function Test-Case {
    param(
        [string]$Name,
        [string]$TestIP,
        [string]$ExpectedRegion,
        [string]$ExpectedLayer = "",
        [string]$ConfigFile = ""
    )
    $script:total++

    $params = @{
        TestIP  = $TestIP
        DryRun  = $true
        Force   = $true
    }
    if ($ConfigFile) { $params.ConfigFile = $ConfigFile }

    try {
        # Capture stream 1 (Write-Output = JSON) while suppressing stream 6 (Write-Host)
        $jsonOutput = & $detectScript @params 6>$null 3>$null 2>$null

        # Parse the JSON result — the script outputs a single JSON line via Write-Output
        $parsed = $null
        if ($jsonOutput) {
            # $jsonOutput may be a single string or array; take the last non-empty line
            $jsonLine = ($jsonOutput | Where-Object { $_ -and $_.ToString().Trim().StartsWith("{") }) |
                Select-Object -Last 1
            if ($jsonLine) {
                $parsed = $jsonLine | ConvertFrom-Json
            }
        }

        if ($parsed) {
            $detectedRegion = $parsed.region
            $detectedLayer = $parsed.matchLayer
        }
        else {
            $detectedRegion = "PARSE_ERROR"
            $detectedLayer = ""
        }

        $regionMatch = ($detectedRegion -eq $ExpectedRegion)
        $layerMatch = (-not $ExpectedLayer) -or ($detectedLayer -eq $ExpectedLayer)

        if ($regionMatch -and $layerMatch) {
            Write-Host "  PASS  $Name" -ForegroundColor Green
            Write-Host "        IP=$TestIP -> Region=$detectedRegion Layer=$detectedLayer" -ForegroundColor DarkGray
            $script:passed++
        }
        else {
            Write-Host "  FAIL  $Name" -ForegroundColor Red
            Write-Host "        IP=$TestIP" -ForegroundColor Yellow
            Write-Host "        Expected: Region=$ExpectedRegion Layer=$ExpectedLayer" -ForegroundColor Yellow
            Write-Host "        Got:      Region=$detectedRegion Layer=$detectedLayer" -ForegroundColor Red
            $script:failed++
        }
    }
    catch {
        Write-Host "  FAIL  $Name (EXCEPTION)" -ForegroundColor Red
        Write-Host "        $_" -ForegroundColor Red
        $script:failed++
    }
}

# === Header ===
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Zscaler Region Detection Test Suite v2.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Verify detect script exists
if (-not (Test-Path $detectScript)) {
    Write-Host "ERROR: Detect script not found at $detectScript" -ForegroundColor Red
    exit 1
}

# === Test Group 1: Layer 1 — Zscaler Public PSE CIDRs ===
Write-Host "--- Layer 1: Zscaler China Public PSE ---" -ForegroundColor White

Test-Case -Name "Beijing PSE (bjs1)" -TestIP "211.144.19.50" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Beijing PSE (bjs1) - first IP" -TestIP "211.144.19.1" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Beijing PSE (bjs1) - last IP" -TestIP "211.144.19.254" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Beijing III PSE (bjs3)" -TestIP "220.243.154.100" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Beijing III PSE (bjs3) - /23 upper" -TestIP "220.243.155.200" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Shanghai PSE (sha1)" -TestIP "58.220.95.8" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Shanghai II PSE (sha2) - range 1" -TestIP "116.196.192.50" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Shanghai II PSE (sha2) - range 2" -TestIP "140.210.152.12" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Shanghai II PSE (sha2) - /23 upper" -TestIP "140.210.153.200" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Tianjin PSE (tsn1)" -TestIP "221.122.91.32" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"

# === Test Group 2: Layer 2 — China IP List ===
Write-Host ""
Write-Host "--- Layer 2: China IP List (Private PSE / China Premium) ---" -ForegroundColor White

# These are real China IPs that are NOT Zscaler PSEs — they'd be Private PSE or CBC IPs
Test-Case -Name "China Telecom range" -TestIP "1.12.0.1" -ExpectedRegion "CN" -ExpectedLayer "L2_ChinaIPList"
Test-Case -Name "China Mobile range" -TestIP "36.128.0.1" -ExpectedRegion "CN" -ExpectedLayer "L2_ChinaIPList"
Test-Case -Name "China IP (1.80.x)" -TestIP "1.80.0.1" -ExpectedRegion "CN" -ExpectedLayer "L2_ChinaIPList"

# === Test Group 3: Non-China IPs ===
Write-Host ""
Write-Host "--- Non-China IPs (should be NON-CN) ---" -ForegroundColor White

Test-Case -Name "Zscaler US PSE" -TestIP "104.129.192.1" -ExpectedRegion "NON-CN"
Test-Case -Name "Google DNS" -TestIP "8.8.8.8" -ExpectedRegion "NON-CN"
Test-Case -Name "Cloudflare" -TestIP "1.1.1.1" -ExpectedRegion "NON-CN"
Test-Case -Name "AWS US-East" -TestIP "3.5.0.1" -ExpectedRegion "NON-CN"
Test-Case -Name "Private RFC1918" -TestIP "192.168.1.1" -ExpectedRegion "NON-CN"
Test-Case -Name "Loopback" -TestIP "127.0.0.1" -ExpectedRegion "NON-CN"

# === Test Group 4: Layer 3 — Custom Config ===
Write-Host ""
Write-Host "--- Layer 3: Custom Config (Private PSE ranges) ---" -ForegroundColor White

# Create a temporary config file
$tempConfig = Join-Path $env:TEMP "test-pse-config.json"
@'
{
    "china_ranges": [
        { "cidr": "10.100.0.0/24", "label": "Test Private PSE Shanghai" },
        { "cidr": "172.16.50.0/24", "label": "Test ZPA PSE Beijing" }
    ]
}
'@ | Set-Content $tempConfig -Encoding UTF8

Test-Case -Name "Custom Private PSE range" -TestIP "10.100.0.50" -ExpectedRegion "CN" -ExpectedLayer "L3_CustomConfig" -ConfigFile $tempConfig
Test-Case -Name "Custom ZPA PSE range" -TestIP "172.16.50.100" -ExpectedRegion "CN" -ExpectedLayer "L3_CustomConfig" -ConfigFile $tempConfig
Test-Case -Name "Custom range miss" -TestIP "10.100.1.50" -ExpectedRegion "NON-CN" -ConfigFile $tempConfig

# Cleanup
Remove-Item $tempConfig -ErrorAction SilentlyContinue

# === Test Group 5: Edge Cases ===
Write-Host ""
Write-Host "--- Edge Cases ---" -ForegroundColor White

Test-Case -Name "Beijing PSE network address" -TestIP "211.144.19.0" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
Test-Case -Name "Beijing PSE broadcast" -TestIP "211.144.19.255" -ExpectedRegion "CN" -ExpectedLayer "L1_PublicPSE"
# Adjacent IPs are still China IPs (Layer 2) — verify Layer changes from L1 to L2
Test-Case -Name "Adjacent above Beijing /24 (L2)" -TestIP "211.144.20.0" -ExpectedRegion "CN" -ExpectedLayer "L2_ChinaIPList"
Test-Case -Name "Adjacent below Beijing /24 (L2)" -TestIP "211.144.18.255" -ExpectedRegion "CN" -ExpectedLayer "L2_ChinaIPList"
Test-Case -Name "Non-China IP near PSE range" -TestIP "104.129.192.50" -ExpectedRegion "NON-CN"

# === Summary ===
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Results: $passed passed, $failed failed, $total total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($failed -gt 0) {
    Write-Host "Some tests FAILED. Review output above." -ForegroundColor Red
    exit 1
}
else {
    Write-Host "All tests PASSED." -ForegroundColor Green
    exit 0
}
