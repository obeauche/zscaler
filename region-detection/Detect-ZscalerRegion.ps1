<#
.SYNOPSIS
    Detects whether a device is connected to a China-based Zscaler service edge
    by checking the gateway IP against known China infrastructure.

.DESCRIPTION
    Leverages Zscaler's own datacenter selection instead of independent geolocation.
    ZCC routes users to the nearest PSE based on latency — if the connected PSE is
    in China, the user is in China.

    Three-layer IP matching:
      Layer 1: Known Zscaler China Public PSE CIDRs (6 ranges from config.zscaler.com)
      Layer 2: Comprehensive China IP list (covers Private PSEs + China Premium/CBC/Zenlayer)
      Layer 3: Customer-configured custom ranges (for edge cases)

    This handles all deployment scenarios:
      - Zscaler Public PSE in China (Beijing, Shanghai, Tianjin)
      - ZIA/ZPA Private Service Edges deployed in China
      - China Premium (CBC/Zenlayer partner infrastructure)

    Detection flow:
      1. Verify ZCC is in TUNNEL_FORWARDING state
      2. Determine gateway IP (ip.zscaler.com or tunnel process TCP connections)
      3. Match gateway IP through three layers
      4. Write result to registry for ZCC device posture consumption

.PARAMETER TestIP
    Simulate detection with a specific IP (for testing without ZCC).

.PARAMETER DryRun
    Run detection without writing to registry.

.PARAMETER Force
    Skip ZCC tunnel state check.

.PARAMETER ChinaIPList
    Path to China IP CIDR list file (one CIDR per line, # comments allowed).
    Used for Layer 2 matching (Private PSEs, China Premium).
    Defaults to cn-ipv4.txt in the script directory.

.PARAMETER ConfigFile
    JSON config file with customer-specific Private PSE ranges.

.PARAMETER Install
    Install as a Windows scheduled task (every 30 min + on logon).

.PARAMETER LogPath
    Path to log file.

.PARAMETER RegistryPath
    Registry path for results.

.EXAMPLE
    .\Detect-ZscalerRegion.ps1

.EXAMPLE
    .\Detect-ZscalerRegion.ps1 -TestIP "211.144.19.50" -DryRun

.EXAMPLE
    # Test with a China Premium (CBC) IP
    .\Detect-ZscalerRegion.ps1 -TestIP "103.40.100.5" -DryRun

.EXAMPLE
    # With custom Private PSE config
    .\Detect-ZscalerRegion.ps1 -ConfigFile ".\pse-config.json"

.NOTES
    Version:  2.0.1
    Author:   Olivier Beauchemin
    Requires: PowerShell 5.1+, Administrator (for registry write)
#>

[CmdletBinding()]
param(
    [string]$TestIP,
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Install,
    [string]$ChinaIPList,
    [string]$ConfigFile,
    [string]$LogPath = "$env:ProgramData\Zscaler\GeoLocation\detection.log",
    [string]$RegistryPath = "HKLM:\SOFTWARE\Zscaler\GeoLocation"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:Version = "2.0.1"

# --- Default China IP list path: same directory as script ---
if (-not $ChinaIPList) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $ChinaIPList = Join-Path $scriptDir "cn-ipv4.txt"
}

#region --- Configuration ---

# Layer 1: Zscaler China Public PSE IPv4 CIDRs
# Source: config.zscaler.com/api/{cloud}/cenr/json (same across all ZIA clouds)
# Updated: 2026-03-20
$script:ZSCALER_CHINA_PSE = @(
    @{ CIDR = "211.144.19.0/24";   Location = "Beijing";      Code = "bjs1" }
    @{ CIDR = "220.243.154.0/23";  Location = "Beijing III";   Code = "bjs3" }
    @{ CIDR = "58.220.95.0/24";    Location = "Shanghai";      Code = "sha1" }
    @{ CIDR = "116.196.192.0/24";  Location = "Shanghai II";   Code = "sha2" }
    @{ CIDR = "140.210.152.0/23";  Location = "Shanghai II";   Code = "sha2" }
    @{ CIDR = "221.122.91.0/24";   Location = "Tianjin";       Code = "tsn1" }
)

# ZCC state
$script:ZCC_STATE_PATH = "HKCU:\Software\Zscaler\App"
$script:ZCC_TUNNEL_PROCESS = "ZSATunnel"
$script:IP_CHECK_URL = "https://ip.zscaler.com/"
$script:HTTP_TIMEOUT = 10

#endregion

#region --- Logging ---

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "DEBUG" { if ($VerbosePreference -eq "Continue") { Write-Host $entry -ForegroundColor Gray } }
        default { Write-Host $entry }
    }

    try {
        $logDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
    }
    catch {}
}

#endregion

#region --- CIDR Matching ---

function ConvertTo-UInt32 {
    param([string]$IP)
    $octets = $IP.Split(".")
    if ($octets.Count -ne 4) { throw "Invalid IPv4 address: $IP" }
    [uint32]$result = 0
    for ($i = 0; $i -lt 4; $i++) {
        $octet = [int]$octets[$i]
        if ($octet -lt 0 -or $octet -gt 255) { throw "Invalid octet in IP: $IP" }
        $result = ($result -shl 8) -bor $octet
    }
    return $result
}

function Test-IPInCIDR {
    param([string]$IP, [string]$CIDR)
    try {
        $parts = $CIDR.Split("/")
        $networkIP = $parts[0]
        $prefixLen = [int]$parts[1]

        $ipUint = ConvertTo-UInt32 $IP
        $netUint = ConvertTo-UInt32 $networkIP

        if ($prefixLen -eq 0) { return $true }
        if ($prefixLen -eq 32) { return $ipUint -eq $netUint }

        [uint32]$mask = [uint32]::MaxValue -shl (32 - $prefixLen)
        return ($ipUint -band $mask) -eq ($netUint -band $mask)
    }
    catch {
        return $false
    }
}

function Test-ChinaIP {
    <#
    .SYNOPSIS
        Three-layer China IP matching.
    .OUTPUTS
        Hashtable: IsChina, MatchLayer, Location, CIDR
    #>
    param([string]$GatewayIP)

    # --- Layer 1: Known Zscaler China Public PSE CIDRs (fast, specific) ---
    foreach ($entry in $script:ZSCALER_CHINA_PSE) {
        if (Test-IPInCIDR -IP $GatewayIP -CIDR $entry.CIDR) {
            Write-Log "Layer 1 match: $GatewayIP in $($entry.CIDR) ($($entry.Location))" -Level DEBUG
            return @{
                IsChina    = $true
                MatchLayer = "L1_PublicPSE"
                Location   = $entry.Location
                CIDR       = $entry.CIDR
                Detail     = "Zscaler Public PSE: $($entry.Code)"
            }
        }
    }

    # --- Layer 2: Comprehensive China IP list (Private PSE, China Premium) ---
    if (Test-Path $ChinaIPList) {
        $cidrs = Get-Content $ChinaIPList -ErrorAction SilentlyContinue |
            Where-Object { $_ -and -not $_.StartsWith("#") } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+/\d+" }

        Write-Log "Layer 2: Checking against $($cidrs.Count) China CIDRs" -Level DEBUG

        foreach ($cidr in $cidrs) {
            if (Test-IPInCIDR -IP $GatewayIP -CIDR $cidr) {
                Write-Log "Layer 2 match: $GatewayIP in $cidr" -Level DEBUG
                return @{
                    IsChina    = $true
                    MatchLayer = "L2_ChinaIPList"
                    Location   = "China (IP geolocation)"
                    CIDR       = $cidr
                    Detail     = "China IP list match (Private PSE / China Premium)"
                }
            }
        }
    }
    else {
        Write-Log "Layer 2 skipped: China IP list not found at $ChinaIPList" -Level WARN
    }

    # --- Layer 3: Custom config file (customer Private PSE ranges) ---
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        try {
            $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json

            if ($config.china_ranges) {
                foreach ($entry in $config.china_ranges) {
                    if (Test-IPInCIDR -IP $GatewayIP -CIDR $entry.cidr) {
                        Write-Log "Layer 3 match: $GatewayIP in $($entry.cidr) ($($entry.label))" -Level DEBUG
                        return @{
                            IsChina    = $true
                            MatchLayer = "L3_CustomConfig"
                            Location   = $entry.label
                            CIDR       = $entry.cidr
                            Detail     = "Custom config: $($entry.label)"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "Layer 3 config parse error: $_" -Level WARN
        }
    }

    return @{
        IsChina    = $false
        MatchLayer = "None"
        Location   = $null
        CIDR       = $null
        Detail     = $null
    }
}

#endregion

#region --- ZCC State Detection ---

function Test-ZCCConnected {
    $result = @{
        Connected    = $false
        ZWSState     = "UNKNOWN"
        ZPAState     = "UNKNOWN"
        NetworkState = "UNKNOWN"
    }

    try {
        if (-not (Test-Path $script:ZCC_STATE_PATH)) {
            Write-Log "ZCC registry path not found" -Level WARN
            return $result
        }

        $props = Get-ItemProperty -Path $script:ZCC_STATE_PATH -ErrorAction SilentlyContinue
        if ($props.ZWS_State) { $result.ZWSState = $props.ZWS_State }
        if ($props.ZPA_State) { $result.ZPAState = $props.ZPA_State }
        if ($props.ZNW_State) { $result.NetworkState = $props.ZNW_State }

        $result.Connected = ($result.ZWSState -eq "TUNNEL_FORWARDING")
    }
    catch {
        Write-Log "Failed to read ZCC state: $_" -Level ERROR
    }

    return $result
}

#endregion

#region --- Gateway IP Detection ---

function Get-GatewayFromIpZscaler {
    try {
        Write-Log "Querying ip.zscaler.com..." -Level DEBUG

        $response = Invoke-WebRequest -Uri $script:IP_CHECK_URL `
            -UseBasicParsing -TimeoutSec $script:HTTP_TIMEOUT -ErrorAction Stop
        $body = $response.Content

        $throughZscaler = $body -match "You are accessing the Internet via Zscaler"

        if ($body -match "from the IP address\s*(?:<[^>]+>\s*)*([\d\.]+)") {
            $ip = $Matches[1]
            Write-Log "ip.zscaler.com: $ip (through Zscaler: $throughZscaler)" -Level INFO
            return @{ IP = $ip; ThroughZscaler = $throughZscaler; Method = "ip.zscaler.com" }
        }

        Write-Log "Could not parse IP from ip.zscaler.com" -Level WARN
        return $null
    }
    catch {
        Write-Log "ip.zscaler.com failed: $_" -Level WARN
        return $null
    }
}

function Get-GatewayFromTunnelProcess {
    try {
        $procs = Get-Process -Name $script:ZCC_TUNNEL_PROCESS -ErrorAction SilentlyContinue
        if (-not $procs) {
            Write-Log "ZSATunnel process not found" -Level WARN
            return $null
        }

        $pids = $procs | ForEach-Object { $_.Id }

        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object {
                $_.OwningProcess -in $pids -and
                $_.RemoteAddress -ne "127.0.0.1" -and
                $_.RemoteAddress -ne "::1"
            }

        if (-not $connections) {
            Write-Log "No TCP connections for ZSATunnel" -Level WARN
            return $null
        }

        $conn = $connections |
            Where-Object { $_.RemotePort -in @(443, 80) } |
            Select-Object -First 1

        if (-not $conn) { $conn = $connections | Select-Object -First 1 }

        $ip = $conn.RemoteAddress
        Write-Log "ZSATunnel connected to: ${ip}:$($conn.RemotePort)" -Level INFO
        return @{ IP = $ip; ThroughZscaler = $true; Method = "ZSATunnel TCP" }
    }
    catch {
        Write-Log "Tunnel inspection failed: $_" -Level WARN
        return $null
    }
}

function Get-PSEGatewayIP {
    <#
    .SYNOPSIS
        Determine the PSE gateway IP using available methods.
    .DESCRIPTION
        Tries ip.zscaler.com first (preferred — confirms Zscaler routing),
        falls back to inspecting ZSATunnel process TCP connections.
    #>
    $result = Get-GatewayFromIpZscaler
    if ($result -and $result.IP) { return $result }

    $result = Get-GatewayFromTunnelProcess
    if ($result -and $result.IP) { return $result }

    Write-Log "All gateway detection methods failed" -Level ERROR
    return $null
}

#endregion

#region --- Registry Output ---

function Write-RegistryResult {
    <#
    .SYNOPSIS
        Write detection result to Windows registry for ZCC Device Posture consumption.
    .DESCRIPTION
        Creates/updates HKLM:\SOFTWARE\Zscaler\GeoLocation with region detection results.
        Tracks previous region for audit trail. Skips write in DryRun mode.
    #>
    param(
        [string]$Region,
        [string]$GatewayIP,
        [string]$PSELocation,
        [string]$MatchLayer,
        [string]$DetectionMethod,
        [string]$Confidence
    )

    if ($DryRun) {
        Write-Log "[DRY RUN] Would write: Region=$Region, IP=$GatewayIP, Location=$PSELocation, Layer=$MatchLayer" -Level INFO
        return
    }

    try {
        if (-not (Test-Path $RegistryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        }

        $previousRegion = $null
        try {
            $previousRegion = (Get-ItemProperty -Path $RegistryPath -Name "CountryCode" -ErrorAction SilentlyContinue).CountryCode
        } catch {}

        $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
        Set-ItemProperty -Path $RegistryPath -Name "CountryCode"      -Value $Region            -Type String
        Set-ItemProperty -Path $RegistryPath -Name "GatewayIP"        -Value $GatewayIP         -Type String
        $locationValue = if ($PSELocation) { $PSELocation } else { "Unknown" }
        Set-ItemProperty -Path $RegistryPath -Name "PSELocation"      -Value $locationValue -Type String
        Set-ItemProperty -Path $RegistryPath -Name "MatchLayer"       -Value $MatchLayer        -Type String
        Set-ItemProperty -Path $RegistryPath -Name "DetectionMethod"  -Value $DetectionMethod   -Type String
        Set-ItemProperty -Path $RegistryPath -Name "Confidence"       -Value $Confidence        -Type String
        Set-ItemProperty -Path $RegistryPath -Name "LastDetection"    -Value $timestamp         -Type String
        Set-ItemProperty -Path $RegistryPath -Name "ScriptVersion"    -Value $script:Version    -Type String

        if ($previousRegion -and $previousRegion -ne $Region) {
            Set-ItemProperty -Path $RegistryPath -Name "PreviousRegion" -Value $previousRegion -Type String
            Set-ItemProperty -Path $RegistryPath -Name "RegionChanged"  -Value $timestamp      -Type String
            Write-Log "Region CHANGED: $previousRegion -> $Region" -Level WARN
        }

        Write-Log "Registry updated: CountryCode=$Region" -Level INFO
    }
    catch {
        Write-Log "Registry write failed: $_" -Level ERROR
        throw
    }
}

#endregion

#region --- Scheduled Task ---

function Install-DetectionTask {
    param([int]$IntervalMinutes = 30)

    $taskName = "Zscaler Region Detection"
    $scriptPath = $PSCommandPath

    if (-not $scriptPath) {
        Write-Log "Cannot install: script path unknown" -Level ERROR
        return $false
    }

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$scriptPath`""

        $triggerSchedule = New-ScheduledTaskTrigger -Once -At (Get-Date) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

        $triggerLogon = New-ScheduledTaskTrigger -AtLogOn

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

        Register-ScheduledTask `
            -TaskName $taskName -Action $action `
            -Trigger @($triggerSchedule, $triggerLogon) `
            -Principal $principal -Settings $settings `
            -Description "Zscaler PSE region detection v$($script:Version)" `
            -Force | Out-Null

        Write-Log "Scheduled task '$taskName' installed (every ${IntervalMinutes}m + logon)" -Level INFO
        return $true
    }
    catch {
        Write-Log "Task install failed: $_" -Level ERROR
        return $false
    }
}

#endregion

#region --- Main ---

function Invoke-Detection {

    Write-Log "=== Zscaler Region Detection v$($script:Version) ===" -Level INFO
    Write-Log "Mode: $(if ($TestIP) {'TestIP'} elseif ($DryRun) {'DryRun'} else {'Live'})" -Level INFO

    # Handle --install
    if ($Install) {
        Install-DetectionTask
        return @{ Success = $true; Action = "Installed scheduled task" }
    }

    # --- Phase 1: Get gateway IP ---
    if ($TestIP) {
        # Validate IP address format
        if ($TestIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            Write-Log "Invalid IP address format: $TestIP" -Level ERROR
            return @{ Success = $false; Region = "UNKNOWN"; Reason = "Invalid IP format" }
        }
        Write-Log "Test IP: $TestIP" -Level INFO
        $gatewayResult = @{ IP = $TestIP; ThroughZscaler = $false; Method = "TestIP" }
    }
    else {
        if (-not $Force) {
            $zccState = Test-ZCCConnected
            Write-Log "ZCC: ZWS=$($zccState.ZWSState), ZPA=$($zccState.ZPAState), Net=$($zccState.NetworkState)" -Level INFO

            if (-not $zccState.Connected) {
                Write-Log "ZCC not in TUNNEL_FORWARDING ($($zccState.ZWSState))" -Level WARN
                Write-RegistryResult -Region "UNKNOWN" -GatewayIP "N/A" -PSELocation "N/A" `
                    -MatchLayer "N/A" -DetectionMethod "ZCC not connected" -Confidence "NONE"
                return @{ Success = $false; Region = "UNKNOWN"; Reason = "ZCC not tunneling" }
            }
        }

        $gatewayResult = Get-PSEGatewayIP
        if (-not $gatewayResult) {
            return @{ Success = $false; Region = "UNKNOWN"; Reason = "Gateway detection failed" }
        }
    }

    $gatewayIP = $gatewayResult.IP
    $method = $gatewayResult.Method
    $throughZscaler = $gatewayResult.ThroughZscaler

    $confidence = switch ($true) {
        ($method -eq "TestIP")                                      { "TEST" }
        ($throughZscaler -and $method -eq "ip.zscaler.com")         { "HIGH" }
        ($method -eq "ZSATunnel TCP")                               { "HIGH" }
        default                                                     { "MEDIUM" }
    }

    # --- Phase 2: Three-layer China matching ---
    $match = Test-ChinaIP -GatewayIP $gatewayIP

    $region = if ($match.IsChina) { "CN" } else { "NON-CN" }

    if ($match.IsChina) {
        Write-Log "CHINA DETECTED [$($match.MatchLayer)]: $gatewayIP -> $($match.Location) ($($match.CIDR))" -Level WARN
        Write-Log "Detail: $($match.Detail)" -Level INFO
    }
    else {
        Write-Log "Non-China: $gatewayIP (checked all layers)" -Level INFO
    }

    # --- Phase 3: Write result ---
    Write-RegistryResult `
        -Region $region -GatewayIP $gatewayIP `
        -PSELocation $match.Location -MatchLayer $match.MatchLayer `
        -DetectionMethod $method -Confidence $confidence

    $result = @{
        Success        = $true
        Region         = $region
        GatewayIP      = $gatewayIP
        PSELocation    = $match.Location
        MatchLayer     = $match.MatchLayer
        CIDR           = $match.CIDR
        Detail         = $match.Detail
        Method         = $method
        Confidence     = $confidence
        ThroughZscaler = $throughZscaler
    }

    Write-Log "Done: Region=$region, IP=$gatewayIP, Layer=$($match.MatchLayer), Confidence=$confidence" -Level INFO
    return $result
}

$result = Invoke-Detection

# Output JSON for structured consumption (ZDX Remediation, automation tools)
$jsonResult = @{
    success        = $result.Success
    region         = $result.Region
    gatewayIP      = $result.GatewayIP
    pseLocation    = $result.PSELocation
    matchLayer     = $result.MatchLayer
    confidence     = $result.Confidence
    method         = $result.Method
    scriptVersion  = $script:Version
    timestamp      = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssK")
} | ConvertTo-Json -Compress
Write-Output $jsonResult

#endregion
