# Changelog

All notable changes to the Zscaler GeoLocation Detection Script are documented here.

## [2.0.1] - 2026-03-20

### Security
- **Fixed command injection in macOS script** - `detect-zscaler-region.sh` Layer 3 config parsing passed `$CONFIG_FILE` path directly into inline Python via string interpolation. A crafted file path containing single quotes could inject arbitrary Python code. Now passes paths and IPs as `sys.argv` arguments instead of string interpolation.
- **Added IP address format validation** - Both Windows and macOS scripts now validate `-TestIP`/`--test-ip` input against `^\d+\.\d+\.\d+\.\d+$` before processing.

### Added
- **`generate-china-ip-list.py`** - Standalone script to regenerate `cn-ipv4.txt` without depending on the zbrain site or any database. Fetches ASN data directly from `bgp.tools/asns.csv`. Only requires `pip install httpx`; MaxMind GeoIP is optional (`--maxmind-db`).
- **ZDX Remediation deployment guide** - README now includes requirements, setup steps, and JSON output format for ZDX script deployment (requires Advanced Plus subscription).
- **JSON output** - Windows script now outputs structured JSON to stdout for ZDX Remediation result capture and automation tools.
- **Function documentation** - Added comment-based help (`.SYNOPSIS`/`.DESCRIPTION`) to `Write-RegistryResult` and `Get-PSEGatewayIP`.

### Fixed
- **PowerShell 5.1 compatibility** - Replaced `??` null-coalescing operator (PowerShell 7+ only) with `if/else` conditional in `Write-RegistryResult`. The script header claims PS 5.1+ compatibility; this fix ensures it.

## [2.0.0] - 2026-03-20

### Changed — Complete Architecture Redesign

**Replaced 5-method geolocation with PSE-based detection.** The v1.x script attempted
independent geolocation (GPS, WiFi BSSID, cellular MCC, IP geo API, timezone) which
proved fragile: WiFi failed on non-English locales, IP geo was useless behind the GFW,
cellular isn't available on most corporate laptops, and GPS requires Windows Location
Service permissions.

**v2.0 leverages Zscaler's own datacenter selection.** ZCC already routes users to the
nearest PSE based on latency. If the connected PSE is in China, the user is in China.
The script just reads the answer Zscaler already computed.

### Added
- **Three-layer IP matching:**
  - Layer 1: Known Zscaler China Public PSE CIDRs (6 ranges from config.zscaler.com CENR API)
  - Layer 2: Comprehensive China IP list (`cn-ipv4.txt`, 2,246 CIDRs from RIR+GeoIP+BGP) — catches Private Service Edges and China Premium (CBC/Zenlayer) infrastructure
  - Layer 3: Customer-configured JSON file (`pse-config.json`) for Private PSE edge cases
- **macOS support:** `detect-zscaler-region.sh` — bash script with identical detection logic
  - launchd periodic job installation (`--install`)
  - JSON result output to `/Library/Application Support/Zscaler/GeoLocation/region.json`
- **Cross-platform test suites:** `Test-RegionDetection.ps1` (Windows) and `test-region-detection.sh` (macOS/Linux) with 27 test cases covering all layers and edge cases
- **Gateway detection methods:**
  - Primary: Parse `ip.zscaler.com` response for PSE egress IP
  - Fallback: Inspect `ZSATunnel` process TCP connections (Windows: `Get-NetTCPConnection`, macOS: `lsof`)
- **Config file support:** `pse-config.sample.json` template for customer Private PSE ranges
- **Audit trail:** PreviousRegion tracking for region change detection
- **Confidence levels:** HIGH (confirmed through Zscaler), MEDIUM, TEST, NONE

### Removed
- GPS detection (Windows Location Services API)
- WiFi BSSID triangulation (Mozilla Location Service)
- Cellular tower geolocation (MCC/MNC extraction)
- IP geolocation APIs (ip-api.com, ipinfo.io)
- Timezone heuristic fallback
- Reverse geocoding (BigDataCloud API)
- WMI permanent event subscription
- Self-signed code signing
- Windows Event Log integration
- 10MB log rotation

### Files
- `Detect-ZscalerRegion.ps1` — Windows detection (replaces Setup-ZscalerGeoLocation.ps1)
- `detect-zscaler-region.sh` — macOS detection (NEW)
- `Test-RegionDetection.ps1` — Windows test harness (replaces Test-GeoDetection.ps1)
- `test-region-detection.sh` — macOS/Linux test harness (NEW)
- `cn-ipv4.txt` — China IP CIDR list for Layer 2 matching (NEW)
- `pse-config.sample.json` — Sample customer config for Layer 3 (NEW)

### Why
| Aspect | v1.x (5-method geolocation) | v2.0 (PSE-based) |
|--------|----------------------------|-------------------|
| External APIs | 3 (ip-api, Mozilla, BigDataCloud) | 0-1 (ip.zscaler.com) |
| Failure modes | GPS timeout, WiFi locale, cell unavailable | ZCC not connected (clear signal) |
| China accuracy | Poor (IP geo through GFW, WiFi DB sparse) | Perfect (Zscaler already solved it) |
| Dependencies | .NET Location API, WiFi adapter, admin rights | Only ZCC |
| Lines of code | ~1,900 | ~350 per platform |
| Platforms | Windows only | Windows + macOS |

## [1.0.1] - 2026-03-09

### Fixed
- **Parse errors on PowerShell 5.1** - Unicode em dash characters (U+2014) caused cascading parse failures when scripts were saved as UTF-8 without BOM. Windows-1252 encoding interprets the 3-byte UTF-8 sequence as broken characters including a stray double-quote. Replaced all em dashes with ASCII hyphens in both scripts.
- **IP Geolocation confidence was 'High' - changed to 'Medium'** - IP-based geolocation is city-level accuracy at best and returns the VPN/proxy exit point, not the user's physical location. This is especially important for Zscaler users who are always behind a proxy. RawSource field now explicitly notes VPN/proxy caveat.
- **GPS GeoCoordinateWatcher resource leak** - The COM watcher object was not disposed if an unexpected exception occurred between `.Start()` and the if/else branches. Wrapped in try/finally to guarantee cleanup.
- **WiFi BSSID multi-match bug** - On machines with multiple WiFi adapters, the BSSID regex could return an array instead of a single string, sending malformed JSON to the Mozilla Location Service. Fixed by taking only the first match via `Select-Object -First 1`.
- **Banner version constant** - `$Script:VERSION` was still '1.0.0', not matching the script metadata. Fixed to '1.0.1'.

### Added
- Debug logging in Test-GeoDetection.ps1: writes `Test-GeoDetection-Debug.log` alongside the script with full environment info (PS version, OS, admin status, execution policy, culture), per-method timing and errors, network adapter diagnostics, and Windows Location Service status. If file write fails, prints log to console for copy/paste.

### Known Limitations
- Mozilla Location Service (MLS) may be deprecated - WiFi and Cell tower methods will silently fall back to the next method if MLS is unreachable.
- ip-api.com uses HTTP (not HTTPS) on its free tier - some corporate firewalls may block this. The script falls back to ipinfo.io (HTTPS) if ip-api.com fails.

## [1.0.0] - 2026-02-25

### Added
- 5 detection methods in priority order: GPS, WiFi AP, Cellular Tower, IP Geolocation, Timezone
- GPS detection via Windows Location Services API (System.Device.Location)
- WiFi access point triangulation via Mozilla Location Service
- Cellular tower geolocation via MCC/MNC extraction from mobile broadband interfaces
- IP geolocation via ip-api.com with ipinfo.io fallback (no API keys needed)
- Timezone-to-country heuristic fallback (always returns a result)
- MCC-to-country lookup table covering 60+ countries (ITU E.212)
- Reverse geocoding via BigDataCloud free API
- Registry output to HKLM:\SOFTWARE\Zscaler\GeoLocation\ (CountryCode, City, Region, Lat/Lon, Confidence, etc.)
- Windows Scheduled Task with configurable interval (default 60 min)
- Network change event trigger via WMI permanent event subscription (optional)
- Self-signed code signing for testing (-Sign parameter)
- Windows Event Log integration (source: ZscalerGeoLocation, Application log)
- Local log file with 10MB auto-rotation
- Complete uninstall support (-Uninstall removes all artifacts)
- Interactive guided installation (-Install)
- Silent mode for mass deployment (-Silent)
- Status dashboard (-Status)
- Lightweight manual test script (Test-GeoDetection.ps1)
