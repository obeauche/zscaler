# Zscaler Region Detection

Detects whether a device is connected to a China-based Zscaler service edge and writes the result for ZCC Device Posture consumption. Enables country-specific ZIA SSL Inspection Policies — for example, using a China-compliant CA certificate when a user is physically in China.

**Platforms:** Windows (PowerShell 5.1+) and macOS (bash)

## How It Works

Instead of attempting independent geolocation (GPS, WiFi, cellular, IP geo APIs), this script leverages **Zscaler's own datacenter selection**. ZCC already routes users to the nearest PSE based on latency — if the connected PSE is in China, the user is in China.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ENDPOINT (Windows / macOS)                       │
│                                                                     │
│  Detect-ZscalerRegion.ps1 / detect-zscaler-region.sh               │
│                                                                     │
│  1. Verify ZCC is tunneling (registry / process check)             │
│  2. Get gateway IP (ip.zscaler.com or tunnel process TCP)          │
│  3. Three-layer matching:                                           │
│     ├─ L1: Zscaler China Public PSE CIDRs (6 ranges)              │
│     ├─ L2: China IP list (Private PSE / China Premium)             │
│     └─ L3: Custom config (customer Private PSE ranges)             │
│  4. Write result                                                    │
│     ├─ Windows: HKLM:\SOFTWARE\Zscaler\GeoLocation\CountryCode    │
│     └─ macOS:   /Library/Application Support/Zscaler/.../region.json│
│                                               │                     │
│  ZCC Device Posture Profile ◄─────────────────┘                    │
│    Reads CountryCode / region.json                                  │
│    Evaluates posture rule (CountryCode == "CN")                     │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ZSCALER CLOUD                                    │
│                                                                     │
│  Device Trust Level → SSL Inspection Policy                        │
│    IF posture matches China                                         │
│    THEN Action = DECRYPT with Override CA = China-PKI-Cert         │
└─────────────────────────────────────────────────────────────────────┘
```

### Three-Layer Matching

| Layer | What | Covers | Speed |
|-------|------|--------|-------|
| **L1** | 6 Zscaler China Public PSE CIDRs | Beijing, Beijing III, Shanghai, Shanghai II, Tianjin | Instant (6 comparisons) |
| **L2** | China IP list (`cn-ipv4.txt`, 2,246 CIDRs) | ZIA/ZPA Private Service Edges in China, China Premium (CBC/Zenlayer) | Fast (~2K comparisons) |
| **L3** | Custom JSON config (`pse-config.json`) | Customer-specific Private PSE ranges | Instant |

This handles all deployment scenarios:
- **Zscaler Public PSE** in China → Layer 1 match
- **ZIA/ZPA Private Service Edge** deployed in China → Layer 2 match (China IP)
- **China Premium** (CBC/Zenlayer partner infrastructure) → Layer 2 match (China IP)
- **Customer Private PSE** with unusual IPs → Layer 3 match (custom config)

### vs v1.x (5-Method Geolocation)

| Aspect | v1.x | v2.0 |
|--------|------|------|
| External APIs | 3 (ip-api, Mozilla, BigDataCloud) | 0-1 (ip.zscaler.com) |
| Failure modes | GPS timeout, WiFi locale, cell unavailable | ZCC not connected (clear signal) |
| China accuracy | Poor (IP geo behind GFW, WiFi DB sparse) | Deterministic (Zscaler already solved it) |
| Dependencies | .NET Location API, WiFi adapter | Only ZCC |
| Lines of code | ~1,900 | ~350 per platform |
| Platforms | Windows only | Windows + macOS |

## Quick Start

### Windows

```powershell
# Test with a known China PSE IP (no admin, no ZCC needed)
.\Detect-ZscalerRegion.ps1 -TestIP "211.144.19.50" -DryRun

# Live detection (requires ZCC connected + admin)
.\Detect-ZscalerRegion.ps1

# Install as scheduled task (every 30 min + on logon)
.\Detect-ZscalerRegion.ps1 -Install
```

### macOS

```bash
# Test with a known China PSE IP
./detect-zscaler-region.sh --test-ip 211.144.19.50 --dry-run

# Live detection (requires ZCC connected + sudo)
sudo ./detect-zscaler-region.sh

# Install as launchd job (every 30 min)
sudo ./detect-zscaler-region.sh --install
```

## Exit Codes (macOS)

| Code | Meaning | Description |
|------|---------|-------------|
| `0` | NON-CN | Not routing through a China Zscaler PSE |
| `1` | CN | China PSE detected (not an error -- use this to trigger policy) |
| `2` | UNKNOWN | ZCC not connected or gateway detection failed |
| `3` | Script error | Bad arguments, invalid IP format, missing permissions |

These structured exit codes allow automation scripts and MDM tools to branch on the result without parsing stdout:

```bash
./detect-zscaler-region.sh --dry-run --force --test-ip "$IP"
case $? in
    0) echo "Non-China" ;;
    1) echo "China -- apply China SSL policy" ;;
    2) echo "Unknown -- ZCC not connected" ;;
    3) echo "Script error" ;;
esac
```

## Files

| File | Purpose |
|------|---------|
| `Detect-ZscalerRegion.ps1` | Windows detection script |
| `detect-zscaler-region.sh` | macOS detection script |
| `Test-RegionDetection.ps1` | Windows test harness (27 tests) |
| `test-region-detection.sh` | macOS/Linux test harness (30 tests) |
| `cn-ipv4.txt` | China IP CIDR list for Layer 2 (2,246 ranges) |
| `pse-config.sample.json` | Sample config for customer Private PSE ranges |
| `generate-china-ip-list.py` | Standalone script to regenerate cn-ipv4.txt |
| `CHANGELOG.md` | Version history |

## Configuration

### Parameters

**Windows:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-TestIP` | — | Simulate with a specific IP (no ZCC needed) |
| `-DryRun` | off | Run without writing to registry |
| `-Force` | off | Skip ZCC tunnel state check |
| `-ChinaIPList` | `./cn-ipv4.txt` | Path to China IP CIDR list |
| `-ConfigFile` | — | JSON config with custom Private PSE ranges |
| `-Install` | off | Install as Windows scheduled task |
| `-LogPath` | `$env:ProgramData\Zscaler\GeoLocation\detection.log` | Log file |
| `-RegistryPath` | `HKLM:\SOFTWARE\Zscaler\GeoLocation` | Registry output path |

**macOS:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--test-ip IP` | — | Simulate with a specific IP |
| `--dry-run` | off | Run without writing result file |
| `--force` | off | Skip ZCC state check |
| `--china-ip-list F` | `./cn-ipv4.txt` | Path to China IP CIDR list |
| `--config FILE` | — | JSON config with custom ranges |
| `--install` | off | Install as launchd periodic job |
| `--verbose` | off | Debug logging |

### Custom Config for Private Service Edges

If your organization deploys **ZIA/ZPA Private Service Edges** in China or uses **China Premium** infrastructure with IPs not in the standard China IP list, create a `pse-config.json`:

```json
{
    "china_ranges": [
        { "cidr": "10.100.0.0/24", "label": "ZIA Private PSE - Shanghai Office" },
        { "cidr": "172.16.50.0/24", "label": "ZPA Private SE - Beijing DC" },
        { "cidr": "203.0.113.0/24", "label": "China Premium (CBC) - Custom" }
    ]
}
```

Then run with `--config pse-config.json` (macOS) or `-ConfigFile pse-config.json` (Windows).

### Output

**Windows Registry** (`HKLM:\SOFTWARE\Zscaler\GeoLocation`):

| Value | Type | Example | Description |
|-------|------|---------|-------------|
| `CountryCode` | REG_SZ | `CN` | Region code: `CN`, `NON-CN`, or `UNKNOWN` |
| `GatewayIP` | REG_SZ | `211.144.19.50` | PSE gateway IP detected |
| `PSELocation` | REG_SZ | `Beijing` | PSE datacenter location |
| `MatchLayer` | REG_SZ | `L1_PublicPSE` | Which matching layer triggered |
| `DetectionMethod` | REG_SZ | `ip.zscaler.com` | How gateway IP was obtained |
| `Confidence` | REG_SZ | `HIGH` | HIGH, MEDIUM, TEST, or NONE |
| `LastDetection` | REG_SZ | `2026-03-20T10:30:00+08:00` | ISO 8601 timestamp |
| `PreviousRegion` | REG_SZ | `NON-CN` | Previous value (audit trail) |

**macOS** (`/Library/Application Support/Zscaler/GeoLocation/region.json`):

```json
{
    "region": "CN",
    "gateway_ip": "211.144.19.50",
    "pse_location": "Beijing",
    "match_layer": "L1_PublicPSE",
    "detection_method": "ip.zscaler.com",
    "confidence": "HIGH",
    "last_detection": "2026-03-20T02:30:00Z",
    "script_version": "2.0.0",
    "previous_region": "NON-CN"
}
```

## Testing

### Run the Test Suite

```powershell
# Windows — 27 test cases, no admin/ZCC needed
.\Test-RegionDetection.ps1
```

```bash
# macOS/Linux — 30 test cases, no root/ZCC needed
./test-region-detection.sh
```

Tests cover:
- **Layer 1**: All 6 Zscaler China PSE CIDRs (10 tests with boundary IPs)
- **Layer 2**: China IP list matching for Private PSE / China Premium scenarios
- **Layer 3**: Custom config file matching
- **Non-China**: 6 known non-China IPs (Zscaler US, Google, Cloudflare, AWS, RFC1918, loopback)
- **Edge cases**: Network addresses, broadcasts, boundary crossings, layer transitions
- **Exit codes**: Validates 0 (NON-CN), 1 (CN), and 3 (invalid input) exit codes

### Manual Testing

```powershell
# Test specific IPs
.\Detect-ZscalerRegion.ps1 -TestIP "211.144.19.50" -DryRun    # Beijing PSE → CN
.\Detect-ZscalerRegion.ps1 -TestIP "58.220.95.8" -DryRun      # Shanghai PSE → CN
.\Detect-ZscalerRegion.ps1 -TestIP "1.12.0.1" -DryRun         # China Telecom (L2) → CN
.\Detect-ZscalerRegion.ps1 -TestIP "104.129.192.1" -DryRun    # Zscaler US → NON-CN
.\Detect-ZscalerRegion.ps1 -TestIP "8.8.8.8" -DryRun          # Google → NON-CN
```

### Updating the China IP List

The `cn-ipv4.txt` file contains 2,246 high-confidence China CIDRs generated from three-way intersection of RIR delegated stats, MaxMind GeoLite2, and BGP routing data.

**Regenerate with the standalone script (no external dependencies):**

```bash
# Install requirements
pip install httpx

# Generate with RIR + BGP validation (recommended)
python generate-china-ip-list.py

# For best accuracy, add MaxMind GeoLite2 (free license key)
# Sign up at https://www.maxmind.com/en/geolite2/signup
python generate-china-ip-list.py --maxmind-db /path/to/GeoLite2-City.mmdb

# Custom output path
python generate-china-ip-list.py --output /path/to/cn-ipv4.txt
```

The list should be regenerated quarterly or when significant China IP allocation changes occur.

## ZCC Integration Guide

### Step 1: Create a Device Posture Profile

1. In the **Zscaler Client Connector Portal**, go to **Administration > Device Posture**
2. Click **Add Device Posture**
3. Configure:
   - **Name:** `GeoLocation - China`
   - **Platform:** Windows (or macOS)
   - **Frequency:** `15` minutes
   - **Posture Type:** Registry Key (Windows) or File Check (macOS)
   - **Windows:** Path=`HKLM\SOFTWARE\Zscaler\GeoLocation`, Value=`CountryCode`, Match=`CN`
   - **macOS:** Check for file `/Library/Application Support/Zscaler/GeoLocation/region.json` containing `"region": "CN"`
4. Click **Save**

### Step 2: Create a ZIA Posture Profile

1. In the **ZCC Portal**, go to **Administration > ZIA Posture Profile**
2. Click **Add ZIA Posture**
3. Map:
   - **High Trust:** Default posture (domestic)
   - **Medium Trust:** `GeoLocation - China`
4. **Assign to App Profile** and **Save**

### Step 3: Create SSL Inspection Policy Rule

1. In **ZIA Admin Portal**, go to **Web Policy > SSL Inspection Policy**
2. Add rule:
   - **Name:** `China - Country-Specific Certificate`
   - **Device Trust Level:** Medium
   - **Action:** Decrypt with China-PKI CA certificate
3. Position **above** the default SSL inspection rule
4. **Activate Changes**

## ZDX Remediation Deployment (Alternative)

The detection script is compatible with **ZDX Remediation** (requires Advanced Plus subscription, Limited Availability). This lets you push the script to endpoints remotely instead of using Scheduled Tasks.

### Requirements

| Requirement | Detail |
|-------------|--------|
| **ZDX Subscription** | Advanced Plus |
| **ZCC Version** | 4.8+ (Windows) |
| **ZDX Module** | 4.6+ (Windows) |
| **Script Signing** | Code signing certificate required |
| **Execution Policy** | `AllSigned` on target devices |

### Setup

1. **Sign the script** with a code signing certificate:
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert |
       Where-Object { $_.Subject -match "YourCertName" }
   Set-AuthenticodeSignature -FilePath .\Detect-ZscalerRegion.ps1 `
       -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
   ```

2. **Deploy `cn-ipv4.txt`** to a known path on endpoints (e.g., via GPO or SCCM):
   ```
   C:\ProgramData\Zscaler\GeoLocation\cn-ipv4.txt
   ```

3. **Upload to ZDX** (Administration > Remediation > Add Script):
   - Upload the signed `Detect-ZscalerRegion.ps1`
   - Add parameter: Name=`ChinaIPList`, Value=`C:\ProgramData\Zscaler\GeoLocation\cn-ipv4.txt`
   - Enable "Run Script with Elevated Permissions (System Account)"

4. **Start a Remediation Job** targeting desired devices

The script outputs JSON for ZDX result capture:
```json
{"success":true,"region":"CN","gatewayIP":"211.144.19.50","pseLocation":"Beijing","matchLayer":"L1_PublicPSE","confidence":"HIGH","method":"ip.zscaler.com","scriptVersion":"2.0.0","timestamp":"2026-03-20T10:30:00+08:00"}
```

### References

| Document | URL |
|----------|-----|
| About Scripts | https://help.zscaler.com/zdx/about-scripts |
| Preparing Certification and Signing | https://help.zscaler.com/zdx/preparing-certification-and-signing-script |
| Managing Scripts | https://help.zscaler.com/zdx/managing-remote-scripts |
| Configuring Remediation Settings | https://help.zscaler.com/zdx/configuring-remote-script-run-settings |

## Prerequisites

| Requirement | Windows | macOS |
|-------------|---------|-------|
| **OS** | Windows 10/11 | macOS 10.15+ |
| **Shell** | PowerShell 5.1+ | bash |
| **Privileges** | Administrator (registry write) | root (file write) |
| **ZCC** | Installed, enrolled, tunneling | Installed, enrolled, tunneling |
| **Network** | HTTPS to ip.zscaler.com (optional) | HTTPS to ip.zscaler.com (optional) |
| **API Keys** | None | None |

## Standalone China IP List Generator

`generate-china-ip-list.py` regenerates `cn-ipv4.txt` independently -- no database, no zbrain site needed.

### How It Works

The script intersects up to three independent data sources to classify China IP ranges by confidence:

| Source | What | Required |
|--------|------|----------|
| **APNIC RIR** | Authoritative IPv4 delegation registry | Always (fetched automatically) |
| **bgp.tools** | BGP routing table + ASN country registry | Default on (fetched automatically) |
| **MaxMind GeoLite2** | Commercial geolocation database | Optional (`--maxmind-db`) |

Confidence tiers:
- **HIGH** = all available sources agree
- **MEDIUM** = majority agree
- **LOW** = only RIR allocation (others disagree or absent)

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--output`, `-o` | `cn-ipv4.txt` | Output file path |
| `--maxmind-db` | -- | Path to GeoLite2-City.mmdb (free license key from [MaxMind](https://www.maxmind.com/en/geolite2/signup)) |
| `--skip-bgp` | off | Skip BGP validation (faster but less accurate) |
| `--include-medium` | off | Include MEDIUM confidence CIDRs (default: HIGH only) |

### Usage

```bash
pip install httpx                                          # one-time setup

python generate-china-ip-list.py                           # RIR + BGP (recommended)
python generate-china-ip-list.py --maxmind-db GeoLite2-City.mmdb  # best accuracy
python generate-china-ip-list.py --skip-bgp                # fastest (RIR only)
python generate-china-ip-list.py -o /path/to/cn-ipv4.txt   # custom output
```

The script also writes a `cn-ipv4.stats.json` file alongside the output with source counts and tier breakdowns.

### External Calls

| Service | URL | Data Sent | Purpose |
|---------|-----|-----------|---------|
| APNIC | `ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest` | None | RIR delegation data |
| bgp.tools | `bgp.tools/table.txt` | User-Agent header | BGP routing table |
| bgp.tools | `bgp.tools/asns.csv` | User-Agent header | ASN country registry |

## Security

### Detection Scripts — External Calls

| Service | URL | Data Sent | Purpose |
|---------|-----|-----------|---------|
| ip.zscaler.com | `https://ip.zscaler.com/` | Source IP (implicit) | Identify PSE gateway IP |

No other external APIs are called by the detection scripts. No API keys, tokens, or credentials stored.

### IP List Generator — External Calls

| Service | URL | Data Sent | Purpose |
|---------|-----|-----------|---------|
| APNIC FTP | `https://ftp.apnic.net/...` | None | China IPv4 allocations |
| bgp.tools | `https://bgp.tools/table.txt` | User-Agent | Global BGP routing table |
| bgp.tools | `https://bgp.tools/asns.csv` | User-Agent | ASN country mappings |

The User-Agent header identifies the tool (`china-ip-list-generator/1.0`). No authentication or API keys required.

### Input Validation

- **IP addresses**: Both scripts validate `-TestIP`/`--test-ip` format before processing
- **Config files**: Parsed with standard JSON libraries; file paths passed as arguments (not interpolated into code)
- **CIDR lists**: Validated against `^\d+\.\d+\.\d+\.\d+/\d+$` regex; malformed lines are skipped

### What These Scripts Do NOT Do

- Do not collect WiFi BSSIDs, GPS coordinates, or cellular identifiers
- Do not call third-party geolocation APIs (detection scripts)
- Do not modify any Zscaler configuration
- Do not require or store API keys (detection scripts)
- Do not install services or drivers
- Do not execute arbitrary code from config files

## Zscaler Documentation References

| # | Document | URL |
|---|----------|-----|
| [1] | About Scripts (ZDX) | https://help.zscaler.com/zdx/about-scripts |
| [2] | Configuring Device Posture Profiles | https://help.zscaler.com/zscaler-client-connector/configuring-device-posture-profiles |
| [3] | Adding ZIA Posture Profiles | https://help.zscaler.com/zscaler-client-connector/adding-zia-posture-profiles |
| [4] | Managing Scripts (ZDX) | https://help.zscaler.com/zdx/managing-scripts |
| [5] | Preparing Script Signing | https://help.zscaler.com/zdx/preparing-certification-and-signing-script |
