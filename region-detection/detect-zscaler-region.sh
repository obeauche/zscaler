#!/bin/bash
# detect-zscaler-region.sh — Zscaler PSE-Based Region Detection for macOS
#
# Detects whether a device is connected to a China-based Zscaler service edge
# by checking the gateway IP against known China infrastructure.
#
# Three-layer matching:
#   Layer 1: Known Zscaler China Public PSE CIDRs (6 ranges)
#   Layer 2: Comprehensive China IP list (Private PSEs + China Premium/CBC/Zenlayer)
#   Layer 3: Customer-configured custom ranges
#
# Usage:
#   sudo ./detect-zscaler-region.sh                           # Normal detection
#   ./detect-zscaler-region.sh --test-ip 211.144.19.50 --dry-run  # Test China PSE
#   ./detect-zscaler-region.sh --test-ip 103.40.100.5 --dry-run   # Test China Premium
#   ./detect-zscaler-region.sh --help
#
# Version: 2.0.0
# Author:  Olivier Beauchemin
# Requires: macOS 10.15+, root for writing result file

set -euo pipefail

VERSION="2.0.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# --- Configuration ---
RESULT_DIR="/Library/Application Support/Zscaler/GeoLocation"
RESULT_FILE="${RESULT_DIR}/region.json"
LOG_FILE="${RESULT_DIR}/detection.log"
IP_CHECK_URL="https://ip.zscaler.com/"
HTTP_TIMEOUT=10

# Default China IP list path (same directory as script)
CHINA_IP_LIST="${SCRIPT_DIR}/cn-ipv4.txt"

# Layer 1: Zscaler China Public PSE CIDRs
# Source: config.zscaler.com CENR API, same across all ZIA clouds. Updated 2026-03-20.
ZSCALER_CHINA_PSE=(
    "211.144.19.0/24|Beijing|bjs1"
    "220.243.154.0/23|Beijing III|bjs3"
    "58.220.95.0/24|Shanghai|sha1"
    "116.196.192.0/24|Shanghai II|sha2"
    "140.210.152.0/23|Shanghai II|sha2"
    "221.122.91.0/24|Tianjin|tsn1"
)

# --- Argument Parsing ---
TEST_IP=""
DRY_RUN=false
FORCE=false
VERBOSE=false
INSTALL_LAUNCHD=false
CONFIG_FILE=""

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Detect Zscaler PSE region for SSL inspection policy selection.

Options:
  --test-ip IP        Simulate detection with a specific IP
  --dry-run           Run without writing result file
  --force             Skip ZCC state check
  --verbose           Debug logging
  --china-ip-list F   Path to China IP CIDR list (default: ./cn-ipv4.txt)
  --config FILE       JSON config with custom Private PSE ranges
  --install           Install as launchd periodic job
  --help              Show this help

Matching Layers:
  L1: Zscaler China Public PSE CIDRs (6 ranges from config.zscaler.com)
  L2: China IP list file (covers Private PSEs + China Premium/CBC/Zenlayer)
  L3: Custom config file (customer-specific Private PSE ranges)

Examples:
  sudo $SCRIPT_NAME                                      # Normal detection
  $SCRIPT_NAME --test-ip 211.144.19.50 --dry-run        # Zscaler Public PSE
  $SCRIPT_NAME --test-ip 103.40.100.5 --dry-run         # China Premium IP
  $SCRIPT_NAME --test-ip 10.0.50.1 --config pse.json    # Private PSE
  sudo $SCRIPT_NAME --install                            # Install launchd job

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test-ip)        TEST_IP="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=true; shift ;;
        --force)          FORCE=true; shift ;;
        --verbose)        VERBOSE=true; shift ;;
        --china-ip-list)  CHINA_IP_LIST="$2"; shift 2 ;;
        --config)         CONFIG_FILE="$2"; shift 2 ;;
        --install)        INSTALL_LAUNCHD=true; shift ;;
        --help|-h)        usage ;;
        *)                echo "Unknown option: $1"; usage ;;
    esac
done

# --- Logging ---

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    local entry="[$ts] [$level] $msg"

    case "$level" in
        ERROR) printf '\033[31m%s\033[0m\n' "$entry" ;;
        WARN)  printf '\033[33m%s\033[0m\n' "$entry" ;;
        DEBUG) [[ "$VERBOSE" == true ]] && printf '\033[90m%s\033[0m\n' "$entry" || true ;;
        *)     echo "$entry" ;;
    esac

    # File output
    if mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
        echo "$entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# --- CIDR Matching ---

ip_to_uint32() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

test_ip_in_cidr() {
    local ip="$1" cidr="$2"
    local network="${cidr%/*}" prefix_len="${cidr#*/}"
    local ip_uint net_uint mask

    ip_uint=$(ip_to_uint32 "$ip")
    net_uint=$(ip_to_uint32 "$network")

    if [[ "$prefix_len" -eq 0 ]]; then return 0; fi

    mask=$(( (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF ))

    [[ $(( ip_uint & mask )) -eq $(( net_uint & mask )) ]]
}

test_china_ip() {
    # Three-layer China IP matching
    # Returns pipe-delimited: "layer|location|cidr|detail"
    local gateway_ip="$1"

    # --- Layer 1: Zscaler China Public PSE CIDRs ---
    for entry in "${ZSCALER_CHINA_PSE[@]}"; do
        local cidr location code
        IFS='|' read -r cidr location code <<< "$entry"
        if test_ip_in_cidr "$gateway_ip" "$cidr"; then
            log DEBUG "Layer 1 match: $gateway_ip in $cidr ($location)"
            echo "L1_PublicPSE|${location}|${cidr}|Zscaler Public PSE: ${code}"
            return 0
        fi
    done

    # --- Layer 2: Comprehensive China IP list ---
    if [[ -f "$CHINA_IP_LIST" ]]; then
        local cidr_count=0
        while IFS= read -r line; do
            # Skip comments and empty lines
            [[ -z "$line" || "$line" == \#* ]] && continue
            line="${line%%[[:space:]]*}"  # trim trailing whitespace
            [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
            cidr_count=$((cidr_count + 1))

            if test_ip_in_cidr "$gateway_ip" "$line"; then
                log DEBUG "Layer 2 match: $gateway_ip in $line"
                echo "L2_ChinaIPList|China (IP geolocation)|${line}|China IP list match (Private PSE / China Premium)"
                return 0
            fi
        done < "$CHINA_IP_LIST"
        log DEBUG "Layer 2: Checked $cidr_count CIDRs, no match"
    else
        log WARN "Layer 2 skipped: $CHINA_IP_LIST not found"
    fi

    # --- Layer 3: Custom config file ---
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        # Parse JSON config with python3 (available on macOS).
        # SECURITY: Pass file path and IP as command-line arguments to avoid
        # shell injection via crafted file paths or IP strings.
        local custom_matches
        custom_matches=$(python3 - "$CONFIG_FILE" "$gateway_ip" <<'PYEOF'
import json, sys
try:
    config_path = sys.argv[1]
    ip = sys.argv[2]
    config = json.load(open(config_path))
    ip_parts = list(map(int, ip.split('.')))
    ip_uint = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]

    for entry in config.get('china_ranges', []):
        cidr = entry['cidr']
        net_str, prefix = cidr.split('/')
        prefix = int(prefix)
        net_parts = list(map(int, net_str.split('.')))
        net_uint = (net_parts[0] << 24) + (net_parts[1] << 16) + (net_parts[2] << 8) + net_parts[3]
        mask = ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF) if prefix < 32 else 0xFFFFFFFF
        if (ip_uint & mask) == (net_uint & mask):
            label = entry.get('label', 'Custom range')
            print(f'L3_CustomConfig|{label}|{cidr}|Custom config: {label}')
            sys.exit(0)
except Exception as e:
    print(f'ERROR|Config parse error|N/A|{e}', file=sys.stderr)
sys.exit(1)
PYEOF
        ) && {
            echo "$custom_matches"
            return 0
        }
    fi

    return 1
}

# --- ZCC State Detection ---

test_zcc_connected() {
    # Check if ZCC is running and tunneling on macOS

    if ! pgrep -q "Zscaler" 2>/dev/null; then
        log WARN "Zscaler processes not running"
        return 1
    fi

    # Check for tunnel process
    if pgrep -q "ZSATunnel" 2>/dev/null || pgrep -q "ZscalerTunnel" 2>/dev/null; then
        log DEBUG "ZCC tunnel process found"
        return 0
    fi

    # Check for network activity from Zscaler processes
    if lsof -i -n 2>/dev/null | grep -q "Zscaler" 2>/dev/null; then
        log DEBUG "Zscaler network connections found"
        return 0
    fi

    log WARN "ZCC tunnel process not detected"
    return 1
}

# --- Gateway IP Detection ---

get_gateway_from_ip_zscaler() {
    local response
    response=$(curl -s --max-time "$HTTP_TIMEOUT" -L "$IP_CHECK_URL" 2>/dev/null) || {
        log WARN "ip.zscaler.com request failed"
        return 1
    }

    local through_zscaler="false"
    echo "$response" | grep -q "You are accessing the Internet via Zscaler" && through_zscaler="true"

    local gateway_ip
    gateway_ip=$(echo "$response" | grep -oE "from the IP address [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")

    if [[ -z "$gateway_ip" ]]; then
        log WARN "Could not parse IP from ip.zscaler.com"
        return 1
    fi

    log INFO "ip.zscaler.com: $gateway_ip (through Zscaler: $through_zscaler)"
    echo "${gateway_ip}|${through_zscaler}|ip.zscaler.com"
}

get_gateway_from_tunnel_process() {
    local tunnel_pid
    tunnel_pid=$(pgrep -x "ZSATunnel" 2>/dev/null || pgrep -x "ZscalerTunnel" 2>/dev/null || true)

    if [[ -z "$tunnel_pid" ]]; then
        log WARN "Tunnel process not found"
        return 1
    fi

    local remote_ip
    remote_ip=$(lsof -i TCP -n -P 2>/dev/null | grep "$tunnel_pid" | grep "ESTABLISHED" | grep ":443->" | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | tail -1)

    if [[ -z "$remote_ip" ]]; then
        remote_ip=$(lsof -i TCP -n -P 2>/dev/null | grep "$tunnel_pid" | grep "ESTABLISHED" | head -1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | tail -1)
    fi

    if [[ -z "$remote_ip" ]]; then
        log WARN "No remote connections for tunnel process"
        return 1
    fi

    log INFO "Tunnel connected to: $remote_ip"
    echo "${remote_ip}|true|tunnel_process"
}

get_pse_gateway_ip() {
    local result
    result=$(get_gateway_from_ip_zscaler) && { echo "$result"; return 0; }
    result=$(get_gateway_from_tunnel_process) && { echo "$result"; return 0; }
    log ERROR "All gateway detection methods failed"
    return 1
}

# --- Result Output ---

write_result() {
    local region="$1" gateway_ip="$2" pse_location="$3" match_layer="$4" method="$5" confidence="$6"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if [[ "$DRY_RUN" == true ]]; then
        log INFO "[DRY RUN] Would write: Region=$region, IP=$gateway_ip, Location=$pse_location, Layer=$match_layer"
        return 0
    fi

    if ! mkdir -p "$RESULT_DIR" 2>/dev/null; then
        log ERROR "Cannot create $RESULT_DIR (run with sudo)"
        return 1
    fi

    local previous_region=""
    if [[ -f "$RESULT_FILE" ]]; then
        # SECURITY: Pass file path as argument, not string interpolation
        previous_region=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('region',''))" "$RESULT_FILE" 2>/dev/null || true)
    fi

    cat > "$RESULT_FILE" <<JSONEOF
{
    "region": "$region",
    "gateway_ip": "$gateway_ip",
    "pse_location": "${pse_location:-Unknown}",
    "match_layer": "$match_layer",
    "detection_method": "$method",
    "confidence": "$confidence",
    "last_detection": "$timestamp",
    "script_version": "$VERSION",
    "previous_region": "$previous_region"
}
JSONEOF

    chmod 644 "$RESULT_FILE"

    if [[ -n "$previous_region" && "$previous_region" != "$region" ]]; then
        log WARN "Region CHANGED: $previous_region -> $region"
    fi

    log INFO "Result written: region=$region"
}

# --- launchd Installation ---

install_launchd() {
    local plist_path="/Library/LaunchDaemons/com.zscaler.regiondetection.plist"
    local script_path="${SCRIPT_DIR}/${SCRIPT_NAME}"

    if [[ $EUID -ne 0 ]]; then
        log ERROR "Must run as root to install launchd job"
        exit 1
    fi

    cat > "$plist_path" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.zscaler.regiondetection</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$script_path</string>
    </array>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Application Support/Zscaler/GeoLocation/launchd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Application Support/Zscaler/GeoLocation/launchd-stderr.log</string>
</dict>
</plist>
PLISTEOF

    chmod 644 "$plist_path"
    launchctl load "$plist_path" 2>/dev/null || true
    log INFO "launchd job installed at $plist_path (every 30 min)"
}

# --- Main ---

main() {
    log INFO "=== Zscaler Region Detection v${VERSION} (macOS) ==="
    local mode="Live"
    [[ -n "$TEST_IP" ]] && mode="TestIP"
    [[ "$DRY_RUN" == true ]] && mode="${mode}+DryRun"
    log INFO "Mode: $mode"

    if [[ "$INSTALL_LAUNCHD" == true ]]; then
        install_launchd
        exit 0
    fi

    local gateway_ip="" through_zscaler="" method="" confidence=""

    if [[ -n "$TEST_IP" ]]; then
        # Validate IP format before using it
        if ! [[ "$TEST_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log ERROR "Invalid IP address format: $TEST_IP"
            exit 1
        fi
        gateway_ip="$TEST_IP"
        through_zscaler="false"
        method="test_ip"
        confidence="TEST"
    else
        # Phase 1: Verify ZCC connected
        if [[ "$FORCE" != true ]]; then
            if ! test_zcc_connected; then
                log WARN "ZCC not connected"
                write_result "UNKNOWN" "N/A" "N/A" "N/A" "zcc_not_connected" "NONE"
                echo "RESULT: UNKNOWN (ZCC not connected)"
                exit 1
            fi
        fi

        # Phase 2: Get gateway IP
        local gw_result
        gw_result=$(get_pse_gateway_ip) || {
            log ERROR "Gateway detection failed"
            echo "RESULT: UNKNOWN (gateway detection failed)"
            exit 1
        }
        IFS='|' read -r gateway_ip through_zscaler method <<< "$gw_result"

        if [[ "$through_zscaler" == "true" && "$method" == "ip.zscaler.com" ]]; then
            confidence="HIGH"
        elif [[ "$method" == "tunnel_process" ]]; then
            confidence="HIGH"
        else
            confidence="MEDIUM"
        fi
    fi

    # Phase 3: Three-layer China matching
    local match_result region pse_location match_layer detail
    match_result=$(test_china_ip "$gateway_ip") && {
        IFS='|' read -r match_layer pse_location _cidr detail <<< "$match_result"
        region="CN"
        log WARN "CHINA DETECTED [$match_layer]: $gateway_ip -> $pse_location"
        log INFO "Detail: $detail"
    } || {
        region="NON-CN"
        pse_location=""
        match_layer="None"
        log INFO "Non-China: $gateway_ip (all layers checked)"
    }

    # Phase 4: Write result
    write_result "$region" "$gateway_ip" "$pse_location" "$match_layer" "$method" "$confidence"

    # Summary
    echo ""
    echo "============================================"
    echo "  Region:     $region"
    echo "  Gateway IP: $gateway_ip"
    echo "  PSE:        ${pse_location:-N/A}"
    echo "  Layer:      $match_layer"
    echo "  Method:     $method"
    echo "  Confidence: $confidence"
    echo "============================================"
}

main "$@"
