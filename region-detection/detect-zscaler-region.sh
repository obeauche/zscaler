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
# Version: 2.1.1
# Author:  Olivier Beauchemin
# Requires: macOS 10.15+, root for writing result file

set -euo pipefail

VERSION="2.1.1"
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

Exit Codes:
  0  NON-CN: not routing through China Zscaler PSE
  1  CN: China PSE detected (not an error — use this to trigger policy)
  2  UNKNOWN: ZCC not connected or gateway detection failed
  3  Script error: bad arguments, missing permissions

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
        *)                echo "Unknown option: $1" >&2; exit 3 ;;
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
        ERROR) printf '\033[31m%s\033[0m\n' "$entry" >&2 ;;
        WARN)  printf '\033[33m%s\033[0m\n' "$entry" >&2 ;;
        DEBUG) [[ "$VERBOSE" == true ]] && printf '\033[90m%s\033[0m\n' "$entry" >&2 || true ;;
        *)     echo "$entry" >&2 ;;
    esac

    # File output
    if mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
        echo "$entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# --- CIDR Matching ---

# Convert a dotted-decimal IPv4 address (e.g. "192.168.1.1") to a single
# 32-bit unsigned integer so CIDR range comparisons can be done with simple
# arithmetic instead of string operations.
ip_to_uint32() {
    local ip="$1"
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Return 0 (true) if $ip falls inside $cidr, 1 (false) otherwise.
#
# How it works:
#   A /prefix_len network mask has the top prefix_len bits set to 1 and the
#   rest set to 0.  Building that mask in bash:
#     mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
#   The & 0xFFFFFFFF trims the result to 32 bits because bash uses 64-bit
#   signed integers — without it, a /0 left-shift would overflow.
#
#   Two IPs are in the same subnet when their masked values are identical:
#     (ip & mask) == (network_address & mask)
test_ip_in_cidr() {
    local ip="$1" cidr="$2"
    local network="${cidr%/*}" prefix_len="${cidr#*/}"
    local ip_uint net_uint mask

    ip_uint=$(ip_to_uint32 "$ip")
    net_uint=$(ip_to_uint32 "$network")

    if [[ "$prefix_len" -eq 0 ]]; then return 0; fi  # /0 matches everything

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

    # --- Layer 2: Comprehensive China IP list (awk for performance) ---
    # cn-ipv4.txt contains ~2,200 CIDRs. A pure bash loop over that many
    # entries takes 1-3 seconds; awk processes the same file in ~50ms because
    # it reads line-by-line in a native loop without fork overhead.
    #
    # POSIX awk has no bitwise operators, so the subnet test uses integer
    # division as an equivalent:
    #   Right-shifting both IPs by (32 - prefix) discards the host bits,
    #   leaving only the network bits.  If those truncated values are equal,
    #   the IP is inside the subnet — same result as (ip & mask) == (net & mask).
    #   Example: 192.168.1.50 in 192.168.1.0/24 → shift=8
    #     int(3232235826 / 256) == int(3232235776 / 256)  → 12632952 == 12632952 ✓
    if [[ -f "$CHINA_IP_LIST" ]]; then
        local l2_match
        l2_match=$(awk -v ip="$gateway_ip" '
            /^#/             { next }
            /^[[:space:]]*$/ { next }
            {
                cidr = $1
                if (cidr !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/) { next }
                split(cidr, parts, "/")
                prefix = parts[2] + 0
                if (prefix < 1 || prefix > 32) { next }
                split(parts[1], net_parts, ".")
                net_int = net_parts[1]*16777216 + net_parts[2]*65536 + net_parts[3]*256 + net_parts[4]
                split(ip, ip_parts, ".")
                ip_int = ip_parts[1]*16777216 + ip_parts[2]*65536 + ip_parts[3]*256 + ip_parts[4]
                shift = 32 - prefix
                if (int(ip_int / (2^shift)) == int(net_int / (2^shift))) {
                    print cidr
                    exit 0
                }
            }
        ' "$CHINA_IP_LIST") && [[ -n "$l2_match" ]] && {
            log DEBUG "Layer 2 match: $gateway_ip in $l2_match"
            echo "L2_ChinaIPList|China (IP geolocation)|${l2_match}|China IP list match (Private PSE / China Premium)"
            return 0
        }
        log DEBUG "Layer 2: No match in $CHINA_IP_LIST"
    else
        log WARN "Layer 2 skipped: $CHINA_IP_LIST not found"
    fi

    # --- Layer 3: Custom config file (no python3) ---
    # Parses pse-config.json using a line-by-line awk state machine instead of
    # a real JSON parser — avoids the Python 3 dependency required for MDM
    # deployment scenarios where Python may not be present.
    #
    # The awk block is NOT a general JSON parser. It relies on the known
    # structure of pse-config.json (one key per line, objects closed by "}"):
    #   1. When a line contains "cidr", extract the value between the quotes.
    #   2. When a line contains "label", extract the value between the quotes.
    #   3. When a closing "}" is seen and a cidr was captured, emit "cidr|label"
    #      and reset state for the next object.
    # This works correctly for the expected format; it will silently produce
    # wrong results if the JSON is minified (multiple keys on one line).
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        local cidr label
        while IFS='|' read -r cidr label; do
            [[ -z "$cidr" ]] && continue
            if test_ip_in_cidr "$gateway_ip" "$cidr"; then
                log DEBUG "Layer 3 match: $gateway_ip in $cidr ($label)"
                echo "L3_CustomConfig|${label:-Custom range}|${cidr}|Custom config: ${label:-Custom range}"
                return 0
            fi
        done < <(awk '
            /"cidr"/ {
                line = $0
                sub(/.*"cidr"[[:space:]]*:[[:space:]]*"/, "", line)
                sub(/".*/, "", line)
                cidr = line
            }
            /"label"/ {
                line = $0
                sub(/.*"label"[[:space:]]*:[[:space:]]*"/, "", line)
                sub(/".*/, "", line)
                label = line
            }
            /\}/ {
                if (cidr != "") { print cidr "|" label; cidr = ""; label = "" }
            }
        ' "$CONFIG_FILE" 2>/dev/null)
    fi

    return 1
}

# --- ZCC State Detection ---

test_zcc_connected() {
    if pgrep -f "[Zz]scaler" > /dev/null 2>&1; then
        log DEBUG "Zscaler process detected"
        return 0
    fi
    if [[ -d "/Applications/Zscaler/Zscaler.app" ]] && \
       pgrep -f "Zscaler.app" > /dev/null 2>&1; then
        log DEBUG "Zscaler.app process detected"
        return 0
    fi
    log WARN "No Zscaler processes found"
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
    gateway_ip=$(echo "$response" | grep "from the IP address" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | head -1)

    if [[ -z "$gateway_ip" ]]; then
        log WARN "Could not parse IP from ip.zscaler.com"
        return 1
    fi

    log INFO "ip.zscaler.com: $gateway_ip (through Zscaler: $through_zscaler)"
    echo "${gateway_ip}|${through_zscaler}|ip.zscaler.com"
}

get_gateway_from_tunnel_process() {
    local tunnel_pid
    tunnel_pid=$(pgrep -x "ZSATunnel" 2>/dev/null \
        || pgrep -x "ZscalerTunnel" 2>/dev/null \
        || pgrep -f "[Zz]scaler" 2>/dev/null | head -1 \
        || true)

    if [[ -z "$tunnel_pid" ]]; then
        log WARN "No Zscaler process found for tunnel detection"
        return 1
    fi

    local remote_ip
    remote_ip=$(lsof -i TCP -n -P -p "$tunnel_pid" 2>/dev/null | awk '
        /ESTABLISHED/ && /:443->/ {
            line = $0
            sub(/.*->/, "", line)
            sub(/:.*/, "", line)
            if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print line; exit 0 }
        }
    ') || true

    if [[ -z "$remote_ip" ]]; then
        remote_ip=$(lsof -i TCP -n -P -p "$tunnel_pid" 2>/dev/null | awk '
            /ESTABLISHED/ {
                line = $0
                sub(/.*->/, "", line)
                sub(/:.*/, "", line)
                if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { print line; exit 0 }
            }
        ') || true
    fi

    if [[ -z "$remote_ip" ]]; then
        log WARN "No established connections found for Zscaler process (pid=$tunnel_pid)"
        return 1
    fi

    log INFO "Tunnel connected to: $remote_ip (pid=$tunnel_pid)"
    echo "${remote_ip}|true|tunnel_process"
}

get_pse_gateway_ip() {
    local result
    result=$(get_gateway_from_ip_zscaler) && { echo "$result"; return 0; }
    result=$(get_gateway_from_tunnel_process) && { echo "$result"; return 0; }
    log ERROR "All gateway detection methods failed"
    return 1
}

# --- JSON Helper ---

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
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
        previous_region=$(grep '"region"' "$RESULT_FILE" 2>/dev/null \
            | sed 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
            || true)
    fi

    cat > "$RESULT_FILE" <<JSONEOF
{
    "region": "$(json_escape "$region")",
    "gateway_ip": "$(json_escape "$gateway_ip")",
    "pse_location": "$(json_escape "${pse_location:-Unknown}")",
    "match_layer": "$(json_escape "$match_layer")",
    "detection_method": "$(json_escape "$method")",
    "confidence": "$(json_escape "$confidence")",
    "last_detection": "$(json_escape "$timestamp")",
    "script_version": "$(json_escape "$VERSION")",
    "previous_region": "$(json_escape "$previous_region")"
}
JSONEOF

    chmod 644 "$RESULT_FILE"

    if [[ -n "$previous_region" && "$previous_region" != "$region" ]]; then
        log WARN "Region CHANGED: $previous_region -> $region"
    fi

    log INFO "Result written: region=$region"
}

# --- Log Rotation ---

rotate_log() {
    local max_lines=500
    if [[ -f "$LOG_FILE" ]]; then
        local line_count
        line_count=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d ' ') || return 0
        if [[ "$line_count" -gt "$max_lines" ]]; then
            local tmp="${LOG_FILE}.tmp.$$"
            tail -n "$max_lines" "$LOG_FILE" > "$tmp" 2>/dev/null \
                && mv "$tmp" "$LOG_FILE" 2>/dev/null \
                || rm -f "$tmp" 2>/dev/null
        fi
    fi
}

# --- launchd Installation ---

install_launchd() {
    local plist_path="/Library/LaunchDaemons/com.zscaler.regiondetection.plist"
    local script_path="${SCRIPT_DIR}/${SCRIPT_NAME}"

    if [[ $EUID -ne 0 ]]; then
        log ERROR "Must run as root to install launchd job"
        exit 3
    fi

    # Build extra arguments to pass through to the plist
    local extra_args=""
    if [[ -n "$CONFIG_FILE" ]]; then
        extra_args="${extra_args}        <string>--config</string>
        <string>${CONFIG_FILE}</string>
"
    fi
    if [[ "$CHINA_IP_LIST" != "${SCRIPT_DIR}/cn-ipv4.txt" ]]; then
        extra_args="${extra_args}        <string>--china-ip-list</string>
        <string>${CHINA_IP_LIST}</string>
"
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
${extra_args}    </array>
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
    rotate_log
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
            exit 3
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
                exit 2
            fi
        fi

        # Phase 2: Get gateway IP
        local gw_result
        gw_result=$(get_pse_gateway_ip) || {
            log ERROR "Gateway detection failed"
            write_result "UNKNOWN" "N/A" "N/A" "N/A" "gateway_detection" "NONE"
            echo "RESULT: UNKNOWN (gateway detection failed)"
            exit 2
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

    # Structured exit codes
    case "$region" in
        CN)     exit 1 ;;
        NON-CN) exit 0 ;;
        *)      exit 2 ;;
    esac
}

main "$@"
