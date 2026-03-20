#!/bin/bash
# test-region-detection.sh — Test harness for detect-zscaler-region.sh
#
# Validates CIDR matching, three-layer detection, and edge cases.
# Runs without root, ZCC, or network access.
#
# Usage: ./test-region-detection.sh
#
# Version: 2.0.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DETECT_SCRIPT="${SCRIPT_DIR}/detect-zscaler-region.sh"

PASSED=0
FAILED=0
TOTAL=0

# Colors
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
GRAY='\033[90m'
RESET='\033[0m'

test_case() {
    local name="$1"
    local test_ip="$2"
    local expected_region="$3"
    local expected_layer="${4:-}"
    local extra_args="${5:-}"
    TOTAL=$((TOTAL + 1))

    # Run detection in dry-run + force mode, capture output
    local output
    output=$(bash "$DETECT_SCRIPT" --test-ip "$test_ip" --dry-run --force $extra_args 2>&1) || true

    # Parse region from summary block
    local detected_region
    detected_region=$(echo "$output" | grep "Region:" | tail -1 | sed 's/.*Region:[[:space:]]*//' | tr -d '[:space:]')

    # Parse layer from summary block
    local detected_layer
    detected_layer=$(echo "$output" | grep "Layer:" | tail -1 | sed 's/.*Layer:[[:space:]]*//' | tr -d '[:space:]')

    local region_ok=false
    [[ "$detected_region" == "$expected_region" ]] && region_ok=true

    local layer_ok=true
    if [[ -n "$expected_layer" ]]; then
        [[ "$detected_layer" == "$expected_layer" ]] || layer_ok=false
    fi

    if [[ "$region_ok" == true && "$layer_ok" == true ]]; then
        printf "  ${GREEN}PASS${RESET}  %s\n" "$name"
        printf "  ${GRAY}      IP=%s -> Region=%s Layer=%s${RESET}\n" "$test_ip" "$detected_region" "$detected_layer"
        PASSED=$((PASSED + 1))
    else
        printf "  ${RED}FAIL${RESET}  %s\n" "$name"
        printf "  ${YELLOW}      IP=%s${RESET}\n" "$test_ip"
        printf "  ${YELLOW}      Expected: Region=%s Layer=%s${RESET}\n" "$expected_region" "$expected_layer"
        printf "  ${RED}      Got:      Region=%s Layer=%s${RESET}\n" "$detected_region" "$detected_layer"
        FAILED=$((FAILED + 1))
    fi
}

# === Header ===
echo ""
printf "${CYAN}============================================${RESET}\n"
printf "${CYAN}  Zscaler Region Detection Test Suite v2.0${RESET}\n"
printf "${CYAN}  Platform: macOS / Linux${RESET}\n"
printf "${CYAN}============================================${RESET}\n"
echo ""

# Verify detect script exists
if [[ ! -f "$DETECT_SCRIPT" ]]; then
    printf "${RED}ERROR: Detect script not found at %s${RESET}\n" "$DETECT_SCRIPT"
    exit 1
fi

# Verify China IP list exists
if [[ ! -f "${SCRIPT_DIR}/cn-ipv4.txt" ]]; then
    printf "${YELLOW}WARNING: cn-ipv4.txt not found — Layer 2 tests will fail${RESET}\n"
fi

# === Test Group 1: Layer 1 — Zscaler Public PSE ===
echo "--- Layer 1: Zscaler China Public PSE ---"

test_case "Beijing PSE (bjs1)"           "211.144.19.50"    "CN"     "L1_PublicPSE"
test_case "Beijing PSE - first IP"       "211.144.19.1"     "CN"     "L1_PublicPSE"
test_case "Beijing PSE - last IP"        "211.144.19.254"   "CN"     "L1_PublicPSE"
test_case "Beijing III PSE (bjs3)"       "220.243.154.100"  "CN"     "L1_PublicPSE"
test_case "Beijing III - /23 upper half" "220.243.155.200"  "CN"     "L1_PublicPSE"
test_case "Shanghai PSE (sha1)"          "58.220.95.8"      "CN"     "L1_PublicPSE"
test_case "Shanghai II - range 1"        "116.196.192.50"   "CN"     "L1_PublicPSE"
test_case "Shanghai II - range 2"        "140.210.152.12"   "CN"     "L1_PublicPSE"
test_case "Shanghai II - /23 upper"      "140.210.153.200"  "CN"     "L1_PublicPSE"
test_case "Tianjin PSE (tsn1)"           "221.122.91.32"    "CN"     "L1_PublicPSE"

# === Test Group 2: Layer 2 — China IP List ===
echo ""
echo "--- Layer 2: China IP List (Private PSE / China Premium) ---"

test_case "China Telecom range"    "1.12.0.1"    "CN"  "L2_ChinaIPList"
test_case "China Mobile range"     "36.128.0.1"  "CN"  "L2_ChinaIPList"
test_case "China IP (1.80.x)"      "1.80.0.1"    "CN"  "L2_ChinaIPList"

# === Test Group 3: Non-China IPs ===
echo ""
echo "--- Non-China IPs (should be NON-CN) ---"

test_case "Zscaler US PSE"    "104.129.192.1"  "NON-CN"
test_case "Google DNS"        "8.8.8.8"        "NON-CN"
test_case "Cloudflare"        "1.1.1.1"        "NON-CN"
test_case "AWS US-East"       "3.5.0.1"        "NON-CN"
test_case "Private RFC1918"   "192.168.1.1"    "NON-CN"
test_case "Loopback"          "127.0.0.1"      "NON-CN"

# === Test Group 4: Layer 3 — Custom Config ===
echo ""
echo "--- Layer 3: Custom Config (Private PSE ranges) ---"

# Create temp config
TEMP_CONFIG=$(mktemp /tmp/test-pse-config.XXXXXX.json)
cat > "$TEMP_CONFIG" <<'CONFIGEOF'
{
    "china_ranges": [
        { "cidr": "10.100.0.0/24", "label": "Test Private PSE Shanghai" },
        { "cidr": "172.16.50.0/24", "label": "Test ZPA PSE Beijing" }
    ]
}
CONFIGEOF

test_case "Custom Private PSE range"  "10.100.0.50"   "CN"     "L3_CustomConfig"  "--config $TEMP_CONFIG"
test_case "Custom ZPA PSE range"      "172.16.50.100" "CN"     "L3_CustomConfig"  "--config $TEMP_CONFIG"
test_case "Custom range miss"         "10.100.1.50"   "NON-CN" ""                 "--config $TEMP_CONFIG"

rm -f "$TEMP_CONFIG"

# === Test Group 5: Edge Cases ===
echo ""
echo "--- Edge Cases ---"

test_case "Beijing PSE network addr"     "211.144.19.0"    "CN"     "L1_PublicPSE"
test_case "Beijing PSE broadcast"        "211.144.19.255"  "CN"     "L1_PublicPSE"
# Adjacent IPs are still China IPs (Layer 2 catches them) — verify Layer changes from L1 to L2
test_case "Adjacent above Beijing /24 (L2)" "211.144.20.0"    "CN"     "L2_ChinaIPList"
test_case "Adjacent below Beijing /24 (L2)" "211.144.18.255"  "CN"     "L2_ChinaIPList"
# Use a genuinely non-China IP for boundary test
test_case "Non-China IP near PSE range"     "104.129.192.50"  "NON-CN"

# === Summary ===
echo ""
printf "${CYAN}============================================${RESET}\n"
if [[ $FAILED -eq 0 ]]; then
    printf "${GREEN}  Results: %d passed, %d failed, %d total${RESET}\n" "$PASSED" "$FAILED" "$TOTAL"
else
    printf "${RED}  Results: %d passed, %d failed, %d total${RESET}\n" "$PASSED" "$FAILED" "$TOTAL"
fi
printf "${CYAN}============================================${RESET}\n"
echo ""

if [[ $FAILED -gt 0 ]]; then
    printf "${RED}Some tests FAILED.${RESET}\n"
    exit 1
else
    printf "${GREEN}All tests PASSED.${RESET}\n"
    exit 0
fi
