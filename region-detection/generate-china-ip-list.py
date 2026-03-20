#!/usr/bin/env python3
"""
Standalone China IP List Generator for Zscaler Region Detection

Produces a high-confidence cn-ipv4.txt CIDR list by intersecting up to three
independent data sources:

  1. RIR Allocation  - APNIC delegated stats (authoritative registry)
  2. Geolocation     - MaxMind GeoLite2-City MMDB (optional)
  3. BGP Routing     - bgp.tools global table + ASN country registry

The output file is used by Detect-ZscalerRegion.ps1 / detect-zscaler-region.sh
for Layer 2 matching (Private Service Edges and China Premium infrastructure).

Requirements:
  pip install httpx            # required
  pip install geoip2           # optional (for MaxMind validation)

Usage:
  # Full 3-source pipeline (RIR + GeoIP + BGP)
  python generate-china-ip-list.py --maxmind-db /path/to/GeoLite2-City.mmdb

  # 2-source pipeline (RIR + BGP, no MaxMind)
  python generate-china-ip-list.py

  # RIR-only (fastest, least accurate)
  python generate-china-ip-list.py --skip-bgp

  # Custom output path
  python generate-china-ip-list.py --output /path/to/cn-ipv4.txt

MaxMind GeoLite2:
  Sign up for a free license key at https://www.maxmind.com/en/geolite2/signup
  Download GeoLite2-City.mmdb and pass it via --maxmind-db
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required. Install with: pip install httpx", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("china-ip-gen")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# APNIC is the authoritative RIR for China
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"

BGP_TOOLS_TABLE_URL = "https://bgp.tools/table.txt"
BGP_TOOLS_ASNS_URL = "https://bgp.tools/asns.csv"
BGP_TOOLS_UA = "china-ip-list-generator/1.0 (github.com/obeauche/zscaler)"

COUNTRY = "CN"


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1: RIR Allocation Parsing
# ═══════════════════════════════════════════════════════════════════════════

def count_to_cidrs(start_ip: str, count: int) -> list[ipaddress.IPv4Network]:
    """Convert RIR start_ip + count format to minimal CIDR list."""
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(int(start) + count - 1)
    return list(ipaddress.summarize_address_range(start, end))


async def fetch_rir_allocations(client: httpx.AsyncClient) -> list[ipaddress.IPv4Network]:
    """Fetch and parse APNIC delegated stats for China IPv4 allocations."""
    log.info("Fetching APNIC delegated stats...")
    t0 = time.monotonic()
    resp = await client.get(APNIC_URL, timeout=60)
    resp.raise_for_status()
    elapsed = time.monotonic() - t0
    log.info("  Downloaded in %.1fs (%d bytes)", elapsed, len(resp.content))

    cidrs = []
    count_entries = 0
    for line in resp.text.splitlines():
        if line.startswith("#") or line.startswith("2"):
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        if parts[1].upper() != COUNTRY:
            continue
        if parts[2] != "ipv4":
            continue

        start_ip = parts[3]
        ip_count = int(parts[4])
        cidrs.extend(count_to_cidrs(start_ip, ip_count))
        count_entries += 1

    log.info("  Parsed %d CN IPv4 entries -> %d CIDRs", count_entries, len(cidrs))

    collapsed = list(ipaddress.collapse_addresses(cidrs))
    log.info("  Collapsed to %d CIDRs", len(collapsed))
    return collapsed


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2: MaxMind GeoIP Cross-Validation (optional)
# ═══════════════════════════════════════════════════════════════════════════

def geoip_validate(
    cidrs: list[ipaddress.IPv4Network], mmdb_path: str | None
) -> dict[str, list[ipaddress.IPv4Network]]:
    """Cross-validate CIDRs against MaxMind GeoIP database."""
    if not mmdb_path:
        log.info("GeoIP: skipped (no --maxmind-db provided)")
        return {"confirmed": cidrs, "mixed": [], "disagree": [], "error": []}

    try:
        import geoip2.database
    except ImportError:
        log.warning("geoip2 not installed (pip install geoip2) -- skipping GeoIP")
        return {"confirmed": cidrs, "mixed": [], "disagree": [], "error": []}

    if not os.path.exists(mmdb_path):
        log.warning("MaxMind DB not found at %s -- skipping", mmdb_path)
        return {"confirmed": cidrs, "mixed": [], "disagree": [], "error": []}

    reader = geoip2.database.Reader(mmdb_path)
    results: dict[str, list] = {"confirmed": [], "mixed": [], "disagree": [], "error": []}

    for net in cidrs:
        net_int = int(net.network_address)
        num_addrs = net.num_addresses
        if net.prefixlen >= 31:
            samples = [net.network_address]
        else:
            samples = [
                ipaddress.IPv4Address(net_int + 1),
                ipaddress.IPv4Address(net_int + num_addrs // 2),
                ipaddress.IPv4Address(net_int + num_addrs - 2),
            ]

        matches = 0
        tested = 0
        for ip in samples:
            try:
                resp = reader.city(ip)
                tested += 1
                if resp.country.iso_code == COUNTRY:
                    matches += 1
            except Exception:
                pass

        if tested == 0:
            results["error"].append(net)
        elif matches == tested:
            results["confirmed"].append(net)
        elif matches > 0:
            results["mixed"].append(net)
        else:
            results["disagree"].append(net)

    reader.close()
    log.info(
        "GeoIP: %d confirmed, %d mixed, %d disagree, %d error",
        len(results["confirmed"]), len(results["mixed"]),
        len(results["disagree"]), len(results["error"]),
    )
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3: BGP Routing Cross-Validation
# ═══════════════════════════════════════════════════════════════════════════

async def fetch_bgp_table(client: httpx.AsyncClient) -> dict[ipaddress.IPv4Network, int]:
    """Download bgp.tools full table and parse into prefix -> origin_asn dict."""
    log.info("Fetching bgp.tools global routing table...")
    t0 = time.monotonic()
    resp = await client.get(
        BGP_TOOLS_TABLE_URL,
        headers={"User-Agent": BGP_TOOLS_UA},
        timeout=120,
    )
    resp.raise_for_status()
    elapsed = time.monotonic() - t0
    log.info("  Downloaded in %.1fs (%d bytes)", elapsed, len(resp.content))

    bgp_table: dict[ipaddress.IPv4Network, int] = {}
    for line in resp.text.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        prefix_str, asn_str = parts
        if ":" in prefix_str:
            continue  # skip IPv6
        try:
            net = ipaddress.IPv4Network(prefix_str, strict=False)
            asn = int(asn_str)
            bgp_table[net] = asn
        except (ValueError, TypeError):
            continue

    log.info("  Parsed %d IPv4 BGP prefixes", len(bgp_table))
    return bgp_table


async def fetch_country_asns(client: httpx.AsyncClient) -> set[int]:
    """Fetch China ASNs directly from bgp.tools/asns.csv (no database needed)."""
    log.info("Fetching bgp.tools ASN registry...")
    t0 = time.monotonic()
    resp = await client.get(
        BGP_TOOLS_ASNS_URL,
        headers={"User-Agent": BGP_TOOLS_UA},
        timeout=60,
    )
    resp.raise_for_status()
    elapsed = time.monotonic() - t0
    log.info("  Downloaded in %.1fs (%d bytes)", elapsed, len(resp.content))

    asns: set[int] = set()
    for line in resp.text.splitlines():
        # Format: ASN,Name,Country,RIR  (header: asn,name,country,rir)
        if line.startswith("asn,") or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            country_code = parts[2].strip().upper()
            if country_code == COUNTRY:
                asn = int(parts[0].strip())
                asns.add(asn)
        except (ValueError, IndexError):
            continue

    log.info("  Found %d China ASNs", len(asns))
    return asns


def bgp_validate(
    cidrs: list[ipaddress.IPv4Network],
    bgp_table: dict[ipaddress.IPv4Network, int],
    country_asns: set[int],
) -> dict[str, list[ipaddress.IPv4Network]]:
    """Cross-validate CIDRs against BGP routing table and ASN country data."""
    results: dict[str, list] = {"confirmed": [], "foreign_asn": [], "unrouted": []}

    # Index BGP prefixes by first octet for faster lookup
    bgp_by_octet: dict[int, list[tuple[ipaddress.IPv4Network, int]]] = defaultdict(list)
    for prefix, asn in bgp_table.items():
        first_octet = int(prefix.network_address) >> 24
        bgp_by_octet[first_octet].append((prefix, asn))

    for net in cidrs:
        start_octet = int(net.network_address) >> 24
        end_octet = int(net.broadcast_address) >> 24
        candidate_octets = set(range(start_octet, min(end_octet + 1, 256)))

        found_country_asn = False
        found_foreign_asn = False
        found_any = False

        for octet in candidate_octets:
            for bgp_prefix, bgp_asn in bgp_by_octet.get(octet, []):
                if net.overlaps(bgp_prefix):
                    found_any = True
                    if bgp_asn in country_asns:
                        found_country_asn = True
                    else:
                        found_foreign_asn = True

        if found_country_asn:
            results["confirmed"].append(net)
        elif found_foreign_asn:
            results["foreign_asn"].append(net)
        elif not found_any:
            results["unrouted"].append(net)

    log.info(
        "BGP: %d confirmed (CN ASN), %d foreign ASN, %d unrouted",
        len(results["confirmed"]), len(results["foreign_asn"]), len(results["unrouted"]),
    )
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4: Intersection & Output
# ═══════════════════════════════════════════════════════════════════════════

def intersect_and_classify(
    rir_cidrs: list[ipaddress.IPv4Network],
    geoip_results: dict[str, list[ipaddress.IPv4Network]],
    bgp_results: dict[str, list[ipaddress.IPv4Network]] | None,
) -> dict[str, list[ipaddress.IPv4Network]]:
    """Classify CIDRs into confidence tiers based on multi-source agreement."""
    geoip_confirmed = set(geoip_results["confirmed"])
    geoip_mixed = set(geoip_results["mixed"])

    bgp_confirmed = set(bgp_results["confirmed"]) if bgp_results else None

    high = []
    medium = []
    low = []

    for net in rir_cidrs:
        geo_ok = net in geoip_confirmed
        geo_partial = net in geoip_mixed
        bgp_ok = net in bgp_confirmed if bgp_confirmed is not None else None

        if bgp_ok is None:
            # 2-source mode (no BGP) or 1-source (RIR only)
            if geo_ok:
                high.append(net)
            elif geo_partial:
                medium.append(net)
            else:
                low.append(net)
        else:
            # 3-source mode
            if geo_ok and bgp_ok:
                high.append(net)
            elif geo_ok or bgp_ok or geo_partial:
                medium.append(net)
            else:
                low.append(net)

    log.info(
        "Classification: %d HIGH, %d MEDIUM, %d LOW confidence",
        len(high), len(medium), len(low),
    )
    return {"high": high, "medium": medium, "low": low}


def count_ips(cidrs: list[ipaddress.IPv4Network]) -> int:
    return sum(net.num_addresses for net in cidrs)


def write_output(
    output_path: Path,
    classified: dict[str, list[ipaddress.IPv4Network]],
    include_medium: bool,
    sources_used: list[str],
    elapsed: float,
):
    """Write the cn-ipv4.txt output file."""
    cidrs = sorted(classified["high"])
    if include_medium:
        cidrs = sorted(set(cidrs) | set(classified["medium"]))

    tier_label = "HIGH + MEDIUM" if include_medium else "HIGH only"
    source_label = " + ".join(sources_used)

    header_lines = [
        f"# China (CN) IPv4 CIDR List",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"# Sources: {source_label}",
        f"# Confidence: {tier_label}",
        f"# CIDRs: {len(cidrs)}",
        f"# IPs: {count_ips(cidrs):,}",
        f"# Pipeline: generate-china-ip-list.py",
        f"# Elapsed: {elapsed:.1f}s",
        f"#",
        f"# Usage: Place alongside Detect-ZscalerRegion.ps1 / detect-zscaler-region.sh",
        f"#        for Layer 2 matching (Private PSE / China Premium detection).",
        f"#",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for line in header_lines:
            f.write(line + "\n")
        for net in cidrs:
            f.write(f"{net}\n")

    log.info("Wrote %s (%d CIDRs, %s IPs)", output_path, len(cidrs), f"{count_ips(cidrs):,}")

    # Also write stats JSON alongside
    stats_path = output_path.with_suffix(".stats.json")
    stats = {
        "country": COUNTRY,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 1),
        "sources": sources_used,
        "confidence": tier_label,
        "tiers": {
            tier: {"cidrs": len(classified[tier]), "ips": count_ips(classified[tier])}
            for tier in ("high", "medium", "low")
        },
        "output_cidrs": len(cidrs),
        "output_ips": count_ips(cidrs),
    }
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    log.info("Wrote %s", stats_path)


# ═══════════════════════════════════════════════════════════════════════════
# Main Pipeline
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    parser = argparse.ArgumentParser(
        description="Generate cn-ipv4.txt for Zscaler Region Detection (Layer 2 matching)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                   # RIR + BGP (default)
  %(prog)s --maxmind-db GeoLite2-City.mmdb   # RIR + GeoIP + BGP (best)
  %(prog)s --skip-bgp                        # RIR only (fastest)
  %(prog)s --include-medium                  # Include medium-confidence CIDRs
  %(prog)s --output /path/to/cn-ipv4.txt     # Custom output path
        """,
    )
    parser.add_argument(
        "--output", "-o",
        default="cn-ipv4.txt",
        help="Output file path (default: cn-ipv4.txt)",
    )
    parser.add_argument(
        "--maxmind-db",
        default=None,
        help="Path to MaxMind GeoLite2-City.mmdb for GeoIP validation (optional)",
    )
    parser.add_argument(
        "--skip-bgp",
        action="store_true",
        help="Skip BGP validation (faster but less accurate)",
    )
    parser.add_argument(
        "--include-medium",
        action="store_true",
        help="Include MEDIUM confidence CIDRs (default: HIGH only)",
    )
    args = parser.parse_args()

    output_path = Path(args.output)

    log.info("=" * 60)
    log.info("China IP List Generator")
    log.info("=" * 60)
    t_start = time.monotonic()

    sources_used = ["APNIC RIR"]

    async with httpx.AsyncClient(follow_redirects=True) as client:
        # Phase 1: RIR allocations (always)
        log.info("")
        log.info("--- Phase 1: APNIC RIR Allocation ---")
        rir_cidrs = await fetch_rir_allocations(client)
        log.info("RIR: %d CIDRs covering %s IPs", len(rir_cidrs), f"{count_ips(rir_cidrs):,}")

        if not rir_cidrs:
            log.error("No RIR allocations found for CN -- check network connectivity")
            sys.exit(1)

        # Phase 2: GeoIP validation (optional)
        log.info("")
        log.info("--- Phase 2: GeoIP Validation ---")
        geoip_results = geoip_validate(rir_cidrs, args.maxmind_db)
        if args.maxmind_db and os.path.exists(args.maxmind_db):
            sources_used.append("MaxMind GeoLite2")

        # Phase 3: BGP validation (optional)
        bgp_results = None
        if not args.skip_bgp:
            log.info("")
            log.info("--- Phase 3: BGP Validation ---")
            bgp_table = await fetch_bgp_table(client)
            country_asns = await fetch_country_asns(client)
            if country_asns:
                bgp_results = bgp_validate(rir_cidrs, bgp_table, country_asns)
                sources_used.append("bgp.tools")
            else:
                log.warning("No CN ASNs found -- skipping BGP validation")
        else:
            log.info("")
            log.info("--- Phase 3: BGP Validation (SKIPPED) ---")

        # Phase 4: Intersect & output
        log.info("")
        log.info("--- Phase 4: Classification & Output ---")
        classified = intersect_and_classify(rir_cidrs, geoip_results, bgp_results)

        elapsed = time.monotonic() - t_start
        write_output(output_path, classified, args.include_medium, sources_used, elapsed)

    # Summary
    log.info("")
    log.info("=" * 60)
    log.info("COMPLETE in %.1fs", elapsed)
    log.info("=" * 60)
    for tier in ("high", "medium", "low"):
        c = classified[tier]
        log.info("  %-8s %6d CIDRs  %12s IPs", tier.upper(), len(c), f"{count_ips(c):,}")
    log.info("")
    log.info("  Output: %s", output_path)
    log.info("  Sources: %s", " + ".join(sources_used))
    if not args.maxmind_db:
        log.info("")
        log.info("  TIP: For better accuracy, pass --maxmind-db GeoLite2-City.mmdb")
        log.info("  Get a free license key at https://www.maxmind.com/en/geolite2/signup")


if __name__ == "__main__":
    asyncio.run(main())
