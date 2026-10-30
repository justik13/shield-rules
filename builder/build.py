#!/usr/bin/env python3
"""Shield Rules Builder.

Fetches and compiles IPv4 prefix lists for network protection:
1. rkn.txt: Regulators and active scanning subnets (inbound DROP).
2. vk.txt: VK, OK, and Messenger Max services (outbound REJECT on foreign nodes).
"""

from __future__ import annotations

import ipaddress
import logging
import sys
import urllib.request
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("shield-builder")

# Primary verified upstream feeds
UPSTREAM_RKN_URL = "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-v4.txt"
UPSTREAM_VK_URL = "https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist-vk-v4.txt"

# Core autonomous systems to query directly via RIPE Stat API
CORE_RKN_ASNS = [
    "AS61280",  # FGUP "GRCHC" / CMU SSOP
    "AS34500",  # FGUP CTSPI MGA Russia
    "AS51932",  # FGUP Goskorporatsiya po OrVD
    "AS57835",  # JSC ELEKTROSVYAZ
    "AS197153", # GUVD Sverdlovsk
    "AS206684", # FGUP VNIIOFI
    "AS216080", # FSUE ZashchitaInfoTrans
]

CORE_VK_ASNS = [
    "AS47764",  # VK Company
    "AS47541",  # VK / Mail.ru
    "AS47542",  # VK / Odnoklassniki
    "AS48287",  # VK LLC
    "AS16276",  # VK
    "AS209405", # VK
    "AS212450", # VK
    "AS212502", # VK
    "AS214944", # VK
    "AS216390", # VK
]


def fetch_url(url: str, timeout: int = 30) -> list[str]:
    """Fetch text lines from URL."""
    req = urllib.request.Request(url, headers={"User-Agent": "ShieldRulesBuilder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return []


def fetch_as_prefixes(asn: str) -> list[str]:
    """Fetch announced prefixes for ASN from RIPE Stat API."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    req = urllib.request.Request(url, headers={"User-Agent": "ShieldRulesBuilder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            prefixes = data.get("data", {}).get("prefixes", [])
            return [p.get("prefix") for p in prefixes if p.get("prefix")]
    except Exception as exc:
        logger.warning("Failed to query RIPE Stat for %s: %s", asn, exc)
        return []


def sanitize_and_sort_cidrs(raw_entries: list[str]) -> list[str]:
    """Validate, deduplicate, collapse, and sort IPv4 CIDR blocks."""
    networks = set()
    for raw in raw_entries:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            if net.version == 4:
                # Exclude loopback, multicast, private RFC1918, link-local
                if not (net.is_loopback or net.is_multicast or net.is_private or net.is_link_local):
                    networks.add(net)
        except ValueError:
            continue

    # Collapse overlapping networks and sort
    collapsed = ipaddress.collapse_addresses(networks)
    return [str(net) for net in sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))]


def build_rkn_list() -> list[str]:
    """Build sanitized RKN prefix list."""
    entries = fetch_url(UPSTREAM_RKN_URL)
    for asn in CORE_RKN_ASNS:
        entries.extend(fetch_as_prefixes(asn))
    return sanitize_and_sort_cidrs(entries)


def build_vk_list() -> list[str]:
    """Build sanitized VK prefix list."""
    entries = fetch_url(UPSTREAM_VK_URL)
    for asn in CORE_VK_ASNS:
        entries.extend(fetch_as_prefixes(asn))
    return sanitize_and_sort_cidrs(entries)


def main() -> int:
    logger.info("Building RKN prefix list...")
    rkn_cidrs = build_rkn_list()
    if rkn_cidrs:
        with open("rkn.txt", "w", encoding="utf-8") as f:
            f.write("# Autonomous IP Prefix List: Regulators & Scanners (Inbound DROP)\n")
            f.write(f"# Total: {len(rkn_cidrs)} prefixes\n")
            f.write("\n".join(rkn_cidrs) + "\n")
        logger.info("Successfully wrote %d prefixes to rkn.txt", len(rkn_cidrs))
    else:
        logger.error("RKN prefix list is empty, skipping write to prevent truncation")

    logger.info("Building VK/Max prefix list...")
    vk_cidrs = build_vk_list()
    if vk_cidrs:
        with open("vk.txt", "w", encoding="utf-8") as f:
            f.write("# Autonomous IP Prefix List: VK / OK / Messenger Max (Outbound REJECT)\n")
            f.write(f"# Total: {len(vk_cidrs)} prefixes\n")
            f.write("\n".join(vk_cidrs) + "\n")
        logger.info("Successfully wrote %d prefixes to vk.txt", len(vk_cidrs))
    else:
        logger.error("VK/Max prefix list is empty, skipping write to prevent truncation")

    return 0


if __name__ == "__main__":
    sys.exit(main())
