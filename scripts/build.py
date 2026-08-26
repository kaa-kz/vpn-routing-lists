#!/usr/bin/env python3
"""Build ru-blocked-custom and client-specific text artifacts.

Source parity with runetfreedom/russia-blocked-geosite:
  ru-blocked = Community Antifilter + Re:filter

Local policy is then applied:
  ru-blocked-custom = (upstream union + additions) - exclusions

Exclusions are suffix-aware: excluding example.com also excludes sub.example.com.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

COMMUNITY_URL = "https://community.antifilter.download/list/domains.lst"
REFILTER_URL = "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/refs/heads/main/domains_all.lst"


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-routing-lists-builder/1.0"})
    with urllib.request.urlopen(req, timeout=120) as response:
        data = response.read()
    return data.decode("utf-8-sig")


def clean_rule(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    line = line.split("#", 1)[0].strip()
    if not line:
        return None

    # Upstream files are currently plain domains, but accept common geosite
    # prefixes defensively so the builder does not silently break if a source
    # changes representation.
    for prefix in ("domain:", "full:"):
        if line.startswith(prefix):
            line = line[len(prefix):]
            break

    # This custom category intentionally contains only suffix/domain rules.
    if line.startswith(("regexp:", "keyword:", "include:")):
        return None

    line = line.split()[0].strip().rstrip(".").lower()
    if not line or "." not in line:
        return None
    return line


def parse_rules(text: str) -> set[str]:
    out: set[str] = set()
    for raw in text.splitlines():
        rule = clean_rule(raw)
        if rule:
            out.add(rule)
    return out


def read_local(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return parse_rules(path.read_text(encoding="utf-8"))


def excluded(domain: str, exclusions: set[str]) -> bool:
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in exclusions)


def to_ascii_domain(domain: str) -> str:
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--community-data", required=True, type=Path)
    parser.add_argument("--publish", required=True, type=Path)
    parser.add_argument("--exclusions", default=Path("source/exclusions.txt"), type=Path)
    parser.add_argument("--additions", default=Path("source/additions.txt"), type=Path)
    args = parser.parse_args()

    args.community_data.mkdir(parents=True, exist_ok=True)
    args.publish.mkdir(parents=True, exist_ok=True)

    community_text = fetch_text(COMMUNITY_URL)
    refilter_text = fetch_text(REFILTER_URL)

    community = parse_rules(community_text)
    refilter = parse_rules(refilter_text)
    exclusions = read_local(args.exclusions)
    additions = read_local(args.additions)

    upstream = community | refilter
    combined = upstream | additions
    custom = {d for d in combined if not excluded(d, exclusions)}
    ordered = sorted(custom)

    # V2Fly input: an omitted prefix is a subdomain/suffix rule.
    geosite_source = "\n".join(ordered) + "\n"
    (args.community_data / "ru-blocked-custom").write_text(geosite_source, encoding="utf-8")

    plain = geosite_source
    (args.publish / "ru-blocked-custom.txt").write_text(plain, encoding="utf-8")

    shadowrocket_lines = [f"DOMAIN-SUFFIX,{to_ascii_domain(d)}" for d in ordered]
    shadowrocket = "\n".join(shadowrocket_lines) + "\n"
    (args.publish / "shadowrocket-ru-blocked.list").write_text(shadowrocket, encoding="utf-8")

    removed = sorted(d for d in combined if excluded(d, exclusions))
    missing_exclusions = sorted(e for e in exclusions if not any(d == e or d.endswith("." + e) for d in combined))

    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "upstream": {
            "community_antifilter": COMMUNITY_URL,
            "refilter": REFILTER_URL,
        },
        "counts": {
            "community_antifilter": len(community),
            "refilter": len(refilter),
            "upstream_union": len(upstream),
            "local_additions": len(additions),
            "local_exclusions": len(exclusions),
            "custom_final": len(custom),
            "rules_removed_by_exclusions": len(removed),
        },
        "excluded_suffixes": sorted(exclusions),
        "removed_rules": removed,
        "exclusions_not_present_upstream_or_additions": missing_exclusions,
        "sha256": {
            "ru-blocked-custom.txt": sha256_bytes(plain.encode("utf-8")),
            "shadowrocket-ru-blocked.list": sha256_bytes(shadowrocket.encode("utf-8")),
        },
    }
    (args.publish / "build-metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    # Safety assertions for the confirmed exception.
    if "cloudflare-dns.com" in exclusions:
        if any(d == "cloudflare-dns.com" or d.endswith(".cloudflare-dns.com") for d in custom):
            raise SystemExit("cloudflare-dns.com exclusion failed")

    if not ordered:
        raise SystemExit("custom list is unexpectedly empty")

    print(json.dumps(metadata["counts"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
