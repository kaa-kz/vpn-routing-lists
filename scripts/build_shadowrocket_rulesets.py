#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SECTION_MAP = {
    "# ru-blocked-cleaned -> PROXY": "ru-blocked-cleaned.list",
    "# geosite:meta -> PROXY": "meta.list",
    "# geosite:telegram -> PROXY": "telegram.list",
    "# geosite:youtube -> PROXY": "youtube.list",
    "# SERVER_BLOCK -> DIRECT": "server-blocklist.list",
    "# geosite:category-bank-ru -> DIRECT": "category-bank-ru.list",
    "# geosite:category-ru -> DIRECT": "category-ru.list",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_policy(line: str) -> str:
    p = [x.strip() for x in line.split(",")]
    if len(p) < 3:
        raise RuntimeError(f"bad managed rule: {line}")
    typ = p[0].upper()
    if typ in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOIP"}:
        return ",".join(p[:2])
    if typ in {"IP-CIDR", "IP-CIDR6"}:
        tail = [x for x in p[3:] if x]
        return ",".join(p[:2] + tail)
    raise RuntimeError(f"unsupported managed rule: {line}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--managed", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--manifest-output", required=True)
    a = ap.parse_args()

    managed = Path(a.managed)
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    buckets = {name: [] for name in SECTION_MAP.values()}
    current = None
    for raw in managed.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line == "[Rule]":
            continue
        if line.startswith("#"):
            current = SECTION_MAP.get(line)
            continue
        if current:
            buckets[current].append(strip_policy(line))

    for name, values in buckets.items():
        if not values:
            raise RuntimeError(f"empty RULE-SET section: {name}")
        dedup = list(dict.fromkeys(values))
        if len(dedup) != len(values):
            values = dedup
        (out / name).write_text("\n".join(values) + "\n", encoding="utf-8", newline="\n")

    if len(buckets["ru-blocked-cleaned.list"]) != 15767:
        raise RuntimeError(f"ru-blocked-cleaned count mismatch: {len(buckets['ru-blocked-cleaned.list'])}")
    if "DOMAIN,zonafilm.ru" in buckets["ru-blocked-cleaned.list"] or "DOMAIN-SUFFIX,zonafilm.ru" in buckets["ru-blocked-cleaned.list"]:
        raise RuntimeError("zonafilm.ru must not be in ru-blocked-cleaned")

    manifest = {
        "format": "Shadowrocket RULE-SET",
        "files": {
            name: {"rules": len(values), "sha256": sha256(out / name)}
            for name, values in buckets.items()
        },
    }
    Path(a.manifest_output).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
