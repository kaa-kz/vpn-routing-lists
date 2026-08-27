#!/usr/bin/env python3
"""Build exact-hostname client artifacts for ru-blocked-cleaned.

Input is the canonical cleaned hostname list. The same hostnames are emitted as:
- Shadowrocket RULE-SET lines: DOMAIN,<hostname>
- V2Ray geosite source lines: full:<hostname>

Using exact/full rules is intentional: do not widen a hostname to its parent suffix.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_hostnames(path: Path, expected_count: int) -> list[str]:
    items = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(items) != expected_count:
        raise SystemExit(f"expected {expected_count} hostnames, got {len(items)}")
    if len(items) != len(set(items)):
        raise SystemExit("duplicate hostnames in canonical input")
    for host in items:
        if host != host.lower():
            raise SystemExit(f"hostname is not lowercase: {host}")
        if any(ch.isspace() for ch in host):
            raise SystemExit(f"hostname contains whitespace: {host!r}")
        if host.startswith(".") or host.endswith("."):
            raise SystemExit(f"hostname has leading/trailing dot: {host}")
    return items


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--expected-count", type=int, default=15759)
    args = ap.parse_args()

    src = Path(args.input)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    geosite_source_dir = out / "geosite-source"
    geosite_source_dir.mkdir(parents=True, exist_ok=True)

    hosts = load_hostnames(src, args.expected_count)

    shadowrocket = out / "ru-blocked-cleaned.list"
    shadowrocket.write_text("".join(f"DOMAIN,{host}\n" for host in hosts), encoding="utf-8")

    geosite_source = geosite_source_dir / "ru-blocked-cleaned"
    geosite_source.write_text("".join(f"full:{host}\n" for host in hosts), encoding="utf-8")

    # Independent exact-set validation.
    shadow_hosts = [line.split(",", 1)[1] for line in shadowrocket.read_text(encoding="utf-8").splitlines() if line]
    geosite_hosts = [line[5:] for line in geosite_source.read_text(encoding="utf-8").splitlines() if line]
    if shadow_hosts != hosts:
        raise SystemExit("Shadowrocket output does not exactly match canonical input")
    if geosite_hosts != hosts:
        raise SystemExit("geosite source does not exactly match canonical input")

    print(f"input_count={len(hosts)}")
    print(f"input_sha256={sha256(src)}")
    print(f"shadowrocket_count={len(shadow_hosts)}")
    print(f"shadowrocket_sha256={sha256(shadowrocket)}")
    print(f"geosite_source_count={len(geosite_hosts)}")
    print(f"geosite_source_sha256={sha256(geosite_source)}")


if __name__ == "__main__":
    main()
