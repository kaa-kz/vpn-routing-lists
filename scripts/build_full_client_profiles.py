#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
from pathlib import Path


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rule_policy(line: str) -> str | None:
    if line.startswith("[") or not line or line.startswith("#"):
        return None
    parts = [p.strip() for p in line.split(",")]
    if "PROXY" in parts:
        return "PROXY"
    if "DIRECT" in parts:
        return "DIRECT"
    return None


def load_managed_rules(path: Path) -> tuple[list[str], list[str]]:
    proxy: list[str] = []
    direct: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        policy = rule_policy(line)
        if policy == "PROXY":
            proxy.append(line)
        elif policy == "DIRECT":
            direct.append(line)
    if not proxy or not direct:
        fail("managed Shadowrocket rules must contain both PROXY and DIRECT rules")
    if len(proxy) != len(set(proxy)):
        fail("duplicate managed PROXY rules")
    if len(direct) != len(set(direct)):
        fail("duplicate managed DIRECT rules")
    return proxy, direct


def load_server_ipv4(server_dir: Path) -> tuple[str, list[str]]:
    manifest = json.loads((server_dir / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    ipv4_file = server_dir / manifest["ipv4_file"]
    ips: list[str] = []
    for raw in ipv4_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] != "ip-cidr":
            fail(f"bad SERVER_BLOCK IPv4 line: {line!r}")
        ips.append(fields[1])
    if len(ips) != manifest["ipv4_cidr_count"]:
        fail("SERVER_BLOCK IPv4 count mismatch")
    return version, ips


def build_shadowrocket(template_path: Path, managed_path: Path, version_name: str, output: Path) -> dict:
    template = template_path.read_text(encoding="utf-8")
    for token in ("__VERSION__", "__MANAGED_PROXY_RULES__", "__MANAGED_DIRECT_RULES__"):
        if token not in template:
            fail(f"Shadowrocket template token missing: {token}")

    proxy, direct = load_managed_rules(managed_path)
    proxy_block = "# Managed canonical PROXY rules — " + version_name + "\n" + "\n".join(proxy)
    direct_block = "# Managed canonical DIRECT rules — " + version_name + "\n" + "\n".join(direct)
    text = template.replace("__VERSION__", version_name)
    text = text.replace("__MANAGED_PROXY_RULES__", proxy_block)
    text = text.replace("__MANAGED_DIRECT_RULES__", direct_block)
    if "__" in text:
        fail("unresolved Shadowrocket template token")

    proxy_anchor = "DOMAIN,003.su,PROXY"
    direct_anchor = "DOMAIN-SUFFIX,ru,DIRECT"
    if proxy_anchor not in text or direct_anchor not in text:
        fail("required canonical Shadowrocket anchors missing")
    if text.index(proxy_anchor) > text.index(direct_anchor):
        fail("Shadowrocket first-match invariant violated: ru-blocked-cleaned must precede .ru DIRECT")
    if "denylist release 2.4.1" in text.lower():
        fail("stale 2.4.1 marker remains in Shadowrocket profile")
    if not text.rstrip().splitlines()[-4:].count("FINAL,PROXY") and "FINAL,PROXY" not in text:
        fail("Shadowrocket FINAL,PROXY missing")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")
    return {
        "proxy_managed_rules": len(proxy),
        "direct_managed_rules": len(direct),
        "sha256": sha256(output),
        "bytes": output.stat().st_size,
    }


def build_happ(template_path: Path, server_dir: Path, version_name: str, output: Path, timestamp: int) -> dict:
    obj = json.loads(template_path.read_text(encoding="utf-8"))
    server_version, ipv4 = load_server_ipv4(server_dir)
    expected_name = server_version.replace(".", "-")
    if version_name != expected_name:
        fail(f"HAPP version name {version_name!r} does not match SERVER_BLOCK {server_version!r}")

    obj["Name"] = version_name
    obj["LastUpdated"] = timestamp
    obj["Geositeurl"] = "https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/client/geosite.dat"

    direct_ip = [x for x in obj.get("DirectIp", []) if x not in ipv4]
    direct_ip.extend(ipv4)
    obj["DirectIp"] = direct_ip

    required_direct = ["geosite:server-blocklist", "geosite:category-bank-ru", "geosite:category-ru"]
    required_proxy = ["geosite:ru-blocked-cleaned", "geosite:meta", "geosite:telegram", "geosite:youtube"]
    for v in reversed(required_direct):
        if v in obj["DirectSites"]:
            obj["DirectSites"].remove(v)
        obj["DirectSites"].insert(0, v)
    for v in reversed(required_proxy):
        if v in obj["ProxySites"]:
            obj["ProxySites"].remove(v)
        obj["ProxySites"].insert(0, v)

    if obj.get("RouteOrder") != "block-proxy-direct":
        fail("HAPP RouteOrder must be block-proxy-direct")
    if len(set(obj["DirectSites"])) != len(obj["DirectSites"]):
        fail("duplicate HAPP DirectSites entries")
    if len(set(obj["ProxySites"])) != len(obj["ProxySites"]):
        fail("duplicate HAPP ProxySites entries")
    if len(set(obj["DirectIp"])) != len(obj["DirectIp"]):
        fail("duplicate HAPP DirectIp entries")

    payload = json.dumps(obj, ensure_ascii=False, indent=4, sort_keys=False).encode("utf-8")
    uri = "happ://routing/add/" + base64.b64encode(payload).decode("ascii") + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(uri, encoding="utf-8", newline="\n")

    # Round-trip validation.
    encoded = output.read_text(encoding="utf-8").strip().split("happ://routing/add/", 1)[1]
    check = json.loads(base64.b64decode(encoded).decode("utf-8"))
    if check["Name"] != version_name or check["Geositeurl"] != obj["Geositeurl"]:
        fail("HAPP round-trip validation failed")

    return {
        "name": check["Name"],
        "direct_sites": len(check["DirectSites"]),
        "proxy_sites": len(check["ProxySites"]),
        "direct_ip": len(check["DirectIp"]),
        "proxy_ip": len(check["ProxyIp"]),
        "sha256": sha256(output),
        "bytes": output.stat().st_size,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--version-name", required=True)
    p.add_argument("--managed-shadowrocket", required=True)
    p.add_argument("--server-block-dir", required=True)
    p.add_argument("--shadow-template", default="config/shadowrocket-base-template.conf")
    p.add_argument("--happ-template", default="config/happ-base-template.json")
    p.add_argument("--shadow-output", required=True)
    p.add_argument("--happ-output", required=True)
    p.add_argument("--manifest-output", required=True)
    p.add_argument("--timestamp", type=int, default=0)
    a = p.parse_args()

    timestamp = a.timestamp or int(time.time())
    shadow = build_shadowrocket(Path(a.shadow_template), Path(a.managed_shadowrocket), a.version_name, Path(a.shadow_output))
    happ = build_happ(Path(a.happ_template), Path(a.server_block_dir), a.version_name, Path(a.happ_output), timestamp)
    manifest = {
        "version": a.version_name,
        "shadowrocket": shadow,
        "happ": happ,
    }
    out = Path(a.manifest_output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
