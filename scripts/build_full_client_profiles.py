#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import time
from pathlib import Path


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ordered_unique(values: list[str]) -> tuple[list[str], int]:
    seen = set()
    out = []
    removed = 0
    for v in values:
        if v in seen:
            removed += 1
            continue
        seen.add(v)
        out.append(v)
    return out, removed


def parse_shadow_rule(line: str):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("["):
        return None
    p = [x.strip() for x in line.split(",")]
    typ = p[0].upper()
    if typ in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP") and len(p) >= 3:
        policy = p[2].upper()
        if policy not in ("PROXY", "DIRECT"):
            return None
        if typ == "DOMAIN":
            kind, value = "full", p[1].lower()
        elif typ == "DOMAIN-SUFFIX":
            kind, value = "domain", p[1].lower()
        elif typ == "DOMAIN-KEYWORD":
            kind, value = "keyword", p[1].lower()
        elif typ in ("IP-CIDR", "IP-CIDR6"):
            kind, value = "ip", p[1]
        else:
            kind, value = "geoip", p[1].lower()
        return (kind, value, policy, line)
    return None


def rule_key(rule):
    return (rule[0], rule[1])


def load_managed(path: Path):
    proxy, direct = [], []
    for raw in path.read_text(encoding="utf-8").splitlines():
        r = parse_shadow_rule(raw)
        if not r:
            continue
        (proxy if r[2] == "PROXY" else direct).append(r)
    if not proxy or not direct:
        fail("managed rules must contain PROXY and DIRECT")
    return proxy, direct


def load_manual(path: Path):
    j = json.loads(path.read_text(encoding="utf-8"))
    if j.get("precedence") != "PROXY_OVER_DIRECT":
        fail("manual policy precedence must be PROXY_OVER_DIRECT")
    out = []
    for policy, sitekey, ipkey in [
        ("PROXY", "proxy_sites", "proxy_ip"),
        ("DIRECT", "direct_sites", "direct_ip"),
    ]:
        for token in j.get(sitekey, []):
            if ":" not in token:
                fail(f"bad manual site token: {token}")
            pre, val = token.split(":", 1)
            pre, val = pre.lower(), val.lower()
            if pre not in ("domain", "full", "keyword"):
                fail(f"unsupported manual site token: {token}")
            out.append((pre, val, policy, token))
        for token in j.get(ipkey, []):
            low = token.lower()
            if low.startswith("geoip:"):
                out.append(("geoip", low.split(":", 1)[1], policy, token))
            else:
                ipaddress.ip_network(token, strict=False)
                out.append(("ip", token, policy, token))

    proxy_keys = {rule_key(r) for r in out if r[2] == "PROXY"}
    ded, seen = [], set()
    for r in out:
        k = (r[0], r[1], r[2])
        if k in seen:
            continue
        seen.add(k)
        if r[2] == "DIRECT" and rule_key(r) in proxy_keys:
            continue
        ded.append(r)
    return j, ded


def domain_covered(cover_kind, cover_value, target_kind, target_value):
    if cover_kind == "domain":
        if target_kind in ("domain", "full"):
            return target_value == cover_value or target_value.endswith("." + cover_value)
    if cover_kind == "full" and target_kind == "full":
        return target_value == cover_value
    if cover_kind == "keyword" and target_kind == "keyword":
        return target_value == cover_value
    return False


def covered_by(rule, covers):
    kind, val, policy, _ = rule
    for ck, cv, cp, _ in covers:
        if cp != policy:
            continue
        if kind in ("domain", "full", "keyword") and ck in ("domain", "full", "keyword"):
            if domain_covered(ck, cv, kind, val):
                return True
        elif kind == ck and val == cv:
            return True
    return False


def overridden_by_proxy(rule, proxy_rules):
    if rule[2] != "DIRECT":
        return False
    kind, val, _, _ = rule
    for pk, pv, pp, _ in proxy_rules:
        if pp != "PROXY":
            continue
        if kind in ("domain", "full", "keyword") and pk in ("domain", "full", "keyword"):
            if domain_covered(pk, pv, kind, val):
                return True
        elif kind == pk and val == pv:
            return True
    return False


def filter_manual(manual_rules, managed_proxy, managed_direct):
    emitted, covered_same, overridden = [], [], []
    for r in manual_rules:
        same = managed_proxy if r[2] == "PROXY" else managed_direct
        if covered_by(r, same):
            covered_same.append(r)
            continue
        if overridden_by_proxy(r, managed_proxy):
            overridden.append(r)
            continue
        emitted.append(r)
    return emitted, covered_same, overridden


def shadow_line(rule):
    kind, val, policy, _ = rule
    if kind == "domain":
        return f"DOMAIN-SUFFIX,{val},{policy}"
    if kind == "full":
        return f"DOMAIN,{val},{policy}"
    if kind == "keyword":
        return f"DOMAIN-KEYWORD,{val},{policy}"
    if kind == "geoip":
        return f"GEOIP,{val.upper()},{policy}"
    if kind == "ip":
        typ = "IP-CIDR6" if ":" in val else "IP-CIDR"
        return f"{typ},{val},{policy},no-resolve"
    fail(f"unknown rule kind {kind}")


def happ_token(rule):
    kind, val, policy, _ = rule
    if kind in ("domain", "full", "keyword"):
        return f"{kind}:{val}", "site"
    if kind == "geoip":
        return f"geoip:{val}", "ip"
    if kind == "ip":
        return val, "ip"
    fail(f"unknown rule kind {kind}")


def load_server_ipv4(server_dir: Path):
    m = json.loads((server_dir / "manifest.json").read_text(encoding="utf-8"))
    ips = []
    for raw in (server_dir / m["ipv4_file"]).read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        f = raw.strip().split("\t")
        if len(f) != 2 or f[0] != "ip-cidr":
            fail(f"bad server IPv4 line {raw!r}")
        ips.append(f[1])
    if len(ips) != m["ipv4_cidr_count"]:
        fail("server IPv4 count mismatch")
    return m, ips


def build_shadow(template_path, managed_path, manual_path, version, output):
    template = template_path.read_text(encoding="utf-8")
    for tok in (
        "__VERSION__",
        "__MANAGED_PROXY_RULES__",
        "__COMMON_PROXY_RULES__",
        "__MANAGED_DIRECT_RULES__",
        "__COMMON_DIRECT_RULES__",
    ):
        if tok not in template:
            fail(f"missing Shadow template token {tok}")

    managed_proxy, managed_direct = load_managed(managed_path)
    _, manual = load_manual(manual_path)
    emitted, covered, overridden = filter_manual(manual, managed_proxy, managed_direct)
    common_proxy = [r for r in emitted if r[2] == "PROXY"]
    common_direct = [r for r in emitted if r[2] == "DIRECT"]

    mp, seen = [], set()
    for r in managed_proxy:
        k = (r[0], r[1], r[2])
        if k not in seen:
            seen.add(k)
            mp.append(r)
    proxy_sem = mp + common_proxy

    md, seen_d = [], set()
    for r in managed_direct:
        if overridden_by_proxy(r, proxy_sem):
            continue
        k = (r[0], r[1], r[2])
        if k not in seen_d:
            seen_d.add(k)
            md.append(r)

    text = template.replace("__VERSION__", version)
    text = text.replace("__MANAGED_PROXY_RULES__", "\n".join(shadow_line(r) for r in mp))
    text = text.replace("__COMMON_PROXY_RULES__", "\n".join(shadow_line(r) for r in common_proxy))
    text = text.replace("__MANAGED_DIRECT_RULES__", "\n".join(shadow_line(r) for r in md))
    text = text.replace("__COMMON_DIRECT_RULES__", "\n".join(shadow_line(r) for r in common_direct))
    if "__" in text:
        fail("unresolved Shadow template token")

    z = "DOMAIN-SUFFIX,zonafilm.ru,PROXY"
    if z not in text:
        fail("zonafilm.ru explicit PROXY missing")
    ru = "DOMAIN-SUFFIX,ru,DIRECT"
    if ru in text and text.index(z) > text.index(ru):
        fail("zonafilm PROXY must precede .ru DIRECT")
    if "FINAL,PROXY" not in text:
        fail("FINAL,PROXY missing")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8", newline="\n")
    return {
        "managed_proxy_rules": len(mp),
        "managed_direct_rules": len(md),
        "manual_source_rules": len(manual),
        "manual_emitted_rules": len(emitted),
        "manual_covered_by_managed": len(covered),
        "manual_direct_overridden_by_managed_proxy": len(overridden),
        "common_proxy_emitted": len(common_proxy),
        "common_direct_emitted": len(common_direct),
        "sha256": sha256(output),
        "bytes": output.stat().st_size,
    }, emitted, covered, overridden


def build_happ(template_path, server_dir, version, output, timestamp, emitted_manual):
    obj = json.loads(template_path.read_text(encoding="utf-8"))
    server_manifest, server_ips = load_server_ipv4(server_dir)
    obj["Name"] = version
    obj["LastUpdated"] = timestamp
    obj["Geositeurl"] = "https://raw.githubusercontent.com/kaa-kz/vpn-routing-lists/client/geosite.dat"

    for r in emitted_manual:
        token, bucket = happ_token(r)
        if bucket == "site":
            dest = obj["ProxySites"] if r[2] == "PROXY" else obj["DirectSites"]
        else:
            dest = obj["ProxyIp"] if r[2] == "PROXY" else obj["DirectIp"]
        dest.append(token)

    obj["DirectIp"].extend(server_ips)
    for key in ("DirectSites", "ProxySites", "DirectIp", "ProxyIp"):
        obj[key], _ = ordered_unique(obj.get(key, []))

    if obj.get("RouteOrder") != "block-proxy-direct":
        fail("HAPP RouteOrder must be block-proxy-direct")
    if "domain:zonafilm.ru" not in obj["ProxySites"]:
        fail("HAPP zonafilm.ru explicit PROXY missing")
    if set(obj["ProxySites"]) & set(obj["DirectSites"]):
        fail("HAPP exact site policy conflict")
    if set(obj["ProxyIp"]) & set(obj["DirectIp"]):
        fail("HAPP exact IP policy conflict")

    payload = json.dumps(obj, ensure_ascii=False, indent=4, sort_keys=False).encode("utf-8")
    uri = "happ://routing/add/" + base64.b64encode(payload).decode("ascii") + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(uri, encoding="utf-8", newline="\n")
    check = json.loads(base64.b64decode(uri.strip().split("happ://routing/add/", 1)[1]).decode("utf-8"))
    if check["Name"] != version:
        fail("HAPP name mismatch")

    return {
        "name": check["Name"],
        "server_block_version": server_manifest["version"],
        "direct_sites": len(check["DirectSites"]),
        "proxy_sites": len(check["ProxySites"]),
        "direct_ip": len(check["DirectIp"]),
        "proxy_ip": len(check["ProxyIp"]),
        "sha256": sha256(output),
        "bytes": output.stat().st_size,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--version-name", required=True)
    p.add_argument("--managed-shadowrocket", required=True)
    p.add_argument("--server-block-dir", required=True)
    p.add_argument("--manual-policy", default="config/client-manual-common.json")
    p.add_argument("--shadow-template", default="config/shadowrocket-base-template.conf")
    p.add_argument("--happ-template", default="config/happ-base-template.json")
    p.add_argument("--shadow-output", required=True)
    p.add_argument("--happ-output", required=True)
    p.add_argument("--manifest-output", required=True)
    p.add_argument("--timestamp", type=int, default=0)
    a = p.parse_args()

    ts = a.timestamp or int(time.time())
    shadow, emitted, covered, overridden = build_shadow(
        Path(a.shadow_template),
        Path(a.managed_shadowrocket),
        Path(a.manual_policy),
        a.version_name,
        Path(a.shadow_output),
    )
    happ = build_happ(
        Path(a.happ_template),
        Path(a.server_block_dir),
        a.version_name,
        Path(a.happ_output),
        ts,
        emitted,
    )
    manifest = {
        "version": a.version_name,
        "shadowrocket": shadow,
        "happ": happ,
        "shared_manual": {
            "emitted": len(emitted),
            "covered_by_managed": len(covered),
            "direct_overridden_by_proxy": len(overridden),
        },
    }
    out = Path(a.manifest_output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
