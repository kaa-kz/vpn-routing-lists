#!/usr/bin/env python3
"""Interactive/non-interactive client routing bundle orchestrator."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = ROOT / "canonical/server-block"
RU_CANONICAL = ROOT / "generated/final/ru-blocked-server-allow.cleaned.txt"
RU_ORCHESTRATOR = ROOT / "scripts/ru_blocked_orchestrator.py"
POLICY_DEFAULT = ROOT / "config/client-category-policy.json"
GO_BUILDER = ROOT / "scripts/build_client_bundle.go"
RUNET_GEOSITE_URL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
RUNET_SHA_URL = RUNET_GEOSITE_URL + ".sha256sum"


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def lines(path: Path) -> list[str]:
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-routing-client-bundle/1"})
    with urllib.request.urlopen(req, timeout=180) as r:
        data = r.read()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%SZ")


def detect_server_version(requested: str) -> tuple[str, Path, dict]:
    if requested == "latest":
        latest = SERVER_ROOT / "LATEST"
        if not latest.exists():
            fail("canonical/server-block/LATEST not found")
        version = latest.read_text(encoding="utf-8").strip()
    else:
        version = requested
    d = SERVER_ROOT / "versions" / version
    manifest_path = d / "manifest.json"
    if not manifest_path.exists():
        fail(f"SERVER_BLOCK {version} manifest not found")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return version, d, manifest


def pick_ru_mode(mode: str, server_version: str, server_manifest: dict) -> str:
    if mode != "interactive":
        return mode
    current_count = len(lines(RU_CANONICAL)) if RU_CANONICAL.exists() else 0
    print("\nНайдены исходники:")
    print(f"  SERVER_BLOCK {server_version}: {server_manifest['domain_suffix_count']} доменов + {server_manifest['ipv4_cidr_count']} IPv4")
    print(f"  ru-blocked-cleaned: {current_count} hostname")
    print("\nru-blocked-cleaned:")
    print("  1 — использовать готовый канонический список")
    print("  2 — пересобрать FAST (текущая база NXDOMAIN)")
    print("  3 — пересобрать FULL (полный DNS-аудит)")
    choice = input("Выбор [1]: ").strip() or "1"
    return {"1": "existing", "2": "refresh-fast", "3": "refresh-full"}.get(choice) or fail("неверный выбор")


def build_ru_source(mode: str, run_id: str) -> Path:
    if mode == "existing":
        if not RU_CANONICAL.exists():
            fail("canonical ru-blocked-cleaned not found")
        return RU_CANONICAL
    nxmode = "fast" if mode == "refresh-fast" else "full"
    child_id = f"{run_id}-ru"
    cmd = [sys.executable, str(RU_ORCHESTRATOR), "stage1", "--run-id", child_id, "--nxdomain-mode", nxmode]
    print("[RUN]", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)
    candidate = ROOT / "runs" / child_id / "04_final/ru-blocked-cleaned.txt"
    if not candidate.exists():
        fail("ru-blocked-cleaned candidate was not created")
    return candidate


def get_runet_geosite(run: Path, supplied: str | None) -> Path:
    if supplied:
        p = Path(supplied).resolve()
        if not p.exists():
            fail(f"Runet geosite not found: {p}")
        return p
    dst = run / "inputs/runet-freedom/geosite.dat"
    sha_file = run / "inputs/runet-freedom/geosite.dat.sha256sum"
    print("[DOWNLOAD] Runet Freedom geosite.dat")
    download(RUNET_GEOSITE_URL, dst)
    download(RUNET_SHA_URL, sha_file)
    expected = sha_file.read_text(encoding="utf-8").split()[0].lower()
    actual = sha256(dst)
    if actual != expected:
        fail(f"Runet geosite SHA mismatch: {actual} != {expected}")
    return dst


def run_go_builder(run: Path, runet: Path, ru: Path, server_dir: Path, policy: Path) -> tuple[Path, Path, Path]:
    out = run / "output"
    out.mkdir(parents=True, exist_ok=True)
    happ = out / "geosite.dat"
    sr = out / "shadowrocket-routing.conf"
    manifest = out / "manifest.json"
    module_dir = run / "work/go"
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "go.mod").write_text(
        "module clientbundle\n\ngo 1.25\n\nrequire (\n"
        "  github.com/v2fly/v2ray-core/v5 v5.52.0\n"
        "  google.golang.org/protobuf v1.36.12\n)\n",
        encoding="utf-8",
    )
    subprocess.run(["go", "mod", "download"], cwd=module_dir, check=True)
    cmd = [
        "go", "run", str(GO_BUILDER),
        "--runet-geosite", str(runet),
        "--ru-cleaned", str(ru),
        "--server-block-dir", str(server_dir),
        "--policy", str(policy),
        "--happ-output", str(happ),
        "--shadowrocket-output", str(sr),
        "--manifest-output", str(manifest),
    ]
    print("[BUILD] Happ + Shadowrocket")
    subprocess.run(cmd, cwd=module_dir, check=True)
    return happ, sr, manifest


def publish(happ: Path, sr: Path, manifest: Path) -> Path:
    dst = ROOT / "generated/clients/client-bundle"
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copy2(happ, dst / "geosite.dat")
    shutil.copy2(sr, dst / "shadowrocket-routing.conf")
    shutil.copy2(manifest, dst / "manifest.json")
    return dst


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--ru-mode", choices=["interactive", "existing", "refresh-fast", "refresh-full"], default="interactive" if sys.stdin.isatty() else "existing")
    p.add_argument("--server-version", default="latest")
    p.add_argument("--policy", default=str(POLICY_DEFAULT))
    p.add_argument("--runet-geosite")
    p.add_argument("--run-id")
    p.add_argument("--publish", action="store_true")
    a = p.parse_args()

    run_id = a.run_id or utc_run_id()
    run = ROOT / "runs/client-bundles" / run_id
    if run.exists():
        fail(f"run already exists: {run_id}")
    run.mkdir(parents=True)

    server_version, server_dir, server_manifest = detect_server_version(a.server_version)
    ru_mode = pick_ru_mode(a.ru_mode, server_version, server_manifest)
    ru = build_ru_source(ru_mode, run_id)
    runet = get_runet_geosite(run, a.runet_geosite)
    policy = Path(a.policy).resolve()
    if not policy.exists():
        fail(f"policy not found: {policy}")

    print("\nВыбрано:")
    print(f"  SERVER_BLOCK: {server_version} ({server_manifest['domain_suffix_count']} domains + {server_manifest['ipv4_cidr_count']} IPv4)")
    print(f"  ru-blocked-cleaned: {ru_mode} ({len(lines(ru))})")
    print(f"  Runet Freedom geosite: {sha256(runet)}")
    print(f"  policy: {policy.relative_to(ROOT) if policy.is_relative_to(ROOT) else policy}")

    happ, sr, manifest = run_go_builder(run, runet, ru, server_dir, policy)
    m = json.loads(manifest.read_text(encoding="utf-8"))
    if m["server_block_version"] != server_version:
        fail("output server version mismatch")
    if m["ru_blocked_cleaned"] != len(lines(ru)):
        fail("output ru-blocked-cleaned count mismatch")

    if a.publish:
        dst = publish(happ, sr, manifest)
        print(f"PUBLISHED={dst.relative_to(ROOT)}")

    print("\nГОТОВО")
    print(f"HAPP={happ.relative_to(ROOT)}")
    print(f"SHADOWROCKET={sr.relative_to(ROOT)}")
    print(f"MANIFEST={manifest.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
