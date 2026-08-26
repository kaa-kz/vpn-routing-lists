#!/usr/bin/env python3
"""Resumable hostname-only DNS + web availability classifier.

Input hostnames are preserved exactly (apart from surrounding whitespace) and each
input hostname must finish in exactly one of four final classes:

  01_LIVE_WEB.txt
  02_DNS_ALIVE_WEB_DEAD.txt
  03_NXDOMAIN_DEAD.txt
  04_UNCERTAIN_RECHECK.txt

No hostname is deleted. The script keeps an append-only JSONL journal, a CSV
technical log, checkpoint metadata, progress/heartbeat output, and supports safe
resume after an interrupted GitHub Actions run.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import os
import signal
import ssl
import subprocess
import sys
import time
import traceback
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import aiohttp
import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype


FINAL_CLASSES = (
    "01_LIVE_WEB",
    "02_DNS_ALIVE_WEB_DEAD",
    "03_NXDOMAIN_DEAD",
    "04_UNCERTAIN_RECHECK",
)
OUTPUT_FILENAMES = {
    "01_LIVE_WEB": "01_LIVE_WEB.txt",
    "02_DNS_ALIVE_WEB_DEAD": "02_DNS_ALIVE_WEB_DEAD.txt",
    "03_NXDOMAIN_DEAD": "03_NXDOMAIN_DEAD.txt",
    "04_UNCERTAIN_RECHECK": "04_UNCERTAIN_RECHECK.txt",
}
DNS_SERVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
}
DNS_TYPES = ("A", "AAAA", "CNAME")
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)
CSV_FIELDS = [
    "hostname",
    "input_index",
    "final_class",
    "dns_class",
    "dns_a",
    "dns_aaaa",
    "dns_cname",
    "dns_resolver_summary",
    "https_status",
    "https_insecure_retry",
    "https_effective_url",
    "https_redirect_chain",
    "https_error",
    "http_status",
    "http_effective_url",
    "http_redirect_chain",
    "http_error",
    "web_reason",
    "elapsed_ms",
    "timestamp_utc",
]


@dataclass(frozen=True)
class Config:
    input_path: Path
    output_dir: Path
    state_dir: Path
    expected_count: int
    concurrency: int
    dns_timeout: float
    dns_hard_timeout: float
    http_connect_timeout: float
    http_total_timeout: float
    hostname_hard_timeout: float
    max_redirects: int
    progress_every: int
    heartbeat_seconds: float
    watchdog_seconds: float
    checkpoint_every: int
    checkpoint_seconds: float
    soft_limit_seconds: float
    git_checkpoint: bool


class StopRequested(Exception):
    pass


class SoftLimitReached(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_input(path: Path, expected_count: int) -> list[str]:
    raw = path.read_text(encoding="utf-8").splitlines()
    hostnames = [line.strip() for line in raw if line.strip()]
    if expected_count and len(hostnames) != expected_count:
        raise RuntimeError(
            f"Input count mismatch: expected {expected_count}, got {len(hostnames)}"
        )
    duplicates = [h for h, n in Counter(hostnames).items() if n > 1]
    if duplicates:
        preview = ", ".join(duplicates[:10])
        raise RuntimeError(f"Input contains duplicate hostnames ({len(duplicates)}): {preview}")
    return hostnames


def safe_json_dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_partial_results(path: Path) -> tuple[dict[str, dict[str, Any]], int]:
    results: dict[str, dict[str, Any]] = {}
    malformed = 0
    if not path.exists():
        return results, malformed
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                hostname = obj.get("hostname")
                if isinstance(hostname, str) and hostname:
                    results[hostname] = obj
                else:
                    malformed += 1
            except json.JSONDecodeError:
                malformed += 1
                print(f"[WARN] Ignoring malformed JSONL line {line_number}", flush=True)
    return results, malformed


def append_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def dns_records_from_response(response: dns.message.Message) -> dict[str, list[str]]:
    out = {"A": [], "AAAA": [], "CNAME": []}
    for rrset in response.answer:
        rdtype = dns.rdatatype.to_text(rrset.rdtype)
        if rdtype not in out:
            continue
        for item in rrset:
            text = item.to_text().rstrip(".")
            if text not in out[rdtype]:
                out[rdtype].append(text)
    return out


async def one_dns_query(server_ip: str, hostname: str, qtype: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        query = dns.message.make_query(hostname, qtype, use_edns=True)
        response = await asyncio.wait_for(
            dns.asyncquery.udp(query, server_ip, timeout=timeout),
            timeout=timeout + 0.5,
        )
        if response.flags & dns.flags.TC:
            response = await asyncio.wait_for(
                dns.asyncquery.tcp(query, server_ip, timeout=timeout),
                timeout=timeout + 0.5,
            )
        records = dns_records_from_response(response)
        return {
            "rcode": dns.rcode.to_text(response.rcode()),
            "records": records,
            "error": "",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
    except Exception as exc:  # network and parser failures stay diagnostic, not fatal
        return {
            "rcode": "ERROR",
            "records": {"A": [], "AAAA": [], "CNAME": []},
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }


def resolver_verdict(per_type: dict[str, dict[str, Any]]) -> str:
    any_records = any(
        result.get("records", {}).get(kind)
        for result in per_type.values()
        for kind in DNS_TYPES
    )
    if any_records:
        return "ALIVE"

    rcodes = [result.get("rcode") for result in per_type.values()]
    nx_count = sum(1 for r in rcodes if r == "NXDOMAIN")
    noerror_count = sum(1 for r in rcodes if r == "NOERROR")
    error_count = sum(1 for r in rcodes if r == "ERROR")

    # Conservative first-pass rule: require at least two independent qtypes from
    # the same resolver to say NXDOMAIN, with no contradictory NOERROR answer.
    if nx_count >= 2 and noerror_count == 0:
        return "NXDOMAIN"
    if noerror_count >= 1:
        return "NODATA"
    if error_count == len(DNS_TYPES):
        return "ERROR"
    return "MIXED"


async def check_dns(hostname: str, timeout: float, hard_timeout: float) -> dict[str, Any]:
    async def run_all() -> dict[str, Any]:
        tasks: dict[tuple[str, str], asyncio.Task] = {}
        for resolver_name, server_ip in DNS_SERVERS.items():
            for qtype in DNS_TYPES:
                tasks[(resolver_name, qtype)] = asyncio.create_task(
                    one_dns_query(server_ip, hostname, qtype, timeout)
                )

        detailed: dict[str, dict[str, Any]] = {
            name: {} for name in DNS_SERVERS
        }
        for (resolver_name, qtype), task in tasks.items():
            detailed[resolver_name][qtype] = await task

        resolver_states = {
            name: resolver_verdict(per_type)
            for name, per_type in detailed.items()
        }

        a_records: list[str] = []
        aaaa_records: list[str] = []
        cname_records: list[str] = []
        for per_type in detailed.values():
            for result in per_type.values():
                records = result.get("records", {})
                for value in records.get("A", []):
                    if value not in a_records:
                        a_records.append(value)
                for value in records.get("AAAA", []):
                    if value not in aaaa_records:
                        aaaa_records.append(value)
                for value in records.get("CNAME", []):
                    if value not in cname_records:
                        cname_records.append(value)

        if any(state == "ALIVE" for state in resolver_states.values()):
            dns_class = "DNS_ALIVE"
        elif all(state == "NXDOMAIN" for state in resolver_states.values()):
            dns_class = "NXDOMAIN_CONFIRMED"
        else:
            dns_class = "DNS_UNCERTAIN"

        return {
            "dns_class": dns_class,
            "a": a_records,
            "aaaa": aaaa_records,
            "cname": cname_records,
            "resolver_states": resolver_states,
            "details": detailed,
        }

    try:
        return await asyncio.wait_for(run_all(), timeout=hard_timeout)
    except asyncio.TimeoutError:
        return {
            "dns_class": "DNS_UNCERTAIN",
            "a": [],
            "aaaa": [],
            "cname": [],
            "resolver_states": {name: "HARD_TIMEOUT" for name in DNS_SERVERS},
            "details": {},
            "hard_timeout": True,
        }


async def fetch_with_redirects(
    session: aiohttp.ClientSession,
    url: str,
    max_redirects: int,
    ssl_value: Any,
) -> dict[str, Any]:
    current = url
    chain: list[str] = []
    first_status: int | None = None
    last_status: int | None = None
    observed_response = False

    for hop in range(max_redirects + 1):
        try:
            async with session.get(
                current,
                allow_redirects=False,
                ssl=ssl_value,
                headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            ) as response:
                observed_response = True
                status = int(response.status)
                last_status = status
                if first_status is None:
                    first_status = status
                location = response.headers.get("Location", "")
                if 300 <= status < 400 and location and hop < max_redirects:
                    next_url = urljoin(current, location)
                    chain.append(f"{status} {current} -> {next_url}")
                    current = next_url
                    continue
                return {
                    "responded": True,
                    "status": first_status,
                    "final_status": last_status,
                    "effective_url": current,
                    "redirect_chain": chain,
                    "error": "",
                }
        except Exception as exc:
            if observed_response:
                return {
                    "responded": True,
                    "status": first_status,
                    "final_status": last_status,
                    "effective_url": current,
                    "redirect_chain": chain,
                    "error": f"redirect_follow_error: {type(exc).__name__}: {exc}",
                }
            raise

    return {
        "responded": observed_response,
        "status": first_status,
        "final_status": last_status,
        "effective_url": current,
        "redirect_chain": chain,
        "error": "redirect_limit_reached",
    }


def is_tls_verification_error(exc: BaseException) -> bool:
    return isinstance(
        exc,
        (
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientSSLError,
            ssl.SSLCertVerificationError,
            ssl.SSLError,
        ),
    )


async def check_web(
    session: aiohttp.ClientSession,
    hostname: str,
    max_redirects: int,
) -> dict[str, Any]:
    https_result: dict[str, Any]
    http_result: dict[str, Any]
    insecure_retry = False

    try:
        https_result = await fetch_with_redirects(
            session, f"https://{hostname}/", max_redirects, True
        )
    except Exception as exc:
        https_result = {
            "responded": False,
            "status": None,
            "effective_url": f"https://{hostname}/",
            "redirect_chain": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
        if is_tls_verification_error(exc):
            insecure_retry = True
            try:
                https_result = await fetch_with_redirects(
                    session, f"https://{hostname}/", max_redirects, False
                )
                https_result["insecure_tls"] = True
            except Exception as exc2:
                https_result = {
                    "responded": False,
                    "status": None,
                    "effective_url": f"https://{hostname}/",
                    "redirect_chain": [],
                    "error": f"insecure_retry_failed: {type(exc2).__name__}: {exc2}",
                    "insecure_tls": True,
                }

    if https_result.get("responded"):
        return {
            "web_alive": True,
            "reason": "HTTPS_RESPONDED",
            "https": https_result,
            "http": {},
            "https_insecure_retry": insecure_retry,
        }

    try:
        http_result = await fetch_with_redirects(
            session, f"http://{hostname}/", max_redirects, None
        )
    except Exception as exc:
        http_result = {
            "responded": False,
            "status": None,
            "effective_url": f"http://{hostname}/",
            "redirect_chain": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

    if http_result.get("responded"):
        return {
            "web_alive": True,
            "reason": "HTTP_RESPONDED",
            "https": https_result,
            "http": http_result,
            "https_insecure_retry": insecure_retry,
        }

    return {
        "web_alive": False,
        "reason": "NO_HTTP_OR_HTTPS_RESPONSE",
        "https": https_result,
        "http": http_result,
        "https_insecure_retry": insecure_retry,
    }


def compact_resolver_summary(dns_result: dict[str, Any]) -> str:
    states = dns_result.get("resolver_states", {})
    return ";".join(f"{name}={states.get(name, '')}" for name in DNS_SERVERS)


def result_to_csv_row(result: dict[str, Any]) -> dict[str, Any]:
    dns_result = result.get("dns", {})
    web = result.get("web", {})
    https = web.get("https", {}) or {}
    http = web.get("http", {}) or {}
    return {
        "hostname": result.get("hostname", ""),
        "input_index": result.get("input_index", ""),
        "final_class": result.get("final_class", ""),
        "dns_class": dns_result.get("dns_class", ""),
        "dns_a": ";".join(dns_result.get("a", []) or []),
        "dns_aaaa": ";".join(dns_result.get("aaaa", []) or []),
        "dns_cname": ";".join(dns_result.get("cname", []) or []),
        "dns_resolver_summary": compact_resolver_summary(dns_result),
        "https_status": https.get("status", ""),
        "https_insecure_retry": web.get("https_insecure_retry", False),
        "https_effective_url": https.get("effective_url", ""),
        "https_redirect_chain": " | ".join(https.get("redirect_chain", []) or []),
        "https_error": https.get("error", ""),
        "http_status": http.get("status", ""),
        "http_effective_url": http.get("effective_url", ""),
        "http_redirect_chain": " | ".join(http.get("redirect_chain", []) or []),
        "http_error": http.get("error", ""),
        "web_reason": web.get("reason", ""),
        "elapsed_ms": result.get("elapsed_ms", ""),
        "timestamp_utc": result.get("timestamp_utc", ""),
    }


async def process_hostname(
    index: int,
    hostname: str,
    cfg: Config,
    session: aiohttp.ClientSession,
) -> dict[str, Any]:
    started = time.monotonic()

    async def inner() -> dict[str, Any]:
        dns_result = await check_dns(hostname, cfg.dns_timeout, cfg.dns_hard_timeout)

        if dns_result["dns_class"] == "NXDOMAIN_CONFIRMED":
            final_class = "03_NXDOMAIN_DEAD"
            web: dict[str, Any] = {}
        elif dns_result["dns_class"] == "DNS_UNCERTAIN":
            final_class = "04_UNCERTAIN_RECHECK"
            web = {}
        else:
            web = await check_web(session, hostname, cfg.max_redirects)
            final_class = (
                "01_LIVE_WEB" if web.get("web_alive") else "02_DNS_ALIVE_WEB_DEAD"
            )

        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": final_class,
            "dns": dns_result,
            "web": web,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }

    try:
        return await asyncio.wait_for(inner(), timeout=cfg.hostname_hard_timeout)
    except asyncio.TimeoutError:
        # A hard per-hostname timeout is deliberately uncertain on the first pass.
        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": "04_UNCERTAIN_RECHECK",
            "dns": {
                "dns_class": "DNS_UNCERTAIN",
                "a": [],
                "aaaa": [],
                "cname": [],
                "resolver_states": {name: "HOSTNAME_HARD_TIMEOUT" for name in DNS_SERVERS},
            },
            "web": {"reason": "HOSTNAME_HARD_TIMEOUT"},
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }
    except Exception as exc:
        # Unexpected per-hostname failures do not kill the whole scan or become DEAD.
        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": "04_UNCERTAIN_RECHECK",
            "dns": {
                "dns_class": "DNS_UNCERTAIN",
                "a": [],
                "aaaa": [],
                "cname": [],
                "resolver_states": {name: "PROCESSING_EXCEPTION" for name in DNS_SERVERS},
            },
            "web": {"reason": f"PROCESSING_EXCEPTION: {type(exc).__name__}: {exc}"},
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }


def counts_from_results(results: dict[str, dict[str, Any]]) -> Counter:
    return Counter(r.get("final_class", "") for r in results.values())


def make_bar(done: int, total: int, width: int = 30) -> str:
    if total <= 0:
        return "[" + "-" * width + "]"
    filled = min(width, int(width * done / total))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def write_progress_file(
    path: Path,
    processed: int,
    total: int,
    results: dict[str, dict[str, Any]],
    rate: float,
    last_hostname: str,
    active_workers: int,
    oldest_request_seconds: float,
    checkpoint_number: int,
    status: str = "RUNNING",
) -> None:
    counts = counts_from_results(results)
    pct = 100.0 * processed / total if total else 100.0
    lines = [
        f"status={status}",
        f"timestamp_utc={utc_now()}",
        f"progress={processed}/{total}",
        f"percent={pct:.2f}",
        f"01_LIVE_WEB={counts['01_LIVE_WEB']}",
        f"02_DNS_ALIVE_WEB_DEAD={counts['02_DNS_ALIVE_WEB_DEAD']}",
        f"03_NXDOMAIN_DEAD={counts['03_NXDOMAIN_DEAD']}",
        f"04_UNCERTAIN_RECHECK={counts['04_UNCERTAIN_RECHECK']}",
        f"rate_host_per_sec={rate:.2f}",
        f"last_hostname={last_hostname}",
        f"active_workers={active_workers}",
        f"oldest_request_seconds={oldest_request_seconds:.1f}",
        f"checkpoint_number={checkpoint_number}",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_checkpoint_metadata(
    cfg: Config,
    input_sha256: str,
    total: int,
    results: dict[str, dict[str, Any]],
    checkpoint_number: int,
    status: str,
) -> None:
    counts = counts_from_results(results)
    data = {
        "version": 1,
        "status": status,
        "timestamp_utc": utc_now(),
        "input_path": str(cfg.input_path),
        "input_sha256": input_sha256,
        "input_count": total,
        "processed_count": len(results),
        "remaining_count": total - len(results),
        "checkpoint_number": checkpoint_number,
        "counts": {name: counts[name] for name in FINAL_CLASSES},
        "config": {
            "concurrency": cfg.concurrency,
            "dns_servers": DNS_SERVERS,
            "dns_types": DNS_TYPES,
            "dns_timeout": cfg.dns_timeout,
            "dns_hard_timeout": cfg.dns_hard_timeout,
            "http_connect_timeout": cfg.http_connect_timeout,
            "http_total_timeout": cfg.http_total_timeout,
            "hostname_hard_timeout": cfg.hostname_hard_timeout,
            "max_redirects": cfg.max_redirects,
            "watchdog_seconds": cfg.watchdog_seconds,
        },
    }
    safe_json_dump(cfg.state_dir / "checkpoint.json", data)


def git_checkpoint(state_dir: Path, processed: int, total: int) -> bool:
    try:
        inside = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if inside.returncode != 0:
            print("[CHECKPOINT] Not in a git worktree; persistent git checkpoint skipped", flush=True)
            return False

        branch = os.environ.get("GITHUB_REF_NAME") or subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()

        subprocess.run(["git", "add", str(state_dir)], timeout=30, check=True)
        diff = subprocess.run(["git", "diff", "--cached", "--quiet"], timeout=10, check=False)
        if diff.returncode == 0:
            return True

        subprocess.run(
            ["git", "commit", "-m", f"Checkpoint hostname scan {processed}/{total}"],
            timeout=60,
            check=True,
        )
        push = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if push.returncode != 0:
            print(f"[CHECKPOINT][WARN] git push failed: {push.stderr.strip()}", flush=True)
            return False
        print(f"[CHECKPOINT] Persisted {processed}/{total} to branch {branch}", flush=True)
        return True
    except Exception as exc:
        print(f"[CHECKPOINT][WARN] persistent git checkpoint failed: {type(exc).__name__}: {exc}", flush=True)
        return False


def build_final_outputs(
    cfg: Config,
    hostnames: list[str],
    results: dict[str, dict[str, Any]],
    input_sha256: str,
) -> None:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)

    for class_name, filename in OUTPUT_FILENAMES.items():
        members = [h for h in hostnames if results[h]["final_class"] == class_name]
        (cfg.output_dir / filename).write_text(
            "\n".join(members) + ("\n" if members else ""), encoding="utf-8"
        )

    csv_path = cfg.output_dir / "domain-check-results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for hostname in hostnames:
            writer.writerow(result_to_csv_row(results[hostname]))

    counts = counts_from_results(results)
    total_from_classes = sum(counts[name] for name in FINAL_CLASSES)
    seen_membership = sum(
        1 for hostname in hostnames if results.get(hostname, {}).get("final_class") in FINAL_CLASSES
    )
    missing = [h for h in hostnames if h not in results]
    invalid_class = [
        h for h in hostnames
        if h in results and results[h].get("final_class") not in FINAL_CLASSES
    ]

    summary = [
        "DOMAIN CHECK COMPLETED",
        "======================",
        f"timestamp_utc={utc_now()}",
        f"input_sha256={input_sha256}",
        f"input={len(hostnames)}",
        f"01_LIVE_WEB={counts['01_LIVE_WEB']}",
        f"02_DNS_ALIVE_WEB_DEAD={counts['02_DNS_ALIVE_WEB_DEAD']}",
        f"03_NXDOMAIN_DEAD={counts['03_NXDOMAIN_DEAD']}",
        f"04_UNCERTAIN_RECHECK={counts['04_UNCERTAIN_RECHECK']}",
        f"class_total={total_from_classes}",
        f"classified_input_members={seen_membership}",
        f"missing={len(missing)}",
        f"invalid_class={len(invalid_class)}",
        f"duplicates=0",
    ]
    (cfg.output_dir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

    if total_from_classes != len(hostnames) or missing or invalid_class:
        raise RuntimeError(
            "Final invariant failed: 01+02+03+04 must equal input exactly once"
        )


def validate_resume_state(cfg: Config, input_sha256: str, total: int) -> None:
    checkpoint_path = cfg.state_dir / "checkpoint.json"
    if not checkpoint_path.exists():
        return
    data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    old_hash = data.get("input_sha256")
    old_count = data.get("input_count")
    if old_hash and old_hash != input_sha256:
        raise RuntimeError(
            f"Refusing to mix checkpoint with changed input: {old_hash} != {input_sha256}"
        )
    if old_count is not None and int(old_count) != total:
        raise RuntimeError(
            f"Refusing to mix checkpoint with changed input count: {old_count} != {total}"
        )


def print_progress(
    processed: int,
    total: int,
    results: dict[str, dict[str, Any]],
    start_time: float,
    last_hostname: str,
    active_workers: int,
    oldest_request_seconds: float,
    checkpoint_number: int,
    label: str = "PROGRESS",
) -> None:
    elapsed = max(time.monotonic() - start_time, 0.001)
    rate = processed / elapsed
    counts = counts_from_results(results)
    pct = 100.0 * processed / total if total else 100.0
    print(
        f"[{label}] {make_bar(processed, total)} {pct:6.2f}% "
        f"{processed}/{total} | "
        f"LIVE={counts['01_LIVE_WEB']} "
        f"DNS_WEB_DEAD={counts['02_DNS_ALIVE_WEB_DEAD']} "
        f"NXDOMAIN={counts['03_NXDOMAIN_DEAD']} "
        f"UNCERTAIN={counts['04_UNCERTAIN_RECHECK']} | "
        f"rate={rate:.2f} host/s active={active_workers} "
        f"oldest={oldest_request_seconds:.1f}s last={last_hostname} "
        f"checkpoint={checkpoint_number}",
        flush=True,
    )


async def run_scan(cfg: Config) -> int:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    partial_path = cfg.state_dir / "results.partial.jsonl"
    progress_path = cfg.state_dir / "progress.txt"

    hostnames = load_input(cfg.input_path, cfg.expected_count)
    input_sha256 = sha256_file(cfg.input_path)
    validate_resume_state(cfg, input_sha256, len(hostnames))

    results, malformed = read_partial_results(partial_path)
    unknown_saved = [h for h in results if h not in set(hostnames)]
    if unknown_saved:
        raise RuntimeError(
            f"Checkpoint contains {len(unknown_saved)} hostnames not present in current input"
        )

    print("=" * 72, flush=True)
    print("HOSTNAME AVAILABILITY CHECK", flush=True)
    print("=" * 72, flush=True)
    print(f"input={cfg.input_path}", flush=True)
    print(f"input_sha256={input_sha256}", flush=True)
    print(f"input_count={len(hostnames)}", flush=True)
    print(f"resume_processed={len(results)}", flush=True)
    print(f"resume_malformed_jsonl_lines={malformed}", flush=True)
    print(f"concurrency={cfg.concurrency}", flush=True)
    print(f"dns_servers={DNS_SERVERS}", flush=True)
    print(
        f"timeouts: dns={cfg.dns_timeout}s dns_hard={cfg.dns_hard_timeout}s "
        f"http_connect={cfg.http_connect_timeout}s http_total={cfg.http_total_timeout}s "
        f"hostname_hard={cfg.hostname_hard_timeout}s",
        flush=True,
    )

    remaining = [(i + 1, h) for i, h in enumerate(hostnames) if h not in results]
    if not remaining:
        build_final_outputs(cfg, hostnames, results, input_sha256)
        write_checkpoint_metadata(cfg, input_sha256, len(hostnames), results, 0, "COMPLETE")
        print("[INFO] No remaining hostnames; existing checkpoint is complete", flush=True)
        return 0

    timeout = aiohttp.ClientTimeout(
        total=cfg.http_total_timeout,
        connect=cfg.http_connect_timeout,
        sock_connect=cfg.http_connect_timeout,
        sock_read=max(1.0, cfg.http_total_timeout - cfg.http_connect_timeout),
    )
    connector = aiohttp.TCPConnector(
        limit=max(cfg.concurrency * 2, 64),
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )

    run_start = time.monotonic()
    last_completion = run_start
    last_progress_print = run_start
    last_checkpoint = run_start
    last_hostname = ""
    completed_since_checkpoint = 0
    checkpoint_number = 0
    persistent_checkpoint_failures = 0
    stop_requested = False

    loop = asyncio.get_running_loop()

    def request_stop() -> None:
        nonlocal stop_requested
        stop_requested = True
        print("[SIGNAL] Graceful stop requested; finishing current workers", flush=True)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
        except (NotImplementedError, RuntimeError):
            pass

    pending: dict[asyncio.Task, tuple[int, str, float]] = {}
    cursor = 0

    def schedule_more(session: aiohttp.ClientSession) -> None:
        nonlocal cursor
        while (
            not stop_requested
            and len(pending) < cfg.concurrency
            and cursor < len(remaining)
        ):
            if time.monotonic() - run_start >= cfg.soft_limit_seconds:
                break
            index, hostname = remaining[cursor]
            cursor += 1
            task = asyncio.create_task(process_hostname(index, hostname, cfg, session))
            pending[task] = (index, hostname, time.monotonic())

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        trust_env=False,
    ) as session:
        schedule_more(session)

        while pending:
            now = time.monotonic()
            if now - run_start >= cfg.soft_limit_seconds:
                stop_requested = True

            done, _ = await asyncio.wait(
                set(pending.keys()),
                timeout=min(cfg.heartbeat_seconds, 10.0),
                return_when=asyncio.FIRST_COMPLETED,
            )

            if not done:
                now = time.monotonic()
                oldest = max((now - meta[2] for meta in pending.values()), default=0.0)
                if now - last_progress_print >= cfg.heartbeat_seconds:
                    print_progress(
                        len(results), len(hostnames), results, run_start, last_hostname,
                        len(pending), oldest, checkpoint_number, label="HEARTBEAT"
                    )
                    elapsed = max(now - run_start, 0.001)
                    write_progress_file(
                        progress_path, len(results), len(hostnames), results,
                        len(results) / elapsed, last_hostname, len(pending), oldest,
                        checkpoint_number,
                    )
                    last_progress_print = now

                if now - last_completion >= cfg.watchdog_seconds:
                    for task in pending:
                        task.cancel()
                    write_checkpoint_metadata(
                        cfg, input_sha256, len(hostnames), results,
                        checkpoint_number, "WATCHDOG_ABORT"
                    )
                    raise RuntimeError(
                        f"Watchdog fired: no hostname completed for {cfg.watchdog_seconds}s"
                    )
                continue

            for task in done:
                index, hostname, started_at = pending.pop(task)
                try:
                    result = task.result()
                except Exception as exc:
                    result = {
                        "hostname": hostname,
                        "input_index": index,
                        "final_class": "04_UNCERTAIN_RECHECK",
                        "dns": {
                            "dns_class": "DNS_UNCERTAIN",
                            "a": [], "aaaa": [], "cname": [],
                            "resolver_states": {name: "TASK_EXCEPTION" for name in DNS_SERVERS},
                        },
                        "web": {"reason": f"TASK_EXCEPTION: {type(exc).__name__}: {exc}"},
                        "elapsed_ms": round((time.monotonic() - started_at) * 1000),
                        "timestamp_utc": utc_now(),
                    }

                append_result(partial_path, result)
                results[hostname] = result
                last_hostname = hostname
                last_completion = time.monotonic()
                completed_since_checkpoint += 1

            schedule_more(session)

            now = time.monotonic()
            oldest = max((now - meta[2] for meta in pending.values()), default=0.0)
            if (
                len(results) % cfg.progress_every == 0
                or now - last_progress_print >= cfg.heartbeat_seconds
                or not pending
            ):
                print_progress(
                    len(results), len(hostnames), results, run_start, last_hostname,
                    len(pending), oldest, checkpoint_number
                )
                elapsed = max(now - run_start, 0.001)
                write_progress_file(
                    progress_path, len(results), len(hostnames), results,
                    len(results) / elapsed, last_hostname, len(pending), oldest,
                    checkpoint_number,
                )
                last_progress_print = now

            checkpoint_due = (
                completed_since_checkpoint >= cfg.checkpoint_every
                or now - last_checkpoint >= cfg.checkpoint_seconds
            )
            if checkpoint_due:
                checkpoint_number += 1
                write_checkpoint_metadata(
                    cfg, input_sha256, len(hostnames), results,
                    checkpoint_number, "RUNNING"
                )
                if cfg.git_checkpoint:
                    if not git_checkpoint(cfg.state_dir, len(results), len(hostnames)):
                        persistent_checkpoint_failures += 1
                completed_since_checkpoint = 0
                last_checkpoint = time.monotonic()

            if stop_requested and pending:
                # No new work is scheduled; current bounded tasks finish naturally.
                pass

        # If we stopped before scheduling everything, persist and ask for resume.
        if cursor < len(remaining):
            checkpoint_number += 1
            write_checkpoint_metadata(
                cfg, input_sha256, len(hostnames), results,
                checkpoint_number, "PAUSED_FOR_RESUME"
            )
            elapsed = max(time.monotonic() - run_start, 0.001)
            write_progress_file(
                progress_path, len(results), len(hostnames), results,
                len(results) / elapsed, last_hostname, 0, 0.0,
                checkpoint_number, status="PAUSED_FOR_RESUME",
            )
            if cfg.git_checkpoint:
                git_checkpoint(cfg.state_dir, len(results), len(hostnames))
            print(
                f"[PAUSE] Saved {len(results)}/{len(hostnames)}; rerun resumes remaining hostnames",
                flush=True,
            )
            return 75

    if len(results) != len(hostnames):
        raise RuntimeError(
            f"Scan finished scheduler but results count is {len(results)} != {len(hostnames)}"
        )

    build_final_outputs(cfg, hostnames, results, input_sha256)
    checkpoint_number += 1
    write_checkpoint_metadata(
        cfg, input_sha256, len(hostnames), results,
        checkpoint_number, "COMPLETE"
    )
    elapsed = max(time.monotonic() - run_start, 0.001)
    write_progress_file(
        progress_path, len(results), len(hostnames), results,
        len(results) / elapsed, last_hostname, 0, 0.0,
        checkpoint_number, status="COMPLETE",
    )

    counts = counts_from_results(results)
    print("=" * 72, flush=True)
    print("DOMAIN CHECK COMPLETED", flush=True)
    print("=" * 72, flush=True)
    print(f"INPUT:                    {len(hostnames):,}", flush=True)
    print(f"01 LIVE_WEB:              {counts['01_LIVE_WEB']:,}", flush=True)
    print(f"02 DNS_ALIVE_WEB_DEAD:    {counts['02_DNS_ALIVE_WEB_DEAD']:,}", flush=True)
    print(f"03 NXDOMAIN_DEAD:         {counts['03_NXDOMAIN_DEAD']:,}", flush=True)
    print(f"04 UNCERTAIN_RECHECK:     {counts['04_UNCERTAIN_RECHECK']:,}", flush=True)
    print(f"TOTAL:                    {sum(counts[name] for name in FINAL_CLASSES):,}", flush=True)
    print("Missing:                  0", flush=True)
    print("Duplicates:               0", flush=True)
    print(f"Persistent checkpoint warnings: {persistent_checkpoint_failures}", flush=True)

    return 0


def parse_args() -> Config:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", default="generated/ru-blocked-server-allow.txt")
    p.add_argument("--output-dir", default="generated/domain-check")
    p.add_argument("--state-dir", default="state/domain-check")
    p.add_argument("--expected-count", type=int, default=21989)
    p.add_argument("--concurrency", type=int, default=64)
    p.add_argument("--dns-timeout", type=float, default=2.5)
    p.add_argument("--dns-hard-timeout", type=float, default=5.0)
    p.add_argument("--http-connect-timeout", type=float, default=3.0)
    p.add_argument("--http-total-timeout", type=float, default=8.0)
    p.add_argument("--hostname-hard-timeout", type=float, default=35.0)
    p.add_argument("--max-redirects", type=int, default=10)
    p.add_argument("--progress-every", type=int, default=100)
    p.add_argument("--heartbeat-seconds", type=float, default=30.0)
    p.add_argument("--watchdog-seconds", type=float, default=90.0)
    p.add_argument("--checkpoint-every", type=int, default=250)
    p.add_argument("--checkpoint-seconds", type=float, default=120.0)
    p.add_argument("--soft-limit-seconds", type=float, default=19200.0)
    p.add_argument("--git-checkpoint", action="store_true")
    args = p.parse_args()
    return Config(
        input_path=Path(args.input),
        output_dir=Path(args.output_dir),
        state_dir=Path(args.state_dir),
        expected_count=args.expected_count,
        concurrency=args.concurrency,
        dns_timeout=args.dns_timeout,
        dns_hard_timeout=args.dns_hard_timeout,
        http_connect_timeout=args.http_connect_timeout,
        http_total_timeout=args.http_total_timeout,
        hostname_hard_timeout=args.hostname_hard_timeout,
        max_redirects=args.max_redirects,
        progress_every=args.progress_every,
        heartbeat_seconds=args.heartbeat_seconds,
        watchdog_seconds=args.watchdog_seconds,
        checkpoint_every=args.checkpoint_every,
        checkpoint_seconds=args.checkpoint_seconds,
        soft_limit_seconds=args.soft_limit_seconds,
        git_checkpoint=args.git_checkpoint,
    )


def main() -> int:
    cfg = parse_args()
    try:
        return asyncio.run(run_scan(cfg))
    except KeyboardInterrupt:
        print("[FATAL] KeyboardInterrupt", file=sys.stderr, flush=True)
        return 130
    except Exception as exc:
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        error_text = (
            f"timestamp_utc={utc_now()}\n"
            f"exception={type(exc).__name__}: {exc}\n\n"
            + traceback.format_exc()
        )
        (cfg.state_dir / "error.log").write_text(error_text, encoding="utf-8")
        print(error_text, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
