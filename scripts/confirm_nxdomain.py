#!/usr/bin/env python3
"""Strict, resumable confirmation of NXDOMAIN candidates.

This stage performs DNS-only verification. It does not delete or rewrite source
lists and it does not perform HTTP/HTTPS checks.

Every input hostname is classified exactly once into:
  01_CONFIRMED_NXDOMAIN.txt
  02_DNS_ALIVE_RESCUED.txt
  03_INCONSISTENT_DNS.txt
  04_UNCERTAIN_RECHECK.txt

Method:
- query A through four independent recursive resolvers;
- retry UDP problems over TCP;
- when a hostname is not clearly alive, discover the closest authoritative zone;
- query authoritative nameservers directly with recursion disabled;
- confirm NXDOMAIN only from authoritative answers (AA flag), requiring at least
  two authoritative nameservers when the zone advertises two or more;
- preserve ambiguous/time-out cases for another recheck.

The script writes an append-only JSONL journal, progress/checkpoint metadata,
technical CSV, and supports resume after interruption.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import os
import signal
import subprocess
import sys
import time
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.asyncquery
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype


FINAL_CLASSES = (
    "01_CONFIRMED_NXDOMAIN",
    "02_DNS_ALIVE_RESCUED",
    "03_INCONSISTENT_DNS",
    "04_UNCERTAIN_RECHECK",
)
OUTPUT_FILES = {
    "01_CONFIRMED_NXDOMAIN": "01_CONFIRMED_NXDOMAIN.txt",
    "02_DNS_ALIVE_RESCUED": "02_DNS_ALIVE_RESCUED.txt",
    "03_INCONSISTENT_DNS": "03_INCONSISTENT_DNS.txt",
    "04_UNCERTAIN_RECHECK": "04_UNCERTAIN_RECHECK.txt",
}
RECURSIVE_RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}
DISCOVERY_RESOLVERS = ("1.1.1.1", "8.8.8.8")
CSV_FIELDS = [
    "hostname",
    "input_index",
    "final_class",
    "reason",
    "recursive_summary",
    "zone",
    "authoritative_ns",
    "authoritative_summary",
    "elapsed_ms",
    "timestamp_utc",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_input(path: Path, expected: int) -> list[str]:
    items = [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if expected and len(items) != expected:
        raise RuntimeError(f"Input count mismatch: expected {expected}, got {len(items)}")
    dup = [h for h, n in Counter(items).items() if n > 1]
    if dup:
        raise RuntimeError(f"Input contains {len(dup)} duplicate hostnames; first={dup[:5]}")
    return items


def safe_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path: Path) -> tuple[dict[str, dict[str, Any]], int]:
    out: dict[str, dict[str, Any]] = {}
    malformed = 0
    if not path.exists():
        return out, malformed
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                hostname = obj.get("hostname")
                if hostname:
                    out[str(hostname)] = obj
                else:
                    malformed += 1
            except json.JSONDecodeError:
                malformed += 1
                print(f"[WARN] malformed JSONL line {line_no}; ignored", flush=True)
    return out, malformed


def answer_values(response: dns.message.Message, qtype: str) -> list[str]:
    wanted = dns.rdatatype.from_text(qtype)
    values: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype != wanted:
            continue
        for item in rrset:
            text = item.to_text().rstrip(".")
            if text not in values:
                values.append(text)
    return values


async def raw_query(
    sem: asyncio.Semaphore,
    server: str,
    qname: str,
    qtype: str,
    timeout: float,
    recursive: bool,
) -> dict[str, Any]:
    """DNS query with UDP first and TCP retry on timeout/truncation/bad rcode."""
    started = time.monotonic()
    query = dns.message.make_query(qname, qtype, use_edns=True)
    if recursive:
        query.flags |= dns.flags.RD
    else:
        query.flags &= ~dns.flags.RD

    async def one(transport: str) -> dns.message.Message:
        async with sem:
            if transport == "udp":
                return await asyncio.wait_for(
                    dns.asyncquery.udp(query, server, timeout=timeout), timeout=timeout + 0.5
                )
            return await asyncio.wait_for(
                dns.asyncquery.tcp(query, server, timeout=timeout), timeout=timeout + 0.5
            )

    first_error = ""
    try:
        response = await one("udp")
        rcode = dns.rcode.to_text(response.rcode())
        if not (response.flags & dns.flags.TC) and rcode in ("NOERROR", "NXDOMAIN"):
            return {
                "rcode": rcode,
                "aa": bool(response.flags & dns.flags.AA),
                "answers": answer_values(response, qtype),
                "transport": "udp",
                "error": "",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        first_error = f"udp_rcode={rcode} tc={bool(response.flags & dns.flags.TC)}"
    except Exception as exc:
        first_error = f"udp {type(exc).__name__}: {exc}"

    try:
        response = await one("tcp")
        return {
            "rcode": dns.rcode.to_text(response.rcode()),
            "aa": bool(response.flags & dns.flags.AA),
            "answers": answer_values(response, qtype),
            "transport": "tcp",
            "error": first_error,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
    except Exception as exc:
        return {
            "rcode": "ERROR",
            "aa": False,
            "answers": [],
            "transport": "none",
            "error": f"{first_error}; tcp {type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }


async def recursive_check(
    sem: asyncio.Semaphore, hostname: str, timeout: float
) -> dict[str, Any]:
    tasks = {
        name: asyncio.create_task(raw_query(sem, ip, hostname, "A", timeout, True))
        for name, ip in RECURSIVE_RESOLVERS.items()
    }
    details = {name: await task for name, task in tasks.items()}
    counts = Counter(result["rcode"] for result in details.values())
    return {
        "details": details,
        "noerror": counts["NOERROR"],
        "nxdomain": counts["NXDOMAIN"],
        "other": sum(v for k, v in counts.items() if k not in ("NOERROR", "NXDOMAIN")),
    }


async def discover_zone(
    sem: asyncio.Semaphore, hostname: str, timeout: float
) -> tuple[str, list[dict[str, Any]]]:
    """Find deepest ancestor with an SOA answer using independent recursors."""
    qname = dns.name.from_text(hostname)
    diagnostics: list[dict[str, Any]] = []
    candidate = qname
    while candidate != dns.name.root:
        text = candidate.to_text().rstrip(".")
        if not text:
            break
        for resolver_ip in DISCOVERY_RESOLVERS:
            result = await raw_query(sem, resolver_ip, text, "SOA", timeout, True)
            diagnostics.append({"candidate": text, "resolver": resolver_ip, **result})
            if result["rcode"] == "NOERROR" and result["answers"]:
                return text, diagnostics
        candidate = candidate.parent()
    return "", diagnostics


async def get_zone_ns(
    sem: asyncio.Semaphore, zone: str, timeout: float
) -> tuple[list[str], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    names: list[str] = []
    for resolver_ip in DISCOVERY_RESOLVERS:
        result = await raw_query(sem, resolver_ip, zone, "NS", timeout, True)
        diagnostics.append({"resolver": resolver_ip, **result})
        if result["rcode"] == "NOERROR":
            for value in result["answers"]:
                value = value.rstrip(".")
                if value not in names:
                    names.append(value)
        if names:
            break
    return names, diagnostics


async def resolve_ns_ips(
    sem: asyncio.Semaphore, ns_name: str, timeout: float
) -> list[str]:
    ips: list[str] = []
    for qtype in ("A", "AAAA"):
        for resolver_ip in DISCOVERY_RESOLVERS:
            result = await raw_query(sem, resolver_ip, ns_name, qtype, timeout, True)
            if result["rcode"] == "NOERROR":
                for value in result["answers"]:
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    if value not in ips:
                        ips.append(value)
            if ips:
                break
        if ips:
            break
    return ips


async def authoritative_check(
    sem: asyncio.Semaphore,
    hostname: str,
    timeout: float,
    max_ns: int,
) -> dict[str, Any]:
    zone, zone_diag = await discover_zone(sem, hostname, timeout)
    if not zone:
        return {
            "zone": "",
            "zone_discovery": zone_diag,
            "ns_names": [],
            "ns_lookup": [],
            "responses": [],
            "verdict": "UNCERTAIN",
            "reason": "ZONE_DISCOVERY_FAILED",
        }

    ns_names, ns_diag = await get_zone_ns(sem, zone, timeout)
    if not ns_names:
        return {
            "zone": zone,
            "zone_discovery": zone_diag,
            "ns_names": [],
            "ns_lookup": ns_diag,
            "responses": [],
            "verdict": "UNCERTAIN",
            "reason": "AUTHORITATIVE_NS_NOT_FOUND",
        }

    ns_names = ns_names[:max_ns]
    responses: list[dict[str, Any]] = []
    for ns_name in ns_names:
        ips = await resolve_ns_ips(sem, ns_name, timeout)
        if not ips:
            responses.append({"ns": ns_name, "ip": "", "rcode": "ERROR", "aa": False, "error": "NS_IP_NOT_FOUND"})
            continue

        chosen: dict[str, Any] | None = None
        for ip in ips[:2]:
            result = await raw_query(sem, ip, hostname, "A", timeout, False)
            chosen = {"ns": ns_name, "ip": ip, **result}
            if result["aa"] and result["rcode"] in ("NOERROR", "NXDOMAIN"):
                break
        if chosen:
            responses.append(chosen)

    auth_nx = {r["ns"] for r in responses if r.get("aa") and r.get("rcode") == "NXDOMAIN"}
    auth_ok = {r["ns"] for r in responses if r.get("aa") and r.get("rcode") == "NOERROR"}

    if auth_nx and auth_ok:
        verdict = "INCONSISTENT"
        reason = "AUTHORITATIVE_NXDOMAIN_NOERROR_CONFLICT"
    elif auth_ok:
        verdict = "ALIVE"
        reason = "AUTHORITATIVE_NOERROR"
    else:
        required = 1 if len(ns_names) == 1 else 2
        if len(auth_nx) >= required:
            verdict = "NXDOMAIN"
            reason = f"AUTHORITATIVE_NXDOMAIN_{len(auth_nx)}_NS"
        else:
            verdict = "UNCERTAIN"
            reason = f"INSUFFICIENT_AUTHORITATIVE_NXDOMAIN_{len(auth_nx)}_OF_{required}"

    return {
        "zone": zone,
        "zone_discovery": zone_diag,
        "ns_names": ns_names,
        "ns_lookup": ns_diag,
        "responses": responses,
        "verdict": verdict,
        "reason": reason,
    }


def recursive_summary(rec: dict[str, Any]) -> str:
    return ";".join(
        f"{name}={rec['details'][name].get('rcode','')}"
        for name in RECURSIVE_RESOLVERS
    )


def authoritative_summary(auth: dict[str, Any]) -> str:
    return ";".join(
        f"{r.get('ns','')}@{r.get('ip','')}={r.get('rcode','')}/AA={int(bool(r.get('aa')))}"
        for r in auth.get("responses", [])
    )


async def process_hostname(
    index: int,
    hostname: str,
    sem: asyncio.Semaphore,
    dns_timeout: float,
    hostname_timeout: float,
    max_ns: int,
) -> dict[str, Any]:
    started = time.monotonic()

    async def inner() -> dict[str, Any]:
        rec = await recursive_check(sem, hostname, dns_timeout)

        # Strong positive consensus is enough to rescue without authoritative work.
        if rec["noerror"] >= 3 and rec["nxdomain"] == 0:
            final_class = "02_DNS_ALIVE_RESCUED"
            reason = "RECURSIVE_NOERROR_CONSENSUS"
            auth: dict[str, Any] = {}
        else:
            auth = await authoritative_check(sem, hostname, dns_timeout, max_ns)
            if auth["verdict"] == "NXDOMAIN":
                final_class = "01_CONFIRMED_NXDOMAIN"
                reason = auth["reason"]
            elif auth["verdict"] == "ALIVE":
                final_class = "02_DNS_ALIVE_RESCUED"
                reason = auth["reason"]
            elif auth["verdict"] == "INCONSISTENT":
                final_class = "03_INCONSISTENT_DNS"
                reason = auth["reason"]
            elif rec["noerror"] > 0 and rec["nxdomain"] > 0:
                final_class = "03_INCONSISTENT_DNS"
                reason = "RECURSIVE_NXDOMAIN_NOERROR_CONFLICT_AUTH_UNRESOLVED"
            else:
                final_class = "04_UNCERTAIN_RECHECK"
                reason = auth.get("reason", "DNS_UNCERTAIN")

        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": final_class,
            "reason": reason,
            "recursive": rec,
            "authoritative": auth,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }

    try:
        return await asyncio.wait_for(inner(), timeout=hostname_timeout)
    except asyncio.TimeoutError:
        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": "04_UNCERTAIN_RECHECK",
            "reason": "HOSTNAME_HARD_TIMEOUT",
            "recursive": {},
            "authoritative": {},
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }
    except Exception as exc:
        return {
            "hostname": hostname,
            "input_index": index,
            "final_class": "04_UNCERTAIN_RECHECK",
            "reason": f"PROCESSING_EXCEPTION: {type(exc).__name__}: {exc}",
            "recursive": {},
            "authoritative": {},
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "timestamp_utc": utc_now(),
        }


def counts(results: dict[str, dict[str, Any]]) -> Counter:
    return Counter(r.get("final_class", "") for r in results.values())


def make_bar(done: int, total: int, width: int = 28) -> str:
    filled = int(width * done / total) if total else width
    filled = max(0, min(width, filled))
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def write_progress(path: Path, results: dict[str, dict[str, Any]], total: int, rate: float, last: str, active: int, checkpoint: int, status: str) -> None:
    c = counts(results)
    done = len(results)
    pct = 100 * done / total if total else 100.0
    text = "\n".join([
        f"status={status}",
        f"timestamp_utc={utc_now()}",
        f"progress={done}/{total}",
        f"percent={pct:.2f}",
        f"01_CONFIRMED_NXDOMAIN={c['01_CONFIRMED_NXDOMAIN']}",
        f"02_DNS_ALIVE_RESCUED={c['02_DNS_ALIVE_RESCUED']}",
        f"03_INCONSISTENT_DNS={c['03_INCONSISTENT_DNS']}",
        f"04_UNCERTAIN_RECHECK={c['04_UNCERTAIN_RECHECK']}",
        f"rate_host_per_sec={rate:.2f}",
        f"last_hostname={last}",
        f"active_workers={active}",
        f"checkpoint_number={checkpoint}",
    ]) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_checkpoint(path: Path, input_sha: str, total: int, results: dict[str, dict[str, Any]], checkpoint: int, status: str, cfg: argparse.Namespace) -> None:
    c = counts(results)
    safe_json(path, {
        "version": 1,
        "status": status,
        "timestamp_utc": utc_now(),
        "input_sha256": input_sha,
        "input_count": total,
        "processed_count": len(results),
        "remaining_count": total - len(results),
        "checkpoint_number": checkpoint,
        "counts": {name: c[name] for name in FINAL_CLASSES},
        "config": {
            "hostname_concurrency": cfg.concurrency,
            "dns_query_concurrency": cfg.dns_query_concurrency,
            "dns_timeout": cfg.dns_timeout,
            "hostname_hard_timeout": cfg.hostname_hard_timeout,
            "max_authoritative_ns": cfg.max_authoritative_ns,
            "recursive_resolvers": RECURSIVE_RESOLVERS,
        },
    })


def git_checkpoint(state_dir: Path, done: int, total: int) -> bool:
    try:
        check = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=10)
        if check.returncode != 0:
            return False
        branch = os.environ.get("GITHUB_REF_NAME") or subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=10, check=True
        ).stdout.strip()
        subprocess.run(["git", "add", str(state_dir)], timeout=30, check=True)
        if subprocess.run(["git", "diff", "--cached", "--quiet"], timeout=10).returncode == 0:
            return True
        subprocess.run(["git", "commit", "-m", f"Checkpoint NXDOMAIN confirmation {done}/{total}"], timeout=60, check=True)
        push = subprocess.run(["git", "push", "origin", f"HEAD:{branch}"], capture_output=True, text=True, timeout=90)
        if push.returncode != 0:
            print(f"[CHECKPOINT][WARN] push failed: {push.stderr.strip()}", flush=True)
            return False
        print(f"[CHECKPOINT] persisted {done}/{total}", flush=True)
        return True
    except Exception as exc:
        print(f"[CHECKPOINT][WARN] {type(exc).__name__}: {exc}", flush=True)
        return False


def validate_resume(checkpoint_path: Path, input_sha: str, total: int) -> None:
    if not checkpoint_path.exists():
        return
    data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if data.get("input_sha256") and data["input_sha256"] != input_sha:
        raise RuntimeError("Checkpoint input hash differs from current input")
    if data.get("input_count") is not None and int(data["input_count"]) != total:
        raise RuntimeError("Checkpoint input count differs from current input")


def build_outputs(output_dir: Path, hostnames: list[str], results: dict[str, dict[str, Any]], input_sha: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for class_name, filename in OUTPUT_FILES.items():
        members = [h for h in hostnames if results[h]["final_class"] == class_name]
        (output_dir / filename).write_text("\n".join(members) + ("\n" if members else ""), encoding="utf-8")

    with (output_dir / "nxdomain-confirm-results.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for hostname in hostnames:
            r = results[hostname]
            rec = r.get("recursive", {})
            auth = r.get("authoritative", {})
            writer.writerow({
                "hostname": hostname,
                "input_index": r.get("input_index", ""),
                "final_class": r.get("final_class", ""),
                "reason": r.get("reason", ""),
                "recursive_summary": recursive_summary(rec) if rec.get("details") else "",
                "zone": auth.get("zone", ""),
                "authoritative_ns": ";".join(auth.get("ns_names", []) or []),
                "authoritative_summary": authoritative_summary(auth),
                "elapsed_ms": r.get("elapsed_ms", ""),
                "timestamp_utc": r.get("timestamp_utc", ""),
            })

    c = counts(results)
    total = sum(c[name] for name in FINAL_CLASSES)
    missing = [h for h in hostnames if h not in results]
    invalid = [h for h in hostnames if results.get(h, {}).get("final_class") not in FINAL_CLASSES]
    summary = "\n".join([
        "NXDOMAIN CONFIRMATION COMPLETED",
        "===============================",
        f"timestamp_utc={utc_now()}",
        f"input_sha256={input_sha}",
        f"input={len(hostnames)}",
        f"01_CONFIRMED_NXDOMAIN={c['01_CONFIRMED_NXDOMAIN']}",
        f"02_DNS_ALIVE_RESCUED={c['02_DNS_ALIVE_RESCUED']}",
        f"03_INCONSISTENT_DNS={c['03_INCONSISTENT_DNS']}",
        f"04_UNCERTAIN_RECHECK={c['04_UNCERTAIN_RECHECK']}",
        f"class_total={total}",
        f"missing={len(missing)}",
        f"invalid_class={len(invalid)}",
        "duplicates=0",
    ]) + "\n"
    (output_dir / "summary.txt").write_text(summary, encoding="utf-8")
    if total != len(hostnames) or missing or invalid:
        raise RuntimeError("Final invariant failed: all input hostnames must be classified exactly once")


async def run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    state_dir = Path(args.state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    partial_path = state_dir / "results.partial.jsonl"
    checkpoint_path = state_dir / "checkpoint.json"
    progress_path = state_dir / "progress.txt"

    hostnames = load_input(input_path, args.expected_count)
    input_sha = sha256_file(input_path)
    validate_resume(checkpoint_path, input_sha, len(hostnames))
    results, malformed = read_jsonl(partial_path)
    input_set = set(hostnames)
    foreign = [h for h in results if h not in input_set]
    if foreign:
        raise RuntimeError(f"Checkpoint contains {len(foreign)} hostnames outside current input")

    print("=" * 72, flush=True)
    print("STRICT NXDOMAIN CONFIRMATION", flush=True)
    print("=" * 72, flush=True)
    print(f"input={input_path}", flush=True)
    print(f"input_sha256={input_sha}", flush=True)
    print(f"input_count={len(hostnames)}", flush=True)
    print(f"resume_processed={len(results)}", flush=True)
    print(f"malformed_jsonl_lines={malformed}", flush=True)
    print(f"hostname_concurrency={args.concurrency}", flush=True)
    print(f"dns_query_concurrency={args.dns_query_concurrency}", flush=True)

    remaining = [(i + 1, h) for i, h in enumerate(hostnames) if h not in results]
    if not remaining:
        build_outputs(output_dir, hostnames, results, input_sha)
        write_checkpoint(checkpoint_path, input_sha, len(hostnames), results, 0, "COMPLETE", args)
        return 0

    sem = asyncio.Semaphore(args.dns_query_concurrency)
    run_start = time.monotonic()
    last_completion = run_start
    last_print = run_start
    last_checkpoint_time = run_start
    completed_since_checkpoint = 0
    checkpoint_no = 0
    last_hostname = ""
    stop_requested = False
    loop = asyncio.get_running_loop()

    def stop() -> None:
        nonlocal stop_requested
        stop_requested = True
        print("[SIGNAL] graceful stop requested", flush=True)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop)
        except (NotImplementedError, RuntimeError):
            pass

    pending: dict[asyncio.Task, tuple[int, str, float]] = {}
    cursor = 0

    def schedule() -> None:
        nonlocal cursor
        while not stop_requested and len(pending) < args.concurrency and cursor < len(remaining):
            if time.monotonic() - run_start >= args.soft_limit_seconds:
                break
            index, hostname = remaining[cursor]
            cursor += 1
            task = asyncio.create_task(process_hostname(
                index, hostname, sem, args.dns_timeout, args.hostname_hard_timeout, args.max_authoritative_ns
            ))
            pending[task] = (index, hostname, time.monotonic())

    schedule()
    while pending:
        if time.monotonic() - run_start >= args.soft_limit_seconds:
            stop_requested = True

        done, _ = await asyncio.wait(set(pending), timeout=10, return_when=asyncio.FIRST_COMPLETED)
        now = time.monotonic()
        if not done:
            if now - last_print >= args.heartbeat_seconds:
                elapsed = max(now - run_start, 0.001)
                c = counts(results)
                print(
                    f"[HEARTBEAT] {make_bar(len(results), len(hostnames))} "
                    f"{len(results)}/{len(hostnames)} CONFIRMED={c['01_CONFIRMED_NXDOMAIN']} "
                    f"RESCUED={c['02_DNS_ALIVE_RESCUED']} INCONSISTENT={c['03_INCONSISTENT_DNS']} "
                    f"UNCERTAIN={c['04_UNCERTAIN_RECHECK']} rate={len(results)/elapsed:.2f} active={len(pending)}",
                    flush=True,
                )
                write_progress(progress_path, results, len(hostnames), len(results)/elapsed, last_hostname, len(pending), checkpoint_no, "RUNNING")
                last_print = now
            if now - last_completion >= args.watchdog_seconds:
                for task in pending:
                    task.cancel()
                write_checkpoint(checkpoint_path, input_sha, len(hostnames), results, checkpoint_no, "WATCHDOG_ABORT", args)
                raise RuntimeError(f"Watchdog: no hostname completed for {args.watchdog_seconds}s")
            continue

        for task in done:
            index, hostname, started = pending.pop(task)
            try:
                result = task.result()
            except Exception as exc:
                result = {
                    "hostname": hostname,
                    "input_index": index,
                    "final_class": "04_UNCERTAIN_RECHECK",
                    "reason": f"TASK_EXCEPTION: {type(exc).__name__}: {exc}",
                    "recursive": {},
                    "authoritative": {},
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                    "timestamp_utc": utc_now(),
                }
            append_jsonl(partial_path, result)
            results[hostname] = result
            last_hostname = hostname
            last_completion = time.monotonic()
            completed_since_checkpoint += 1

        schedule()
        now = time.monotonic()
        if len(results) % args.progress_every == 0 or now - last_print >= args.heartbeat_seconds or not pending:
            elapsed = max(now - run_start, 0.001)
            c = counts(results)
            pct = 100 * len(results) / len(hostnames)
            print(
                f"[PROGRESS] {make_bar(len(results), len(hostnames))} {pct:6.2f}% {len(results)}/{len(hostnames)} | "
                f"CONFIRMED={c['01_CONFIRMED_NXDOMAIN']} RESCUED={c['02_DNS_ALIVE_RESCUED']} "
                f"INCONSISTENT={c['03_INCONSISTENT_DNS']} UNCERTAIN={c['04_UNCERTAIN_RECHECK']} | "
                f"rate={len(results)/elapsed:.2f} host/s active={len(pending)} last={last_hostname} checkpoint={checkpoint_no}",
                flush=True,
            )
            write_progress(progress_path, results, len(hostnames), len(results)/elapsed, last_hostname, len(pending), checkpoint_no, "RUNNING")
            last_print = now

        if completed_since_checkpoint >= args.checkpoint_every or now - last_checkpoint_time >= args.checkpoint_seconds:
            checkpoint_no += 1
            write_checkpoint(checkpoint_path, input_sha, len(hostnames), results, checkpoint_no, "RUNNING", args)
            if args.git_checkpoint:
                git_checkpoint(state_dir, len(results), len(hostnames))
            completed_since_checkpoint = 0
            last_checkpoint_time = time.monotonic()

    if cursor < len(remaining):
        checkpoint_no += 1
        write_checkpoint(checkpoint_path, input_sha, len(hostnames), results, checkpoint_no, "PAUSED_FOR_RESUME", args)
        elapsed = max(time.monotonic() - run_start, 0.001)
        write_progress(progress_path, results, len(hostnames), len(results)/elapsed, last_hostname, 0, checkpoint_no, "PAUSED_FOR_RESUME")
        if args.git_checkpoint:
            git_checkpoint(state_dir, len(results), len(hostnames))
        return 75

    if len(results) != len(hostnames):
        raise RuntimeError(f"Scheduler finished with {len(results)} results for {len(hostnames)} inputs")

    build_outputs(output_dir, hostnames, results, input_sha)
    checkpoint_no += 1
    write_checkpoint(checkpoint_path, input_sha, len(hostnames), results, checkpoint_no, "COMPLETE", args)
    elapsed = max(time.monotonic() - run_start, 0.001)
    write_progress(progress_path, results, len(hostnames), len(results)/elapsed, last_hostname, 0, checkpoint_no, "COMPLETE")

    c = counts(results)
    print("=" * 72, flush=True)
    print("NXDOMAIN CONFIRMATION COMPLETED", flush=True)
    print("=" * 72, flush=True)
    print(f"INPUT:                 {len(hostnames):,}", flush=True)
    print(f"CONFIRMED_NXDOMAIN:    {c['01_CONFIRMED_NXDOMAIN']:,}", flush=True)
    print(f"DNS_ALIVE_RESCUED:     {c['02_DNS_ALIVE_RESCUED']:,}", flush=True)
    print(f"INCONSISTENT_DNS:      {c['03_INCONSISTENT_DNS']:,}", flush=True)
    print(f"UNCERTAIN_RECHECK:     {c['04_UNCERTAIN_RECHECK']:,}", flush=True)
    print(f"TOTAL:                 {sum(c[name] for name in FINAL_CLASSES):,}", flush=True)
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--state-dir", required=True)
    p.add_argument("--expected-count", type=int, default=6224)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--dns-query-concurrency", type=int, default=12)
    p.add_argument("--dns-timeout", type=float, default=4.0)
    p.add_argument("--hostname-hard-timeout", type=float, default=90.0)
    p.add_argument("--max-authoritative-ns", type=int, default=4)
    p.add_argument("--progress-every", type=int, default=50)
    p.add_argument("--heartbeat-seconds", type=float, default=30.0)
    p.add_argument("--watchdog-seconds", type=float, default=180.0)
    p.add_argument("--checkpoint-every", type=int, default=100)
    p.add_argument("--checkpoint-seconds", type=float, default=180.0)
    p.add_argument("--soft-limit-seconds", type=float, default=19200.0)
    p.add_argument("--git-checkpoint", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        state_dir = Path(args.state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        error = f"timestamp_utc={utc_now()}\nexception={type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        (state_dir / "error.log").write_text(error, encoding="utf-8")
        print(error, file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
