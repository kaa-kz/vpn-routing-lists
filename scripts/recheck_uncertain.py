#!/usr/bin/env python3
"""Strict second-pass recheck for 04_UNCERTAIN_RECHECK hostnames.

The source 04 list is never modified. Every hostname is classified exactly once
into a nested recheck output directory:
  01_LIVE_WEB.txt
  02_DNS_ALIVE_WEB_DEAD.txt
  03_NXDOMAIN_DEAD.txt
  04_STILL_UNCERTAIN.txt

DNS load is intentionally bounded by a global query semaphore. UDP failures are
retried over TCP. A/AAAA/CNAME are checked at hostname granularity; any real DNS
record means DNS_ALIVE. NXDOMAIN is accepted only when all three independent
resolvers agree. All ambiguous/error cases remain uncertain.
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

DNS_SERVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
}
FINAL_CLASSES = (
    "01_LIVE_WEB",
    "02_DNS_ALIVE_WEB_DEAD",
    "03_NXDOMAIN_DEAD",
    "04_STILL_UNCERTAIN",
)
OUT_NAMES = {name: f"{name}.txt" for name in FINAL_CLASSES}
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0 Safari/537.36"
CSV_FIELDS = [
    "hostname", "input_index", "final_class", "dns_class",
    "dns_a", "dns_aaaa", "dns_cname", "resolver_summary",
    "https_status", "https_effective_url", "https_error",
    "http_status", "http_effective_url", "http_error",
    "web_reason", "elapsed_ms", "timestamp_utc",
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
        raise RuntimeError(f"input count mismatch: expected={expected} got={len(items)}")
    if len(items) != len(set(items)):
        raise RuntimeError("input contains duplicate hostnames")
    return items


def atomic_json(path: Path, obj: Any) -> None:
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


def load_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                host = obj.get("hostname")
                if host:
                    out[host] = obj
            except json.JSONDecodeError:
                print(f"[WARN] malformed JSONL line {n} ignored", flush=True)
    return out


def extract_records(response: dns.message.Message) -> dict[str, list[str]]:
    out = {"A": [], "AAAA": [], "CNAME": []}
    for rrset in response.answer:
        kind = dns.rdatatype.to_text(rrset.rdtype)
        if kind not in out:
            continue
        for rdata in rrset:
            value = rdata.to_text().rstrip(".")
            if value not in out[kind]:
                out[kind].append(value)
    return out


async def dns_transport_query(
    semaphore: asyncio.Semaphore,
    server_ip: str,
    hostname: str,
    qtype: str,
    timeout: float,
) -> dict[str, Any]:
    """UDP query, then TCP fallback on transport failure/timeout."""
    async with semaphore:
        started = time.monotonic()
        q = dns.message.make_query(hostname, qtype, use_edns=True)
        udp_error = ""
        try:
            response = await asyncio.wait_for(
                dns.asyncquery.udp(q, server_ip, timeout=timeout), timeout=timeout + 0.5
            )
            if response.flags & dns.flags.TC:
                response = await asyncio.wait_for(
                    dns.asyncquery.tcp(q, server_ip, timeout=timeout), timeout=timeout + 0.5
                )
            return {
                "rcode": dns.rcode.to_text(response.rcode()),
                "records": extract_records(response),
                "transport": "udp" if not (response.flags & dns.flags.TC) else "tcp",
                "error": "",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        except Exception as exc:
            udp_error = f"{type(exc).__name__}: {exc}"

        try:
            response = await asyncio.wait_for(
                dns.asyncquery.tcp(q, server_ip, timeout=timeout), timeout=timeout + 0.5
            )
            return {
                "rcode": dns.rcode.to_text(response.rcode()),
                "records": extract_records(response),
                "transport": "tcp_fallback",
                "error": f"udp_failed: {udp_error}",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        except Exception as exc:
            return {
                "rcode": "ERROR",
                "records": {"A": [], "AAAA": [], "CNAME": []},
                "transport": "udp+tcp_failed",
                "error": f"udp={udp_error}; tcp={type(exc).__name__}: {exc}",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }


def has_any_record(result: dict[str, Any]) -> bool:
    rec = result.get("records", {})
    return any(rec.get(kind) for kind in ("A", "AAAA", "CNAME"))


async def strict_dns_check(
    hostname: str,
    query_sem: asyncio.Semaphore,
    timeout: float,
    hard_timeout: float,
) -> dict[str, Any]:
    async def run() -> dict[str, Any]:
        details: dict[str, dict[str, Any]] = {name: {} for name in DNS_SERVERS}

        # Stage 1: A on all three resolvers. An A reply may itself contain CNAME.
        a_tasks = {
            name: asyncio.create_task(dns_transport_query(query_sem, ip, hostname, "A", timeout))
            for name, ip in DNS_SERVERS.items()
        }
        for name, task in a_tasks.items():
            details[name]["A"] = await task

        if any(has_any_record(details[name]["A"]) for name in DNS_SERVERS):
            return finalize_dns(details, "DNS_ALIVE")

        # NXDOMAIN is a name-level answer. Require unanimity from three resolvers.
        if all(details[name]["A"].get("rcode") == "NXDOMAIN" for name in DNS_SERVERS):
            return finalize_dns(details, "NXDOMAIN_CONFIRMED")

        # Stage 2: only unresolved names need AAAA and CNAME.
        more_tasks: dict[tuple[str, str], asyncio.Task] = {}
        for name, ip in DNS_SERVERS.items():
            for qtype in ("AAAA", "CNAME"):
                more_tasks[(name, qtype)] = asyncio.create_task(
                    dns_transport_query(query_sem, ip, hostname, qtype, timeout)
                )
        for (name, qtype), task in more_tasks.items():
            details[name][qtype] = await task

        if any(
            has_any_record(result)
            for per_resolver in details.values()
            for result in per_resolver.values()
        ):
            return finalize_dns(details, "DNS_ALIVE")

        # A resolver is considered NXDOMAIN if any of its qtypes returned NXDOMAIN;
        # contradictory NOERROR on another qtype prevents that resolver being counted.
        resolver_states: dict[str, str] = {}
        for name, per in details.items():
            rcodes = [x.get("rcode") for x in per.values()]
            if "NOERROR" in rcodes:
                resolver_states[name] = "NODATA"
            elif "NXDOMAIN" in rcodes and all(r in ("NXDOMAIN", "ERROR") for r in rcodes):
                resolver_states[name] = "NXDOMAIN"
            elif all(r == "ERROR" for r in rcodes):
                resolver_states[name] = "ERROR"
            else:
                resolver_states[name] = "MIXED"

        if all(v == "NXDOMAIN" for v in resolver_states.values()):
            return finalize_dns(details, "NXDOMAIN_CONFIRMED", resolver_states)
        return finalize_dns(details, "DNS_UNCERTAIN", resolver_states)

    try:
        return await asyncio.wait_for(run(), timeout=hard_timeout)
    except asyncio.TimeoutError:
        return {
            "dns_class": "DNS_UNCERTAIN",
            "a": [], "aaaa": [], "cname": [],
            "resolver_states": {name: "DNS_HARD_TIMEOUT" for name in DNS_SERVERS},
            "details": {},
        }


def finalize_dns(
    details: dict[str, dict[str, Any]],
    dns_class: str,
    resolver_states: dict[str, str] | None = None,
) -> dict[str, Any]:
    records = {"A": [], "AAAA": [], "CNAME": []}
    for per in details.values():
        for result in per.values():
            for kind in records:
                for value in result.get("records", {}).get(kind, []):
                    if value not in records[kind]:
                        records[kind].append(value)
    if resolver_states is None:
        resolver_states = {}
        for name, per in details.items():
            if any(has_any_record(x) for x in per.values()):
                resolver_states[name] = "ALIVE"
            elif any(x.get("rcode") == "NXDOMAIN" for x in per.values()):
                resolver_states[name] = "NXDOMAIN"
            elif any(x.get("rcode") == "NOERROR" for x in per.values()):
                resolver_states[name] = "NODATA"
            else:
                resolver_states[name] = "ERROR"
    return {
        "dns_class": dns_class,
        "a": records["A"], "aaaa": records["AAAA"], "cname": records["CNAME"],
        "resolver_states": resolver_states,
        "details": details,
    }


async def fetch_once(session: aiohttp.ClientSession, url: str, max_redirects: int, ssl_value: Any) -> dict[str, Any]:
    current = url
    chain: list[str] = []
    first_status: int | None = None
    observed = False
    for hop in range(max_redirects + 1):
        async with session.get(
            current, allow_redirects=False, ssl=ssl_value,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        ) as resp:
            observed = True
            status = int(resp.status)
            if first_status is None:
                first_status = status
            loc = resp.headers.get("Location", "")
            if 300 <= status < 400 and loc and hop < max_redirects:
                nxt = urljoin(current, loc)
                chain.append(f"{status} {current} -> {nxt}")
                current = nxt
                continue
            return {
                "responded": True, "status": first_status, "final_status": status,
                "effective_url": current, "redirect_chain": chain, "error": "",
            }
    return {"responded": observed, "status": first_status, "effective_url": current, "redirect_chain": chain, "error": "redirect_limit"}


def tls_error(exc: BaseException) -> bool:
    return isinstance(exc, (aiohttp.ClientConnectorCertificateError, aiohttp.ClientSSLError, ssl.SSLError))


async def web_check(session: aiohttp.ClientSession, hostname: str, max_redirects: int) -> dict[str, Any]:
    try:
        https = await fetch_once(session, f"https://{hostname}/", max_redirects, True)
    except Exception as exc:
        https = {"responded": False, "status": None, "effective_url": f"https://{hostname}/", "redirect_chain": [], "error": f"{type(exc).__name__}: {exc}"}
        if tls_error(exc):
            try:
                https = await fetch_once(session, f"https://{hostname}/", max_redirects, False)
                https["insecure_tls"] = True
            except Exception as exc2:
                https = {"responded": False, "status": None, "effective_url": f"https://{hostname}/", "redirect_chain": [], "error": f"insecure_retry: {type(exc2).__name__}: {exc2}"}
    if https.get("responded"):
        return {"web_alive": True, "reason": "HTTPS_RESPONDED", "https": https, "http": {}}

    try:
        http = await fetch_once(session, f"http://{hostname}/", max_redirects, None)
    except Exception as exc:
        http = {"responded": False, "status": None, "effective_url": f"http://{hostname}/", "redirect_chain": [], "error": f"{type(exc).__name__}: {exc}"}
    if http.get("responded"):
        return {"web_alive": True, "reason": "HTTP_RESPONDED", "https": https, "http": http}
    return {"web_alive": False, "reason": "NO_HTTP_OR_HTTPS_RESPONSE", "https": https, "http": http}


async def process_one(index: int, hostname: str, args: argparse.Namespace, dns_sem: asyncio.Semaphore, session: aiohttp.ClientSession) -> dict[str, Any]:
    started = time.monotonic()
    async def inner() -> dict[str, Any]:
        dns_result = await strict_dns_check(hostname, dns_sem, args.dns_timeout, args.dns_hard_timeout)
        if dns_result["dns_class"] == "NXDOMAIN_CONFIRMED":
            final_class, web = "03_NXDOMAIN_DEAD", {}
        elif dns_result["dns_class"] == "DNS_UNCERTAIN":
            final_class, web = "04_STILL_UNCERTAIN", {}
        else:
            web = await web_check(session, hostname, args.max_redirects)
            final_class = "01_LIVE_WEB" if web.get("web_alive") else "02_DNS_ALIVE_WEB_DEAD"
        return {
            "hostname": hostname, "input_index": index, "final_class": final_class,
            "dns": dns_result, "web": web,
            "elapsed_ms": round((time.monotonic() - started) * 1000), "timestamp_utc": utc_now(),
        }
    try:
        return await asyncio.wait_for(inner(), timeout=args.hostname_hard_timeout)
    except asyncio.TimeoutError:
        return {
            "hostname": hostname, "input_index": index, "final_class": "04_STILL_UNCERTAIN",
            "dns": {"dns_class": "DNS_UNCERTAIN", "a": [], "aaaa": [], "cname": [], "resolver_states": {n: "HOSTNAME_HARD_TIMEOUT" for n in DNS_SERVERS}},
            "web": {"reason": "HOSTNAME_HARD_TIMEOUT"},
            "elapsed_ms": round((time.monotonic() - started) * 1000), "timestamp_utc": utc_now(),
        }
    except Exception as exc:
        return {
            "hostname": hostname, "input_index": index, "final_class": "04_STILL_UNCERTAIN",
            "dns": {"dns_class": "DNS_UNCERTAIN", "a": [], "aaaa": [], "cname": [], "resolver_states": {n: "PROCESSING_EXCEPTION" for n in DNS_SERVERS}},
            "web": {"reason": f"PROCESSING_EXCEPTION: {type(exc).__name__}: {exc}"},
            "elapsed_ms": round((time.monotonic() - started) * 1000), "timestamp_utc": utc_now(),
        }


def counts(results: dict[str, dict[str, Any]]) -> Counter:
    return Counter(x.get("final_class", "") for x in results.values())


def progress_line(done: int, total: int, results: dict[str, dict[str, Any]], started: float, last: str, active: int) -> str:
    c = counts(results)
    pct = 100 * done / total if total else 100
    width = 30
    fill = int(width * done / total) if total else width
    rate = done / max(time.monotonic() - started, 0.001)
    return (
        f"[PROGRESS] [{'#' * fill}{'-' * (width-fill)}] {pct:6.2f}% {done}/{total} | "
        f"LIVE={c['01_LIVE_WEB']} WEB_DEAD={c['02_DNS_ALIVE_WEB_DEAD']} "
        f"NXDOMAIN={c['03_NXDOMAIN_DEAD']} STILL_UNCERTAIN={c['04_STILL_UNCERTAIN']} | "
        f"rate={rate:.2f} host/s active={active} last={last}"
    )


def checkpoint(state_dir: Path, input_sha: str, total: int, results: dict[str, dict[str, Any]], number: int, status: str, args: argparse.Namespace) -> None:
    c = counts(results)
    atomic_json(state_dir / "checkpoint.json", {
        "version": 1, "status": status, "timestamp_utc": utc_now(),
        "input_sha256": input_sha, "input_count": total,
        "processed_count": len(results), "remaining_count": total-len(results),
        "checkpoint_number": number,
        "counts": {k: c[k] for k in FINAL_CLASSES},
        "config": {
            "hostname_concurrency": args.concurrency,
            "dns_query_concurrency": args.dns_query_concurrency,
            "dns_timeout": args.dns_timeout,
            "dns_hard_timeout": args.dns_hard_timeout,
            "http_connect_timeout": args.http_connect_timeout,
            "http_total_timeout": args.http_total_timeout,
            "hostname_hard_timeout": args.hostname_hard_timeout,
            "dns_servers": DNS_SERVERS,
        },
    })


def persist_git(state_dir: Path, done: int, total: int) -> None:
    try:
        branch = os.environ.get("GITHUB_REF_NAME") or subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
        subprocess.run(["git", "add", str(state_dir)], check=True, timeout=30)
        if subprocess.run(["git", "diff", "--cached", "--quiet"], timeout=10).returncode == 0:
            return
        subprocess.run(["git", "commit", "-m", f"Checkpoint uncertain recheck {done}/{total}"], check=True, timeout=60)
        p = subprocess.run(["git", "push", "origin", f"HEAD:{branch}"], text=True, capture_output=True, timeout=90)
        if p.returncode != 0:
            print(f"[CHECKPOINT][WARN] push failed: {p.stderr.strip()}", flush=True)
        else:
            print(f"[CHECKPOINT] persisted {done}/{total}", flush=True)
    except Exception as exc:
        print(f"[CHECKPOINT][WARN] {type(exc).__name__}: {exc}", flush=True)


def csv_row(r: dict[str, Any]) -> dict[str, Any]:
    d, w = r.get("dns", {}), r.get("web", {})
    hs, hp = w.get("https", {}) or {}, w.get("http", {}) or {}
    rs = d.get("resolver_states", {})
    return {
        "hostname": r.get("hostname", ""), "input_index": r.get("input_index", ""),
        "final_class": r.get("final_class", ""), "dns_class": d.get("dns_class", ""),
        "dns_a": ";".join(d.get("a", []) or []), "dns_aaaa": ";".join(d.get("aaaa", []) or []),
        "dns_cname": ";".join(d.get("cname", []) or []),
        "resolver_summary": ";".join(f"{n}={rs.get(n,'')}" for n in DNS_SERVERS),
        "https_status": hs.get("status", ""), "https_effective_url": hs.get("effective_url", ""), "https_error": hs.get("error", ""),
        "http_status": hp.get("status", ""), "http_effective_url": hp.get("effective_url", ""), "http_error": hp.get("error", ""),
        "web_reason": w.get("reason", ""), "elapsed_ms": r.get("elapsed_ms", ""), "timestamp_utc": r.get("timestamp_utc", ""),
    }


def write_outputs(output_dir: Path, hostnames: list[str], results: dict[str, dict[str, Any]], input_sha: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    c = counts(results)
    for cls, name in OUT_NAMES.items():
        members = [h for h in hostnames if results[h]["final_class"] == cls]
        (output_dir / name).write_text("\n".join(members) + ("\n" if members else ""), encoding="utf-8")
    with (output_dir / "recheck-results.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for h in hostnames:
            writer.writerow(csv_row(results[h]))
    total = sum(c[k] for k in FINAL_CLASSES)
    missing = [h for h in hostnames if h not in results]
    invalid = [h for h in hostnames if h in results and results[h].get("final_class") not in FINAL_CLASSES]
    text = "\n".join([
        "UNCERTAIN RECHECK COMPLETED", "===========================", f"timestamp_utc={utc_now()}",
        f"input_sha256={input_sha}", f"input={len(hostnames)}",
        f"01_LIVE_WEB={c['01_LIVE_WEB']}", f"02_DNS_ALIVE_WEB_DEAD={c['02_DNS_ALIVE_WEB_DEAD']}",
        f"03_NXDOMAIN_DEAD={c['03_NXDOMAIN_DEAD']}", f"04_STILL_UNCERTAIN={c['04_STILL_UNCERTAIN']}",
        f"class_total={total}", f"missing={len(missing)}", f"invalid_class={len(invalid)}", "duplicates=0",
    ]) + "\n"
    (output_dir / "summary.txt").write_text(text, encoding="utf-8")
    if total != len(hostnames) or missing or invalid:
        raise RuntimeError("final invariant failed: outputs do not cover input exactly once")


async def run(args: argparse.Namespace) -> int:
    inp, outdir, statedir = Path(args.input), Path(args.output_dir), Path(args.state_dir)
    hostnames = load_input(inp, args.expected_count)
    input_sha = sha256_file(inp)
    statedir.mkdir(parents=True, exist_ok=True)
    partial = statedir / "results.partial.jsonl"
    existing_cp = statedir / "checkpoint.json"
    if existing_cp.exists():
        cp = json.loads(existing_cp.read_text(encoding="utf-8"))
        if cp.get("input_sha256") and cp["input_sha256"] != input_sha:
            raise RuntimeError("checkpoint input SHA differs from current 04 input")
    results = load_jsonl(partial)
    source_set = set(hostnames)
    if any(h not in source_set for h in results):
        raise RuntimeError("checkpoint contains hostname not present in current input")
    remaining = [(i+1, h) for i, h in enumerate(hostnames) if h not in results]

    print("="*72, flush=True)
    print("STRICT RECHECK: 04_UNCERTAIN_RECHECK", flush=True)
    print(f"input={len(hostnames)} resume={len(results)} remaining={len(remaining)}", flush=True)
    print(f"input_sha256={input_sha}", flush=True)
    print(f"hostname_concurrency={args.concurrency} dns_query_concurrency={args.dns_query_concurrency}", flush=True)
    print(f"dns_timeout={args.dns_timeout}s dns_hard={args.dns_hard_timeout}s http_total={args.http_total_timeout}s", flush=True)

    if not remaining:
        write_outputs(outdir, hostnames, results, input_sha)
        checkpoint(statedir, input_sha, len(hostnames), results, 0, "COMPLETE", args)
        return 0

    dns_sem = asyncio.Semaphore(args.dns_query_concurrency)
    timeout = aiohttp.ClientTimeout(total=args.http_total_timeout, connect=args.http_connect_timeout, sock_connect=args.http_connect_timeout)
    connector = aiohttp.TCPConnector(limit=max(args.concurrency*2, 32), ttl_dns_cache=300, enable_cleanup_closed=True)
    started = time.monotonic()
    last_completion = started
    last_print = started
    last_cp = started
    last_host = ""
    cp_number = 0
    since_cp = 0
    stop = False
    loop = asyncio.get_running_loop()
    def ask_stop() -> None:
        nonlocal stop
        stop = True
        print("[SIGNAL] graceful stop requested", flush=True)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try: loop.add_signal_handler(sig, ask_stop)
        except Exception: pass

    pending: dict[asyncio.Task, tuple[int,str,float]] = {}
    cursor = 0
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, trust_env=False) as session:
        def schedule() -> None:
            nonlocal cursor
            while not stop and len(pending) < args.concurrency and cursor < len(remaining):
                if time.monotonic() - started >= args.soft_limit_seconds:
                    break
                idx, host = remaining[cursor]; cursor += 1
                t = asyncio.create_task(process_one(idx, host, args, dns_sem, session))
                pending[t] = (idx, host, time.monotonic())
        schedule()
        while pending:
            if time.monotonic() - started >= args.soft_limit_seconds:
                stop = True
            done, _ = await asyncio.wait(set(pending), timeout=min(args.heartbeat_seconds, 10), return_when=asyncio.FIRST_COMPLETED)
            now = time.monotonic()
            if not done:
                if now-last_print >= args.heartbeat_seconds:
                    print(progress_line(len(results), len(hostnames), results, started, last_host, len(pending)).replace("[PROGRESS]", "[HEARTBEAT]"), flush=True)
                    last_print = now
                if now-last_completion >= args.watchdog_seconds:
                    for t in pending: t.cancel()
                    checkpoint(statedir, input_sha, len(hostnames), results, cp_number, "WATCHDOG_ABORT", args)
                    raise RuntimeError(f"watchdog: no hostname completed for {args.watchdog_seconds}s")
                continue
            for t in done:
                idx, host, t0 = pending.pop(t)
                try: result = t.result()
                except Exception as exc:
                    result = {"hostname": host, "input_index": idx, "final_class": "04_STILL_UNCERTAIN", "dns": {"dns_class": "DNS_UNCERTAIN", "a": [], "aaaa": [], "cname": [], "resolver_states": {n:"TASK_EXCEPTION" for n in DNS_SERVERS}}, "web": {"reason": f"TASK_EXCEPTION: {type(exc).__name__}: {exc}"}, "elapsed_ms": round((time.monotonic()-t0)*1000), "timestamp_utc": utc_now()}
                append_jsonl(partial, result)
                results[host] = result
                last_host = host
                last_completion = time.monotonic()
                since_cp += 1
            schedule()
            now = time.monotonic()
            if len(results) % args.progress_every == 0 or now-last_print >= args.heartbeat_seconds or not pending:
                print(progress_line(len(results), len(hostnames), results, started, last_host, len(pending)), flush=True)
                last_print = now
            if since_cp >= args.checkpoint_every or now-last_cp >= args.checkpoint_seconds:
                cp_number += 1
                checkpoint(statedir, input_sha, len(hostnames), results, cp_number, "RUNNING", args)
                if args.git_checkpoint: persist_git(statedir, len(results), len(hostnames))
                since_cp = 0; last_cp = time.monotonic()

        if cursor < len(remaining):
            cp_number += 1
            checkpoint(statedir, input_sha, len(hostnames), results, cp_number, "PAUSED_FOR_RESUME", args)
            if args.git_checkpoint: persist_git(statedir, len(results), len(hostnames))
            print(f"[PAUSE] {len(results)}/{len(hostnames)} saved; rerun resumes", flush=True)
            return 75

    if len(results) != len(hostnames):
        raise RuntimeError(f"scheduler ended with {len(results)}/{len(hostnames)} results")
    write_outputs(outdir, hostnames, results, input_sha)
    cp_number += 1
    checkpoint(statedir, input_sha, len(hostnames), results, cp_number, "COMPLETE", args)
    c = counts(results)
    print("="*72, flush=True)
    print("UNCERTAIN RECHECK COMPLETED", flush=True)
    for k in FINAL_CLASSES: print(f"{k}={c[k]}", flush=True)
    print(f"TOTAL={sum(c[k] for k in FINAL_CLASSES)}", flush=True)
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="generated/domain-check/04_UNCERTAIN_RECHECK.txt")
    p.add_argument("--output-dir", default="generated/domain-check/recheck-04")
    p.add_argument("--state-dir", default="state/recheck-04")
    p.add_argument("--expected-count", type=int, default=8189)
    p.add_argument("--concurrency", type=int, default=12)
    p.add_argument("--dns-query-concurrency", type=int, default=18)
    p.add_argument("--dns-timeout", type=float, default=4.0)
    p.add_argument("--dns-hard-timeout", type=float, default=22.0)
    p.add_argument("--http-connect-timeout", type=float, default=4.0)
    p.add_argument("--http-total-timeout", type=float, default=12.0)
    p.add_argument("--hostname-hard-timeout", type=float, default=50.0)
    p.add_argument("--max-redirects", type=int, default=10)
    p.add_argument("--progress-every", type=int, default=50)
    p.add_argument("--heartbeat-seconds", type=float, default=30.0)
    p.add_argument("--watchdog-seconds", type=float, default=120.0)
    p.add_argument("--checkpoint-every", type=int, default=250)
    p.add_argument("--checkpoint-seconds", type=float, default=180.0)
    p.add_argument("--soft-limit-seconds", type=float, default=19200.0)
    p.add_argument("--git-checkpoint", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run(args))
    except Exception as exc:
        statedir = Path(args.state_dir); statedir.mkdir(parents=True, exist_ok=True)
        text = f"timestamp_utc={utc_now()}\nexception={type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        (statedir / "error.log").write_text(text, encoding="utf-8")
        print(text, file=sys.stderr, flush=True)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
