#!/usr/bin/env python3
"""
SPIDER MASS SCANNER
A conservative TCP port checker for IP ranges you own or are explicitly
authorized to assess. It does not perform banner grabbing or exploitation.
"""
import argparse
import asyncio
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
RANGES_PATH = ROOT / "ir_ip_ranges.txt"
RESULTS_DIR = ROOT / "results"
LOGS_DIR = ROOT / "logs"

DEFAULT_CONFIG = {
    "ports": [22, 80, 443, 3389],
    "timeout_seconds": 1.5,
    "concurrency": 100,
    "max_hosts": 4096,
    "delay_between_batches_ms": 0
}

def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg.setdefault("ports", DEFAULT_CONFIG["ports"])
    cfg.setdefault("timeout_seconds", DEFAULT_CONFIG["timeout_seconds"])
    cfg.setdefault("concurrency", DEFAULT_CONFIG["concurrency"])
    cfg.setdefault("max_hosts", DEFAULT_CONFIG["max_hosts"])
    cfg.setdefault("delay_between_batches_ms", 0)
    return cfg

def load_targets(max_hosts):
    if not RANGES_PATH.exists():
        RANGES_PATH.write_text(
            "# Add only IPs/CIDR ranges you own or are authorized to scan.\n"
            "# Example documentation range: 192.0.2.0/29\n",
            encoding="utf-8"
        )
    targets = []
    total = 0
    for line_no, raw in enumerate(RANGES_PATH.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Invalid range on line {line_no}: {value} ({exc})")
        if network.version != 4:
            raise SystemExit(f"IPv6 is not enabled in this starter version (line {line_no}).")
        count = network.num_addresses
        if total + count > max_hosts:
            raise SystemExit(
                f"Target limit exceeded: {total + count} addresses; "
                f"config.json max_hosts is {max_hosts}. Use smaller authorized ranges."
            )
        # Include every address in the supplied CIDR; user controls the exact scope.
        targets.extend(str(ip) for ip in network)
        total += count
    if not targets:
        raise SystemExit("No targets found. Add an authorized IP/CIDR range to ranges.txt.")
    return targets

async def check_port(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"ip": ip, "port": port, "state": "open"}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

async def run_scan(targets, ports, timeout, concurrency, delay_ms):
    semaphore = asyncio.Semaphore(concurrency)
    jobs = [
        check_port(ip, port, timeout, semaphore)
        for ip in targets for port in ports
    ]
    results = []
    total = len(jobs)
    done = 0
    batch_size = max(concurrency * 5, 1)
    for start in range(0, total, batch_size):
        batch = jobs[start:start + batch_size]
        found = await asyncio.gather(*batch)
        results.extend(item for item in found if item)
        done += len(batch)
        print(f"\rChecked {done}/{total} host-port pairs | Open: {len(results)}", end="", flush=True)
        if delay_ms and start + batch_size < total:
            await asyncio.sleep(delay_ms / 1000)
    print()
    return results

def main():
    parser = argparse.ArgumentParser(description="Scan authorized IPv4 ranges for selected TCP ports.")
    parser.add_argument("--ports", help="Comma-separated TCP ports, e.g. 22,80,443")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=LOGS_DIR / "scanner.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    cfg = load_config()
    ports = [int(p) for p in args.ports.split(",")] if args.ports else cfg["ports"]
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise SystemExit("Ports must be integers between 1 and 65535.")
    if cfg["concurrency"] < 1 or cfg["concurrency"] > 500:
        raise SystemExit("Set concurrency between 1 and 500 in config.json.")
    if cfg["timeout_seconds"] <= 0:
        raise SystemExit("timeout_seconds must be greater than zero.")

    targets = load_targets(int(cfg["max_hosts"]))
    print("SPIDER MASS SCANNER")
    print(f"Targets: {len(targets)} | Ports: {ports}")
    print("Scope reminder: scan only systems you own or are explicitly authorized to test.")

    started = time.time()
    results = asyncio.run(run_scan(
        targets, ports, float(cfg["timeout_seconds"]),
        int(cfg["concurrency"]), int(cfg["delay_between_batches_ms"])
    ))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    txt_path = RESULTS_DIR / f"open_ports_{stamp}.txt"
    json_path = RESULTS_DIR / f"results_{stamp}.json"

    # Required compact IP:PORT format, one result per line.
    txt_path.write_text(
        "".join(f'{item["ip"]}:{item["port"]}\n' for item in results),
        encoding="utf-8"
    )
    report = {
        "scanner": "SPIDER MASS SCANNER",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "targets_checked": len(targets),
        "ports_checked": ports,
        "open_count": len(results),
        "duration_seconds": round(time.time() - started, 2),
        "results": results
    }
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logging.info("Finished: %s targets, %s open ports", len(targets), len(results))
    print(f"\nDone. Open ports: {len(results)}")
    print(f"TXT:  {txt_path}")
    print(f"JSON: {json_path}")

if __name__ == "__main__":
    main()
