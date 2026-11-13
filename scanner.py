#!/usr/bin/env python3
"""
SPIDER MASS SCANNER
A conservative TCP port checker for IP ranges you own or are explicitly
authorized to assess. It does not perform banner grabbing or exploitation.

After scan completes, sends results to Telegram as a document.
"""
import argparse
import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
import urllib.request
import urllib.parse
import mimetypes
import uuid
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
    "delay_between_batches_ms": 0,
    "telegram_bot_token": "",
    "telegram_chat_id": ""
}

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    # Environment overrides
    cfg["telegram_bot_token"] = os.environ.get("TG_BOT_TOKEN", cfg["telegram_bot_token"])
    cfg["telegram_chat_id"] = os.environ.get("TG_CHAT_ID", cfg["telegram_chat_id"])
    return cfg

# ─────────────────────────────────────────────
# TARGETS
# ─────────────────────────────────────────────
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
            raise SystemExit(f"IPv6 is not enabled (line {line_no}).")
        count = network.num_addresses
        if total + count > max_hosts:
            raise SystemExit(
                f"Target limit exceeded: {total + count} addresses; "
                f"config.json max_hosts is {max_hosts}."
            )
        targets.extend(str(ip) for ip in network)
        total += count
    if not targets:
        raise SystemExit("No targets found. Add CIDR ranges to ir_ip_ranges.txt.")
    return targets

# ─────────────────────────────────────────────
# SCANNER
# ─────────────────────────────────────────────
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
    jobs = [check_port(ip, port, timeout, semaphore) for ip in targets for port in ports]
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

# ─────────────────────────────────────────────
# TELEGRAM — sendDocument (multipart, zero deps)
# ─────────────────────────────────────────────
def _build_multipart(fields, files):
    """
    fields: dict[str, str]
    files:  list of (field_name, filepath, filename, mime)
    returns (body_bytes, content_type_header)
    """
    boundary = "----SpiderBoundary" + uuid.uuid4().hex
    parts = []

    for name, value in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        parts.append(str(value).encode())
        parts.append(b"\r\n")

    for field_name, path, filename, mime in files:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode()
        )
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        parts.append(Path(path).read_bytes())
        parts.append(b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"

def telegram_send_message(token, chat_id, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true"
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[!] Telegram sendMessage failed: {e}")
        return None

def telegram_send_document(token, chat_id, filepath, caption=""):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    path = Path(filepath)
    mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"

    fields = {
        "chat_id": str(chat_id),
        "caption": caption[:1024],
        "parse_mode": "HTML",
    }
    files = [("document", str(path), path.name, mime)]
    body, ctype = _build_multipart(fields, files)

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", ctype)
    req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[!] Telegram sendDocument HTTP {e.code}: {e.read().decode(errors='ignore')[:200]}")
        return None
    except Exception as e:
        print(f"[!] Telegram sendDocument failed: {e}")
        return None

def push_to_telegram(cfg, txt_path, json_path, results, targets_count, ports, elapsed):
    token = cfg.get("telegram_bot_token", "").strip()
    chat  = str(cfg.get("telegram_chat_id", "")).strip()

    if not token or not chat:
        print("[!] Telegram not configured — skipping upload.")
        print("    Set telegram_bot_token & telegram_chat_id in config.json")
        print("    or export TG_BOT_TOKEN / TG_CHAT_ID env vars.")
        return

    # Summary message first
    summary = (
        f"<b>🕷 SPIDER SCAN COMPLETE</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Targets : <code>{targets_count}</code>\n"
        f"Ports   : <code>{ports}</code>\n"
        f"Open    : <code>{len(results)}</code>\n"
        f"Time    : <code>{elapsed}s</code>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"Files below ↓"
    )
    telegram_send_message(token, chat, summary)

    # TXT (compact IP:PORT) — main deliverable
    if txt_path and Path(txt_path).exists():
        telegram_send_document(
            token, chat, txt_path,
            caption=f"📄 IP:PORT list — {len(results)} open ports"
        )

    # JSON — optional detail
    if json_path and Path(json_path).exists():
        telegram_send_document(
            token, chat, json_path,
            caption="🗂 JSON report (full detail)"
        )

    print("[+] Sent to Telegram.")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Scan authorized IPv4 ranges for selected TCP ports.")
    parser.add_argument("--ports", help="Comma-separated TCP ports, e.g. 22,80,443")
    parser.add_argument("--tg-token", help="Telegram bot token (overrides config)")
    parser.add_argument("--tg-chat", help="Telegram chat ID (overrides config)")
    parser.add_argument("--no-telegram", action="store_true", help="Skip Telegram upload")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    logging.basicConfig(
        filename=LOGS_DIR / "scanner.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    cfg = load_config()
    if args.tg_token: cfg["telegram_bot_token"] = args.tg_token
    if args.tg_chat:  cfg["telegram_chat_id"]  = args.tg_chat

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
    elapsed = round(time.time() - started, 2)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    txt_path = RESULTS_DIR / f"open_ports_{stamp}.txt"
    json_path = RESULTS_DIR / f"results_{stamp}.json"

    # Compact IP:PORT, one per line — this is what gets sent to Telegram
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
        "duration_seconds": elapsed,
        "results": results
    }
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logging.info("Finished: %s targets, %s open ports", len(targets), len(results))
    print(f"\nDone. Open ports: {len(results)}")
    print(f"TXT:  {txt_path}")
    print(f"JSON: {json_path}")

    if not args.no_telegram:
        push_to_telegram(cfg, txt_path, json_path, results, len(targets), ports, elapsed)

if __name__ == "__main__":
    main()
