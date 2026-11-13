import argparse
import asyncio
import ipaddress
import json
import logging
import mimetypes
import os
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
RANGES_PATH = ROOT / "ip.txt"
RESULTS_DIR = ROOT / "results"
LOGS_DIR = ROOT / "logs"

SSH_BANNERS = (b"SSH-2.0-", b"SSH-1.99-", b"SSH-1.5-")

DEFAULT_CONFIG = {
    "ports": [22],
    "timeout_seconds": 0.8,
    "concurrency": 500,
    "max_hosts": 20000000,
    "delay_between_batches_ms": 0,
    "verify_ssh": True,
    "verify_timeout_seconds": 3.0,
    "verify_concurrency": 300,
    "telegram_bot_token": "",
    "telegram_chat_id": ""
}


def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    cfg["telegram_bot_token"] = os.environ.get("TG_BOT_TOKEN", cfg["telegram_bot_token"])
    cfg["telegram_chat_id"] = os.environ.get("TG_CHAT_ID", cfg["telegram_chat_id"])
    return cfg


def load_targets(max_hosts):
    if not RANGES_PATH.exists():
        RANGES_PATH.write_text("# Add IPv4 CIDR ranges here.\n", encoding="utf-8")
    targets = []
    total = 0
    for line_no, raw in enumerate(RANGES_PATH.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Invalid range line {line_no}: {value} ({exc})")
        if network.version != 4:
            raise SystemExit(f"IPv6 not supported (line {line_no}).")
        count = network.num_addresses
        if total + count > max_hosts:
            raise SystemExit(f"Limit: {total + count} > max_hosts {max_hosts}")
        targets.extend(str(ip) for ip in network)
        total += count
    if not targets:
        raise SystemExit("No targets. Add CIDR to ir_ip_ranges.txt.")
    return targets


# ── SCANNER ──
async def check_port(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return {"ip": ip, "port": port}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def run_scan(targets, ports, timeout, concurrency, delay_ms):
    sem = asyncio.Semaphore(concurrency)
    results = []
    total = len(targets) * len(ports)
    done = 0
    batch = 50000
    for i in range(0, len(targets), batch):
        chunk = targets[i:i + batch]
        jobs = [check_port(ip, port, timeout, sem) for ip in chunk for port in ports]
        found = await asyncio.gather(*jobs)
        results.extend(r for r in found if r)
        done += len(jobs)
        print("\r" + f"Scanned {done}/{total} | Open: {len(results)}", end="", flush=True)
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)
    print()
    return results


# ── SSH VERIFIER ──
async def grab_banner(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            try:
                data = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError):
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
                return None
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            if not data or not data.startswith(SSH_BANNERS):
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            if len(banner) < 8 or len(banner) > 255:
                return None
            return {"ip": ip, "port": port, "banner": banner}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def run_verify(pairs, timeout, concurrency):
    sem = asyncio.Semaphore(concurrency)
    results = []
    total = len(pairs)
    done = 0
    batch = 1000
    for i in range(0, total, batch):
        chunk = pairs[i:i + batch]
        jobs = [grab_banner(ip, port, timeout, sem) for ip, port in chunk]
        found = await asyncio.gather(*jobs)
        results.extend(x for x in found if x)
        done += len(chunk)
        print("\r" + f"Verified {done}/{total} | Real SSH: {len(results)}", end="", flush=True)
    print()
    return results


# ── TELEGRAM ──
def _multipart(fields, files):
    boundary = "----Spider" + uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        parts.append(str(v).encode()); parts.append(b"\r\n")
    for name, path, fname, mime in files:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'.encode())
        parts.append(f"Content-Type: {mime}\r\n\r\n".encode())
        parts.append(Path(path).read_bytes()); parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def tg_message(token, chat, text):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": "true"}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[!] sendMessage failed: {e}"); return None


def tg_document(token, chat, filepath, caption=""):
    url = f"https://api.telegram.org/bot{token}/sendDocument"
    path = Path(filepath)
    mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    fields = {"chat_id": str(chat), "caption": caption[:1024], "parse_mode": "HTML"}
    files = [("document", str(path), path.name, mime)]
    body, ctype = _multipart(fields, files)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", ctype)
    req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[!] sendDocument HTTP {e.code}: {e.read().decode(errors='ignore')[:300]}"); return None
    except Exception as e:
        print(f"[!] sendDocument failed: {e}"); return None


def push_telegram(cfg, txt, jsonp, summary_html):
    token = (cfg.get("telegram_bot_token") or "").strip()
    chat = str(cfg.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        print("[!] Telegram not configured. Set telegram_bot_token & telegram_chat_id in config.json.")
        return
    tg_message(token, chat, summary_html)
    if txt and Path(txt).exists():
        tg_document(token, chat, txt, caption="IP:PORT list")
    if jsonp and Path(jsonp).exists():
        tg_document(token, chat, jsonp, caption="JSON with banners")
    print("[+] Sent to Telegram.")


# ── MAIN ──
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ports", help="Comma-separated, e.g. 22,80,443")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--no-telegram", action="store_true")
    parser.add_argument("--tg-token")
    parser.add_argument("--tg-chat")
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
    if args.tg_chat: cfg["telegram_chat_id"] = args.tg_chat

    ports = [int(p) for p in args.ports.split(",")] if args.ports else cfg["ports"]
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise SystemExit("Ports must be 1-65535.")

    targets = load_targets(int(cfg["max_hosts"]))
    print("SPIDER SCANNER v2")
    print(f"Targets: {len(targets)} | Ports: {ports}")
    print(f"Scan: timeout={cfg['timeout_seconds']}s concurrency={cfg['concurrency']}")
    print(f"Verify: {'on' if cfg.get('verify_ssh') and not args.no_verify else 'off'}")
    print("Scope: only systems you own or are authorized to test.")
    print("─" * 60)

    t0 = time.time()
    scan_results = asyncio.run(run_scan(
        targets, ports, float(cfg["timeout_seconds"]),
        int(cfg["concurrency"]), int(cfg["delay_between_batches_ms"])
    ))
    scan_elapsed = round(time.time() - t0, 2)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    txt_path = RESULTS_DIR / f"open_ports_{stamp}.txt"
    json_path = RESULTS_DIR / f"results_{stamp}.json"

    txt_path.write_text(
        "".join(f'{r["ip"]}:{r["port"]}\n' for r in scan_results),
        encoding="utf-8"
    )
    json_path.write_text(json.dumps({
        "scanner": "SPIDER SCANNER v2",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "targets_checked": len(targets),
        "ports_checked": ports,
        "open_count": len(scan_results),
        "scan_duration_seconds": scan_elapsed,
        "results": scan_results
    }, indent=2), encoding="utf-8")

    print(f"\n[+] Scan done: {len(scan_results)} open in {scan_elapsed}s")

    # ── VERIFY SSH ──
    verify_results = None
    verified_txt = None
    verified_json = None
    verify_elapsed = 0

    do_verify = cfg.get("verify_ssh", True) and not args.no_verify and 22 in ports
    if do_verify and scan_results:
        pairs = [(r["ip"], r["port"]) for r in scan_results if r["port"] == 22]
        if pairs:
            print("─" * 60)
            print(f"Verifying {len(pairs)} SSH candidates...")
            t1 = time.time()
            verify_results = asyncio.run(run_verify(
                pairs, float(cfg["verify_timeout_seconds"]),
                int(cfg["verify_concurrency"])
            ))
            verify_elapsed = round(time.time() - t1, 2)

            verified_txt = RESULTS_DIR / f"verified_ssh_{stamp}.txt"
            verified_json = RESULTS_DIR / f"verified_ssh_{stamp}.json"
            verified_txt.write_text(
                "".join(f'{r["ip"]}:{r["port"]}\n' for r in verify_results),
                encoding="utf-8"
            )
            verified_json.write_text(json.dumps({
                "scanner": "SPIDER SCANNER v2",
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "input_checked": len(pairs),
                "real_ssh": len(verify_results),
                "verify_duration_seconds": verify_elapsed,
                "hosts": verify_results
            }, indent=2), encoding="utf-8")
            print(f"\n[+] Verify done: {len(verify_results)} real SSH in {verify_elapsed}s")

    print("─" * 60)
    print(f"TXT:  {txt_path}")
    print(f"JSON: {json_path}")
    if verified_txt:
        print(f"VERIFIED TXT:  {verified_txt}")
        print(f"VERIFIED JSON: {verified_json}")

    if args.no_telegram:
        return

    # ── TELEGRAM ──
    summary = (
        f"<b>SPIDER SCAN COMPLETE</b>\n"
        f"Targets  : <code>{len(targets)}</code>\n"
        f"Ports    : <code>{ports}</code>\n"
        f"Open     : <code>{len(scan_results)}</code>\n"
        f"Scan time: <code>{scan_elapsed}s</code>"
    )
    if verify_results is not None:
        summary += (
            f"\nVerified : <code>{len(verify_results)}</code> real SSH"
            f"\nVerify t : <code>{verify_elapsed}s</code>"
            f"\nFiltered : <code>{len(scan_results) - len(verify_results)}</code> (fake/dead)"
        )

    # send VERIFIED files if exist, else raw scan files
    send_txt = verified_txt if verified_txt else txt_path
    send_json = verified_json if verified_json else json_path
    push_telegram(cfg, send_txt, send_json, summary)

    logging.info("Done. scan=%d verify=%d", len(scan_results),
                 len(verify_results) if verify_results else 0)


if __name__ == "__main__":
    main()