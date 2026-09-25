#!/usr/bin/env python3
"""DNSentinel MVP - local UDP DNS proxy with blocklist + egress monitor.

Stdlib only. Optional: psutil (for richer egress data, falls back to netstat).
Usage:
  python agent.py serve
  python agent.py block add <domain>
  python agent.py block remove <domain>
  python agent.py block list
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")
BLOCK_TXT = os.path.join(BASE_DIR, "blocklist.txt")
BLOCK_JSON = os.path.join(BASE_DIR, "blocklist.json")
LOG_DIR = os.path.join(BASE_DIR, "logs")
DNS_LOG = os.path.join(LOG_DIR, "dns.log")
EGRESS_LOG = os.path.join(LOG_DIR, "egress.log")

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def default_config():
    return {
        "listen": "127.0.0.1",
        "port": 53,
        "upstreams": ["1.1.1.1", "8.8.8.8"],
        "upstream_port": 53,
        "timeout": 3.0,
        "blocklist": BLOCK_TXT,
        "log": DNS_LOG,
        "egress_log": EGRESS_LOG,
        "egress_interval": 10,
    }


def load_config(path=CONFIG_PATH):
    cfg = default_config()
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return cfg
    current_list = None
    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and current_list is not None:
            item = line.strip()
            if item.startswith("-"):
                cfg[current_list].append(item[1:].strip())
            continue
        current_list = None
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip().strip("\"'")
        if val == "":
            if key == "upstreams":
                cfg["upstreams"] = []
                current_list = "upstreams"
            continue
        if key in ("port", "upstream_port", "egress_interval"):
            try:
                cfg[key] = int(val)
            except ValueError:
                pass
        elif key == "timeout":
            try:
                cfg[key] = float(val)
            except ValueError:
                pass
        elif key in ("listen", "blocklist", "log", "egress_log"):
            cfg[key] = val
    if not cfg["upstreams"]:
        cfg["upstreams"] = ["1.1.1.1", "8.8.8.8"]
    return cfg


def block_path(cfg):
    p = cfg.get("blocklist", BLOCK_TXT)
    if not os.path.isabs(p):
        p = os.path.join(BASE_DIR, p)
    return p

def load_blocklist(cfg):
    path = block_path(cfg)
    domains = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                d = raw.strip().lower().rstrip(".")
                if d and not d.startswith("#"):
                    domains.add(d)
    except OSError:
        pass
    return domains


def save_blocklist(cfg, domains):
    path = block_path(cfg)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for d in sorted(domains):
            fh.write(d + "\n")
    os.replace(tmp, path)
    mirror = os.path.join(BASE_DIR, "blocklist.json")
    try:
        with open(mirror, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(sorted(domains), fh, indent=2)
            fh.write("\n")
    except OSError:
        pass


def decode_qname(data):
    labels = []
    i = 12
    while i < len(data):
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:
            break
        i += 1
        labels.append(data[i:i + ln].decode("utf-8", "replace").lower())
        i += ln
    qtype = struct.unpack("!H", data[i:i + 2])[0] if i + 4 <= len(data) else 0
    return ".".join(labels).rstrip("."), QTYPE_NAMES.get(qtype, str(qtype)), i

def build_blocked_response(query, qtype_str):
    if len(query) < 12:
        return b""
    txid = query[0:2]
    flags = struct.pack("!H", 0x8180)
    qdcount = query[4:6]
    ancount = struct.pack("!H", 1)
    header = txid + flags + qdcount + ancount + b"\x00\x00\x00\x00"
    try:
        _, _, qtype_off = decode_qname(query)
        q_end = qtype_off + 4
        question = query[12:q_end]
    except Exception:
        question = b""
    name_ptr = struct.pack("!H", 0xC00C)
    if qtype_str == "AAAA":
        rtype = struct.pack("!HHIH", 28, 1, 60, 16)
        rdata = b"\x00" * 16
    else:
        rtype = struct.pack("!HHIH", 1, 1, 60, 4)
        rdata = b"\x00\x00\x00\x00"
    answer = name_ptr + rtype + rdata
    return header + question + answer


def forward_upstream(query, cfg):
    for ip in cfg["upstreams"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(cfg.get("timeout", 3.0))
            s.sendto(query, (ip, cfg.get("upstream_port", 53)))
            resp, _ = s.recvfrom(4096)
            s.close()
            return resp
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            continue
    return None


def ensure_logdir(path):
    d = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass


def log_dns(cfg, client, domain, qtype, action, latency_ms):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "client": client,
        "domain": domain,
        "qtype": qtype,
        "action": action,
        "latency_ms": round(latency_ms, 2),
    }
    ensure_logdir(cfg.get("log", DNS_LOG))
    try:
        with open(cfg.get("log", DNS_LOG), "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass
def egress_via_psutil():
    import psutil
    rows = []
    for c in psutil.net_connections(kind="tcp"):
        if c.status == "ESTABLISHED" and c.raddr:
            try:
                proc = psutil.Process(c.pid) if c.pid else None
                pname = proc.name() if proc else "?"
            except Exception:
                pname = "?"
            rows.append({
                "proto": "tcp",
                "local": "%s:%s" % (c.laddr.ip, c.laddr.port) if c.laddr else "?",
                "remote": "%s:%s" % (c.raddr.ip, c.raddr.port),
                "pid": c.pid,
                "proc": pname,
            })
    return rows


def egress_via_netstat():
    rows = []
    try:
        out = subprocess.check_output(["netstat", "-ano", "-p", "TCP"],
                                      text=True, stderr=subprocess.STDOUT, timeout=10)
    except Exception:
        return rows
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "ESTABLISHED":
            rows.append({
                "proto": "tcp",
                "local": parts[1],
                "remote": parts[2],
                "pid": parts[4],
                "proc": "?",
            })
    return rows


def egress_snapshot():
    try:
        return egress_via_psutil()
    except Exception:
        pass
    return egress_via_netstat()


def egress_loop(cfg, stop_event):
    interval = int(cfg.get("egress_interval", 10))
    epath = cfg.get("egress_log", EGRESS_LOG)
    ensure_logdir(epath)
    while not stop_event.is_set():
        try:
            rows = egress_snapshot()
            rec = {"ts": datetime.now(timezone.utc).isoformat(),
                   "active_tcp": len(rows), "conns": rows[:200]}
            with open(epath, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass
        stop_event.wait(interval)
def handle_query(data, addr, sock, cfg, blocked):
    t0 = time.time()
    client = addr[0]
    domain, qtype, _ = decode_qname(data) if len(data) >= 12 else ("?", "?", 0)
    if domain in blocked:
        resp = build_blocked_response(data, qtype)
        try:
            sock.sendto(resp, addr)
        except Exception:
            pass
        log_dns(cfg, client, domain, qtype, "blocked", (time.time() - t0) * 1000)
        return
    resp = forward_upstream(data, cfg)
    if resp:
        try:
            sock.sendto(resp, addr)
        except Exception:
            pass
        log_dns(cfg, client, domain, qtype, "forwarded", (time.time() - t0) * 1000)
    else:
        log_dns(cfg, client, domain, qtype, "failed", (time.time() - t0) * 1000)


def serve(cfg):
    blocked = load_blocklist(cfg)
    mtime = os.path.getmtime(block_path(cfg)) if os.path.exists(block_path(cfg)) else 0
    listen = cfg.get("listen", "127.0.0.1")
    port = int(cfg.get("port", 53))
    stop = threading.Event()
    th = threading.Thread(target=egress_loop, args=(cfg, stop), daemon=True)
    th.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((listen, port))
    except PermissionError:
        print("ERROR: cannot bind %s:%d (need admin/root for port 53)" % (listen, port))
        stop.set()
        return 1
    print("DNSentinel serving on %s:%d, upstreams=%s" % (listen, port, ",".join(cfg["upstreams"])))
    try:
        while True:
            try:
                if os.path.exists(block_path(cfg)):
                    mt = os.path.getmtime(block_path(cfg))
                    if mt != mtime:
                        mtime = mt
                        blocked = load_blocklist(cfg)
            except OSError:
                pass
            sock.settimeout(1.0)
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            threading.Thread(target=handle_query, args=(data, addr, sock, cfg, blocked), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sock.close()
    return 0
def cmd_block(argv, cfg):
    blocked = load_blocklist(cfg)
    if not argv or argv[0] == "list":
        for d in sorted(blocked):
            print(d)
        return 0
    if argv[0] == "add" and len(argv) >= 2:
        d = argv[1].strip().lower().rstrip(".")
        blocked.add(d)
        save_blocklist(cfg, blocked)
        print("blocked: " + d)
        return 0
    if argv[0] == "remove" and len(argv) >= 2:
        d = argv[1].strip().lower().rstrip(".")
        blocked.discard(d)
        save_blocklist(cfg, blocked)
        print("unblocked: " + d)
        return 0
    print("usage: agent.py block [add|remove|list] [domain]")
    return 2


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cfg = load_config()
    if not argv or argv[0] == "serve":
        return serve(cfg)
    if argv[0] == "block":
        return cmd_block(argv[1:], cfg)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
