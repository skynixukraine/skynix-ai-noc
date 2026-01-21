from __future__ import annotations
import os, re, time, json, gzip, hmac, hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import yaml
import requests

# ----------------- utils -----------------
PRIVATE_V4 = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
]

def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    if ":" in ip:  # ipv6 minimal handling
        return ip in ("::1",) or ip.lower().startswith(("fe80:", "fc", "fd"))
    return any(r.match(ip) for r in PRIVATE_V4)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def hmac_sig(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()

def redact_line(line: str, query_keys: List[str]) -> str:
    # mask common query params: token=..., password=...
    # keep it simple MVP: replace key=VALUE with key=***
    for k in query_keys:
        line = re.sub(rf"({re.escape(k)}=)[^&\s]+", r"\1***", line, flags=re.IGNORECASE)
    # mask Authorization headers if present in logs
    line = re.sub(r"(authorization:\s*)(bearer\s+)?[A-Za-z0-9\-\._~\+/]+=*", r"\1***", line, flags=re.IGNORECASE)
    return line

# ----------------- parsers (autodetect) -----------------
NGINX_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/(?P<httpver>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"(?:\s+"(?P<xff>[^"]*)")?(?:\s+rt=(?P<rt>[0-9\.]+))?.*$'
)

# fallback for method/uri/status inside quotes
REQ_IN_LINE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})')

IP_ANY = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})")

def extract_realip(ip: Optional[str], xff: Optional[str]) -> Optional[str]:
    # prefer first public ip from xff list
    if xff:
        parts = [p.strip() for p in xff.split(",")]
        for p in parts:
            m = IP_ANY.search(p)
            if m:
                cand = m.group("ip")
                if not is_private_ip(cand):
                    return cand
    # fallback
    return ip

def parse_nginx_access(line: str) -> Dict[str, Any]:
    m = NGINX_COMBINED.match(line)
    if m:
        ip = m.group("ip")
        method = m.group("method")
        uri = m.group("uri")
        status = int(m.group("status"))
        rt = m.group("rt")
        xff = m.group("xff") or ""
        realip = extract_realip(ip, xff)
        out = {
            "ip": ip,
            "realip": realip or ip,
            "method": method,
            "uri": uri,
            "status": status,
            "rt": float(rt) if rt else None,
            "parser_id": "nginx_combined_v1",
            "extra": {"xff": xff} if xff else {},
        }
        return out

    # fallback: try to find request/status and first ip
    ipm = IP_ANY.search(line)
    reqm = REQ_IN_LINE.search(line)
    out = {"parser_id": "unknown", "extra": {}}
    if ipm:
        out["ip"] = ipm.group("ip")
        out["realip"] = out["ip"]
    if reqm:
        out["method"] = reqm.group("method")
        out["uri"] = reqm.group("uri")
        out["status"] = int(reqm.group("status"))
    return out

def parse_nginx_error(line: str) -> Dict[str, Any]:
    # basic: detect upstream patterns + client ip if present
    low = line.lower()
    out = {"parser_id": "nginx_error_v1", "extra": {}}
    ipm = re.search(r"client:\s*(\S+)", line)
    if ipm:
        out["ip"] = ipm.group(1).rstrip(",")
        out["realip"] = out["ip"]
    if "upstream timed out" in low or "connect() failed" in low or "connection refused" in low:
        out["extra"]["upstream_problem"] = True
    return out

def parse_openvpn_log(line: str) -> Dict[str, Any]:
    low = line.lower()
    out = {"parser_id": "openvpn_log_v1", "extra": {}}
    # best-effort src ip
    ipm = IP_ANY.search(line)
    if ipm:
        out["ip"] = ipm.group("ip")
        out["realip"] = out["ip"]
    # username/common name often in brackets or after 'user='; keep best effort
    um = re.search(r"(?:user|username|common name)[:=]\s*([A-Za-z0-9_\-\.@]+)", low)
    if um:
        out["username"] = um.group(1)
    if "auth_failed" in low or "auth failed" in low:
        out["extra"]["auth_failed"] = True
    if "tls error" in low or "tls handshake failed" in low:
        out["extra"]["tls_error"] = True
    return out

def parse_openvpn_status(text: str) -> List[Dict[str, Any]]:
    # openvpn-status.log has sections; parse CLIENT_LIST lines:
    # CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,...
    events = []
    for line in text.splitlines():
        if line.startswith("CLIENT_LIST,"):
            parts = line.split(",")
            if len(parts) >= 8:
                cn = parts[1]
                real_addr = parts[2].split(":")[0]
                br = parts[4]
                bs = parts[5]
                events.append({
                    "parser_id": "openvpn_status_v1",
                    "username": cn,
                    "ip": real_addr,
                    "realip": real_addr,
                    "extra": {"bytes_received": br, "bytes_sent": bs}
                })
    return events

# ----------------- tail + poll -----------------
@dataclass
class Source:
    service: str
    path: str
    mode: str = "tail"
    poll_seconds: int = 10

def read_cfg(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_offset(state_file: str) -> int:
    try:
        with open(state_file, "r") as f:
            return int(f.read().strip() or "0")
    except Exception:
        return 0

def save_offset(state_file: str, off: int) -> None:
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w") as f:
        f.write(str(off))

def tail_lines(path: str, state_file: str, max_lines: int = 2000) -> List[str]:
    # simple tail with byte offset; handles truncation
    off = load_offset(state_file)
    lines = []
    try:
        st = os.stat(path)
        if off > st.st_size:
            off = 0
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read()
            new_off = f.tell()
        if data:
            text = data.decode("utf-8", errors="replace")
            lines = text.splitlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
        save_offset(state_file, new_off)
    except FileNotFoundError:
        # keep offset
        return []
    except Exception:
        return []
    return lines

def read_file_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

# ----------------- sender + spool -----------------
def encode_batch(events: List[dict], use_gzip: bool) -> (bytes, dict):
    body = json.dumps(events, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if use_gzip:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    return body, headers

def send_batch(url: str, agent_id: str, secret: str, events: List[dict], use_gzip: bool, timeout: int) -> bool:
    body, headers = encode_batch(events, use_gzip)
    sig = hmac_sig(secret.encode("utf-8"), body)
    headers["X-Agent-Id"] = agent_id
    headers["X-Signature"] = sig
    try:
        r = requests.post(url, data=body, headers=headers, timeout=timeout)
        return r.status_code >= 200 and r.status_code < 300
    except Exception:
        return False

def spool_write(spool_dir: str, events: List[dict]) -> None:
    os.makedirs(spool_dir, exist_ok=True)
    name = f"{int(time.time()*1000)}.json"
    path = os.path.join(spool_dir, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False)

def spool_drain(spool_dir: str) -> List[str]:
    if not os.path.isdir(spool_dir):
        return []
    files = sorted([os.path.join(spool_dir, x) for x in os.listdir(spool_dir) if x.endswith(".json")])
    return files

def spool_read(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def spool_delete(path: str) -> None:
    try:
        os.remove(path)
    except Exception:
        pass

# ----------------- main loop -----------------
def build_event(cfg: dict, source: Source, line: str, parsed: dict) -> dict:
    e = {
        "ts": now_iso(),
        "agent_id": cfg["agent_id"],
        "host": cfg["host"],
        "service": source.service,
        "message": line,
        "parser_id": parsed.get("parser_id", "unknown"),
        "realip": parsed.get("realip"),
        # normalized optional fields
        "ip": parsed.get("ip"),
        "method": parsed.get("method"),
        "uri": parsed.get("uri"),
        "status": parsed.get("status"),
        "rt": parsed.get("rt"),
        "extra": parsed.get("extra", {}),
    }
    # ensure required: realip fallback
    if not e["realip"]:
        e["realip"] = e["ip"]
    return e

def parse_by_service(service: str, line: str) -> dict:
    if service == "nginx_access":
        return parse_nginx_access(line)
    if service == "nginx_error":
        return parse_nginx_error(line)
    if service in ("openvpn_log",):
        return parse_openvpn_log(line)
    # unknown service: just raw
    return {"parser_id":"unknown","extra":{}}

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    args = ap.parse_args()

    cfg = read_cfg(args.config)
    center = cfg["center"]
    storage = cfg["storage"]
    red = cfg.get("redaction", {})
    qkeys = red.get("query_keys", ["token","password","apikey","api_key"])
    redact_enabled = bool(red.get("enabled", True))

    sources = []
    for s in cfg.get("sources", []):
        sources.append(Source(
            service=s["service"],
            path=s["path"],
            mode=s.get("mode","tail"),
            poll_seconds=int(s.get("poll_seconds",10))
        ))

    state_dir = storage["state_dir"]
    spool_dir = storage["spool_dir"]

    batch_max = int(center.get("batch_max_events", 500))
    flush_every = float(center.get("flush_interval_seconds", 2))
    timeout = int(center.get("timeout_seconds", 10))
    use_gzip = bool(center.get("gzip", True))

    buffer: List[dict] = []
    last_flush = time.time()
    last_poll: Dict[str, float] = {}

    while True:
        # 1) drain spool first
        for fpath in spool_drain(spool_dir)[:5]:
            try:
                evs = spool_read(fpath)
                ok = send_batch(center["url"], cfg["agent_id"], center["hmac_secret"], evs, use_gzip, timeout)
                if ok:
                    spool_delete(fpath)
                else:
                    break
            except Exception:
                break

        # 2) read sources
        for src in sources:
            if src.mode == "poll":
                lp = last_poll.get(src.path, 0)
                if time.time() - lp < src.poll_seconds:
                    continue
                last_poll[src.path] = time.time()
                text = read_file_text(src.path)
                if not text:
                    continue
                if src.service == "openvpn_status":
                    ev_items = parse_openvpn_status(text)
                    for item in ev_items:
                        line = "CLIENT_LIST"  # keep minimal
                        e = build_event(cfg, src, line, item)
                        buffer.append(e)
                else:
                    # generic poll: single event snapshot
                    parsed = {"parser_id": "snapshot", "extra": {}}
                    e = build_event(cfg, src, text[:2000], parsed)
                    buffer.append(e)
                continue

            # tail mode
            state_file = os.path.join(state_dir, re.sub(r"[^A-Za-z0-9_\-\.]+","_", src.path) + ".offset")
            lines = tail_lines(src.path, state_file)
            if not lines:
                continue
            for line in lines:
                if not line.strip():
                    continue
                if redact_enabled:
                    line = redact_line(line, qkeys)
                parsed = parse_by_service(src.service, line)
                e = build_event(cfg, src, line, parsed)
                buffer.append(e)
                if len(buffer) >= batch_max:
                    break

        # 3) flush by timer / size
        if buffer and (len(buffer) >= batch_max or (time.time() - last_flush) >= flush_every):
            ok = send_batch(center["url"], cfg["agent_id"], center["hmac_secret"], buffer, use_gzip, timeout)
            if not ok:
                spool_write(spool_dir, buffer)
            buffer = []
            last_flush = time.time()

        time.sleep(0.5)

if __name__ == "__main__":
    main()

