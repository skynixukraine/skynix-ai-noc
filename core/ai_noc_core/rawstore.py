from __future__ import annotations
import gzip, os, json
from datetime import datetime, timezone

def utc_day_path(ts: datetime) -> str:
    ts = ts.astimezone(timezone.utc)
    return f"{ts.year:04d}/{ts.month:02d}/{ts.day:02d}"

def append_raw(base_dir: str, host: str, service: str, events: list[dict]) -> None:
    # /raw/YYYY/MM/DD/host/service.jsonl.gz
    if not events:
        return
    ts = parse_ts(events[0].get("ts")) or datetime.now(timezone.utc)
    rel = utc_day_path(ts)
    out_dir = os.path.join(base_dir, rel, host or "unknown")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{service or 'unknown'}.jsonl.gz")
    # append to gzip: safest is to append as separate gzip members
    with open(path, "ab") as f:
        with gzip.GzipFile(fileobj=f, mode="ab") as gz:
            for e in events:
                gz.write((json.dumps(e, ensure_ascii=False) + "\n").encode("utf-8"))

def parse_ts(v):
    if not v:
        return None
    try:
        # accepts ISO8601 Z
        if isinstance(v, str) and v.endswith("Z"):
            v = v[:-1] + "+00:00"
        return datetime.fromisoformat(v)
    except Exception:
        return None

