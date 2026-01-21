from __future__ import annotations
import gzip, json, os
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from .security import verify_hmac
from .rawstore import append_raw
from .db import get_conn
from .rules import process_events

router = APIRouter()

def _decompress_if_needed(req: Request, body: bytes) -> bytes:
    if req.headers.get("Content-Encoding","").lower() == "gzip":
        return gzip.decompress(body)
    return body

def _decode_events(raw: bytes) -> list[dict]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    events = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events

@router.post("/ingest")
async def ingest(req: Request):
    agent_id = (req.headers.get("X-Agent-Id") or "").strip()
    sig = (req.headers.get("X-Signature") or "").strip()

    body = await req.body()

    # Verify HMAC per-agent secret
    # Secrets are simple env mapping: AGENT_SECRET__srv_web_01=...
    key = f"AGENT_SECRET__{agent_id}"
    secret = os.environ.get(key, "").encode("utf-8")
    if not secret or not verify_hmac(secret, body, sig):
        raise HTTPException(status_code=401, detail="bad signature")

    raw = _decompress_if_needed(req, body)
    events = _decode_events(raw)

    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="invalid payload")

    # Basic normalization guard
    now = datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    for e in events:
        e.setdefault("agent_id", agent_id)
        e.setdefault("ts", now)

    # Store raw (gzip members)
    raw_dir = os.environ.get("RAW_DIR", "/var/lib/ai-noc/raw")
    # group by host/service for raw store
    grouped = {}
    for e in events:
        host = e.get("host") or "unknown"
        service = e.get("service") or "unknown"
        grouped.setdefault((host, service), []).append(e)
    for (host, service), batch in grouped.items():
        append_raw(raw_dir, host, service, batch)

    # Process rules + incidents in Postgres
    with get_conn() as conn:
        created_or_updated = process_events(conn, events)

    return {"ok": True, "received": len(events), "incidents_touched": created_or_updated}

