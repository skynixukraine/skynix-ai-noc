from __future__ import annotations
import json, hashlib
from datetime import datetime, timezone, timedelta
from psycopg import Connection

# --- helpers ---
def _parse_ts(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)

def _fingerprint(parts: list[str]) -> str:
    return hashlib.sha256(("|".join(parts)).encode("utf-8")).hexdigest()

def upsert_incident(conn: Connection, *, severity:int, type_:str, title:str, summary:str,
                    host:str|None, service:str|None, evidence:dict, counters:dict, fingerprint:str) -> None:
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute("""
        INSERT INTO incidents (first_seen,last_seen,severity,type,title,summary,host,service,fingerprint,evidence,counters,is_open)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,TRUE)
        ON CONFLICT (fingerprint) DO UPDATE SET
          last_seen = EXCLUDED.last_seen,
          severity = LEAST(incidents.severity, EXCLUDED.severity),
          title = EXCLUDED.title,
          summary = EXCLUDED.summary,
          evidence = incidents.evidence || EXCLUDED.evidence,
          counters = incidents.counters || EXCLUDED.counters,
          is_open = TRUE
        """, (now, now, severity, type_, title, summary, host, service, fingerprint,
              json.dumps(evidence, ensure_ascii=False), json.dumps(counters, ensure_ascii=False)))
    conn.commit()

def process_events(conn: Connection, events: list[dict]) -> int:
    """
    Rules v0:
    - Web bruteforce: many 401/403 same realip + uri within 5min
    - Web scanning: many 404 same realip with many distinct uri within 10min
    - Web upstream outage: many 502/504 on host within 2min OR nginx_error contains upstream timeout/refused
    - VPN bruteforce: many AUTH_FAILED/TLS Error same src within 10min
    """
    now = datetime.now(timezone.utc)
    # time windows
    w5  = now - timedelta(minutes=5)
    w10 = now - timedelta(minutes=10)
    w2  = now - timedelta(minutes=2)

    # in-memory aggregation per ingest batch (simple MVP)
    web_401 = {}   # (host, realip, uri) -> count
    web_404 = {}   # (host, realip) -> {count, set(uri)}
    web_5xx = {}   # host -> count
    err_up  = {}   # host -> count
    vpn_bad = {}   # (host, src_or_user) -> count

    touched = 0

    for e in events:
        host = e.get("host")
        svc = e.get("service")
        ts = e.get("ts")
        try:
            t = _parse_ts(ts) if isinstance(ts,str) else now
        except Exception:
            t = now

        if svc == "nginx_access":
            realip = e.get("realip") or e.get("ip")
            status = e.get("status")
            uri = e.get("uri")
            if not realip or not isinstance(status, int) or not uri:
                continue

            if status in (401,403) and t >= w5:
                key = (host, realip, uri)
                web_401[key] = web_401.get(key,0) + 1

            if status == 404 and t >= w10:
                key = (host, realip)
                rec = web_404.get(key)
                if not rec:
                    rec = {"count":0, "uris": set()}
                    web_404[key] = rec
                rec["count"] += 1
                rec["uris"].add(uri)

            if status in (502,503,504) and t >= w2:
                web_5xx[host] = web_5xx.get(host,0) + 1

        elif svc == "nginx_error":
            msg = (e.get("message") or "").lower()
            if t < w2:
                continue
            if "upstream timed out" in msg or "connect() failed" in msg or "connection refused" in msg:
                err_up[host] = err_up.get(host,0) + 1

        elif svc in ("openvpn_log","openvpn_status"):
            msg = (e.get("message") or "").lower()
            if t < w10:
                continue
            if "auth_failed" in msg or "auth failed" in msg or "tls error" in msg or "tls handshake failed" in msg:
                src = e.get("realip") or e.get("ip") or e.get("username") or "unknown"
                key = (host, src)
                vpn_bad[key] = vpn_bad.get(key,0) + 1

    # thresholds
    for (host, realip, uri), cnt in web_401.items():
        if cnt >= 30:
            fp = _fingerprint(["web_bruteforce", host or "", realip, uri])
            upsert_incident(
                conn,
                severity=2,
                type_="web_bruteforce",
                title=f"Web bruteforce: {cnt}x 401/403 on {uri}",
                summary=f"Detected {cnt} unauthorized requests from {realip} to {uri} within 5 minutes.",
                host=host, service="nginx_access",
                evidence={"realip": realip, "uri": uri, "count": cnt},
                counters={"count": cnt},
                fingerprint=fp
            )
            touched += 1

    for (host, realip), rec in web_404.items():
        if rec["count"] >= 50 and len(rec["uris"]) >= 10:
            fp = _fingerprint(["web_scanning", host or "", realip])
            upsert_incident(
                conn,
                severity=3,
                type_="web_scanning",
                title=f"Web scanning: {rec['count']}x 404 from {realip}",
                summary=f"Detected likely scanning from {realip}: {rec['count']} 404s across {len(rec['uris'])} unique URIs within 10 minutes.",
                host=host, service="nginx_access",
                evidence={"realip": realip, "count": rec["count"], "unique_uris": len(rec["uris"])},
                counters={"count": rec["count"], "unique_uris": len(rec["uris"])},
                fingerprint=fp
            )
            touched += 1

    for host, cnt in web_5xx.items():
        if cnt >= 20:
            fp = _fingerprint(["web_upstream_5xx", host or ""])
            upsert_incident(
                conn,
                severity=1,
                type_="web_upstream_5xx",
                title=f"Upstream errors: {cnt}x 5xx (502/503/504)",
                summary=f"Detected {cnt} upstream-related 5xx responses on host {host} within 2 minutes.",
                host=host, service="nginx_access",
                evidence={"count": cnt},
                counters={"count": cnt},
                fingerprint=fp
            )
            touched += 1

    for host, cnt in err_up.items():
        if cnt >= 5:
            fp = _fingerprint(["web_upstream_errorlog", host or ""])
            upsert_incident(
                conn,
                severity=1,
                type_="web_upstream_errorlog",
                title=f"Nginx upstream errors in error.log ({cnt})",
                summary=f"Detected upstream connectivity/timeouts in nginx error log ({cnt} hits) within 2 minutes.",
                host=host, service="nginx_error",
                evidence={"count": cnt},
                counters={"count": cnt},
                fingerprint=fp
            )
            touched += 1

    for (host, src), cnt in vpn_bad.items():
        if cnt >= 20:
            fp = _fingerprint(["vpn_auth_fail", host or "", str(src)])
            upsert_incident(
                conn,
                severity=2,
                type_="vpn_auth_fail",
                title=f"OpenVPN auth/tls failures: {cnt} events",
                summary=f"Detected {cnt} OpenVPN auth/tls failures for {src} within 10 minutes.",
                host=host, service="openvpn_log",
                evidence={"src": src, "count": cnt},
                counters={"count": cnt},
                fingerprint=fp
            )
            touched += 1

    return touched

