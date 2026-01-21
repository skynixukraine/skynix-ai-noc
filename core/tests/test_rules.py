from __future__ import annotations

from datetime import datetime, timezone

import ai_noc_core.rules as rules


def _collect_incidents(monkeypatch):
    calls = []

    def _fake_upsert_incident(conn, **kwargs):
        calls.append(kwargs)

    monkeypatch.setattr(rules, "upsert_incident", _fake_upsert_incident)
    return calls


def test_parse_ts_accepts_z_suffix():
    parsed = rules._parse_ts("2024-06-01T12:30:00Z")
    assert parsed.tzinfo is timezone.utc
    assert parsed.isoformat() == "2024-06-01T12:30:00+00:00"


def test_fingerprint_is_stable():
    assert rules._fingerprint(["a", "b"]) == rules._fingerprint(["a", "b"])
    assert rules._fingerprint(["a", "b"]) != rules._fingerprint(["a", "c"])


def test_process_events_records_web_bruteforce(monkeypatch):
    calls = _collect_incidents(monkeypatch)
    now = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "host": "edge-1",
            "service": "nginx_access",
            "ts": now,
            "realip": "203.0.113.10",
            "status": 401,
            "uri": "/login",
        }
        for _ in range(30)
    ]

    touched = rules.process_events(object(), events)

    assert touched == 1
    assert calls[0]["type_"] == "web_bruteforce"
    assert calls[0]["severity"] == 2
    assert calls[0]["evidence"]["count"] == 30


def test_process_events_records_scanning_and_vpn(monkeypatch):
    calls = _collect_incidents(monkeypatch)
    now = datetime.now(timezone.utc).isoformat()

    scan_events = [
        {
            "host": "edge-2",
            "service": "nginx_access",
            "ts": now,
            "realip": "198.51.100.9",
            "status": 404,
            "uri": f"/missing/{idx % 12}",
        }
        for idx in range(50)
    ]
    vpn_events = [
        {
            "host": "vpn-1",
            "service": "openvpn_log",
            "ts": now,
            "realip": "198.51.100.25",
            "message": "AUTH_FAILED",
        }
        for _ in range(20)
    ]

    touched = rules.process_events(object(), scan_events + vpn_events)

    types = {call["type_"] for call in calls}
    assert touched == 2
    assert "web_scanning" in types
    assert "vpn_auth_fail" in types


def test_process_events_ignores_below_threshold(monkeypatch):
    calls = _collect_incidents(monkeypatch)
    now = datetime.now(timezone.utc).isoformat()

    events = [
        {
            "host": "edge-3",
            "service": "nginx_access",
            "ts": now,
            "realip": "203.0.113.99",
            "status": 401,
            "uri": "/login",
        }
        for _ in range(10)
    ]

    touched = rules.process_events(object(), events)

    assert touched == 0
    assert calls == []
