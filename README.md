# AI-NOC Core

AI-NOC Core is a lightweight, logs-first Network Operations Center engine designed for real-world infrastructure where log formats vary, dashboards are not required, and operational output must be actionable.

The system collects raw web and VPN logs via agents, automatically adapts to existing log formats, extracts real client IPs, correlates events into incidents, and delivers alerts and reports without requiring changes to Nginx or OpenVPN configurations.

## Key Principles

- Logs-first architecture (no metrics, no dashboards)
- Config-driven (no defaults, no assumptions)
- No log format changes required
- Raw logs are always preserved
- Real client IP extraction (X-Forwarded-For aware)
- Rule-based, deterministic correlation
- Email-first output (alerts and weekly reports)
- Works on Ubuntu/Debian and CentOS/RHEL

## Architecture Overview

AI-NOC consists of two components:

- Agent — runs on servers and collects logs
- Core — central FastAPI service for ingestion, correlation, and reporting

## Agent

### Responsibilities

- Tail configured log files (Nginx access/error, OpenVPN logs)
- Poll OpenVPN status file (optional)
- Autodetect log formats
- Extract normalized fields when possible
- Preserve raw log lines
- Redact sensitive data
- Batch, compress, and send events
- Authenticate using HMAC
- Spool data locally if the core is unavailable

## Core

### Responsibilities

- Receive events via POST /ingest
- Verify agent authenticity
- Store raw logs as gzip-compressed JSON Lines
- Correlate events into incidents
- Deduplicate incidents using fingerprints
- Persist incidents in PostgreSQL
- Generate alerts and reports

## Event Model

### Required Fields

- ts — UTC timestamp (ISO 8601)
- agent_id
- host
- service
- message — raw log line (after redaction)
- realip — resolved real client IP

### Optional Normalized Fields

- ip
- method
- uri
- status
- rt — request time (seconds)
- parser_id
- extra

### Example Event

```json
{
  "ts": "2026-01-21T12:34:56Z",
  "agent_id": "srv-web-01",
  "host": "web-01",
  "service": "nginx_access",
  "realip": "1.2.3.4",
  "message": "10.0.0.5 - - [21/Jan/2026:12:34:56 +0000] \"GET /login HTTP/1.1\" 401 169",
  "ip": "10.0.0.5",
  "method": "GET",
  "uri": "/login",
  "status": 401,
  "rt": 0.123,
  "parser_id": "nginx_combined_v1",
  "extra": {
    "xff": "1.2.3.4, 10.0.0.5"
  }
}
```

## Transport Protocol

Agents send events to the core using POST /ingest.

### Required Headers

- X-Agent-Id
- X-Signature — HMAC-SHA256 of the raw request body
- Content-Encoding: gzip (optional)

Transport metadata is strictly separated from observed log data.
Fields such as method, uri, and status originate only from parsed logs.

## Quick Start (Local)

### Prerequisites

- Docker
- Docker Compose

### Create examples directory

```bash
mkdir -p examples
```

### Start Core and database

```bash
cd examples
docker compose up -d --build
```

### Health check

```bash
curl http://localhost:8080/health
```

```json
{"ok": true}
```

## Agent Configuration

### General Rules

- All log paths must be explicitly defined
- There are no default paths or formats

### Example Configuration

```yaml
agent_id: srv-web-01
host: web-01

center:
  url: "http://localhost:8080/ingest"
  hmac_secret: "CHANGE_ME_long_random_secret"
  gzip: true
  timeout_seconds: 10
  batch_max_events: 300
  flush_interval_seconds: 2

storage:
  state_dir: "/var/lib/ai-noc-agent/state"
  spool_dir: "/var/lib/ai-noc-agent/spool"

redaction:
  enabled: true
  query_keys:
    - token
    - access_token
    - password
    - apikey
    - api_key

sources:
  - service: nginx_access
    path: /custom/path/nginx-access.log

  - service: nginx_error
    path: /custom/path/nginx-error.log

  - service: openvpn_log
    path: /custom/path/openvpn.log

  - service: openvpn_status
    path: /custom/path/openvpn-status.log
    mode: poll
    poll_seconds: 10
```

## Agent Installation

### Requirements

- Python 3.11+
- Ubuntu/Debian or CentOS/RHEL
- Read access to configured log files

### Install Agent

```bash
cd agent
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

### Run Agent Manually

```bash
ai-noc-agent --config /etc/ai-noc-agent/config.yml
```

## Running Agent as a Service

### systemd Unit Example

```ini
[Unit]
Description=AI-NOC Log Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ai-noc-agent --config /etc/ai-noc-agent/config.yml
Restart=always
RestartSec=2
User=root

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/ai-noc-agent

[Install]
WantedBy=multi-user.target
```

### Enable and Start

```bash
systemctl daemon-reload
systemctl enable --now ai-noc-agent
journalctl -u ai-noc-agent -f
```

## Core Configuration

### Environment Variables

```bash
DATABASE_URL=postgresql://user:password@host:5432/ainoc
RAW_DIR=/var/lib/ai-noc/raw
AGENT_SECRET__srv-web-01=super-long-random-secret
```

## Real Client IP Resolution

The agent determines realip using best-effort logic:

1. Extract IPs from X-Forwarded-For when present
2. Select the first public IP
3. Filter private and loopback ranges
4. Fall back to source IP if needed

No Nginx configuration changes are required.

## Rule Engine (v0)

### Web (Nginx)

- Brute force detection via repeated 401/403
- Scanning detection via mass 404 across multiple URIs
- Upstream outage detection via 502/503/504 spikes and error log patterns

### VPN (OpenVPN)

- Authentication failures
- TLS handshake failures
- Connection flapping via status file

Rules are deterministic, time-window based, and explainable.

## Data Storage

### Raw Logs

- Stored as gzip-compressed JSON Lines
- Organized by date, host, and service
- Always preserved for forensic analysis

### Incidents

- Stored in PostgreSQL
- Deduplicated using fingerprints
- Updated as new evidence arrives

## Security

- HMAC authentication per agent
- No shared secrets between agents
- Invalid or unsigned requests are rejected
- Sensitive data is redacted before transmission

## License

MIT
