#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luxedeum, LLC d/b/a Monster Gaming

"""lux_sentinel.py — Defensive security monitoring agent.

Always-on service monitoring AI fleet infrastructure with heuristics from:
  - Palo Alto Networks Unit 42 threat intelligence
  - Verizon DBIR attack pattern analysis
  - MITRE ATT&CK framework technique mapping

Scans: credential exposure, file permissions, port exposure, HTTP auth,
NATS auth, DB role isolation, log anomalies, service integrity.

Reports: PG security_findings + NATS security.sentinel.*
Health: HTTP :SENTINEL_PORT /health /findings /metrics
"""

import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Thread

import psycopg2
import psycopg2.extras

PORT = int(os.environ.get("SENTINEL_PORT", "8776"))
SCAN_INTERVAL = int(os.environ.get("SENTINEL_SCAN_INTERVAL", "3600"))
DB_URL = os.environ.get("DATABASE_URL", "")
NATS_URL = os.environ.get("NATS_URL", "nats://127.0.0.1:4222")
FLEET_DIR = "/var/lib/ai-fleet"
PROMPTS_DIR = "/etc/ai-fleet/prompts"
CONFIG_DIR = "/etc/ai-fleet"

_findings_cache = []
_metrics_cache = {}
_last_scan_ts = 0
_scan_count = 0

# ── Heuristic Definitions ─────────────────────────────────────────
# Each maps to a specific scan function with source attribution.

HEURISTICS = [
    {
        "id": "PAN-CRED-001",
        "name": "Hardcoded API Keys in Fleet Scripts",
        "source": "paloalto",
        "mitre": "T1552.001",
        "severity": "critical",
        "description": "Unit 42 IR Report: hardcoded credentials in automation scripts are the #1 initial access vector in cloud/hybrid breaches. Fleet run scripts contain raw API keys readable by any process.",
    },
    {
        "id": "PAN-CRED-002",
        "name": "Sensitive Files World-Readable",
        "source": "paloalto",
        "mitre": "T1552.001",
        "severity": "high",
        "description": "Unit 42: Overly permissive file ACLs on credential stores enable lateral credential harvesting.",
    },
    {
        "id": "PAN-CRED-003",
        "name": "Prompt Files Not Readable by Service Account",
        "source": "paloalto",
        "mitre": "T1499.004",
        "severity": "medium",
        "description": "System prompt files owned by root with 640 perms. Service account can't read, causing silent functional degradation (prompt caching failure, empty system prompts).",
    },
    {
        "id": "PAN-NET-001",
        "name": "Service Bound to 0.0.0.0 Without Auth",
        "source": "paloalto",
        "mitre": "T1190",
        "severity": "high",
        "description": "Unit 42 Cloud Threat Report: services binding all interfaces without authentication are the primary attack surface in hybrid environments.",
    },
    {
        "id": "PAN-NET-002",
        "name": "NATS Bus Without Authentication",
        "source": "paloalto",
        "mitre": "T1040",
        "severity": "high",
        "description": "Unit 42: Unauthenticated message buses enable passive reconnaissance and active message injection.",
    },
    {
        "id": "PAN-SUP-001",
        "name": "Binary Integrity Deviation",
        "source": "paloalto",
        "mitre": "T1554",
        "severity": "high",
        "description": "Unit 42 Supply Chain Report: modified binaries are the hallmark of supply chain compromise. Hash deviations from known-good indicate tampering.",
    },
    {
        "id": "VDBIR-WEB-001",
        "name": "HTTP Endpoint Missing Authentication",
        "source": "verizon_dbir",
        "mitre": "T1078",
        "severity": "high",
        "description": "Verizon DBIR: Web application attacks are the #1 breach pattern. 49% start with credential abuse — endpoints without auth are free entry.",
    },
    {
        "id": "VDBIR-PRIV-001",
        "name": "DB Role Privilege Escalation Path",
        "source": "verizon_dbir",
        "mitre": "T1548",
        "severity": "critical",
        "description": "Verizon DBIR: Privilege misuse accounts for 20% of breaches. DB role separation (your DB role separation policy) must be enforced — fleet_svc must never DELETE/TRUNCATE on knowledge_artifacts.",
    },
    {
        "id": "VDBIR-ERR-001",
        "name": "Information Disclosure via Error Response",
        "source": "verizon_dbir",
        "mitre": "T1082",
        "severity": "medium",
        "description": "Verizon DBIR: Error-based information disclosure gives attackers internal architecture knowledge. Verbose errors on HTTP endpoints leak stack traces, paths, versions.",
    },
    {
        "id": "VDBIR-TIME-001",
        "name": "Detection Latency Baseline",
        "source": "verizon_dbir",
        "mitre": "TA0007",
        "severity": "info",
        "description": "Verizon DBIR: Median time-to-detect is months. This metric tracks our own MTTD to ensure we beat industry baseline.",
    },
    {
        "id": "MITRE-T1046",
        "name": "Unexpected Listening Port",
        "source": "mitre",
        "mitre": "T1046",
        "severity": "medium",
        "description": "New listening ports not in the expected set indicate unauthorized services, backdoors, or misconfiguration.",
    },
    {
        "id": "MITRE-T1543",
        "name": "Unauthorized Systemd Service",
        "source": "mitre",
        "mitre": "T1543.002",
        "severity": "high",
        "description": "New or modified systemd services outside the known registry indicate persistence mechanisms.",
    },
]

HEURISTIC_MAP = {h["id"]: h for h in HEURISTICS}

EXPECTED_PORTS = {
    4222, 5432, 8742, 8760, 8770, 8775, 8776, 8777, 8778,
    9100, 11434, 1933, 1666, 13340, 5002, 18789,
}

KNOWN_SERVICES = {
    "neutron-dispatcher", "luxagentos", "nats-server", "postgresql",
    "lux-seat-watchdog", "luxsre-watchdog", "nats-bridge", "ollama",
    "llm-gateway", "outcome-analyzer", "lux-sentinel", "lux-adversary",
    "neutron-state-keeper", "lux-build-panel", "openclaw-gateway",
    "lux-memory-consolidation", "lux-memory-health", "lux-memory-sleep",
    "lux-memory-projector", "routellm-sidecar", "lux-forge-neutron-adapter",
    "horde-server",
}

API_KEY_PATTERNS = [
    re.compile(r"sk-ant-api\S+"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"xoxb-[0-9]+-[A-Za-z0-9]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:password|secret|token|key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.I),
]

HTTP_SERVICES = [
    ("luxagentos", "http://127.0.0.1:8742/health"),
    ("llm-gateway", "http://127.0.0.1:8760/health"),
    ("state-keeper", "http://127.0.0.1:8770/health"),
    ("outcome-analyzer", "http://127.0.0.1:8775/health"),
    ("build-panel", "http://127.0.0.1:9100/"),
    ("horde-server", "http://127.0.0.1:13340/"),
]


def db_conn():
    return psycopg2.connect(DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def nats_publish(subject, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 4222))
        s.recv(4096)
        data = json.dumps(payload)
        msg = "PUB {} {}\r\n{}\r\n".format(subject, len(data), data)
        s.sendall(msg.encode())
        s.close()
    except Exception as e:
        print("[sentinel] NATS publish error: {}".format(e), file=sys.stderr)


def upsert_finding(conn, finding):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO security_findings
            (finding_id, agent, severity, category, technique, title, description,
             evidence, affected_asset, heuristic_source, status, remediation, first_seen, last_seen)
        VALUES (%(finding_id)s, 'sentinel', %(severity)s, %(category)s, %(technique)s,
                %(title)s, %(description)s, %(evidence)s::jsonb, %(affected_asset)s,
                %(heuristic_source)s, 'open', %(remediation)s, now(), now())
        ON CONFLICT (finding_id) DO UPDATE SET
            last_seen = now(),
            evidence = EXCLUDED.evidence,
            severity = EXCLUDED.severity
        RETURNING id
    """, finding)
    conn.commit()
    return cur.fetchone()["id"]


def record_metric(conn, name, value, dimensions=None):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO security_metrics (metric_name, metric_value, dimensions)
        VALUES (%s, %s, %s)
    """, (name, value, json.dumps(dimensions or {})))
    conn.commit()


# ── Security Scanners ─────────────────────────────────────────────

def scan_credential_exposure():
    """PAN-CRED-001: Grep fleet scripts for hardcoded API keys."""
    findings = []
    fleet_dir = Path(FLEET_DIR)
    if not fleet_dir.exists():
        return findings

    exposed_files = []
    for f in fleet_dir.glob("*.sh"):
        try:
            content = f.read_text()
            for pattern in API_KEY_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    for m in matches:
                        redacted = m[:12] + "..." + m[-4:] if len(m) > 20 else m[:8] + "..."
                        exposed_files.append({"file": str(f), "pattern": redacted, "key_type": pattern.pattern[:20]})
        except PermissionError:
            exposed_files.append({"file": str(f), "error": "permission denied (still a finding — can't audit)"})

    if exposed_files:
        h = HEURISTIC_MAP["PAN-CRED-001"]
        findings.append({
            "finding_id": "PAN-CRED-001-fleet-scripts",
            "severity": h["severity"],
            "category": "credential_access",
            "technique": h["mitre"],
            "title": "{} fleet scripts with hardcoded API keys".format(len(exposed_files)),
            "description": h["description"],
            "evidence": json.dumps({"exposed_count": len(exposed_files), "samples": exposed_files[:5]}),
            "affected_asset": FLEET_DIR,
            "heuristic_source": h["source"],
            "remediation": "Rotate API keys to env-file-only delivery. Run scripts should source credentials from /etc/ai-fleet/fleet.conf, never embed.",
        })
    return findings


def scan_file_permissions():
    """PAN-CRED-002 + PAN-CRED-003: Check sensitive file/dir permissions."""
    findings = []
    sensitive_paths = [
        (FLEET_DIR, "fleet runtime directory"),
        (CONFIG_DIR, "config directory"),
        ("/etc/ai-fleet/fleet.conf", "fleet credentials"),
        ("/etc/ai-fleet/agent.conf", "agent credentials"),
    ]

    for path_str, label in sensitive_paths:
        p = Path(path_str)
        if not p.exists():
            continue
        try:
            st = p.stat()
            mode = stat.S_IMODE(st.st_mode)
            others_read = mode & stat.S_IROTH
            others_exec = mode & stat.S_IXOTH
            if others_read or (p.is_file() and others_exec):
                findings.append({
                    "finding_id": "PAN-CRED-002-{}".format(p.name),
                    "severity": "high",
                    "category": "credential_access",
                    "technique": "T1552.001",
                    "title": "{} is world-readable (mode {:04o})".format(label, mode),
                    "description": HEURISTIC_MAP["PAN-CRED-002"]["description"],
                    "evidence": json.dumps({"path": path_str, "mode": "{:04o}".format(mode), "owner": "{}:{}".format(st.st_uid, st.st_gid)}),
                    "affected_asset": path_str,
                    "heuristic_source": "paloalto",
                    "remediation": "chmod o-rwx {}".format(path_str),
                })
        except PermissionError:
            pass

    prompts_dir = Path(PROMPTS_DIR)
    if prompts_dir.exists():
        unreadable = []
        for f in prompts_dir.glob("*.md"):
            try:
                f.read_text()
            except PermissionError:
                unreadable.append(str(f.name))
        if unreadable:
            findings.append({
                "finding_id": "PAN-CRED-003-prompt-perms",
                "severity": "medium",
                "category": "impact",
                "technique": "T1499.004",
                "title": "{}/{} prompt files unreadable by service account".format(len(unreadable), len(list(prompts_dir.glob("*.md")))),
                "description": HEURISTIC_MAP["PAN-CRED-003"]["description"],
                "evidence": json.dumps({"unreadable": unreadable[:10], "total": len(unreadable)}),
                "affected_asset": PROMPTS_DIR,
                "heuristic_source": "paloalto",
                "remediation": "sudo chgrp aisvc-fleet /etc/ai-fleet/prompts/*.md && sudo chmod g+r /etc/ai-fleet/prompts/*.md",
            })
    return findings


def scan_port_exposure():
    """PAN-NET-001 + MITRE-T1046: Audit listening ports."""
    findings = []
    try:
        out = subprocess.check_output(["ss", "-tlnp"], text=True, timeout=10)
    except Exception:
        return findings

    listening = set()
    bound_all = []
    for line in out.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        addr = parts[3]
        if ":" in addr:
            host, port_s = addr.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                continue
            listening.add(port)
            if host in ("0.0.0.0", "*", "[::]"):
                bound_all.append({"port": port, "address": addr})

    unexpected = listening - EXPECTED_PORTS
    if unexpected:
        findings.append({
            "finding_id": "MITRE-T1046-unexpected-ports",
            "severity": "medium",
            "category": "discovery",
            "technique": "T1046",
            "title": "{} unexpected listening ports".format(len(unexpected)),
            "description": HEURISTIC_MAP["MITRE-T1046"]["description"],
            "evidence": json.dumps({"unexpected": sorted(unexpected), "expected_count": len(EXPECTED_PORTS)}),
            "affected_asset": "network",
            "heuristic_source": "mitre",
            "remediation": "Investigate each unexpected port. Add to EXPECTED_PORTS if authorized, or shut down the service.",
        })

    unauthenticated_on_all = []
    for svc in bound_all:
        if svc["port"] not in (5432, 11434, 18789):
            unauthenticated_on_all.append(svc)

    if unauthenticated_on_all:
        findings.append({
            "finding_id": "PAN-NET-001-bound-all",
            "severity": "high",
            "category": "initial_access",
            "technique": "T1190",
            "title": "{} services on 0.0.0.0 (VPN-accessible)".format(len(unauthenticated_on_all)),
            "description": HEURISTIC_MAP["PAN-NET-001"]["description"],
            "evidence": json.dumps({"services": unauthenticated_on_all}),
            "affected_asset": "network",
            "heuristic_source": "paloalto",
            "remediation": "Bind services to 127.0.0.1 or add authentication. VPN ACLs are not sufficient for defense-in-depth.",
        })
    return findings


def scan_nats_auth():
    """PAN-NET-002: Test if NATS allows unauthenticated subscription."""
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", 4222))
        banner = s.recv(4096).decode()
        s.sendall(b"SUB fleet.dispatch.* 1\r\n")
        s.sendall(b"PING\r\n")
        resp = s.recv(4096).decode()
        s.close()
        if "PONG" in resp and "-ERR" not in resp:
            findings.append({
                "finding_id": "PAN-NET-002-nats-unauth",
                "severity": "high",
                "category": "credential_access",
                "technique": "T1040",
                "title": "NATS accepts unauthenticated subscriptions to fleet.dispatch.*",
                "description": HEURISTIC_MAP["PAN-NET-002"]["description"],
                "evidence": json.dumps({"banner": banner.strip(), "sub_response": resp.strip()}),
                "affected_asset": "nats://127.0.0.1:4222",
                "heuristic_source": "paloalto",
                "remediation": "Enable NATS auth (user/password or token). Configure ACLs to restrict fleet.dispatch.* to dispatcher only.",
            })
    except Exception as e:
        print("[sentinel] NATS auth scan error: {}".format(e), file=sys.stderr)
    return findings


def scan_http_auth():
    """VDBIR-WEB-001: Probe HTTP endpoints for missing authentication."""
    findings = []
    for name, url in HTTP_SERVICES:
        try:
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=5)
            body = resp.read(4096).decode(errors="replace")
            if resp.status == 200:
                has_sensitive = any(kw in body.lower() for kw in ["api_key", "password", "secret", "token", "database_url"])
                sev = "high" if has_sensitive else "medium"
                findings.append({
                    "finding_id": "VDBIR-WEB-001-{}".format(name),
                    "severity": sev,
                    "category": "initial_access",
                    "technique": "T1078",
                    "title": "{} ({}) responds 200 without auth{}".format(name, url, " — LEAKS SENSITIVE DATA" if has_sensitive else ""),
                    "description": HEURISTIC_MAP["VDBIR-WEB-001"]["description"],
                    "evidence": json.dumps({"url": url, "status": resp.status, "body_preview": body[:200], "has_sensitive": has_sensitive}),
                    "affected_asset": url,
                    "heuristic_source": "verizon_dbir",
                    "remediation": "Add bearer token auth or VPN-only binding. Sensitive data in responses requires auth + TLS.",
                })
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                pass
        except Exception:
            pass
    return findings


def scan_http_info_disclosure():
    """VDBIR-ERR-001: Test error responses for information leaks."""
    findings = []
    probe_paths = [
        "/nonexistent", "/../etc/passwd", "/admin", "/debug",
        "/v1/messages?model='; DROP TABLE--", "/state/../../etc/shadow",
    ]
    services = [
        ("luxagentos", "http://127.0.0.1:8742"),
        ("llm-gateway", "http://127.0.0.1:8760"),
        ("state-keeper", "http://127.0.0.1:8770"),
    ]
    for svc_name, base in services:
        for path in probe_paths:
            try:
                url = base + path
                req = urllib.request.Request(url, method="GET")
                resp = urllib.request.urlopen(req, timeout=3)
                body = resp.read(4096).decode(errors="replace")
                if any(kw in body.lower() for kw in ["traceback", "stack trace", "exception", "/home/", "/usr/", "psycopg2", "file \""]):
                    findings.append({
                        "finding_id": "VDBIR-ERR-001-{}-{}".format(svc_name, hashlib.md5(path.encode()).hexdigest()[:8]),
                        "severity": "medium",
                        "category": "reconnaissance",
                        "technique": "T1082",
                        "title": "{} leaks internal details on error path: {}".format(svc_name, path),
                        "description": HEURISTIC_MAP["VDBIR-ERR-001"]["description"],
                        "evidence": json.dumps({"url": url, "body_preview": body[:300]}),
                        "affected_asset": base,
                        "heuristic_source": "verizon_dbir",
                        "remediation": "Return generic error pages. Never expose stack traces, file paths, or library names in HTTP responses.",
                    })
            except Exception:
                pass
    return findings


def scan_db_role_isolation():
    """VDBIR-PRIV-001: Verify fleet_svc cannot DELETE from protected tables."""
    findings = []
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("SELECT current_user")
        role = cur.fetchone()[0]
        if role == "luxagent":
            findings.append({
                "finding_id": "VDBIR-PRIV-001-god-mode",
                "severity": "critical",
                "category": "privilege_escalation",
                "technique": "T1548",
                "title": "Security scanner running as luxagent (god-mode role)",
                "description": HEURISTIC_MAP["VDBIR-PRIV-001"]["description"],
                "evidence": json.dumps({"current_role": role}),
                "affected_asset": "postgresql",
                "heuristic_source": "verizon_dbir",
                "remediation": "Run all fleet services as fleet_svc per your DB role separation policy. Never use luxagent for automated services.",
            })

        try:
            cur.execute("SAVEPOINT role_test")
            cur.execute("DELETE FROM knowledge_artifacts WHERE 1=0")
            cur.execute("ROLLBACK TO role_test")
            findings.append({
                "finding_id": "VDBIR-PRIV-001-delete-allowed",
                "severity": "critical",
                "category": "privilege_escalation",
                "technique": "T1548",
                "title": "Current DB role CAN delete from knowledge_artifacts",
                "description": HEURISTIC_MAP["VDBIR-PRIV-001"]["description"],
                "evidence": json.dumps({"role": role, "operation": "DELETE on knowledge_artifacts succeeded (0 rows, but permission granted)"}),
                "affected_asset": "postgresql",
                "heuristic_source": "verizon_dbir",
                "remediation": "REVOKE DELETE ON knowledge_artifacts FROM {};".format(role),
            })
        except psycopg2.Error:
            cur.execute("ROLLBACK TO role_test")

        conn.close()
    except Exception as e:
        print("[sentinel] DB role scan error: {}".format(e), file=sys.stderr)
    return findings


def scan_systemd_services():
    """MITRE-T1543: Check for unauthorized systemd services."""
    findings = []
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"],
            text=True, timeout=10
        )
        running = set()
        for line in out.strip().split("\n"):
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                name = parts[0].replace(".service", "")
                running.add(name)

        unknown = []
        for svc in running:
            normalized = svc.lower().replace("-", "").replace("_", "")
            is_known = any(
                known.lower().replace("-", "").replace("_", "") in normalized or normalized in known.lower().replace("-", "").replace("_", "")
                for known in KNOWN_SERVICES
            )
            is_system = any(svc.startswith(p) for p in (
                "systemd", "dbus", "cron", "ssh", "network", "snap", "polkit",
                "multipathd", "rsyslog", "ufw", "unattended", "ModemManager",
                "accounts", "getty", "docker", "containerd", "tailscaled",
                "user@", "udisks", "packagekit", "thermald", "irq", "plymouth",
                "power", "wpa_supplicant", "bluetooth", "cups", "avahi",
                "colord", "fwupd", "kerneloops", "switcheroo", "bolt",
            ))
            if not is_known and not is_system:
                unknown.append(svc)

        if unknown:
            findings.append({
                "finding_id": "MITRE-T1543-unknown-services",
                "severity": "medium",
                "category": "persistence",
                "technique": "T1543.002",
                "title": "{} running services not in known registry".format(len(unknown)),
                "description": HEURISTIC_MAP["MITRE-T1543"]["description"],
                "evidence": json.dumps({"unknown_services": unknown}),
                "affected_asset": "systemd",
                "heuristic_source": "mitre",
                "remediation": "Investigate each unknown service. Add to KNOWN_SERVICES if authorized, or disable.",
            })
    except Exception as e:
        print("[sentinel] systemd scan error: {}".format(e), file=sys.stderr)
    return findings


def scan_llm_log_anomalies():
    """VDBIR-TIME-001 + custom: Check LLM call logs for anomalous patterns."""
    findings = []
    try:
        conn = db_conn()
        cur = conn.cursor()

        cur.execute("""
            SELECT bot_id, COUNT(*) as calls,
                   SUM(CASE WHEN response IS NULL THEN 1 ELSE 0 END) as errors,
                   MAX(cost_usd) as max_single_cost
            FROM llm_call_log
            WHERE created_at > now() - interval '24 hours'
            GROUP BY bot_id
            ORDER BY errors DESC
        """)
        rows = cur.fetchall()

        for r in rows:
            error_rate = r["errors"] / r["calls"] if r["calls"] > 0 else 0
            if error_rate > 0.5 and r["calls"] >= 5:
                findings.append({
                    "finding_id": "ANOMALY-ERR-RATE-{}".format(r["bot_id"]),
                    "severity": "medium",
                    "category": "anomaly",
                    "technique": "TA0040",
                    "title": "Bot {} has {:.0%} error rate ({}/{} calls in 24h)".format(
                        r["bot_id"], error_rate, r["errors"], r["calls"]),
                    "description": "High error rates may indicate misconfiguration, compromised prompts, or targeted DoS.",
                    "evidence": json.dumps(dict(r)),
                    "affected_asset": "bot:{}".format(r["bot_id"]),
                    "heuristic_source": "custom",
                    "remediation": "Investigate bot {} dispatch logs and task payloads for anomalies.".format(r["bot_id"]),
                })

            if r["max_single_cost"] and float(r["max_single_cost"]) > 2.0:
                findings.append({
                    "finding_id": "ANOMALY-COST-SPIKE-{}".format(r["bot_id"]),
                    "severity": "high",
                    "category": "impact",
                    "technique": "T1499",
                    "title": "Bot {} single call cost ${:.2f} (spend cap attack vector)".format(
                        r["bot_id"], float(r["max_single_cost"])),
                    "description": "Unusually expensive single calls may indicate prompt injection causing max-token responses or repeated retries.",
                    "evidence": json.dumps(dict(r)),
                    "affected_asset": "bot:{}".format(r["bot_id"]),
                    "heuristic_source": "paloalto",
                    "remediation": "Review bot task payloads. Add per-call cost ceiling in gateway.",
                })

        cur.execute("""
            SELECT COUNT(*) as total_calls,
                   SUM(cost_usd) as total_spend,
                   AVG(cost_usd) as avg_cost
            FROM llm_call_log
            WHERE created_at > now() - interval '24 hours'
        """)
        summary = cur.fetchone()
        conn.close()

        if summary and summary["total_spend"]:
            record_metric(db_conn(), "daily_llm_spend", float(summary["total_spend"]))
            record_metric(db_conn(), "daily_llm_calls", float(summary["total_calls"]))
    except Exception as e:
        print("[sentinel] LLM log anomaly scan error: {}".format(e), file=sys.stderr)
    return findings


# ── Main Scan Orchestrator ────────────────────────────────────────

def run_full_scan():
    global _findings_cache, _metrics_cache, _last_scan_ts, _scan_count

    print("[sentinel] Starting security scan #{}...".format(_scan_count + 1), file=sys.stderr)
    start = time.time()
    all_findings = []

    scanners = [
        ("credential_exposure", scan_credential_exposure),
        ("file_permissions", scan_file_permissions),
        ("port_exposure", scan_port_exposure),
        ("nats_auth", scan_nats_auth),
        ("http_auth", scan_http_auth),
        ("http_info_disclosure", scan_http_info_disclosure),
        ("db_role_isolation", scan_db_role_isolation),
        ("systemd_services", scan_systemd_services),
        ("llm_log_anomalies", scan_llm_log_anomalies),
    ]

    for name, scanner in scanners:
        try:
            findings = scanner()
            all_findings.extend(findings)
            print("[sentinel] {} scan: {} findings".format(name, len(findings)), file=sys.stderr)
        except Exception as e:
            print("[sentinel] {} scan FAILED: {}".format(name, e), file=sys.stderr)

    conn = db_conn()
    for f in all_findings:
        try:
            upsert_finding(conn, f)
        except Exception as e:
            print("[sentinel] upsert error: {}".format(e), file=sys.stderr)

    by_severity = {}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    duration = time.time() - start
    _scan_count += 1
    _last_scan_ts = time.time()
    _findings_cache = all_findings
    _metrics_cache = {
        "scan_count": _scan_count,
        "last_scan_duration_s": round(duration, 1),
        "last_scan_ts": datetime.now(timezone.utc).isoformat(),
        "findings_by_severity": by_severity,
        "total_findings": len(all_findings),
    }

    record_metric(conn, "scan_duration_s", duration)
    record_metric(conn, "total_findings", len(all_findings), by_severity)
    conn.close()

    summary = "scan #{} complete: {} findings ({}) in {:.1f}s".format(
        _scan_count, len(all_findings),
        ", ".join("{}={}".format(k, v) for k, v in sorted(by_severity.items())),
        duration,
    )
    print("[sentinel] {}".format(summary), file=sys.stderr)

    critical = [f for f in all_findings if f["severity"] in ("critical", "high")]
    if critical:
        nats_publish("security.sentinel.alert", {
            "type": "scan_alert",
            "critical_count": len([f for f in critical if f["severity"] == "critical"]),
            "high_count": len([f for f in critical if f["severity"] == "high"]),
            "findings": [{"id": f["finding_id"], "title": f["title"], "severity": f["severity"]} for f in critical],
            "ts": datetime.now(timezone.utc).isoformat(),
        })

    nats_publish("security.sentinel.scan", {
        "type": "scan_complete",
        "scan_number": _scan_count,
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "duration_s": round(duration, 1),
        "ts": datetime.now(timezone.utc).isoformat(),
    })

    return all_findings


# ── HTTP Health Server ────────────────────────────────────────────

class SentinelHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({
                "status": "ok",
                "agent": "lux-sentinel",
                "scan_count": _scan_count,
                "last_scan": _metrics_cache.get("last_scan_ts", "never"),
                "uptime_s": int(time.time() - _start_time),
            })
            self.send_response(200)
        elif self.path == "/findings":
            body = json.dumps({
                "findings": _findings_cache,
                "count": len(_findings_cache),
                "scan_ts": _metrics_cache.get("last_scan_ts", "never"),
            })
            self.send_response(200)
        elif self.path == "/metrics":
            body = json.dumps(_metrics_cache)
            self.send_response(200)
        elif self.path == "/heuristics":
            body = json.dumps(HEURISTICS)
            self.send_response(200)
        else:
            body = json.dumps({"error": "not found"})
            self.send_response(404)

        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())


def start_http():
    server = HTTPServer(("127.0.0.1", PORT), SentinelHandler)
    server.serve_forever()


# ── Main ──────────────────────────────────────────────────────────

_start_time = time.time()
_reload = False

def handle_sighup(sig, frame):
    global _reload
    _reload = True
    print("[sentinel] SIGHUP received — will rescan on next cycle", file=sys.stderr)

def main():
    global _reload
    signal.signal(signal.SIGHUP, handle_sighup)

    print("[sentinel] LuxSentinel starting on :{} (scan every {}s)".format(PORT, SCAN_INTERVAL), file=sys.stderr)
    print("[sentinel] Heuristic sources: {} PAN, {} VDBIR, {} MITRE".format(
        len([h for h in HEURISTICS if h["source"] == "paloalto"]),
        len([h for h in HEURISTICS if h["source"] == "verizon_dbir"]),
        len([h for h in HEURISTICS if h["source"] == "mitre"]),
    ), file=sys.stderr)

    Thread(target=start_http, daemon=True).start()

    run_full_scan()

    while True:
        try:
            time.sleep(SCAN_INTERVAL)
            if _reload:
                print("[sentinel] Reload triggered — running immediate scan", file=sys.stderr)
                _reload = False
            run_full_scan()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print("[sentinel] scan loop error: {}".format(e), file=sys.stderr)
            time.sleep(60)


if __name__ == "__main__":
    main()