"""
pipeline/scorer.py

Rule-based attack surface scoring.  No LLM — pure weighted signals.
Called by ingest.py on every finalised org row before it hits SQLite.

Score range: 0–100.  Higher = more urgent cybersecurity sales prospect.

Design rationale (see docs/architecture.md for full rule-vs-LLM split):
  Rules handle everything deterministic: known bad ports, tag flags, CVE counts.
  LLM handles qualitative synthesis: summaries, outreach copy, nuanced judgement.
"""

import json
import math


def score_org_record(row: dict) -> tuple[float, dict]:
    """
    Compute an attack surface score for a finalised org row.

    Args:
        row: dict produced by OrgAccumulator.finalise() — JSON-encoded
             list/dict fields already stringified.

    Returns:
        (score: float 0-100, signals: dict of contributing signal details)
    """
    signals: dict = {}
    raw = 0.0

    # ── Critical: known vulnerabilities (Shodan CVE data) ─────────────────
    if row.get("has_vulns"):
        vuln_ids = _loads(row.get("vuln_ids", "[]"))
        n = len(vuln_ids)
        cve_score = min(30, n * 10)
        raw += cve_score
        signals["known_cves"] = {
            "label": f"{n} Known CVE(s)",
            "weight": cve_score,
            "detail": vuln_ids[:5],
        }

    # ── Critical: end-of-life software ────────────────────────────────────
    if row.get("has_eol_product"):
        raw += 28
        signals["eol_product"] = {
            "label": "End-of-Life Software Detected",
            "weight": 28,
            "detail": "Running software past vendor support — unpatched CVEs accumulate.",
        }

    # ── High: high-risk ports exposed to the internet ─────────────────────
    risky = _loads(row.get("risky_ports", "[]"))
    if risky:
        port_score = min(24, len(risky) * 8)
        raw += port_score
        port_labels = [_PORT_LABELS.get(p, str(p)) for p in risky]
        signals["risky_ports"] = {
            "label": f"{len(risky)} High-Risk Service(s) Exposed",
            "weight": port_score,
            "detail": port_labels,
        }

    # ── Medium: self-signed TLS certificates ──────────────────────────────
    if row.get("has_self_signed"):
        raw += 14
        signals["self_signed_cert"] = {
            "label": "Self-Signed TLS Certificates",
            "weight": 14,
            "detail": "No trusted CA — susceptible to MitM; indicates weak PKI governance.",
        }

    # ── Medium: IoT devices reachable from the internet ───────────────────
    if row.get("has_iot"):
        raw += 12
        signals["iot_exposure"] = {
            "label": "IoT Devices Exposed",
            "weight": 12,
            "detail": "Unmanaged IoT = broad attack surface with minimal patching cadence.",
        }

    # ── Medium: VPN infrastructure visible ────────────────────────────────
    if row.get("has_vpn"):
        raw += 8
        signals["vpn_exposed"] = {
            "label": "VPN Infrastructure Visible",
            "weight": 8,
            "detail": "VPN endpoint fingerprint-able — credential-stuffing target.",
        }

    # ── Lower: honeypot activity (actively targeted) ──────────────────────
    if row.get("has_honeypot"):
        raw += 8
        signals["honeypot"] = {
            "label": "Honeypot Activity Detected",
            "weight": 8,
            "detail": "Active threat actor interest — already in someone's target list.",
        }

    # ── Breadth: large attack surface multiplies risk ─────────────────────
    n_ips = row.get("total_ips", 0)
    if n_ips > 5:
        breadth = min(10, math.log10(n_ips) * 5)
        raw += breadth
        signals["surface_breadth"] = {
            "label": f"{n_ips} Publicly Exposed IPs",
            "weight": round(breadth, 1),
            "detail": "Larger footprint = more entry points for attackers.",
        }

    # ── Open HTTP services (200 with no auth) ─────────────────────────────
    http_200 = row.get("http_200_count", 0)
    if http_200 > 2:
        open_score = min(5, http_200 * 0.5)
        raw += open_score
        signals["open_http_services"] = {
            "label": f"{http_200} Unauthenticated HTTP Service(s)",
            "weight": round(open_score, 1),
            "detail": "Publicly accessible web services with no authentication layer.",
        }

    score = round(min(100.0, raw), 1)
    return score, signals


def score_tier(score: float) -> str:
    """Human-readable priority tier label."""
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _loads(val) -> list:
    if isinstance(val, list):
        return val
    try:
        return json.loads(val or "[]")
    except Exception:
        return []


_PORT_LABELS: dict[int, str] = {
    21:    "FTP (21)",
    23:    "Telnet (23)",
    25:    "SMTP (25)",
    111:   "RPC (111)",
    135:   "MS-RPC (135)",
    139:   "NetBIOS (139)",
    445:   "SMB (445)",
    1433:  "MSSQL (1433)",
    1521:  "Oracle DB (1521)",
    2375:  "Docker unauthenticated (2375)",
    2376:  "Docker TLS (2376)",
    3306:  "MySQL (3306)",
    3389:  "RDP (3389)",
    4444:  "Backdoor/Metasploit (4444)",
    5432:  "PostgreSQL (5432)",
    5555:  "Android ADB (5555)",
    5900:  "VNC (5900)",
    6379:  "Redis (6379)",
    7001:  "WebLogic (7001)",
    9200:  "Elasticsearch (9200)",
    11211: "Memcached (11211)",
    27017: "MongoDB (27017)",
    50070: "Hadoop NameNode (50070)",
}
