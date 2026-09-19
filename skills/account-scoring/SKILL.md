---
skill: account-scoring
version: 1
description: Score an organisation's cybersecurity sales priority from internet exposure data
trigger: >
  Run this skill whenever you need to assess whether an organisation is a
  qualified cybersecurity sales prospect, given Shodan-style internet scan data.
  Trigger conditions: a new batch of orgs has been ingested, a salesperson asks
  "is this account worth pursuing?", or a scoring threshold needs to be recalibrated.
inputs:
  - org_row: dict — one row from the `orgs` SQLite table, or equivalent fields
outputs:
  - score: float — 0-100 attack surface priority score
  - signals: dict — contributing signals with labels, weights, and detail strings
  - tier: str — "Critical" | "High" | "Medium" | "Low"
dependencies:
  - pipeline/scorer.py       # rule-based scoring logic (no LLM)
  - pipeline/schema.sql      # org table definition
cost: $0 — no LLM calls; pure rules
latency: <1ms per org
---

# Account Scoring Skill

## Purpose

Convert raw internet-exposure signals into a priority score (0–100) that tells
a cybersecurity sales team which organisations to call first.

Higher score = more detectable pain = more urgent prospect.
This is **not** a general business fitness score — it specifically measures
how exposed and how under-secured an organisation's internet footprint is.

## Scoring Formula

Each signal contributes a fixed weight; raw scores are capped at 100.

| Signal                        | Max weight | Source field         |
|-------------------------------|-----------|----------------------|
| Known CVEs (Shodan vuln data) | 30        | `has_vulns`, `vuln_ids` |
| End-of-life software          | 28        | `has_eol_product`    |
| High-risk ports exposed       | 24        | `risky_ports`        |
| Self-signed TLS certs         | 14        | `has_self_signed`    |
| IoT devices exposed           | 12        | `has_iot`            |
| VPN infrastructure visible    |  8        | `has_vpn`            |
| Honeypot activity             |  8        | `has_honeypot`       |
| Attack surface breadth        | 10        | `total_ips`          |
| Open HTTP services            |  5        | `http_200_count`     |

High-risk ports include: Telnet (23), FTP (21), SMB (445), RDP (3389),
MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017),
Elasticsearch (9200), Docker API (2375), and others (see `pipeline/scorer.py`).

## Priority Tiers

| Tier     | Score | Sales action                              |
|----------|-------|-------------------------------------------|
| Critical | ≥ 80  | Call today; assign to senior AE           |
| High     | ≥ 60  | Sequence within 48 hours                  |
| Medium   | ≥ 35  | Add to nurture; personalise outreach      |
| Low      | < 35  | Deprioritise; revisit if signals change   |

## Invocation

### From Python (pipeline or API):
```python
from pipeline.scorer import score_org_record, score_tier

row = {
    "has_eol_product": 1,
    "has_vulns": 0,
    "has_self_signed": 1,
    "has_iot": 0,
    "has_vpn": 0,
    "has_honeypot": 0,
    "has_risky_port": 1,
    "risky_ports": "[3389, 1433]",
    "vuln_ids": "[]",
    "total_ips": 12,
    "http_200_count": 5,
}

score, signals = score_org_record(row)
tier = score_tier(score)

print(f"Score: {score}/100  Tier: {tier}")
for key, sig in signals.items():
    print(f"  {sig['label']} (+{sig['weight']} pts)")
```

### Expected output for the example above:
```
Score: 72.0/100  Tier: High

  End-of-Life Software Detected (+28 pts)
  2 High-Risk Service(s) Exposed (+16 pts)
  Self-Signed TLS Certificates (+14 pts)
  12 Publicly Exposed IPs (+5.4 pts)
  5 Unauthenticated HTTP Service(s) (+2.5 pts)
```

### From the CLI (batch re-score after formula change):
```bash
python - << 'EOF'
import sqlite3, json
from pipeline.scorer import score_org_record

conn = sqlite3.connect("data/orgs.db")
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT * FROM orgs").fetchall()
for row in rows:
    score, signals = score_org_record(dict(row))
    conn.execute(
        "UPDATE orgs SET attack_surface_score=?, signals=? WHERE id=?",
        (score, json.dumps(signals), row["id"])
    )
conn.commit()
print(f"Re-scored {len(rows)} orgs")
EOF
```

## Known Weaknesses

1. **No industry weighting**: A 55-point retail org and a 55-point defence
   contractor have the same score, but the defence contractor is a far hotter
   prospect. Industry context requires a firmographic enrichment step (not yet
   implemented).

2. **Scan freshness not penalised**: An org scanned 6 months ago with a high
   score may have remediated. The `last_seen` field exists but isn't factored
   into the score. Consider applying a decay multiplier for stale records.

3. **Cloud provider false positives**: Google, AWS, and Cloudflare IP ranges
   sometimes resolve to the cloud provider's org rather than the customer.
   Large cloud orgs with high scores are likely false positives. A blocklist
   of known cloud provider org names is recommended.

## Recalibration

Edit weights in `pipeline/scorer.py` and re-run the batch re-score script above.
After recalibrating, re-run `python evals/run_evals.py` to check that high-risk
orgs still surface correctly and low-risk orgs don't false-positive.
