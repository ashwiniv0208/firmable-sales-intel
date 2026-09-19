#!/usr/bin/env python3
"""
pipeline/ingest.py

Stream-decompress a zstd-compressed Shodan JSONL export,
aggregate per-organisation stats, and write to SQLite.

Never holds more than FLUSH_EVERY records in memory at once — safe on
machines with <8 GB RAM even against the full 11.5 GB source file.

Usage:
    python -m pipeline.ingest --input /path/to/dataset.csv.zst
    python -m pipeline.ingest --input /path/to/dataset.csv.zst --db data/orgs.db --limit 500000
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

import zstandard as zstd
from tqdm import tqdm

from pipeline.scorer import score_org_record

# ── Config ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

FLUSH_EVERY = 250_000  # flush accumulator to SQLite after this many parsed records
READ_CHUNK  = 1 << 20  # 1 MB decompression chunks

# Ports that represent serious exposure when internet-facing
RISKY_PORTS: frozenset[int] = frozenset({
    21, 23, 25, 111, 135, 137, 139, 445, 512, 513, 514,
    1433, 1521, 2375, 2376, 3306, 3389, 4444,
    5432, 5555, 5900, 5901, 6379, 7001,
    9200, 9300, 11211, 27017, 28017, 50070,
})


# ── Field extraction ────────────────────────────────────────────────────────

def _parse_tags(raw) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if t]
    return [t.strip() for t in str(raw).split(",") if t.strip()]


def extract_fields(obj: dict) -> dict | None:
    """
    Pull only the fields we care about from a raw Shodan JSONL record.
    Crucially skips http.html (can be 200 KB per record) to keep memory sane.
    Returns None if the org field is missing/empty — those rows can't be grouped.
    """
    org = (obj.get("org") or "").strip()
    if not org:
        return None

    location  = obj.get("location") or {}
    http      = obj.get("http") or {}
    shodan    = obj.get("_shodan") or {}

    # Wappalyzer-style tech fingerprint embedded in http.components
    components: dict[str, list] = {}
    for tech, info in (http.get("components") or {}).items():
        cats = info.get("categories", []) if isinstance(info, dict) else []
        components[tech] = cats

    # ip_str is canonical in Shodan exports; integer `ip` is the fallback
    ip_str = obj.get("ip_str") or str(obj.get("ip", ""))

    return {
        "ip":          ip_str,
        "port":        obj.get("port"),
        "org":         org,
        "isp":         (obj.get("isp") or "").strip(),
        "product":     (obj.get("product") or "").strip(),
        "country":     (location.get("country_name") or "").strip(),
        "http_status": http.get("status"),
        "tags":        _parse_tags(obj.get("tags")),
        "timestamp":   obj.get("timestamp") or "",
        "cpe23":       obj.get("cpe23") or [],
        "vuln_ids":    list((obj.get("vulns") or {}).keys()),
        "domains":     obj.get("domains") or [],
        "components":  components,
        "module":      (shodan.get("module") or ""),
    }


# ── Per-org accumulator ──────────────────────────────────────────────────────

class OrgAccumulator:
    """
    Holds in-memory stats for each org as records stream in.
    Designed to be flushed and reset periodically to cap RAM usage.
    """

    def __init__(self):
        self._data: dict[str, dict] = {}

    def _new_slot(self, name: str) -> dict:
        return {
            "name":         name,
            "isps":         defaultdict(int),
            "countries":    set(),
            "ips":          set(),
            "total_records": 0,
            "ports":        set(),
            "risky_ports":  set(),
            "products":     set(),
            "tech_stack":   defaultdict(set),   # tech → set of category strings
            "cpe23":        set(),
            "domains":      set(),
            "vuln_ids":     set(),
            "tags_seen":    set(),
            "http_200":     0,
            "http_auth":    0,
            "last_seen":    "",
        }

    def add(self, rec: dict):
        name = rec["org"]
        if name not in self._data:
            self._data[name] = self._new_slot(name)
        o = self._data[name]

        if rec["isp"]:
            o["isps"][rec["isp"]] += 1
        if rec["country"]:
            o["countries"].add(rec["country"])
        if rec["ip"]:
            o["ips"].add(rec["ip"])

        o["total_records"] += 1

        port = rec["port"]
        if port:
            o["ports"].add(port)
            if port in RISKY_PORTS:
                o["risky_ports"].add(port)

        if rec["product"]:
            o["products"].add(rec["product"])

        for tech, cats in rec["components"].items():
            o["tech_stack"][tech].update(cats)

        o["cpe23"].update(rec["cpe23"])
        o["domains"].update(rec["domains"])
        o["vuln_ids"].update(rec["vuln_ids"])
        o["tags_seen"].update(rec["tags"])

        status = rec["http_status"]
        if status == 200:
            o["http_200"] += 1
        elif status in (401, 407):
            o["http_auth"] += 1

        ts = rec["timestamp"]
        if ts and ts > o["last_seen"]:
            o["last_seen"] = ts

    def finalise(self) -> list[dict]:
        """Convert accumulator state to flat dicts ready for SQLite upsert."""
        rows = []
        for name, o in self._data.items():
            top_isp = max(o["isps"], key=o["isps"].get) if o["isps"] else ""
            tags    = o["tags_seen"]

            row = {
                "name":              name,
                "isp":               top_isp,
                "countries":         json.dumps(sorted(o["countries"])),
                "total_ips":         len(o["ips"]),
                "total_records":     o["total_records"],
                "exposed_ports":     json.dumps(sorted(o["ports"])),
                "risky_ports":       json.dumps(sorted(o["risky_ports"])),
                "products":          json.dumps(sorted(o["products"])),
                "tech_stack":        json.dumps({k: sorted(v) for k, v in o["tech_stack"].items()}),
                "cpe23_list":        json.dumps(sorted(o["cpe23"])),
                "domains":           json.dumps(sorted(o["domains"])),
                "has_vulns":         int(bool(o["vuln_ids"])),
                "vuln_ids":          json.dumps(sorted(o["vuln_ids"])),
                "has_eol_product":   int("eol-product" in tags),
                "has_self_signed":   int("self-signed" in tags),
                "has_iot":           int("iot" in tags),
                "has_vpn":           int("vpn" in tags),
                "has_honeypot":      int("honeypot" in tags),
                "has_risky_port":    int(bool(o["risky_ports"])),
                "http_200_count":    o["http_200"],
                "http_auth_count":   o["http_auth"],
                "last_seen":         o["last_seen"],
            }

            score, signals = score_org_record(row)
            row["attack_surface_score"] = score
            row["signals"]              = json.dumps(signals)

            rows.append(row)
        return rows


# ── SQLite helpers ───────────────────────────────────────────────────────────

def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    schema = (Path(__file__).parent / "schema.sql").read_text()
    conn.executescript(schema)
    conn.commit()
    return conn


_UPSERT = """
INSERT INTO orgs (
    name, isp, countries, total_ips, total_records,
    exposed_ports, risky_ports, products, tech_stack,
    cpe23_list, domains, has_vulns, vuln_ids,
    has_eol_product, has_self_signed, has_iot, has_vpn, has_honeypot,
    has_risky_port, http_200_count, http_auth_count,
    attack_surface_score, signals, last_seen
) VALUES (
    :name, :isp, :countries, :total_ips, :total_records,
    :exposed_ports, :risky_ports, :products, :tech_stack,
    :cpe23_list, :domains, :has_vulns, :vuln_ids,
    :has_eol_product, :has_self_signed, :has_iot, :has_vpn, :has_honeypot,
    :has_risky_port, :http_200_count, :http_auth_count,
    :attack_surface_score, :signals, :last_seen
)
ON CONFLICT(name) DO UPDATE SET
    total_records        = total_records        + excluded.total_records,
    total_ips            = MAX(total_ips,          excluded.total_ips),
    has_vulns            = MAX(has_vulns,           excluded.has_vulns),
    has_eol_product      = MAX(has_eol_product,     excluded.has_eol_product),
    has_self_signed      = MAX(has_self_signed,      excluded.has_self_signed),
    has_iot              = MAX(has_iot,              excluded.has_iot),
    has_vpn              = MAX(has_vpn,              excluded.has_vpn),
    has_honeypot         = MAX(has_honeypot,         excluded.has_honeypot),
    has_risky_port       = MAX(has_risky_port,       excluded.has_risky_port),
    http_200_count       = http_200_count       + excluded.http_200_count,
    http_auth_count      = http_auth_count      + excluded.http_auth_count,
    attack_surface_score = MAX(attack_surface_score, excluded.attack_surface_score),
    last_seen            = MAX(last_seen,            excluded.last_seen)
"""


def write_batch(conn: sqlite3.Connection, rows: list[dict]):
    conn.executemany(_UPSERT, rows)
    conn.commit()


# ── Main entry point ─────────────────────────────────────────────────────────

def run(input_path: Path, db_path: Path, limit: int | None = None):
    size_gb = input_path.stat().st_size / 1e9
    log.info(f"Input:  {input_path}  ({size_gb:.2f} GB compressed)")
    log.info(f"Output: {db_path}")
    if limit:
        log.info(f"Limit:  {limit:,} records (test mode)")

    conn    = init_db(db_path)
    acc     = OrgAccumulator()
    dctx    = zstd.ZstdDecompressor()

    parsed = skipped = errors = 0

    with open(input_path, "rb") as fh:
        reader = dctx.stream_reader(fh)
        buf    = b""

        with tqdm(unit="rec", unit_scale=True, desc="Ingesting") as pbar:
            while True:
                chunk = reader.read(READ_CHUNK)
                if not chunk:
                    break
                buf += chunk

                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                        rec = extract_fields(obj)
                        if rec is None:
                            skipped += 1
                        else:
                            acc.add(rec)
                            parsed += 1
                    except Exception:
                        errors += 1

                    pbar.update(1)

                    if limit and (parsed + skipped) >= limit:
                        break

                    # Periodic flush to cap RAM
                    if parsed > 0 and parsed % FLUSH_EVERY == 0:
                        log.info(
                            f"Flushing {len(acc._data):,} orgs to SQLite "
                            f"(parsed={parsed:,}  skipped={skipped:,}  errors={errors:,})"
                        )
                        write_batch(conn, acc.finalise())
                        acc = OrgAccumulator()

                if limit and (parsed + skipped) >= limit:
                    break

    # Final flush
    if acc._data:
        write_batch(conn, acc.finalise())

    total_orgs = conn.execute("SELECT COUNT(*) FROM orgs").fetchone()[0]
    log.info("=" * 60)
    log.info(f"Done.   parsed={parsed:,}  skipped={skipped:,}  errors={errors:,}")
    log.info(f"Orgs in DB: {total_orgs:,}")
    conn.close()


def main():
    ap = argparse.ArgumentParser(description="Ingest Shodan JSONL.zst → SQLite")
    ap.add_argument("--input",  required=True, type=Path, help="Path to dataset.csv.zst")
    ap.add_argument("--db",     default=Path("data/orgs.db"), type=Path)
    ap.add_argument("--limit",  type=int, default=None,
                    help="Stop after N lines — for quick smoke-test runs")
    args = ap.parse_args()
    run(args.input, args.db, args.limit)


if __name__ == "__main__":
    main()
