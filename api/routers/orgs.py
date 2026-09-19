"""api/routers/orgs.py — org list, detail, and LLM endpoints."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from api.models import (
    LLMResult, OrgListItem, OrgListResponse, OrgSummary, Signal, StatsResponse,
)
from llm.client import LLMClient, format_org_profile

router  = APIRouter(prefix="/orgs", tags=["orgs"])
DB_PATH = Path(os.getenv("DB_PATH", "data/orgs.db"))
_llm: LLMClient | None = None


def _db() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="Database not found. Run: python -m pipeline.ingest --input <path>",
        )
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _get_llm() -> LLMClient:
    global _llm
    if _llm is None:
        _llm = LLMClient()
    return _llm


def _parse_json(val, default=None):
    if default is None:
        default = []
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val or json.dumps(default))
    except Exception:
        return default


def _row_to_list_item(row) -> OrgListItem:
    signals = _parse_json(row["signals"], {})
    return OrgListItem(
        id=row["id"],
        name=row["name"],
        isp=row["isp"] or "",
        countries=_parse_json(row["countries"]),
        total_ips=row["total_ips"],
        attack_surface_score=row["attack_surface_score"],
        has_eol_product=bool(row["has_eol_product"]),
        has_self_signed=bool(row["has_self_signed"]),
        has_iot=bool(row["has_iot"]),
        has_vulns=bool(row["has_vulns"]),
        has_risky_port=bool(row["has_risky_port"]),
        signal_labels=[v.get("label", k) for k, v in signals.items()],
        last_seen=row["last_seen"],
    )


def _row_to_summary(row) -> OrgSummary:
    signals_raw = _parse_json(row["signals"], {})
    signals = {k: Signal(**v) for k, v in signals_raw.items() if isinstance(v, dict)}
    return OrgSummary(
        id=row["id"],
        name=row["name"],
        isp=row["isp"] or "",
        countries=_parse_json(row["countries"]),
        total_ips=row["total_ips"],
        total_records=row["total_records"],
        exposed_ports=_parse_json(row["exposed_ports"]),
        risky_ports=_parse_json(row["risky_ports"]),
        products=_parse_json(row["products"]),
        tech_stack=_parse_json(row["tech_stack"], {}),
        domains=_parse_json(row["domains"]),
        has_vulns=bool(row["has_vulns"]),
        vuln_ids=_parse_json(row["vuln_ids"]),
        has_eol_product=bool(row["has_eol_product"]),
        has_self_signed=bool(row["has_self_signed"]),
        has_iot=bool(row["has_iot"]),
        has_vpn=bool(row["has_vpn"]),
        has_honeypot=bool(row["has_honeypot"]),
        has_risky_port=bool(row["has_risky_port"]),
        http_200_count=row["http_200_count"],
        http_auth_count=row["http_auth_count"],
        attack_surface_score=row["attack_surface_score"],
        signals=signals,
        last_seen=row["last_seen"],
    )


@router.get("/", response_model=OrgListResponse)
def list_orgs(
    page:            int   = Query(1, ge=1),
    per_page:        int   = Query(50, ge=1, le=200),
    min_score:       float = Query(0, ge=0, le=100),
    country:         Optional[str]  = None,
    has_eol:         Optional[bool] = None,
    has_self_signed: Optional[bool] = None,
    has_iot:         Optional[bool] = None,
    has_vulns:       Optional[bool] = None,
    has_risky_port:  Optional[bool] = None,
    search:          Optional[str]  = None,
    sort_by:         str  = Query("attack_surface_score"),
    sort_dir:        str  = Query("desc"),
):
    allowed_sort = {"attack_surface_score", "total_ips", "total_records", "name"}
    if sort_by not in allowed_sort:
        sort_by = "attack_surface_score"
    direction = "DESC" if sort_dir.lower() == "desc" else "ASC"

    where_clauses = ["attack_surface_score >= ?"]
    params: list = [min_score]

    if has_eol is not None:
        where_clauses.append("has_eol_product = ?")
        params.append(int(has_eol))
    if has_self_signed is not None:
        where_clauses.append("has_self_signed = ?")
        params.append(int(has_self_signed))
    if has_iot is not None:
        where_clauses.append("has_iot = ?")
        params.append(int(has_iot))
    if has_vulns is not None:
        where_clauses.append("has_vulns = ?")
        params.append(int(has_vulns))
    if has_risky_port is not None:
        where_clauses.append("has_risky_port = ?")
        params.append(int(has_risky_port))
    if country:
        where_clauses.append("countries LIKE ?")
        params.append(f"%{country}%")
    if search:
        where_clauses.append("name LIKE ?")
        params.append(f"%{search}%")

    where = " AND ".join(where_clauses)
    offset = (page - 1) * per_page

    conn = _db()
    total = conn.execute(f"SELECT COUNT(*) FROM orgs WHERE {where}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM orgs WHERE {where} ORDER BY {sort_by} {direction} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    conn.close()

    return OrgListResponse(
        total    = total,
        page     = page,
        per_page = per_page,
        items    = [_row_to_list_item(r) for r in rows],
    )


@router.get("/stats", response_model=StatsResponse)
def stats():
    conn = _db()
    row = conn.execute("""
        SELECT
            COUNT(*)                              AS total_orgs,
            SUM(attack_surface_score >= 80)       AS critical_count,
            SUM(attack_surface_score >= 60)       AS high_count,
            SUM(has_eol_product)                  AS eol_count,
            SUM(has_vulns)                        AS vuln_count,
            SUM(has_risky_port)                   AS risky_port_count
        FROM orgs
    """).fetchone()
    countries = [
        r[0] for r in conn.execute(
            "SELECT DISTINCT json_each.value FROM orgs, json_each(countries) ORDER BY 1"
        ).fetchall()
    ]
    top_isps = [
        {"isp": r[0], "count": r[1]}
        for r in conn.execute(
            "SELECT isp, COUNT(*) c FROM orgs WHERE isp != '' GROUP BY isp ORDER BY c DESC LIMIT 10"
        ).fetchall()
    ]
    conn.close()
    return StatsResponse(
        total_orgs=row[0] or 0,
        critical_count=row[1] or 0,
        high_count=row[2] or 0,
        eol_count=row[3] or 0,
        vuln_count=row[4] or 0,
        risky_port_count=row[5] or 0,
        countries=countries,
        top_isps=top_isps,
    )


@router.get("/{org_id}", response_model=OrgSummary)
def get_org(org_id: int):
    conn = _db()
    row  = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Org not found")
    return _row_to_summary(row)


@router.post("/{org_id}/summary", response_model=LLMResult)
def generate_summary(org_id: int, prompt_version: int = 1):
    conn = _db()
    row  = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Org not found")

    profile = format_org_profile(dict(row))
    result  = _get_llm().account_summary(row["name"], profile, prompt_version)
    return LLMResult(
        text           = result["text"],
        cached         = result.get("cached", False),
        prompt_version = result.get("prompt_version", prompt_version),
        model          = result.get("model"),
        cost_usd       = result.get("cost_usd"),
        latency_ms     = result.get("latency_ms"),
    )


@router.post("/{org_id}/outreach", response_model=LLMResult)
def generate_outreach(org_id: int, prompt_version: int = 1):
    conn = _db()
    row  = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Org not found")

    profile = format_org_profile(dict(row))
    result  = _get_llm().outreach_draft(row["name"], profile, prompt_version)
    return LLMResult(
        text           = result["text"],
        cached         = result.get("cached", False),
        prompt_version = result.get("prompt_version", prompt_version),
        model          = result.get("model"),
        cost_usd       = result.get("cost_usd"),
        latency_ms     = result.get("latency_ms"),
    )
