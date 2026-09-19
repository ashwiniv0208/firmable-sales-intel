"""api/models.py — Pydantic response models."""

from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class Signal(BaseModel):
    label:  str
    weight: float
    detail: Any = None


class OrgSummary(BaseModel):
    id:                   int
    name:                 str
    isp:                  str
    countries:            list[str]
    total_ips:            int
    total_records:        int
    exposed_ports:        list[int]
    risky_ports:          list[int]
    products:             list[str]
    tech_stack:           dict[str, list[str]]
    domains:              list[str]
    has_vulns:            bool
    vuln_ids:             list[str]
    has_eol_product:      bool
    has_self_signed:      bool
    has_iot:              bool
    has_vpn:              bool
    has_honeypot:         bool
    has_risky_port:       bool
    http_200_count:       int
    http_auth_count:      int
    attack_surface_score: float
    signals:              dict[str, Signal]
    last_seen:            str | None


class OrgListItem(BaseModel):
    id:                   int
    name:                 str
    isp:                  str
    countries:            list[str]
    total_ips:            int
    attack_surface_score: float
    has_eol_product:      bool
    has_self_signed:      bool
    has_iot:              bool
    has_vulns:            bool
    has_risky_port:       bool
    signal_labels:        list[str]
    last_seen:            str | None


class OrgListResponse(BaseModel):
    total:    int
    page:     int
    per_page: int
    items:    list[OrgListItem]


class LLMResult(BaseModel):
    text:           str
    cached:         bool
    prompt_version: int | None = None
    model:          str | None = None
    cost_usd:       float | None = None
    latency_ms:     int | None = None


class StatsResponse(BaseModel):
    total_orgs:       int
    critical_count:   int   # score >= 80
    high_count:       int   # score >= 60
    eol_count:        int
    vuln_count:       int
    risky_port_count: int
    countries:        list[str]
    top_isps:         list[dict]
