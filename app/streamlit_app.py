"""
app/streamlit_app.py

Streamlit sales intelligence UI.

Run:
    streamlit run app/streamlit_app.py

Reads directly from SQLite for the prospect table.
Calls the FastAPI backend for LLM features (summary, outreach).
If the API is unreachable, LLM buttons degrade gracefully.
"""

from __future__ import annotations

import sys
sys.path.insert(0, str(__file__).rsplit("app", 1)[0])
import json
import os
import sqlite3
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

DB_PATH      = Path(os.getenv("DB_PATH", "data/orgs.db"))
API_BASE     = os.getenv("API_BASE_URL", "http://localhost:8000")
SUMMARY_VER  = 1
OUTREACH_VER = 1

st.set_page_config(
    page_title = "Firmable — Sales Intelligence",
    page_icon  = "🛡️",
    layout     = "wide",
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection | None:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _j(val, default=None):
    if default is None:
        default = []
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val or json.dumps(default))
    except Exception:
        return default


def _score_badge(score: float) -> str:
    if score >= 80:
        return f"🔴 {score:.0f}"
    if score >= 60:
        return f"🟠 {score:.0f}"
    if score >= 35:
        return f"🟡 {score:.0f}"
    return f"🟢 {score:.0f}"


def _tier(score: float) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 35: return "Medium"
    return "Low"


def _signal_chips(row) -> str:
    chips = []
    if row.get("has_eol_product"):  chips.append("EOL Software")
    if row.get("has_vulns"):        chips.append("Known CVEs")
    if row.get("has_risky_port"):   chips.append("Risky Ports")
    if row.get("has_self_signed"):  chips.append("Self-Signed")
    if row.get("has_iot"):          chips.append("IoT")
    if row.get("has_vpn"):          chips.append("VPN Exposed")
    if row.get("has_honeypot"):     chips.append("Honeypot")
    return "  ·  ".join(chips) if chips else "—"


@st.cache_data(ttl=60)
def load_orgs(
    min_score: float,
    countries: list[str],
    f_eol: bool,
    f_self_signed: bool,
    f_iot: bool,
    f_vulns: bool,
    f_risky: bool,
    search: str,
) -> list[dict]:
    conn = _db()
    if not conn:
        return []

    clauses = ["attack_surface_score >= ?"]
    params: list = [min_score]

    if f_eol:          clauses.append("has_eol_product = 1")
    if f_self_signed:  clauses.append("has_self_signed = 1")
    if f_iot:          clauses.append("has_iot = 1")
    if f_vulns:        clauses.append("has_vulns = 1")
    if f_risky:        clauses.append("has_risky_port = 1")
    if search:
        clauses.append("name LIKE ?")
        params.append(f"%{search}%")
    if countries:
        country_filter = " OR ".join(["countries LIKE ?"] * len(countries))
        clauses.append(f"({country_filter})")
        params.extend([f"%{c}%" for c in countries])

    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT * FROM orgs WHERE {where} ORDER BY attack_surface_score DESC LIMIT 500",
        params,
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@st.cache_data(ttl=300)
def load_countries() -> list[str]:
    conn = _db()
    if not conn:
        return []
    rows = conn.execute(
        "SELECT DISTINCT json_each.value FROM orgs, json_each(countries) ORDER BY 1"
    ).fetchall()
    conn.close()
    return [r[0] for r in rows if r[0]]


@st.cache_data(ttl=300)
def load_stats() -> dict:
    conn = _db()
    if not conn:
        return {}
    row = conn.execute("""
        SELECT
            COUNT(*)                        AS total,
            SUM(attack_surface_score >= 80) AS critical,
            SUM(attack_surface_score >= 60) AS high,
            SUM(has_eol_product)            AS eol,
            SUM(has_vulns)                  AS vulns
        FROM orgs
    """).fetchone()
    conn.close()
    return dict(row) if row else {}


def call_api(endpoint: str, method="POST") -> dict | None:
    try:
        url  = f"{API_BASE}{endpoint}"
        resp = (requests.post if method == "POST" else requests.get)(url, timeout=120)
        if resp.status_code == 200:
            return resp.json()
        st.error(f"API error {resp.status_code}: {resp.text[:200]}")
    except requests.exceptions.ConnectionError:
        st.error(
            "⚠️ FastAPI backend not reachable. "
            "Start it with: `uvicorn api.main:app --port 8000`"
        )
    return None


# ── Page ─────────────────────────────────────────────────────────────────────

def main():
    # ── Header ───────────────────────────────────────────────────────────────
    st.title("🛡️ Firmable Sales Intelligence")
    st.caption(
        "Identify and prioritise businesses most likely to need cybersecurity software — "
        "powered by internet-exposure signals from live scan data."
    )

    if not DB_PATH.exists():
        st.warning(
            "**No database found.** Run the ingest pipeline first:\n\n"
            "```bash\n"
            "python -m pipeline.ingest --input /path/to/dataset.csv.zst\n"
            "```"
        )
        st.stop()

    # ── Sidebar filters ───────────────────────────────────────────────────────
    with st.sidebar:
        st.header("🎯 Filter Prospects")

        min_score = st.slider("Min Priority Score", 0, 100, 30, step=5)
        search    = st.text_input("🔍 Company name", placeholder="e.g. Acme Corp")

        countries_all = load_countries()
        sel_countries = st.multiselect("Country", countries_all)

        st.markdown("---")
        st.subheader("Security Signals")
        f_eol         = st.checkbox("🔴 End-of-Life Software")
        f_self_signed = st.checkbox("🟡 Self-Signed Certs")
        f_iot         = st.checkbox("📡 IoT Exposure")
        f_vulns       = st.checkbox("🐛 Known CVEs")
        f_risky       = st.checkbox("🚪 High-Risk Ports")

        st.markdown("---")
        st.caption(
            "**Score guide**\n\n"
            "🔴 80+ Critical · 🟠 60+ High\n\n"
            "🟡 35+ Medium · 🟢 <35 Low"
        )

    # ── Summary metrics ───────────────────────────────────────────────────────
    stats   = load_stats()
    orgs    = load_orgs(min_score, sel_countries, f_eol, f_self_signed, f_iot, f_vulns, f_risky, search)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total in DB",    f"{stats.get('total', 0):,}")
    c2.metric("Matching",       f"{len(orgs):,}")
    c3.metric("🔴 Critical",    f"{stats.get('critical', 0):,}")
    c4.metric("EOL Software",   f"{stats.get('eol', 0):,}")
    c5.metric("Known CVEs",     f"{stats.get('vulns', 0):,}")

    st.markdown("---")

    if not orgs:
        st.info("No prospects match the current filters.")
        return

    # ── Prospect table ────────────────────────────────────────────────────────
    st.subheader(f"🎯 Prospects ({len(orgs):,})")

    display_rows = []
    for o in orgs:
        countries = _j(o.get("countries"))
        display_rows.append({
            "Company":       o["name"],
            "Score":         o["attack_surface_score"],
            "Priority":      _tier(o["attack_surface_score"]),
            "Country":       ", ".join(countries[:2]) if countries else "—",
            "Signals":       _signal_chips(o),
            "Exposed IPs":   o["total_ips"],
            "Last Seen":     (o.get("last_seen") or "")[:10],
            "_id":           o["id"],
        })

    df = pd.DataFrame(display_rows)

    event = st.dataframe(
        df.drop(columns=["_id"]),
        use_container_width=True,
        selection_mode="single-row",
        on_select="rerun",
        key="prospect_table",
        column_config={
            "Score": st.column_config.ProgressColumn(
                "Score", min_value=0, max_value=100, format="%.0f"
            ),
        },
        height=400,
    )

    # ── Drilldown ─────────────────────────────────────────────────────────────
    selected = event.selection.rows  # type: ignore[attr-defined]
    if not selected:
        st.caption("👆 Click a row to see the full account profile and generate outreach.")
        return

    idx = selected[0]
    org = orgs[idx]
    org_id = org["id"]

    st.markdown("---")
    st.subheader(f"📋 {org['name']}")

    left, right = st.columns([3, 2])

    with left:
        # Signal breakdown
        signals = _j(org.get("signals"), {})
        if signals:
            st.markdown("**🚨 Attack Surface Signals**")
            for key, sig in signals.items():
                if isinstance(sig, dict):
                    label  = sig.get("label", key)
                    weight = sig.get("weight", 0)
                    detail = sig.get("detail", "")
                    st.markdown(f"- **{label}** *(+{weight:.0f} pts)*  \n  {detail}")
        else:
            st.info("No significant signals detected.")

        # Score breakdown
        score = org["attack_surface_score"]
        st.metric("Priority Score", f"{score:.0f} / 100", delta=_tier(score))

    with right:
        countries = _j(org.get("countries"))
        st.markdown(f"**🌍 Countries:** {', '.join(countries) or '—'}")
        st.markdown(f"**🏢 ISP:** {org.get('isp') or '—'}")
        st.markdown(f"**📡 Exposed IPs:** {org['total_ips']}")

        risky = _j(org.get("risky_ports"))
        if risky:
            
            port_names = [str(p) for p in risky]
            st.markdown(f"**⚠️ Risky Ports:** {', '.join(port_names)}")

        products = _j(org.get("products"))
        if products:
            st.markdown(f"**🔧 Detected Software:** {', '.join(products[:6])}")

        domains = _j(org.get("domains"))
        if domains:
            st.markdown(f"**🌐 Domains:** {', '.join(domains[:4])}")

        vuln_ids = _j(org.get("vuln_ids"))
        if vuln_ids:
            st.markdown(f"**🐛 CVEs:** {', '.join(vuln_ids[:5])}")

    # ── LLM Features ─────────────────────────────────────────────────────────
    st.markdown("---")
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**🤖 Account Intelligence Summary**")
        st.caption("2-3 sentence brief for a sales rep. Haiku model, cached after first run.")
        if st.button("Generate Summary", key=f"sum_{org_id}"):
            with st.spinner("Generating..."):
                result = call_api(f"/orgs/{org_id}/summary?prompt_version={SUMMARY_VER}")
            if result:
                st.markdown(result["text"])
                if not result.get("cached"):
                    st.caption(
                        f"Model: {result.get('model')}  |  "
                        f"Cost: ${result.get('cost_usd', 0):.5f}  |  "
                        f"Latency: {result.get('latency_ms')}ms"
                    )

    with col_b:
        st.markdown("**✉️ Draft Cold Outreach**")
        st.caption("Personalised first-touch email referencing actual exposure signals. Sonnet model.")
        if st.button("Draft Outreach Email", key=f"out_{org_id}"):
            with st.spinner("Drafting..."):
                result = call_api(f"/orgs/{org_id}/outreach?prompt_version={OUTREACH_VER}")
            if result:
                st.code(result["text"], language=None)
                if not result.get("cached"):
                    st.caption(
                        f"Model: {result.get('model')}  |  "
                        f"Cost: ${result.get('cost_usd', 0):.5f}  |  "
                        f"Latency: {result.get('latency_ms')}ms"
                    )



main()
