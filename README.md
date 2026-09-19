# Firmable Sales Intelligence Platform

AI-native platform that turns internet exposure scan data (Shodan-style JSONL) into prioritised cybersecurity sales prospects.

**Score → Summarise → Outreach** — all in one tool.

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY and dataset path
```

### 3. Run the ingest pipeline

```bash
# Full ingest (takes 20-60 min on an 11.5 GB file)
python -m pipeline.ingest --input /path/to/dataset.csv.zst

# Quick smoke test (first 500K records)
python -m pipeline.ingest --input /path/to/dataset.csv.zst --limit 500000
```

Output: `data/orgs.db` — one row per organisation, fully scored.

### 4. Start the API and UI

```bash
# Terminal 1 — FastAPI backend
uvicorn api.main:app --reload --port 8000

# Terminal 2 — Streamlit UI
streamlit run app/streamlit_app.py
```

Open **http://localhost:8501** for the UI. API docs at **http://localhost:8000/docs**.

---

## Architecture

```
Shodan JSONL.zst → pipeline/ingest.py → data/orgs.db
                                              │
                               ┌──────────────┴────────────┐
                               ▼                           ▼
                         FastAPI (8000)          Streamlit UI (8501)
                               │
                        Anthropic API
                    Haiku (summary) / Sonnet (outreach)
```

Full details: [`docs/architecture.md`](docs/architecture.md)

---

## Prompt Iteration

```bash
# Run evals on current prompt
python evals/run_evals.py

# Test a new prompt version (copy v1.txt → v2.txt, edit, then:)
python evals/run_evals.py --version 2

# Dry-run — see expected signals without making API calls
python evals/run_evals.py --dry-run
```

---

## API Reference

| Method | Endpoint                       | Description                      |
|--------|--------------------------------|----------------------------------|
| GET    | `/orgs`                        | Paginated list with filters      |
| GET    | `/orgs/stats`                  | Dataset summary statistics       |
| GET    | `/orgs/{id}`                   | Single org with all fields       |
| POST   | `/orgs/{id}/summary`           | Generate account intelligence    |
| POST   | `/orgs/{id}/outreach`          | Draft cold outreach email        |

Interactive docs: http://localhost:8000/docs

### Filter parameters (GET /orgs)

| Param          | Type    | Description                      |
|----------------|---------|----------------------------------|
| `min_score`    | float   | Minimum attack surface score     |
| `country`      | string  | Country name substring match     |
| `has_eol`      | bool    | Only EOL-software orgs           |
| `has_vulns`    | bool    | Only orgs with known CVEs        |
| `has_risky_port` | bool  | Only orgs with high-risk ports   |
| `search`       | string  | Org name substring match         |
| `sort_by`      | string  | `attack_surface_score` (default) |

---

## Hosting (free tier)

**Streamlit UI:** Deploy to [Streamlit Community Cloud](https://streamlit.io/cloud) — push to GitHub, connect repo, done.

**FastAPI backend:** Deploy to [Render.com](https://render.com) — free tier, add a `render.yaml`:
```yaml
services:
  - type: web
    name: firmable-api
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

Set `API_BASE_URL` in Streamlit secrets to point at the Render URL.

**Database:** Upload `data/orgs.db` to the Render instance, or use [Turso](https://turso.tech) (free LibSQL tier).

---

## Project Structure

```
firmable/
├── pipeline/         # Ingest + scoring — no LLM
│   ├── ingest.py     # Streaming zstd JSONL → SQLite
│   ├── scorer.py     # Rule-based attack surface scoring
│   └── schema.sql    # DB schema
├── llm/              # Anthropic wrapper + prompt loading
│   ├── client.py     # Two-model client with tracing + cache
│   └── prompt_loader.py
├── api/              # FastAPI backend
│   ├── main.py
│   ├── models.py
│   └── routers/orgs.py
├── app/
│   └── streamlit_app.py
├── prompts/          # Versioned system prompts (plain text)
├── evals/            # Labeled set + eval harness
├── skills/           # Reusable agent skill specs
└── docs/             # Planning, architecture, how-i-build
```

---

## Cost Estimate

| Feature       | Model   | Per call | 1,000 calls |
|---------------|---------|----------|-------------|
| Summary       | Haiku   | $0.001   | $1.00       |
| Outreach      | Sonnet  | $0.005   | $5.00       |
| Scoring       | —       | $0.000   | $0.00       |

Set a budget ceiling in the [Anthropic console](https://console.anthropic.com) — $50/month is comfortable for a 10-rep team.
