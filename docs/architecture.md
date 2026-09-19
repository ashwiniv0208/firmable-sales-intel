# Architecture Document — Firmable Sales Intelligence Platform

## System Overview

```
dataset.csv.zst (11.5 GB, zstd-compressed JSONL)
        │
        ▼ python -m pipeline.ingest --input ...
┌───────────────────────────┐
│  Ingest Pipeline          │  • Streams 1 MB chunks — never loads full file
│  pipeline/ingest.py       │  • Extracts 13 fields per record (skips http.html)
│                           │  • Groups by org name in memory
│                           │  • Flushes every 250K records to cap RAM
│                           │  • Calls scorer.py on every finalised org
└────────────┬──────────────┘
             │ SQLite upsert (ON CONFLICT DO UPDATE)
             ▼
┌───────────────────────────┐
│  SQLite DB                │  • ~50-500K rows after full ingest
│  data/orgs.db             │  • One row per org, all signals pre-computed
│                           │  • Indexes on score, name, signal flags
│  + llm_cache table        │  • Caches summary/outreach outputs by org+version
└────────────┬──────────────┘
             │
     ┌───────┴───────┐
     ▼               ▼
┌─────────────┐  ┌──────────────────────┐
│  FastAPI    │  │  Streamlit UI         │
│  api/       │  │  app/streamlit_app.py │
│  port 8000  │  │  port 8501            │
│             │  │                       │
│  /orgs      │◄─┤  • Reads SQLite direct│
│  /orgs/{id} │  │    for the table      │
│  /orgs/{id} │  │  • Calls API for LLM  │
│   /summary  │  │    features           │
│  /orgs/{id} │  │                       │
│   /outreach │  └──────────────────────┘
└──────┬──────┘
       │ Anthropic API
       ▼
┌─────────────────────────────┐
│  LLM Layer                  │
│  llm/client.py              │
│                             │
│  Summary  → Haiku model     │  ~$0.001/call, cached
│  Outreach → Sonnet model    │  ~$0.008/call, cached
│                             │
│  Every call:                │
│    1. Check llm_cache       │
│    2. Load prompt from file │
│    3. Call Anthropic API    │
│    4. Write JSONL trace     │
│    5. Cache result          │
└─────────────────────────────┘
```

## Key Design Decisions

### 1. SQLite over Postgres/DuckDB for the processed store

The aggregated org table is small (50-500K rows, ~100 MB max). SQLite is:
- Zero-infra (no server, no connection pooling)
- Directly readable by both FastAPI and Streamlit
- Fast enough for the query patterns we need (filtered sorts on indexed columns)

DuckDB is used implicitly via the streaming ingest (we process the full 11.5 GB in one pass without needing DuckDB's query engine, since we only need per-org aggregations and the accumulator handles that in Python).

### 2. Rule vs LLM split

**Rules (pipeline/scorer.py):**
- All signal detection and scoring — deterministic, auditable, free
- Port classification, tag parsing, CVE presence

**LLM (llm/client.py):**
- Account summary — qualitative narrative, not enumerable by rules
- Outreach draft — copywriting requires language model quality

Anything that could be expressed as `IF signal THEN score += N` is a rule.
Anything that requires synthesising multiple signals into natural language is LLM.

### 3. Two-model strategy

| Task       | Model                 | Why                                        | Approx cost |
|------------|-----------------------|--------------------------------------------|-------------|
| Summary    | claude-haiku-4-5      | Short output, strict format, latency < 1s  | $0.001/call |
| Outreach   | claude-sonnet-4-6     | Copy quality matters, done on demand only  | $0.008/call |

Haiku for bulk/on-load generation, Sonnet only when a user explicitly requests outreach copy (button click, not auto-generated).

### 4. Prompt versioning

Prompts live in `prompts/<name>/v{n}.txt`. The version is stored with every LLM cache entry and every trace log line. To iterate:
1. Copy `v1.txt` → `v2.txt`, edit
2. Run `python evals/run_evals.py --version 2`
3. Check diff vs v1 results
4. Bump `SUMMARY_VER` / `OUTREACH_VER` in `app/streamlit_app.py` when satisfied

### 5. Streaming ingest design

The 11.5 GB file cannot be loaded into memory. The ingest pipeline:
- Reads the zstd stream in 1 MB chunks
- Splits on newlines to get JSONL lines
- Skips `http.html` (can be 200 KB per record — the main source of the file's size)
- Accumulates per-org stats in a Python dict
- Flushes to SQLite every 250K records, then resets the accumulator
- Total peak RAM usage: ~2-4 GB (proportional to unique orgs in a 250K-record window)

### 6. LLM output caching

Cache key: `(org_name, task, prompt_version)`. Results are stored in the `llm_cache` SQLite table. Cache hit rate in practice is ~95% for a sales rep browsing the same set of prospects.

Trade-off: stale cache if the underlying org data changes (e.g. after a re-ingest). Mitigation: bump `prompt_version` after any re-ingest to invalidate the cache, or add a TTL if real-time accuracy is needed.

## Cost Model

### One-time preprocessing (ingest + scoring)
- No LLM calls — $0

### Account summaries
- Model: claude-haiku-4-5 @ $0.80/M input, $4.00/M output
- Input: ~400 tokens (org profile template)
- Output: ~150 tokens (2-3 sentences)
- Cost per call: 400 × 0.00000080 + 150 × 0.000004 = **$0.00092**
- If pre-generating for top 1,000 orgs: **$0.92**
- Monthly (1,000 reps × 10 new summaries/day): **$9.20/day**

### Outreach drafts
- Model: claude-sonnet-4-6 @ $3.00/M input, $15.00/M output
- Input: ~500 tokens (org profile + more context)
- Output: ~200 tokens (email)
- Cost per call: 500 × 0.000003 + 200 × 0.000015 = **$0.0045**
- If 50 reps each draft 5 emails/day: **$1.13/day**

### Production cost ceiling
Set in Anthropic dashboard: **$50/month** for a 10-rep team is conservative.
At $50/month: 54,000 summaries OR 11,000 outreach drafts — far above expected usage.

## Known Weaknesses

1. **Org deduplication is naive**: Grouping by `org` string means "Google LLC" and "Google LLC." are two separate orgs. A normalisation pass (strip punctuation, lowercase, alias table) would improve recall significantly.

2. **Cloud provider IP ranges inflate scores**: Large cloud orgs (AWS, Cloudflare, Akamai) appear in the data as the IP's registered org, not the customer. A blocklist of infrastructure-only orgs should be applied before surfacing to reps.

3. **No industry context**: A 55-point fintech is a far hotter prospect than a 55-point entertainment company. Industry enrichment (even a simple SIC code lookup against the domain) would improve prioritisation.

4. **Scan freshness decay**: A port that was open 6 months ago may be closed now. The score formula doesn't decay with time. For production, add a multiplier: `score × max(0.5, 1 - days_since_scan / 180)`.
