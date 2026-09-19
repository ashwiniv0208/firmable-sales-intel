# Planning Document — Firmable Sales Intelligence Platform

## Use Cases Chosen and Why

### Use Case 1: Attack Surface Prospect Scoring
**What:** Score every organisation in the dataset on a 0–100 "cybersecurity urgency" scale derived entirely from their observable internet exposure.

**Why:** This is the core value proposition. A salesperson at a cybersecurity company doesn't want a generic CRM list — they want to know who is in pain *right now*. Internet exposure data is a unique, real-time proxy for security hygiene gaps. An org with Telnet open, MongoDB unauthenticated, and end-of-life software running is provably under-secured; that's a warmer lead than any demographic filter could produce.

**Data signals used:**
- `tags` field: `eol-product`, `self-signed`, `iot`, `vpn`, `honeypot` — tag flags from Shodan's scanner
- `vulns` field: CVE IDs matched to the detected software (Shodan cross-references CPE strings against NVD)
- `port`: high-risk ports (Telnet, FTP, SMB, RDP, Redis, MongoDB, Elasticsearch, Docker API, etc.)
- `http.status`: 200 with no auth layer = open service
- Aggregated: IP count, port diversity, domain count as proxy for attack surface breadth

**Why rules, not LLM:** Scoring is fully deterministic. A port is either risky or it isn't. CVEs are either present or absent. Rules are faster, cheaper, auditable, and don't hallucinate. The formula lives in `pipeline/scorer.py` and can be re-run over the whole DB in seconds.

---

### Use Case 2: Account Intelligence Summary
**What:** For any prospect, generate a 2–3 sentence analyst-grade summary that explains the risk signals in plain English and suggests a sales angle.

**Why:** Sales reps understand numbers in aggregate but need a narrative to open a conversation. "This company has RDP and MongoDB exposed with self-signed certs" is not a cold-call opener. "Hartwell Law Group has SMB and RDP directly internet-facing — the same vector as the 2017 WannaCry ransomware — and their TLS certificates show no PKI programme" is.

**LLM choice:** `claude-haiku-4-5` — summaries are short, the format is strict (2-3 sentences), and Haiku is fast enough for real-time generation. Outputs are cached in SQLite after first generation.

**Eval:** `evals/labeled_set.jsonl` (25 examples) measures recall of expected signals, hallucination rate, presence of a sales angle, and correct length.

---

### Use Case 3: Personalised Cold Outreach Draft
**What:** One-click generation of a personalised first-touch email that references a specific, verifiable technical observation from the prospect's exposure profile.

**Why:** Generic security outreach ("we can help you stay safe") has near-zero response rates. An email that says "We noticed your Elasticsearch index is publicly accessible from port 9200 — a configuration that has been exploited in over 3,000 documented data breaches since 2019" is specific, verifiable, and demonstrates intent without requiring a human to research each account.

**LLM choice:** `claude-sonnet-4-6` — outreach quality matters more than cost here. Haiku-quality writing feels formulaic; Sonnet produces copy that lands as peer-to-peer. Only runs on demand (button click), not in bulk.

---

### Use Case 4: Prospect Filtering and Territory Management
**What:** A filter UI that lets sales teams slice the prospect list by country, signal type, score threshold, or company name search.

**Why:** Territory segmentation is a fundamental sales ops need. A rep covering APAC doesn't want to see US accounts. A specialist in IoT security wants only IoT-flagged orgs. Pure UI/rule work — no LLM.

---

## What We Didn't Build (and Why)

**Industry classification:** We don't know what industry most orgs are in from this dataset alone — it would require external enrichment (e.g. Clearbit, Apollo). We'd score an org higher if it was in healthcare or finance (regulated = more compliance urgency), but the base exposure signals are signal enough for V1.

**Firmographic enrichment:** Revenue, headcount, funding — not in the dataset and would require paid enrichment APIs. Out of scope for a one-week prototype.

**Real-time alerting:** "Alert me when a new EOL product appears for an org I'm watching" — compelling feature, but requires a recurring pipeline job and notification infrastructure. Documented as a roadmap item.
