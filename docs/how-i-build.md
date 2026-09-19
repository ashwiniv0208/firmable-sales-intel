# How I Build — Process Notes

## First Move: Understand the Data Before Writing a Line of Code

When I got the dataset, I didn't reach for a schema or start scaffolding. I opened it first.

The file was named `dataset.csv.zst` but the extension is a lie — it's zstd-compressed JSONL, and the first record tells you everything you need to know about how to structure the whole system. One record showed:

- `http.html` at 2,407 bytes of inline page HTML — that's going to be 100+ GB uncompressed. Skip it in ingest.
- `http.components` with Wappalyzer fingerprints (tech stack detection) — that's real signal.
- `cpe23` with CPE strings — those map directly to the NVD vulnerability database.
- `_shodan.module` — the probe type per record, useful for filtering.
- `org` field on every record — that's how we group IPs into companies.

The 30 minutes spent understanding the data structure saved 8 hours of wrong-direction work. The sample CSV that was provided was a pre-flattened subset; the real file is richer and more complex.

## The Rule/LLM Split Was the First Real Decision

I knew I'd use LLMs, but the first question was: *what specifically shouldn't be LLM?*

My instinct: anything deterministic should be a rule. Ports are either risky or they're not. Tags are either present or absent. CVEs either appear in the Shodan vuln field or they don't. These are binary facts — running them through a language model adds cost, latency, and hallucination risk with no upside.

LLMs earn their place only where the output genuinely requires synthesis across multiple signals into something a human will read and act on. The 2-3 sentence account summary and the personalised outreach email both require that. The scoring formula doesn't.

This led to a clean architecture: the pipeline is entirely rule-based, the API exposes LLM endpoints separately, and the UI only calls them on explicit user action (button click) rather than on page load.

## Two Models for Two Different Jobs

I chose Haiku for summaries and Sonnet for outreach, not to cut costs (though that helps), but because the jobs are different:

**Summary (Haiku):** The format is strict — 2-3 sentences, specific structure, no hedging. Haiku follows a tight format well and is fast enough to feel real-time. I cache results in SQLite, so cost per *impression* is near zero after the first generation.

**Outreach (Sonnet):** Cold email copywriting requires judgement. The difference between a Haiku-quality cold email and a Sonnet-quality one is the difference between a rep sending it and deleting it. Sonnet is only called on demand, so the higher per-call cost is justified.

## Prompt Versioning Was Non-Negotiable

Prompts live in `prompts/<name>/v{n}.txt`. Every LLM call logs the prompt version, and the cache key includes it. This means:

- You can run v1 and v2 prompts side by side, compare outputs on the same org
- `evals/run_evals.py --version 2` diffs against v1 automatically
- A re-ingest doesn't silently use stale prompts

The eval harness (25 labeled examples, recall/precision/hallucination metrics) came before the final prompt. I wrote the examples first, then tuned the prompt until the metrics were acceptable. Working the other direction — prompt first, eval later — tends to produce prompts that are brittle in production.

## What I'd Change for Production

**Org deduplication:** Grouping by the `org` string is naive. "Google LLC", "Google LLC.", and "Google Inc" are three separate orgs in the current system. A normalisation pass with a known-alias table would dramatically improve precision.

**Freshness decay:** A port open 6 months ago may be closed now. I documented the fix: multiply the score by `max(0.5, 1 - days_since_scan / 180)`. It wasn't worth building for a prototype, but it matters for trust at scale.

**Cloud provider false positives:** AWS, Cloudflare, and Akamai appear as `org` for customer IPs. A simple org-name blocklist removes most of the noise. I noted it in the architecture doc and the SKILL.md but didn't implement it — the eval set doesn't contain enough cloud-provider examples to catch it, which is a gap in the labeled set.

**The thing I'd prototype differently:** I built the ingest pipeline before the UI. That meant I was working against synthetic test data for most of the build. I should have built a stub DB loader with 100 fake rows first, validated the entire UI and API surface, then plugged in the real ingest. It's faster to catch API design mistakes when you're not also debugging streaming decompression at the same time.
