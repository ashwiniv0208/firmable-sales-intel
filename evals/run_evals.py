#!/usr/bin/env python3
"""
evals/run_evals.py

One-command eval harness for the account-summary LLM feature.

Usage:
    python evals/run_evals.py                  # run with latest prompt version
    python evals/run_evals.py --version 2      # run with a specific prompt version
    python evals/run_evals.py --dry-run        # show what would be evaluated, no API calls

What it measures:
    Recall    — fraction of expected_signals keywords that appear in the LLM output
    Precision — signals mentioned in output that are real (not forbidden hallucinations)
    Sales angle present — does the output end with an actionable pitch?
    Length OK — is the output 2–4 sentences?

Results are written to evals/results/v{version}_{timestamp}.json
and diffed against the previous run (if one exists) so you can track regressions.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import re
from datetime import datetime, timezone
from pathlib import Path

# Make sure we can import from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from llm.client import LLMClient, format_org_profile
from llm.prompt_loader import load, latest_version

EVALS_DIR   = Path(__file__).parent
RESULTS_DIR = EVALS_DIR / "results"
LABELED_SET = EVALS_DIR / "labeled_set.jsonl"

RESULTS_DIR.mkdir(exist_ok=True)

# Keywords that indicate a sales angle is present at the end of the summary
_SALES_KEYWORDS = [
    "conversation", "pitch", "priorit", "recommend", "approach",
    "management", "protection", "detection", "security", "compliance",
    "remediation", "entry point", "opening", "engage", "urgent",
]


def load_examples() -> list[dict]:
    examples = []
    with open(LABELED_SET, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    return examples


def score_output(output: str, example: dict) -> dict:
    """
    Score a single LLM output against the labeled example.
    Returns a dict of per-metric scores.
    """
    output_lower = output.lower()

    # Recall: fraction of expected signals mentioned
    expected = example.get("expected_signals", [])
    expected_hits = [s for s in expected if s.lower() in output_lower]
    recall = len(expected_hits) / len(expected) if expected else 1.0

    # Precision: no forbidden hallucinations
    forbidden = example.get("forbidden_hallucinations", [])
    hallucinations = [s for s in forbidden if s.lower() in output_lower]
    no_hallucination = len(hallucinations) == 0
    precision = 1.0 - (len(hallucinations) / len(forbidden)) if forbidden else 1.0

    # Sales angle: does output end with actionable language?
    last_sentence = output.strip().split(".")[-2] if "." in output else output
    has_sales_angle = any(kw in last_sentence.lower() for kw in _SALES_KEYWORDS)

    # Length: 2–4 sentences
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", output.strip()) if s.strip()]
    length_ok = 2 <= len(sentences) <= 4

    return {
        "recall":           round(recall, 3),
        "precision":        round(precision, 3),
        "no_hallucination": no_hallucination,
        "has_sales_angle":  has_sales_angle,
        "length_ok":        length_ok,
        "expected_hits":    expected_hits,
        "hallucinations":   hallucinations,
        "sentence_count":   len(sentences),
    }


def run_evals(prompt_version: int, dry_run: bool = False) -> dict:
    examples = load_examples()
    print(f"\n{'=' * 60}")
    print(f"  Account-Summary Eval — Prompt v{prompt_version}")
    print(f"  {len(examples)} examples  |  {'DRY RUN' if dry_run else 'LIVE API'}")
    print(f"{'=' * 60}\n")

    # Sanity-check prompt exists
    try:
        system_prompt = load("account-summary", prompt_version)
        print(f"  Prompt loaded: prompts/account-summary/v{prompt_version}.txt")
        print(f"  First 80 chars: {system_prompt[:80]}...\n")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    if dry_run:
        print("  [dry-run] Skipping API calls. Showing expected signal breakdown:\n")
        for ex in examples:
            print(f"  #{ex['id']:02d} {ex['org_profile']['name']}")
            print(f"       expect: {ex['expected_signals'][:5]}")
            print(f"       forbid: {ex.get('forbidden_hallucinations', [])[:5]}\n")
        return {}

    llm = LLMClient()
    results = []
    total_cost = 0.0

    for i, ex in enumerate(examples, 1):
        org = ex["org_profile"]
        org_name = org["name"]

        print(f"  [{i:02d}/{len(examples)}] {org_name} ... ", end="", flush=True)

        try:
            profile = format_org_profile(org)
            response = llm.account_summary(org_name, profile, prompt_version)
            output   = response["text"]
            cost     = response.get("cost_usd", 0) or 0
            total_cost += cost
            cached   = response.get("cached", False)
        except Exception as exc:
            print(f"ERROR: {exc}")
            results.append({
                "id":      ex["id"],
                "org":     org_name,
                "status":  "error",
                "error":   str(exc),
            })
            continue

        metrics = score_output(output, ex)
        result  = {
            "id":             ex["id"],
            "org":            org_name,
            "status":         "ok",
            "cached":         cached,
            "output":         output,
            "cost_usd":       cost,
            **metrics,
        }
        results.append(result)

        recall_pct = f"{metrics['recall'] * 100:.0f}%"
        prec_pct   = f"{metrics['precision'] * 100:.0f}%"
        flags = (
            ("✅" if metrics["no_hallucination"] else "❌ HALLUC")
            + ("  ✅SA" if metrics["has_sales_angle"] else "  ❌SA")
            + ("  ✅LEN" if metrics["length_ok"] else "  ❌LEN")
        )
        print(f"recall={recall_pct}  prec={prec_pct}  {flags}")

    # ── Aggregate metrics ────────────────────────────────────────────────────
    ok_results = [r for r in results if r.get("status") == "ok"]
    agg = {
        "prompt_version":         prompt_version,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "n_examples":             len(examples),
        "n_ok":                   len(ok_results),
        "mean_recall":            round(sum(r["recall"] for r in ok_results) / max(len(ok_results), 1), 3),
        "mean_precision":         round(sum(r["precision"] for r in ok_results) / max(len(ok_results), 1), 3),
        "hallucination_rate":     round(sum(0 if r["no_hallucination"] else 1 for r in ok_results) / max(len(ok_results), 1), 3),
        "sales_angle_rate":       round(sum(r["has_sales_angle"] for r in ok_results) / max(len(ok_results), 1), 3),
        "length_ok_rate":         round(sum(r["length_ok"] for r in ok_results) / max(len(ok_results), 1), 3),
        "total_cost_usd":         round(total_cost, 5),
        "results":                results,
    }

    # ── Save results ──────────────────────────────────────────────────────────
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = RESULTS_DIR / f"v{prompt_version}_{ts}.json"
    out_path.write_text(json.dumps(agg, indent=2))

    # ── Print summary ─────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"  RESULTS — Prompt v{prompt_version}")
    print(f"{'─' * 60}")
    print(f"  Mean recall:       {agg['mean_recall'] * 100:.1f}%")
    print(f"  Mean precision:    {agg['mean_precision'] * 100:.1f}%")
    print(f"  Hallucination rate:{agg['hallucination_rate'] * 100:.1f}%  (lower is better)")
    print(f"  Sales angle rate:  {agg['sales_angle_rate'] * 100:.1f}%")
    print(f"  Length OK rate:    {agg['length_ok_rate'] * 100:.1f}%")
    print(f"  Total API cost:    ${agg['total_cost_usd']:.5f}")
    print(f"  Results saved:     {out_path}\n")

    # ── Diff against previous version ──────────────────────────────────────────
    prev_results = sorted(
        [p for p in RESULTS_DIR.glob(f"v{prompt_version - 1}_*.json")],
        reverse=True,
    )
    if prev_results and prompt_version > 1:
        prev = json.loads(prev_results[0].read_text())
        print(f"  ── Diff vs v{prompt_version - 1} ({prev_results[0].name}) ──")
        for key in ("mean_recall", "mean_precision", "hallucination_rate", "sales_angle_rate"):
            delta = agg[key] - prev[key]
            symbol = "▲" if delta > 0 else ("▼" if delta < 0 else "→")
            print(f"  {key:25s}: {prev[key] * 100:.1f}% → {agg[key] * 100:.1f}%  {symbol}{abs(delta) * 100:.1f}%")
        print()

    return agg


def main():
    ap = argparse.ArgumentParser(description="Run account-summary evals")
    ap.add_argument(
        "--version", type=int, default=None,
        help="Prompt version to evaluate (default: latest)"
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Print examples without making API calls"
    )
    args = ap.parse_args()

    version = args.version or latest_version("account-summary")
    run_evals(version, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
