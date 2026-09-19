"""
llm/client.py — Google GenAI (new SDK) version
"""
from __future__ import annotations
import json, os, sqlite3, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from google import genai
from google.genai import types
from llm import prompt_loader

SUMMARY_MODEL  = "gemini-3.6-flash"
OUTREACH_MODEL = "gemini-3.6-flash"
_PRICE = {"gemini-2.0-flash": {"input": 0.075e-6, "output": 0.30e-6}}
TRACE_LOG = Path("data/llm_traces.jsonl")
DB_PATH   = Path(os.getenv("DB_PATH", "data/orgs.db"))

class LLMClient:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError("GEMINI_API_KEY not set in .env")
        self._client = genai.Client(api_key=api_key)
        TRACE_LOG.parent.mkdir(parents=True, exist_ok=True)

    def account_summary(self, org_name, org_profile, prompt_version=1):
        return self._call("summary", org_name, org_profile, "account-summary", prompt_version, SUMMARY_MODEL, 1024)

    def outreach_draft(self, org_name, org_profile, prompt_version=1):
        return self._call("outreach", org_name, org_profile, "outreach-draft", prompt_version, OUTREACH_MODEL, 1024)

    def _call(self, task, org_name, user_content, prompt_name, prompt_version, model_name, max_tokens):
        cached = self._cache_get(org_name, task, prompt_version)
        if cached:
            return {"text": cached, "cached": True}

        system_prompt = prompt_loader.load(prompt_name, prompt_version)
        trace_id = str(uuid.uuid4())
        t0 = time.perf_counter()

        try:
            response = self._client.models.generate_content(
                model=model_name,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=max_tokens,
                ),
            )
            latency_ms    = round((time.perf_counter() - t0) * 1000)
            output_text   = response.text
            input_tokens  = response.usage_metadata.prompt_token_count or 0
            output_tokens = response.usage_metadata.candidates_token_count or 0
            price         = _PRICE.get(model_name, {"input": 0, "output": 0})
            cost_usd      = round(input_tokens * price["input"] + output_tokens * price["output"], 6)

            self._write_trace({"trace_id": trace_id, "timestamp": _now(), "org_name": org_name,
                               "task": task, "model": model_name, "input_tokens": input_tokens,
                               "output_tokens": output_tokens, "latency_ms": latency_ms,
                               "cost_usd": cost_usd, "status": "ok"})
            self._cache_set(org_name, task, prompt_version, model_name, output_text, input_tokens, output_tokens, cost_usd)
            return {"text": output_text, "cached": False, "trace_id": trace_id,
                    "cost_usd": cost_usd, "latency_ms": latency_ms,
                    "prompt_version": prompt_version, "model": model_name}

        except Exception as exc:
            self._write_trace({"trace_id": trace_id, "timestamp": _now(), "org_name": org_name,
                               "task": task, "model": model_name, "status": "error", "error": str(exc)})
            raise

    def _write_trace(self, trace):
        with open(TRACE_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(trace) + "\n")

    def _cache_get(self, org_name, task, version):
        try:
            conn = sqlite3.connect(str(DB_PATH))
            row  = conn.execute("SELECT output FROM llm_cache WHERE org_name=? AND task=? AND prompt_version=?",
                                (org_name, task, version)).fetchone()
            conn.close()
            return row[0] if row else None
        except Exception:
            return None

    def _cache_set(self, org_name, task, version, model, output, in_tok, out_tok, cost):
        try:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("INSERT OR REPLACE INTO llm_cache (org_name, task, prompt_version, model, output, input_tokens, output_tokens, cost_usd) VALUES (?,?,?,?,?,?,?,?)",
                         (org_name, task, version, model, output, in_tok, out_tok, cost))
            conn.commit(); conn.close()
        except Exception:
            pass

def _now():
    return datetime.now(timezone.utc).isoformat()

def format_org_profile(row: dict) -> str:
    def _j(val, default="[]"):
        if isinstance(val, (list, dict)): return val
        try: return json.loads(val or default)
        except: return []
    lines = [
        f"Organisation: {row['name']}",
        f"Countries: {', '.join(_j(row.get('countries'))) or 'Unknown'}",
        f"ISP: {row.get('isp') or 'Unknown'}", "",
        f"Attack Surface",
        f"  Exposed IPs: {row.get('total_ips', 0)}",
        f"  Exposed ports: {', '.join(str(p) for p in _j(row.get('exposed_ports'))) or 'none'}",
    ]
    risky = _j(row.get("risky_ports"))
    if risky: lines.append(f"  HIGH-RISK ports: {', '.join(str(p) for p in risky)}")
    products = _j(row.get("products"))
    if products: lines.append(f"  Software: {', '.join(products[:8])}")
    lines += ["", "Security Signals",
        f"  End-of-life software: {'YES' if row.get('has_eol_product') else 'no'}",
        f"  Self-signed TLS:      {'YES' if row.get('has_self_signed') else 'no'}",
        f"  IoT exposed:          {'YES' if row.get('has_iot') else 'no'}",
        f"  VPN visible:          {'YES' if row.get('has_vpn') else 'no'}",
        f"  Honeypot activity:    {'YES' if row.get('has_honeypot') else 'no'}",
    ]
    vuln_ids = _j(row.get("vuln_ids"))
    if vuln_ids: lines.append(f"  Known CVEs: {', '.join(vuln_ids[:5])}")
    lines.append(f"  Open HTTP (no auth): {row.get('http_200_count', 0)}")
    lines.append(f"Attack Surface Score: {row.get('attack_surface_score', 0)}/100")
    return "\n".join(lines)